// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

/*
 * secure_client.c
 *
 * Small development client for the encrypted listener. It verifies the local
 * certificate, speaks the Telnet options used by the server, hides password
 * input when ECHO is negotiated, and restores the terminal before it exits.
 * Its job is local protocol testing, so the feature set stays deliberately small.
 */

#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "telnet_internal.h"
#include "terminal_text.h"

enum {
    TERMINAL_TYPE_IS = 0,
    TERMINAL_TYPE_SEND = 1,
    CHARSET_REQUEST = 1,
    CHARSET_ACCEPTED = 2,
    CHARSET_REJECTED = 3
};

/* Parser states mirror the server wire grammar for local interoperability tests. */
enum client_parse_state {
    CLIENT_DATA = 0,
    CLIENT_IAC,
    CLIENT_OPTION,
    CLIENT_SB_OPTION,
    CLIENT_SB_DATA,
    CLIENT_SB_IAC
};

/* Mutable TLS, Telnet, capability, and UTF-8 rendering state for one client. */
struct client_state {
    SSL *ssl;
    enum client_parse_state parser;
    unsigned char command;
    unsigned char sub_option;
    unsigned char sub_data[256];
    size_t sub_length;
    telnet_q options;
    int utf8_enabled;
    int charset_requested;
    int write_failed;
    unsigned char utf8_pending[4];
    size_t utf8_length;
    size_t utf8_expected;
};

static struct termios saved_terminal;
static int terminal_saved = 0;
static int local_echo_enabled = 1;
static volatile sig_atomic_t stop_requested = 0;
static volatile sig_atomic_t window_changed = 0;

#define CLIENT_HANDSHAKE_TIMEOUT_MS 10000ULL
#define CLIENT_WRITE_TIMEOUT_MS 10000ULL
#define CLIENT_SHUTDOWN_TIMEOUT_MS 3000ULL

static void request_stop(int signal_number)
{
    (void)signal_number;
    stop_requested = 1;
}

static void note_window_change(int signal_number)
{
    (void)signal_number;
    window_changed = 1;
}

static uint64_t monotonic_milliseconds(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }

    return ((uint64_t)now.tv_sec * 1000ULL) +
           ((uint64_t)now.tv_nsec / 1000000ULL);
}

static void restore_terminal(void)
{
    if (terminal_saved) {
        (void)tcsetattr(
            STDIN_FILENO,
            TCSANOW,
            &saved_terminal
        );
    }
}

static int prepare_terminal(void)
{
    if (!isatty(STDIN_FILENO)) {
        return 0;
    }

    if (tcgetattr(STDIN_FILENO, &saved_terminal) != 0) {
        perror("tcgetattr");
        return -1;
    }

    terminal_saved = 1;

    if (atexit(restore_terminal) != 0) {
        fprintf(stderr, "Unable to register terminal cleanup.\n");
        return -1;
    }

    return 0;
}

static void set_local_echo(int enabled)
{
    struct termios current;

    if (!terminal_saved || local_echo_enabled == enabled) {
        return;
    }

    if (tcgetattr(STDIN_FILENO, &current) != 0) {
        return;
    }

    if (enabled) {
        current.c_lflag |= ECHO;
    } else {
        current.c_lflag &= (tcflag_t)~ECHO;
    }

    if (tcsetattr(STDIN_FILENO, TCSANOW, &current) == 0) {
        local_echo_enabled = enabled;
    }
}

static void print_openssl_errors(const char *message)
{
    fprintf(stderr, "%s\n", message);
    ERR_print_errors_fp(stderr);
}

static int retryable_socket_error(
    int ssl_error,
    int socket_errno
)
{
    if (ssl_error == SSL_ERROR_WANT_READ ||
        ssl_error == SSL_ERROR_WANT_WRITE) {
        return 1;
    }

    if (ssl_error == SSL_ERROR_SYSCALL &&
        (socket_errno == EINTR ||
         socket_errno == EAGAIN ||
         socket_errno == EWOULDBLOCK)) {
        return 1;
    }

    return 0;
}

static int set_socket_timeout(
    int fd,
    int option,
    unsigned int timeout_ms
)
{
    struct timeval timeout;

    timeout.tv_sec = (time_t)(timeout_ms / 1000U);
    timeout.tv_usec =
        (suseconds_t)((timeout_ms % 1000U) * 1000U);

    return setsockopt(
        fd,
        SOL_SOCKET,
        option,
        &timeout,
        sizeof(timeout)
    );
}

static int tls_write_all(
    SSL *ssl,
    const unsigned char *data,
    size_t length
)
{
    uint64_t started = monotonic_milliseconds();
    size_t offset = 0;

    while (offset < length) {
        size_t written = 0;
        int result;
        int error;
        int socket_errno;

        ERR_clear_error();
        errno = 0;

        result = SSL_write_ex(
            ssl,
            data + offset,
            length - offset,
            &written
        );
        socket_errno = errno;

        if (result == 1) {
            if (written == 0) {
                return -1;
            }

            offset += written;
            continue;
        }

        error = SSL_get_error(ssl, result);

        if (retryable_socket_error(error, socket_errno)) {
            uint64_t now = monotonic_milliseconds();

            if (started != 0 &&
                now != 0 &&
                now - started < CLIENT_WRITE_TIMEOUT_MS) {
                continue;
            }
        }

        return -1;
    }

    return 0;
}

static void tls_shutdown_bounded(SSL *ssl, int fd)
{
    uint64_t started;

    if (ssl == NULL) {
        return;
    }

    (void)set_socket_timeout(fd, SO_RCVTIMEO, 1000U);
    (void)set_socket_timeout(fd, SO_SNDTIMEO, 1000U);

    started = monotonic_milliseconds();

    for (;;) {
        uint64_t now;
        int result;
        int error;
        int socket_errno;

        ERR_clear_error();
        errno = 0;
        result = SSL_shutdown(ssl);
        socket_errno = errno;

        if (result == 1) {
            return;
        }

        now = monotonic_milliseconds();

        if (started == 0 ||
            now == 0 ||
            now - started >= CLIENT_SHUTDOWN_TIMEOUT_MS) {
            return;
        }

        if (result == 0) {
            continue;
        }

        error = SSL_get_error(ssl, result);

        if (retryable_socket_error(error, socket_errno)) {
            continue;
        }

        return;
    }
}

static void q_send_callback(
    void *context,
    unsigned char command,
    unsigned char option
)
{
    struct client_state *state = context;
    const unsigned char bytes[3] = {
        TELNET_IAC,
        command,
        option
    };

    if (tls_write_all(state->ssl, bytes, sizeof(bytes)) != 0) {
        state->write_failed = 1;
    }
}

static int q_accept_callback(
    void *context,
    telnet_q_direction direction,
    unsigned char option
)
{
    (void)context;

    if (direction == TELNET_Q_LOCAL) {
        switch (option) {
            case TELNET_OPT_BINARY:
            case TELNET_OPT_SUPPRESS_GO_AHEAD:
            case TELNET_OPT_NAWS:
            case TELNET_OPT_TERMINAL_TYPE:
            case TELNET_OPT_CHARSET:
                return 1;

            default:
                return 0;
        }
    }

    switch (option) {
        case TELNET_OPT_BINARY:
        case TELNET_OPT_SUPPRESS_GO_AHEAD:
        case TELNET_OPT_ECHO:
            return 1;

        default:
            return 0;
    }
}

static int send_subnegotiation(
    struct client_state *state,
    unsigned char option,
    const unsigned char *payload,
    size_t payload_length
)
{
    const unsigned char begin[3] = {
        TELNET_IAC,
        TELNET_SB,
        option
    };
    const unsigned char end[2] = {
        TELNET_IAC,
        TELNET_SE
    };
    size_t i;

    if (tls_write_all(state->ssl, begin, sizeof(begin)) != 0) {
        return -1;
    }

    for (i = 0; i < payload_length; ++i) {
        if (payload[i] == TELNET_IAC) {
            const unsigned char escaped[2] = {
                TELNET_IAC,
                TELNET_IAC
            };
            if (tls_write_all(
                    state->ssl,
                    escaped,
                    sizeof(escaped)
                ) != 0) {
                return -1;
            }
        } else if (tls_write_all(
                       state->ssl,
                       payload + i,
                       1
                   ) != 0) {
            return -1;
        }
    }

    return tls_write_all(state->ssl, end, sizeof(end));
}

static int send_window_size(struct client_state *state)
{
    struct winsize size;
    uint16_t width = 80;
    uint16_t height = 24;
    unsigned char payload[4];

    if (!telnet_q_enabled(
            &state->options,
            TELNET_Q_LOCAL,
            TELNET_OPT_NAWS
        )) {
        return 0;
    }

    memset(&size, 0, sizeof(size));

    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &size) == 0) {
        if (size.ws_col != 0) {
            width = size.ws_col;
        }
        if (size.ws_row != 0) {
            height = size.ws_row;
        }
    }

    payload[0] = (unsigned char)(width >> 8);
    payload[1] = (unsigned char)(width & 0xff);
    payload[2] = (unsigned char)(height >> 8);
    payload[3] = (unsigned char)(height & 0xff);

    return send_subnegotiation(
        state,
        TELNET_OPT_NAWS,
        payload,
        sizeof(payload)
    );
}

static unsigned char ascii_upper(unsigned char ch)
{
    if (ch >= 'a' && ch <= 'z') {
        return (unsigned char)(ch - ('a' - 'A'));
    }

    return ch;
}

static void terminal_type_name(char output[41])
{
    const char *term = getenv("TERM");
    size_t length = 0;

    if (term != NULL) {
        while (term[length] != '\0' && length < 40) {
            unsigned char ch = (unsigned char)term[length];

            if (ch < 32 || ch > 126) {
                break;
            }

            output[length] = (char)ascii_upper(ch);
            ++length;
        }
    }

    if (length == 0) {
        memcpy(output, "UNKNOWN", sizeof("UNKNOWN"));
    } else {
        output[length] = '\0';
    }
}

static int send_terminal_type(struct client_state *state)
{
    char type[41];
    unsigned char payload[42];
    size_t length;

    terminal_type_name(type);
    length = strlen(type);

    payload[0] = TERMINAL_TYPE_IS;
    memcpy(payload + 1, type, length);

    return send_subnegotiation(
        state,
        TELNET_OPT_TERMINAL_TYPE,
        payload,
        length + 1
    );
}

static int maybe_request_utf8(struct client_state *state)
{
    const unsigned char payload[] = {
        CHARSET_REQUEST,
        ';',
        'U', 'T', 'F', '-', '8'
    };

    if (state->charset_requested ||
        !telnet_q_enabled(
            &state->options,
            TELNET_Q_LOCAL,
            TELNET_OPT_CHARSET
        ) ||
        !telnet_q_enabled(
            &state->options,
            TELNET_Q_LOCAL,
            TELNET_OPT_BINARY
        ) ||
        !telnet_q_enabled(
            &state->options,
            TELNET_Q_REMOTE,
            TELNET_OPT_BINARY
        )) {
        return 0;
    }

    state->charset_requested = 1;

    return send_subnegotiation(
        state,
        TELNET_OPT_CHARSET,
        payload,
        sizeof(payload)
    );
}


static int write_display_ascii(unsigned char byte)
{
    if ((byte >= 32 && byte <= 126) ||
        byte == '\r' ||
        byte == '\n' ||
        byte == '\t') {
        return write(STDOUT_FILENO, &byte, 1) == 1 ? 0 : -1;
    }

    return 0;
}

static int write_display_byte(
    struct client_state *state,
    unsigned char byte
)
{
    if (state->utf8_length != 0) {
        if ((byte & 0xc0) != 0x80) {
            const unsigned char replacement = '?';
            state->utf8_length = 0;
            state->utf8_expected = 0;
            if (write(STDOUT_FILENO, &replacement, 1) != 1) {
                return -1;
            }
            return write_display_byte(state, byte);
        }

        state->utf8_pending[state->utf8_length++] = byte;

        if (state->utf8_length == state->utf8_expected) {
            char safe[16];
            size_t safe_length;

            if (!terminal_text_utf8_valid(
                    state->utf8_pending,
                    state->utf8_length
                )) {
                safe[0] = '?';
                safe[1] = '\0';
                safe_length = 1;
            } else {
                safe_length = terminal_text_sanitize_utf8(
                    state->utf8_pending,
                    state->utf8_length,
                    safe,
                    sizeof(safe)
                );
            }

            if (safe_length > 0 &&
                write(
                    STDOUT_FILENO,
                    safe,
                    safe_length
                ) != (ssize_t)safe_length) {
                return -1;
            }

            state->utf8_length = 0;
            state->utf8_expected = 0;
        }

        return 0;
    }

    if (byte < 0x80) {
        return write_display_ascii(byte);
    }

    if (!state->utf8_enabled) {
        const unsigned char replacement = '?';
        return write(STDOUT_FILENO, &replacement, 1) == 1 ? 0 : -1;
    }

    if (byte >= 0xc2 && byte <= 0xdf) {
        state->utf8_expected = 2;
    } else if (byte >= 0xe0 && byte <= 0xef) {
        state->utf8_expected = 3;
    } else if (byte >= 0xf0 && byte <= 0xf4) {
        state->utf8_expected = 4;
    } else {
        const unsigned char replacement = '?';
        return write(STDOUT_FILENO, &replacement, 1) == 1 ? 0 : -1;
    }

    state->utf8_pending[0] = byte;
    state->utf8_length = 1;
    return 0;
}

static int handle_subnegotiation(struct client_state *state)
{
    if (state->sub_option == TELNET_OPT_TERMINAL_TYPE &&
        state->sub_length == 1 &&
        state->sub_data[0] == TERMINAL_TYPE_SEND &&
        telnet_q_enabled(
            &state->options,
            TELNET_Q_LOCAL,
            TELNET_OPT_TERMINAL_TYPE
        )) {
        return send_terminal_type(state);
    }

    if (state->sub_option == TELNET_OPT_CHARSET &&
        state->sub_length >= 1) {
        if (state->sub_data[0] == CHARSET_ACCEPTED &&
            state->sub_length == 6 &&
            strncasecmp(
                (const char *)state->sub_data + 1,
                "UTF-8",
                5
            ) == 0) {
            state->utf8_enabled = 1;
        } else if (state->sub_data[0] == CHARSET_REJECTED) {
            state->utf8_enabled = 0;
        }
    }

    return 0;
}

static int process_server_bytes(
    struct client_state *state,
    const unsigned char *data,
    size_t length
)
{
    size_t i;

    for (i = 0; i < length; ++i) {
        unsigned char byte = data[i];

        switch (state->parser) {
            case CLIENT_DATA:
                if (byte == TELNET_IAC) {
                    state->parser = CLIENT_IAC;
                } else if (write_display_byte(state, byte) != 0) {
                    return -1;
                }
                break;

            case CLIENT_IAC:
                if (byte == TELNET_IAC) {
                    if (write_display_byte(state, TELNET_IAC) != 0) {
                        return -1;
                    }
                    state->parser = CLIENT_DATA;
                } else if (byte == TELNET_WILL ||
                           byte == TELNET_WONT ||
                           byte == TELNET_DO ||
                           byte == TELNET_DONT) {
                    state->command = byte;
                    state->parser = CLIENT_OPTION;
                } else if (byte == TELNET_SB) {
                    state->parser = CLIENT_SB_OPTION;
                } else {
                    state->parser = CLIENT_DATA;
                }
                break;

            case CLIENT_OPTION:
            {
                int echo_before = telnet_q_enabled(
                    &state->options,
                    TELNET_Q_REMOTE,
                    TELNET_OPT_ECHO
                );
                int naws_before = telnet_q_enabled(
                    &state->options,
                    TELNET_Q_LOCAL,
                    TELNET_OPT_NAWS
                );

                telnet_q_receive(
                    &state->options,
                    state->command,
                    byte,
                    q_accept_callback,
                    state,
                    q_send_callback,
                    state
                );

                if (state->write_failed) {
                    return -1;
                }

                if (echo_before != telnet_q_enabled(
                        &state->options,
                        TELNET_Q_REMOTE,
                        TELNET_OPT_ECHO
                    )) {
                    set_local_echo(
                        !telnet_q_enabled(
                            &state->options,
                            TELNET_Q_REMOTE,
                            TELNET_OPT_ECHO
                        )
                    );
                }

                if (!naws_before &&
                    telnet_q_enabled(
                        &state->options,
                        TELNET_Q_LOCAL,
                        TELNET_OPT_NAWS
                    ) &&
                    send_window_size(state) != 0) {
                    return -1;
                }

                if (maybe_request_utf8(state) != 0) {
                    return -1;
                }

                state->parser = CLIENT_DATA;
                break;
            }

            case CLIENT_SB_OPTION:
                state->sub_option = byte;
                state->sub_length = 0;
                state->parser = CLIENT_SB_DATA;
                break;

            case CLIENT_SB_DATA:
                if (byte == TELNET_IAC) {
                    state->parser = CLIENT_SB_IAC;
                } else if (state->sub_length >= sizeof(state->sub_data)) {
                    return -1;
                } else {
                    state->sub_data[state->sub_length++] = byte;
                }
                break;

            case CLIENT_SB_IAC:
                if (byte == TELNET_SE) {
                    if (handle_subnegotiation(state) != 0) {
                        return -1;
                    }
                    state->sub_length = 0;
                    state->parser = CLIENT_DATA;
                } else if (byte == TELNET_IAC) {
                    if (state->sub_length >= sizeof(state->sub_data)) {
                        return -1;
                    }
                    state->sub_data[state->sub_length++] = TELNET_IAC;
                    state->parser = CLIENT_SB_DATA;
                } else {
                    state->parser = CLIENT_SB_DATA;
                }
                break;
        }
    }

    return 0;
}

static int send_terminal_input(
    SSL *ssl,
    const unsigned char *input,
    size_t length
)
{
    unsigned char converted[8192];
    size_t output_length = 0;
    size_t i;

    if (length > sizeof(converted) / 2) {
        return -1;
    }

    for (i = 0; i < length; ++i) {
        if (input[i] == '\n') {
            converted[output_length++] = '\r';
            converted[output_length++] = '\n';
        } else if (input[i] == TELNET_IAC) {
            converted[output_length++] = TELNET_IAC;
            converted[output_length++] = TELNET_IAC;
        } else {
            converted[output_length++] = input[i];
        }
    }

    return tls_write_all(ssl, converted, output_length);
}

static int connect_loopback(uint16_t port)
{
    int fd;
    struct sockaddr_in address;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);

    if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1) {
        close(fd);
        return -1;
    }

    if (connect(
            fd,
            (const struct sockaddr *)&address,
            sizeof(address)
        ) != 0) {
        perror("connect");
        close(fd);
        return -1;
    }

    return fd;
}

static SSL_CTX *create_client_context(const char *certificate_path)
{
    SSL_CTX *context = SSL_CTX_new(TLS_client_method());

    if (context == NULL) {
        return NULL;
    }

    if (SSL_CTX_set_min_proto_version(
            context,
            TLS1_3_VERSION
        ) != 1 ||
        SSL_CTX_set_max_proto_version(
            context,
            TLS1_3_VERSION
        ) != 1) {
        SSL_CTX_free(context);
        return NULL;
    }

    SSL_CTX_set_mode(context, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER, NULL);

    if (SSL_CTX_load_verify_locations(
            context,
            certificate_path,
            NULL
        ) != 1) {
        SSL_CTX_free(context);
        return NULL;
    }

    return context;
}

static int connect_tls(SSL *ssl)
{
    uint64_t started = monotonic_milliseconds();

    for (;;) {
        uint64_t now;
        int result;
        int error;
        int socket_errno;

        ERR_clear_error();
        errno = 0;
        result = SSL_connect(ssl);
        socket_errno = errno;

        if (result == 1) {
            return 0;
        }

        error = SSL_get_error(ssl, result);
        now = monotonic_milliseconds();

        if (started == 0 ||
            now == 0 ||
            now - started >= CLIENT_HANDSHAKE_TIMEOUT_MS) {
            return -1;
        }

        if (retryable_socket_error(error, socket_errno)) {
            continue;
        }

        return -1;
    }
}

int main(int argc, char **argv)
{
    const char *certificate_path = "local_tls/server.crt";
    const uint16_t port = 3333;
    SSL_CTX *context = NULL;
    SSL *ssl = NULL;
    int socket_fd = -1;
    int exit_code = EXIT_FAILURE;
    int handshake_complete = 0;
    int fatal_tls_error = 0;
    struct client_state state;

    memset(&state, 0, sizeof(state));
    state.parser = CLIENT_DATA;
    telnet_q_init(&state.options);

    if (argc == 2) {
        certificate_path = argv[1];
    } else if (argc != 1) {
        fprintf(
            stderr,
            "Usage: %s [trusted-certificate]\n",
            argv[0]
        );
        return EXIT_FAILURE;
    }

    if (prepare_terminal() != 0) {
        return EXIT_FAILURE;
    }

    (void)signal(SIGINT, request_stop);
    (void)signal(SIGTERM, request_stop);
    (void)signal(SIGWINCH, note_window_change);
    (void)signal(SIGPIPE, SIG_IGN);

    context = create_client_context(certificate_path);

    if (context == NULL) {
        print_openssl_errors("Unable to create the TLS client context.");
        goto cleanup;
    }

    socket_fd = connect_loopback(port);
    if (socket_fd < 0) {
        goto cleanup;
    }

    if (set_socket_timeout(socket_fd, SO_RCVTIMEO, 1000U) != 0 ||
        set_socket_timeout(socket_fd, SO_SNDTIMEO, 1000U) != 0) {
        perror("setsockopt");
        goto cleanup;
    }

    ssl = SSL_new(context);
    if (ssl == NULL) {
        print_openssl_errors("Unable to create the TLS client.");
        goto cleanup;
    }

    state.ssl = ssl;

    if (SSL_set_fd(ssl, socket_fd) != 1) {
        print_openssl_errors("Unable to attach the socket to TLS.");
        goto cleanup;
    }

    if (SSL_set1_host(ssl, "localhost") != 1 ||
        SSL_set_tlsext_host_name(ssl, "localhost") != 1) {
        print_openssl_errors(
            "Unable to configure certificate verification."
        );
        goto cleanup;
    }

    if (connect_tls(ssl) != 0) {
        fprintf(stderr, "TLS handshake failed.\n");
        fatal_tls_error = 1;
        goto cleanup;
    }

    handshake_complete = 1;

    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        fprintf(stderr, "Server certificate verification failed.\n");
        goto cleanup;
    }

    while (!stop_requested) {
        fd_set reads;
        int maximum_fd;
        int ready;
        int socket_ready = 0;
        int stdin_ready = 0;

        if (window_changed) {
            window_changed = 0;
            if (send_window_size(&state) != 0) {
                goto cleanup;
            }
        }

        if (SSL_pending(ssl) > 0) {
            socket_ready = 1;
        } else {
            FD_ZERO(&reads);
            FD_SET(socket_fd, &reads);
            FD_SET(STDIN_FILENO, &reads);

            maximum_fd = socket_fd > STDIN_FILENO
                ? socket_fd
                : STDIN_FILENO;

            ready = select(
                maximum_fd + 1,
                &reads,
                NULL,
                NULL,
                NULL
            );

            if (ready < 0) {
                if (errno == EINTR) {
                    continue;
                }

                perror("select");
                goto cleanup;
            }

            socket_ready = FD_ISSET(socket_fd, &reads);
            stdin_ready = FD_ISSET(STDIN_FILENO, &reads);
        }

        if (socket_ready) {
            unsigned char buffer[4096];
            size_t received = 0;
            int result;
            int error;
            int socket_errno;

            ERR_clear_error();
            errno = 0;

            result = SSL_read_ex(
                ssl,
                buffer,
                sizeof(buffer),
                &received
            );
            socket_errno = errno;

            if (result == 1) {
                if (received > 0 &&
                    process_server_bytes(
                        &state,
                        buffer,
                        received
                    ) != 0) {
                    fprintf(
                        stderr,
                        "Unsafe or malformed Telnet stream received.\n"
                    );
                    goto cleanup;
                }
            } else {
                error = SSL_get_error(ssl, result);

                if (retryable_socket_error(error, socket_errno)) {
                    continue;
                }

                if (error == SSL_ERROR_ZERO_RETURN) {
                    exit_code = EXIT_SUCCESS;
                    break;
                }

                fatal_tls_error = 1;
                fprintf(
                    stderr,
                    "Connection closed without a clean TLS shutdown.\n"
                );
                goto cleanup;
            }
        }

        if (stdin_ready) {
            unsigned char input[4096];
            ssize_t received = read(
                STDIN_FILENO,
                input,
                sizeof(input)
            );

            if (received == 0) {
                exit_code = EXIT_SUCCESS;
                break;
            }

            if (received < 0) {
                if (errno == EINTR) {
                    continue;
                }

                perror("read");
                goto cleanup;
            }

            if (send_terminal_input(
                    ssl,
                    input,
                    (size_t)received
                ) != 0) {
                goto cleanup;
            }
        }
    }

    if (stop_requested) {
        exit_code = EXIT_SUCCESS;
    }

cleanup:
    set_local_echo(1);

    if (ssl != NULL) {
        if (handshake_complete && !fatal_tls_error) {
            tls_shutdown_bounded(ssl, socket_fd);
        }
        SSL_free(ssl);
    }

    if (socket_fd >= 0) {
        close(socket_fd);
    }

    SSL_CTX_free(context);
    return exit_code;
}
