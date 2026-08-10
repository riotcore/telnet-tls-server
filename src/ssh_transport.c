// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

/*
 * ssh_transport.c
 *
 * SSH is a sibling terminal transport, not Telnet wrapped in encryption. libssh
 * owns key exchange, packet framing, authentication messages, channels, and PTY
 * requests. This file translates the small subset a MUD actually needs into
 * terminal_application: an authenticated account name, terminal capabilities,
 * complete input lines, and trusted output callbacks.
 *
 * There is deliberately no subprocess and no operating-system shell behind an
 * SSH "shell" request. In SSH vocabulary that request is simply the point where
 * an interactive terminal session begins; here it opens the MUD application.
 */

#define _POSIX_C_SOURCE 200809L

#include "ssh_transport.h"

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <libssh/callbacks.h>
#include <libssh/libssh.h>
#include <libssh/server.h>

#define SSH_INPUT_LINE_MAX 512U
#define SSH_INPUT_BYTES_PER_WINDOW 65536U
#define SSH_INPUT_BYTES_WINDOW_MS 5000ULL
#define SSH_INPUT_LINES_PER_WINDOW 30U
#define SSH_INPUT_LINES_WINDOW_MS 10000ULL
#define SSH_AUTH_TIMEOUT_MS 120000ULL
#define SSH_IDLE_TIMEOUT_MS 900000ULL
#define SSH_SESSION_MAX_MS (12ULL * 60ULL * 60ULL * 1000ULL)
#define SSH_EVENT_TICK_MS 1000
#define SSH_WRITE_CHUNK_MAX 16384U

struct rate_window {
    uint64_t started_ms;
    size_t used;
};

struct ssh_connection {
    ssh_session session;
    ssh_channel channel;
    ssh_event event;

    player_store *store;
    security_policy *security;
    audit_log *audit;
    terminal_application_hooks application;
    terminal_output output;
    void *application_session;

    char peer[96];
    char account_name[PLAYER_NAME_MAX + 1];
    terminal_capabilities capabilities;

    struct ssh_server_callbacks_struct server_callbacks;
    struct ssh_channel_callbacks_struct channel_callbacks;

    char line[SSH_INPUT_LINE_MAX + 1];
    size_t line_length;
    int pending_cr;
    int escape_state;
    int authenticated;
    int shell_started;
    int close_requested;
    int write_failed;
    int client_fd;
    int fd_attached_to_session;

    uint64_t connected_ms;
    uint64_t authenticated_ms;
    uint64_t last_activity_ms;
    struct rate_window byte_window;
    struct rate_window line_window;
};

static uint64_t monotonic_milliseconds(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }

    return ((uint64_t)now.tv_sec * 1000ULL) +
           ((uint64_t)now.tv_nsec / 1000000ULL);
}

static int rate_consume(
    struct rate_window *window,
    size_t amount,
    size_t limit,
    uint64_t period_ms,
    uint64_t now_ms
)
{
    if (window->started_ms == 0 || now_ms < window->started_ms ||
        now_ms - window->started_ms >= period_ms) {
        window->started_ms = now_ms;
        window->used = 0;
    }

    if (amount > limit || window->used > limit - amount) {
        return 0;
    }

    window->used += amount;
    return 1;
}

static void audit_connection(
    struct ssh_connection *connection,
    const char *event,
    const char *detail
)
{
    audit_log_event(
        connection != NULL ? connection->audit : NULL,
        event,
        connection != NULL ? connection->peer : "unknown",
        detail
    );
}

static int ascii_equal_ignore_case(const char *left, const char *right)
{
    if (left == NULL || right == NULL) {
        return 0;
    }

    while (*left != '\0' && *right != '\0') {
        unsigned char a = (unsigned char)*left++;
        unsigned char b = (unsigned char)*right++;

        if (a >= 'A' && a <= 'Z') {
            a = (unsigned char)(a + ('a' - 'A'));
        }
        if (b >= 'A' && b <= 'Z') {
            b = (unsigned char)(b + ('a' - 'A'));
        }
        if (a != b) {
            return 0;
        }
    }

    return *left == '\0' && *right == '\0';
}

static int ascii_contains_ignore_case(const char *text, const char *needle)
{
    size_t needle_length;
    size_t i;

    if (text == NULL || needle == NULL) {
        return 0;
    }

    needle_length = strlen(needle);
    if (needle_length == 0) {
        return 1;
    }

    for (i = 0; text[i] != '\0'; ++i) {
        size_t j = 0;
        while (j < needle_length && text[i + j] != '\0') {
            unsigned char a = (unsigned char)text[i + j];
            unsigned char b = (unsigned char)needle[j];

            if (a >= 'A' && a <= 'Z') {
                a = (unsigned char)(a + ('a' - 'A'));
            }
            if (b >= 'A' && b <= 'Z') {
                b = (unsigned char)(b + ('a' - 'A'));
            }
            if (a != b) {
                break;
            }
            ++j;
        }
        if (j == needle_length) {
            return 1;
        }
    }

    return 0;
}

static void copy_terminal_field(char *output, size_t output_size, const char *input)
{
    size_t used = 0;

    if (output == NULL || output_size == 0) {
        return;
    }

    if (input == NULL) {
        input = "";
    }

    while (*input != '\0' && used + 1 < output_size) {
        unsigned char ch = (unsigned char)*input++;
        output[used++] = ch >= 0x20 && ch <= 0x7e ? (char)ch : '?';
    }
    output[used] = '\0';
}

static void notify_capabilities(struct ssh_connection *connection)
{
    if (connection->application_session != NULL &&
        connection->application.capabilities_changed != NULL) {
        connection->application.capabilities_changed(
            connection->application_session,
            &connection->capabilities
        );
    }
}

static int channel_write_all(
    struct ssh_connection *connection,
    const void *data,
    size_t length
)
{
    const unsigned char *bytes = data;
    size_t offset = 0;

    if (connection == NULL || connection->channel == NULL ||
        connection->write_failed) {
        return -1;
    }

    while (offset < length) {
        size_t remaining = length - offset;
        uint32_t chunk = (uint32_t)(
            remaining > SSH_WRITE_CHUNK_MAX
                ? SSH_WRITE_CHUNK_MAX
                : remaining
        );
        int written = ssh_channel_write(
            connection->channel,
            bytes + offset,
            chunk
        );

        if (written <= 0) {
            connection->write_failed = 1;
            audit_connection(
                connection,
                "ssh_write_failure",
                "channel write failed"
            );
            return -1;
        }

        offset += (size_t)written;
    }

    return 0;
}

/* Interactive terminals generally want CRLF even though app text uses '\n'. */
static int write_terminal_text(
    struct ssh_connection *connection,
    const char *text
)
{
    const char *start;
    const char *cursor;

    if (connection == NULL || text == NULL) {
        return -1;
    }

    start = text;
    cursor = text;
    while (*cursor != '\0') {
        if (*cursor == '\n' && (cursor == text || cursor[-1] != '\r')) {
            if (cursor > start &&
                channel_write_all(
                    connection,
                    start,
                    (size_t)(cursor - start)
                ) != 0) {
                return -1;
            }
            if (channel_write_all(connection, "\r\n", 2) != 0) {
                return -1;
            }
            start = cursor + 1;
        }
        ++cursor;
    }

    if (cursor > start) {
        return channel_write_all(
            connection,
            start,
            (size_t)(cursor - start)
        );
    }
    return 0;
}

static void output_write_text(void *context, const char *text)
{
    (void)write_terminal_text((struct ssh_connection *)context, text);
}

static void output_write_prompt(void *context, const char *text)
{
    (void)write_terminal_text((struct ssh_connection *)context, text);
}

static void output_request_close(void *context, const char *message)
{
    struct ssh_connection *connection = context;

    if (connection == NULL) {
        return;
    }

    if (message != NULL) {
        (void)write_terminal_text(connection, message);
    }
    connection->close_requested = 1;
}

static int output_send_gmcp(
    void *context,
    const char *package_name,
    const char *json_payload
)
{
    (void)context;
    (void)package_name;
    (void)json_payload;

    /* GMCP is a Telnet option. SSH sessions get the same application without it. */
    return -1;
}

static int output_write_link(
    void *context,
    const char *uri,
    const char *label
)
{
    struct ssh_connection *connection = context;

    (void)uri;
    if (connection == NULL || label == NULL) {
        return -1;
    }

    /*
     * We do not guess OSC 8 support from an SSH client banner. Until the SSH
     * side has an explicit capability signal, keep the visible text fallback.
     */
    return write_terminal_text(connection, label);
}

static int password_auth_callback(
    ssh_session session,
    const char *user,
    const char *password,
    void *userdata
)
{
    struct ssh_connection *connection = userdata;
    uint64_t now_ms;
    uint64_t retry_after_ms = 0;
    size_t password_length;
    int rehashed = 0;
    int verified;

    (void)session;

    if (connection == NULL || connection->authenticated ||
        user == NULL || password == NULL ||
        !player_store_name_valid(user)) {
        return SSH_AUTH_DENIED;
    }

    password_length = strnlen(password, PLAYER_PASSWORD_MAX + 1U);
    if (password_length < PLAYER_PASSWORD_MIN ||
        password_length > PLAYER_PASSWORD_MAX) {
        audit_connection(
            connection,
            "ssh_login_failure",
            "invalid username or password length"
        );
        return SSH_AUTH_DENIED;
    }

    now_ms = monotonic_milliseconds();
    if (now_ms == 0 ||
        !security_policy_allow_auth_attempt(
            connection->security,
            connection->peer,
            user,
            now_ms,
            &retry_after_ms
        )) {
        (void)retry_after_ms;
        audit_connection(
            connection,
            "ssh_login_throttled",
            "password authentication delayed by shared policy"
        );
        return SSH_AUTH_DENIED;
    }

    verified = player_store_verify_password(
        connection->store,
        user,
        password,
        password_length,
        &rehashed
    );
    if (verified != 1) {
        security_policy_note_auth_failure(
            connection->security,
            connection->peer,
            user,
            now_ms
        );
        audit_connection(
            connection,
            "ssh_login_failure",
            verified < 0 ? "credential store error" : "invalid credentials"
        );
        return SSH_AUTH_DENIED;
    }

    security_policy_note_auth_success(
        connection->security,
        connection->peer,
        user,
        now_ms
    );

    copy_terminal_field(
        connection->account_name,
        sizeof(connection->account_name),
        user
    );
    connection->authenticated = 1;
    connection->authenticated_ms = now_ms;
    connection->last_activity_ms = now_ms;

    audit_connection(
        connection,
        "ssh_login_success",
        rehashed ? "password accepted; verifier upgraded" : "password accepted"
    );
    return SSH_AUTH_SUCCESS;
}

/*
 * Only session channels are registered. libssh 0.10 does not expose the newer
 * direct-tcpip server callback member, and that is fine for this endpoint: a
 * MUD listener has no reason to become a port-forwarding service. With no
 * forwarding handler installed, direct-tcpip requests are rejected by libssh.
 */

static ssh_channel session_channel_callback(
    ssh_session session,
    void *userdata
)
{
    struct ssh_connection *connection = userdata;
    ssh_channel channel;

    if (connection == NULL || !connection->authenticated ||
        connection->channel != NULL) {
        return NULL;
    }

    channel = ssh_channel_new(session);
    if (channel == NULL) {
        return NULL;
    }

    /*
     * Requests such as PTY and shell can follow immediately after the channel
     * opens, so install the callbacks before handing the channel to libssh.
     */
    if (ssh_set_channel_callbacks(
            channel,
            &connection->channel_callbacks
        ) != SSH_OK) {
        ssh_channel_free(channel);
        return NULL;
    }

    connection->channel = channel;
    return channel;
}

static void refresh_term_capabilities(
    struct ssh_connection *connection,
    const char *term
)
{
    copy_terminal_field(
        connection->capabilities.terminal_type,
        sizeof(connection->capabilities.terminal_type),
        term != NULL && term[0] != '\0' ? term : "UNKNOWN"
    );

    connection->capabilities.ansi =
        term != NULL && term[0] != '\0' &&
        !ascii_equal_ignore_case(term, "dumb");
    connection->capabilities.color_256 =
        term != NULL && ascii_contains_ignore_case(term, "256color");
}

static int pty_request_callback(
    ssh_session session,
    ssh_channel channel,
    const char *term,
    int width,
    int height,
    int pxwidth,
    int pxheight,
    void *userdata
)
{
    struct ssh_connection *connection = userdata;

    (void)session;
    (void)channel;
    (void)pxwidth;
    (void)pxheight;

    if (connection == NULL) {
        return -1;
    }

    if (width > 0 && width <= UINT16_MAX) {
        connection->capabilities.width = (uint16_t)width;
    }
    if (height > 0 && height <= UINT16_MAX) {
        connection->capabilities.height = (uint16_t)height;
    }
    refresh_term_capabilities(connection, term);
    notify_capabilities(connection);
    return 0;
}

static int window_change_callback(
    ssh_session session,
    ssh_channel channel,
    int width,
    int height,
    int pxwidth,
    int pxheight,
    void *userdata
)
{
    struct ssh_connection *connection = userdata;

    (void)session;
    (void)channel;
    (void)pxwidth;
    (void)pxheight;

    if (connection == NULL) {
        return -1;
    }

    if (width > 0 && width <= UINT16_MAX) {
        connection->capabilities.width = (uint16_t)width;
    }
    if (height > 0 && height <= UINT16_MAX) {
        connection->capabilities.height = (uint16_t)height;
    }
    notify_capabilities(connection);
    return 0;
}

static int locale_says_utf8(const char *value)
{
    return value != NULL &&
        (ascii_contains_ignore_case(value, "utf-8") ||
         ascii_contains_ignore_case(value, "utf8"));
}

static int env_request_callback(
    ssh_session session,
    ssh_channel channel,
    const char *name,
    const char *value,
    void *userdata
)
{
    struct ssh_connection *connection = userdata;

    (void)session;
    (void)channel;

    if (connection == NULL || name == NULL || value == NULL) {
        return 1;
    }

    /*
     * Environment requests are hints, not a process environment. Accept only
     * the few terminal-related values we understand; never honor arbitrary
     * names such as LD_PRELOAD or shell configuration variables.
     */
    if (ascii_equal_ignore_case(name, "LANG") ||
        ascii_equal_ignore_case(name, "LC_CTYPE")) {
        if (locale_says_utf8(value)) {
            connection->capabilities.utf8 = 1;
            notify_capabilities(connection);
        }
        return 0;
    }

    if (ascii_equal_ignore_case(name, "COLORTERM")) {
        if (ascii_contains_ignore_case(value, "truecolor") ||
            ascii_contains_ignore_case(value, "24bit")) {
            connection->capabilities.truecolor = 1;
            connection->capabilities.color_256 = 1;
            connection->capabilities.ansi = 1;
            notify_capabilities(connection);
        }
        return 0;
    }

    return 1;
}

static int open_application_session(struct ssh_connection *connection)
{
    if (connection->application.open == NULL) {
        (void)write_terminal_text(
            connection,
            "No terminal application is configured for SSH.\n"
        );
        return -1;
    }

    connection->application_session = connection->application.open(
        connection->application.manager_context,
        connection->account_name,
        &connection->output,
        &connection->capabilities
    );

    if (connection->application_session == NULL) {
        audit_connection(
            connection,
            "ssh_application_rejected",
            "authenticated application attachment rejected"
        );
        return -1;
    }

    return 0;
}

static int shell_request_callback(
    ssh_session session,
    ssh_channel channel,
    void *userdata
)
{
    struct ssh_connection *connection = userdata;

    (void)session;
    (void)channel;

    if (connection == NULL || !connection->authenticated ||
        connection->shell_started) {
        return 1;
    }

    connection->shell_started = 1;
    if (open_application_session(connection) != 0) {
        connection->close_requested = 1;
        return 1;
    }

    audit_connection(
        connection,
        "ssh_session_open",
        "interactive terminal application opened"
    );
    return 0;
}

static int complete_input_line(
    struct ssh_connection *connection,
    uint64_t now_ms
)
{
    int close_requested = 0;

    if (!rate_consume(
            &connection->line_window,
            1,
            SSH_INPUT_LINES_PER_WINDOW,
            SSH_INPUT_LINES_WINDOW_MS,
            now_ms
        )) {
        audit_connection(
            connection,
            "ssh_line_flood",
            "line rate limit exceeded"
        );
        (void)write_terminal_text(connection, "Input rate limit exceeded.\n");
        connection->close_requested = 1;
        return -1;
    }

    connection->line[connection->line_length] = '\0';
    if (connection->application_session != NULL &&
        connection->application.line != NULL) {
        close_requested = connection->application.line(
            connection->application_session,
            connection->line,
            connection->line_length
        );
    }

    memset(connection->line, 0, sizeof(connection->line));
    connection->line_length = 0;

    if (close_requested != 0) {
        connection->close_requested = 1;
    }
    return 0;
}

static int handle_input_byte(
    struct ssh_connection *connection,
    unsigned char byte,
    uint64_t now_ms
)
{
    if (connection->pending_cr) {
        connection->pending_cr = 0;
        if (byte == '\n') {
            return 0;
        }
    }

    if (byte == '\r' || byte == '\n') {
        if (channel_write_all(connection, "\r\n", 2) != 0) {
            return -1;
        }
        if (complete_input_line(connection, now_ms) != 0) {
            return -1;
        }
        if (byte == '\r') {
            connection->pending_cr = 1;
        }
        return 0;
    }

    if (byte == 4) { /* Ctrl-D: conventional terminal EOF. */
        connection->close_requested = 1;
        return 0;
    }

    /*
     * There is no operating-system PTY or line discipline behind this channel,
     * so the adapter provides just enough editing for a terminal prompt. Drop
     * CSI/SS3 key sequences rather than turning an arrow key into "[A" input.
     */
    if (connection->escape_state != 0) {
        if (connection->escape_state == 1) {
            connection->escape_state = (byte == '[' || byte == 'O') ? 2 : 0;
            return 0;
        }
        if (byte >= 0x40 && byte <= 0x7e) {
            connection->escape_state = 0;
        }
        return 0;
    }

    if (byte == 0x1b) {
        connection->escape_state = 1;
        return 0;
    }

    if (byte == 8 || byte == 127) {
        if (connection->line_length > 0) {
            size_t previous = connection->line_length - 1;

            while (previous > 0 &&
                   (((unsigned char)connection->line[previous] & 0xc0) == 0x80)) {
                --previous;
            }
            connection->line_length = previous;
            connection->line[connection->line_length] = '\0';
            if (channel_write_all(connection, "\b \b", 3) != 0) {
                return -1;
            }
        }
        return 0;
    }

    if (byte < 0x20) {
        return 0;
    }

    if (connection->line_length >= SSH_INPUT_LINE_MAX) {
        audit_connection(
            connection,
            "ssh_input_overflow",
            "application input line exceeded bound"
        );
        (void)write_terminal_text(connection, "\r\nInput line is too long.\n");
        connection->close_requested = 1;
        return -1;
    }

    connection->line[connection->line_length++] = (char)byte;
    return channel_write_all(connection, &byte, 1);
}

static int channel_data_callback(
    ssh_session session,
    ssh_channel channel,
    void *data,
    uint32_t length,
    int is_stderr,
    void *userdata
)
{
    struct ssh_connection *connection = userdata;
    const unsigned char *bytes = data;
    uint64_t now_ms;
    uint32_t i;

    (void)session;
    (void)channel;

    if (connection == NULL || data == NULL || is_stderr ||
        !connection->shell_started || connection->application_session == NULL) {
        return (int)length;
    }

    now_ms = monotonic_milliseconds();
    if (now_ms == 0 ||
        !rate_consume(
            &connection->byte_window,
            (size_t)length,
            SSH_INPUT_BYTES_PER_WINDOW,
            SSH_INPUT_BYTES_WINDOW_MS,
            now_ms
        )) {
        audit_connection(
            connection,
            "ssh_input_flood",
            "byte rate limit exceeded"
        );
        connection->close_requested = 1;
        return (int)length;
    }

    connection->last_activity_ms = now_ms;
    for (i = 0; i < length && !connection->close_requested; ++i) {
        if (handle_input_byte(connection, bytes[i], now_ms) != 0) {
            break;
        }
    }

    return (int)length;
}

static void channel_eof_callback(
    ssh_session session,
    ssh_channel channel,
    void *userdata
)
{
    struct ssh_connection *connection = userdata;
    (void)session;
    (void)channel;
    if (connection != NULL) {
        connection->close_requested = 1;
    }
}

static void channel_close_callback(
    ssh_session session,
    ssh_channel channel,
    void *userdata
)
{
    struct ssh_connection *connection = userdata;
    (void)session;
    (void)channel;
    if (connection != NULL) {
        connection->close_requested = 1;
    }
}

static int exec_request_callback(
    ssh_session session,
    ssh_channel channel,
    const char *command,
    void *userdata
)
{
    struct ssh_connection *connection = userdata;
    (void)session;
    (void)channel;
    (void)command;
    if (connection != NULL) {
        audit_connection(
            connection,
            "ssh_exec_denied",
            "exec requests are not a MUD shell"
        );
    }
    return 1;
}

static int subsystem_request_callback(
    ssh_session session,
    ssh_channel channel,
    const char *subsystem,
    void *userdata
)
{
    struct ssh_connection *connection = userdata;
    (void)session;
    (void)channel;
    (void)subsystem;
    if (connection != NULL) {
        audit_connection(
            connection,
            "ssh_subsystem_denied",
            "subsystems are disabled"
        );
    }
    return 1;
}

static void initialize_channel_callbacks(struct ssh_connection *connection)
{
    memset(&connection->channel_callbacks, 0, sizeof(connection->channel_callbacks));
    connection->channel_callbacks.userdata = connection;
    ssh_callbacks_init(&connection->channel_callbacks);
    connection->channel_callbacks.channel_data_function = channel_data_callback;
    connection->channel_callbacks.channel_eof_function = channel_eof_callback;
    connection->channel_callbacks.channel_close_function = channel_close_callback;
    connection->channel_callbacks.channel_pty_request_function = pty_request_callback;
    connection->channel_callbacks.channel_shell_request_function = shell_request_callback;
    connection->channel_callbacks.channel_pty_window_change_function =
        window_change_callback;
    connection->channel_callbacks.channel_exec_request_function =
        exec_request_callback;
    connection->channel_callbacks.channel_env_request_function =
        env_request_callback;
    connection->channel_callbacks.channel_subsystem_request_function =
        subsystem_request_callback;
}

static int setup_ssh_session(
    struct ssh_connection *connection,
    const char *host_key_path,
    int client_fd
)
{
    ssh_bind bind = NULL;
    const char *client_banner;
    int result = -1;

    bind = ssh_bind_new();
    connection->session = ssh_new();
    if (bind == NULL || connection->session == NULL) {
        goto cleanup;
    }

    if (ssh_bind_options_set(
            bind,
            SSH_BIND_OPTIONS_HOSTKEY,
            host_key_path
        ) != SSH_OK) {
        audit_connection(connection, "ssh_host_key_error", "unable to load host key");
        goto cleanup;
    }

    memset(&connection->server_callbacks, 0, sizeof(connection->server_callbacks));
    connection->server_callbacks.userdata = connection;
    connection->server_callbacks.auth_password_function = password_auth_callback;
    connection->server_callbacks.channel_open_request_session_function =
        session_channel_callback;
    ssh_callbacks_init(&connection->server_callbacks);

    if (ssh_set_server_callbacks(
            connection->session,
            &connection->server_callbacks
        ) != SSH_OK) {
        goto cleanup;
    }

    ssh_set_auth_methods(connection->session, SSH_AUTH_METHOD_PASSWORD);

    if (ssh_bind_accept_fd(bind, connection->session, client_fd) != SSH_OK) {
        audit_connection(connection, "ssh_accept_failure", "libssh rejected accepted socket");
        goto cleanup;
    }
    connection->fd_attached_to_session = 1;

    if (ssh_handle_key_exchange(connection->session) != SSH_OK) {
        audit_connection(connection, "ssh_kex_failure", "SSH key exchange failed");
        goto cleanup;
    }

    client_banner = ssh_get_clientbanner(connection->session);
    copy_terminal_field(
        connection->capabilities.client_version,
        sizeof(connection->capabilities.client_version),
        client_banner != NULL ? client_banner : "UNKNOWN"
    );

    connection->event = ssh_event_new();
    if (connection->event == NULL ||
        ssh_event_add_session(connection->event, connection->session) != SSH_OK) {
        goto cleanup;
    }

    result = 0;

cleanup:
    if (bind != NULL) {
        ssh_bind_free(bind);
    }
    return result;
}

static void cleanup_ssh_connection(struct ssh_connection *connection)
{
    if (connection->application_session != NULL &&
        connection->application.close != NULL) {
        connection->application.close(connection->application_session);
        connection->application_session = NULL;
    }

    if (connection->channel != NULL) {
        if (ssh_channel_is_open(connection->channel)) {
            (void)ssh_channel_send_eof(connection->channel);
            (void)ssh_channel_close(connection->channel);
        }
        ssh_channel_free(connection->channel);
        connection->channel = NULL;
    }

    if (connection->event != NULL && connection->session != NULL) {
        (void)ssh_event_remove_session(connection->event, connection->session);
    }
    if (connection->event != NULL) {
        ssh_event_free(connection->event);
        connection->event = NULL;
    }

    if (connection->session != NULL) {
        if (ssh_is_connected(connection->session)) {
            ssh_disconnect(connection->session);
        }
        ssh_free(connection->session);
        connection->session = NULL;
    }

    /* Before ssh_bind_accept_fd succeeds, libssh does not own the socket. */
    if (!connection->fd_attached_to_session && connection->client_fd >= 0) {
        close(connection->client_fd);
    }
    connection->client_fd = -1;
}

int ssh_transport_validate_host_key(const char *path)
{
    struct stat info;

    if (path == NULL || lstat(path, &info) != 0 ||
        !S_ISREG(info.st_mode) || S_ISLNK(info.st_mode) ||
        info.st_uid != geteuid() || (info.st_mode & 0077) != 0 ||
        access(path, R_OK) != 0) {
        return -1;
    }

    return 0;
}

int ssh_transport_global_init(void)
{
    return ssh_init() == SSH_OK ? 0 : -1;
}

void ssh_transport_global_cleanup(void)
{
    (void)ssh_finalize();
}

int ssh_transport_run_connection(
    const ssh_transport_connection_config *config
)
{
    struct ssh_connection connection;
    uint64_t now_ms;
    int result = -1;

    if (config == NULL || config->client_fd < 0 || config->peer == NULL ||
        config->host_key_path == NULL || config->store == NULL ||
        config->security == NULL || config->application == NULL) {
        return -1;
    }

    memset(&connection, 0, sizeof(connection));
    connection.client_fd = config->client_fd;
    connection.store = config->store;
    connection.security = config->security;
    connection.audit = config->audit;
    connection.application = *config->application;
    copy_terminal_field(connection.peer, sizeof(connection.peer), config->peer);

    connection.capabilities.width = 80;
    connection.capabilities.height = 24;
    connection.capabilities.secure_transport = 1;
    copy_terminal_field(
        connection.capabilities.terminal_type,
        sizeof(connection.capabilities.terminal_type),
        "UNKNOWN"
    );
    copy_terminal_field(
        connection.capabilities.client_name,
        sizeof(connection.capabilities.client_name),
        "SSH"
    );
    copy_terminal_field(
        connection.capabilities.client_version,
        sizeof(connection.capabilities.client_version),
        "UNKNOWN"
    );

    connection.output.context = &connection;
    connection.output.write_text = output_write_text;
    connection.output.write_prompt = output_write_prompt;
    connection.output.request_close = output_request_close;
    connection.output.send_gmcp = output_send_gmcp;
    connection.output.write_link = output_write_link;
    initialize_channel_callbacks(&connection);

    now_ms = monotonic_milliseconds();
    if (now_ms == 0) {
        goto cleanup;
    }
    connection.connected_ms = now_ms;
    connection.last_activity_ms = now_ms;

    if (setup_ssh_session(
            &connection,
            config->host_key_path,
            config->client_fd
        ) != 0) {
        goto cleanup;
    }

    /*
     * libssh's event context drives authentication and channel callbacks. One
     * event object lives in this worker, so no callback state is shared between
     * SSH connections.
     */
    while (!connection.close_requested &&
           ssh_is_connected(connection.session)) {
        int poll_result = ssh_event_dopoll(
            connection.event,
            SSH_EVENT_TICK_MS
        );

        if (poll_result == SSH_ERROR) {
            audit_connection(
                &connection,
                "ssh_event_failure",
                "event poll failed"
            );
            break;
        }

        now_ms = monotonic_milliseconds();
        if (now_ms == 0) {
            break;
        }

        if (!connection.authenticated &&
            now_ms - connection.connected_ms >= SSH_AUTH_TIMEOUT_MS) {
            audit_connection(
                &connection,
                "ssh_auth_timeout",
                "authentication timed out"
            );
            break;
        }

        if (connection.authenticated && !connection.shell_started &&
            now_ms - connection.authenticated_ms >= SSH_AUTH_TIMEOUT_MS) {
            audit_connection(
                &connection,
                "ssh_channel_timeout",
                "interactive channel timed out"
            );
            break;
        }

        if (connection.shell_started &&
            now_ms - connection.last_activity_ms >= SSH_IDLE_TIMEOUT_MS) {
            (void)write_terminal_text(&connection, "Idle timeout.\n");
            audit_connection(
                &connection,
                "ssh_idle_timeout",
                "session idle timeout"
            );
            break;
        }

        if (now_ms - connection.connected_ms >= SSH_SESSION_MAX_MS) {
            (void)write_terminal_text(&connection, "Session time limit reached.\n");
            audit_connection(
                &connection,
                "ssh_session_timeout",
                "maximum session lifetime reached"
            );
            break;
        }

        if (connection.channel != NULL &&
            (!ssh_channel_is_open(connection.channel) ||
             ssh_channel_is_eof(connection.channel))) {
            break;
        }
    }

    result = connection.authenticated && connection.shell_started ? 0 : -1;

cleanup:
    cleanup_ssh_connection(&connection);
    return result;
}
