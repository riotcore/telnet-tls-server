// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

/*
 * secure_server.c
 *
 * The accept loop lives here because transport admission is one policy even
 * when the wire protocols differ. It polls the small listener set, applies the
 * shared peer/connection limits, then hands each accepted socket to one bounded
 * worker. A slow client therefore blocks its own worker, not accept() for every
 * other player.
 *
 * Plain TCP and TLS both feed the Telnet adapter. SSH takes a different route:
 * libssh owns its handshake and channel protocol. After authentication, SSH
 * and Telnet both hand the session to the same terminal_application hooks.
 */

#define _POSIX_C_SOURCE 200809L

#include "secure_server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "audit_log.h"
#include "player_store.h"
#include "security_policy.h"
#include "telnet_protocol.h"
#include "ssh_transport.h"

/*
 * The reference server caps all transports together. Thread-per-connection is
 * intentionally simple here; the cap makes that simplicity a bounded choice.
 */
#define MAX_ACTIVE_CONNECTIONS 64U
#define TLS_HANDSHAKE_TIMEOUT_MS 10000ULL
#define LOGIN_TIMEOUT_MS 120000ULL
#define IDLE_TIMEOUT_MS 900000ULL
#define SESSION_MAX_MS (12ULL * 60ULL * 60ULL * 1000ULL)
#define TLS_SHUTDOWN_TIMEOUT_MS 3000ULL
#define SOCKET_READ_TICK_MS 250U
#define SOCKET_WRITE_TIMEOUT_MS 10000U
#define MAX_LISTENER_SOCKETS 6U
#define LISTENER_UNAVAILABLE (-2)

/* Shared objects live until the listener and all workers have stopped. */
struct server_runtime {
    SSL_CTX *tls_context;
    player_store *store;
    terminal_application_hooks application;
    telnet_mssp_query_fn mssp_query;
    void *mssp_context;
    const char *ssh_host_key_path;
    security_policy *security;
    audit_log *audit;

    pthread_mutex_t mutex;
    pthread_cond_t condition;
    size_t active_connections;
    int stopping;
};

enum connection_transport_kind {
    CONNECTION_TRANSPORT_TELNET = 0,
    CONNECTION_TRANSPORT_TELNET_TLS,
    CONNECTION_TRANSPORT_SSH
};

/* Immutable connection data transferred to one detached worker thread. */
struct worker_args {
    struct server_runtime *runtime;
    int client_fd;
    enum connection_transport_kind transport;
    char peer[96];
};

/*
 * Telnet writes through one callback regardless of whether the underlying
 * socket is plain or TLS. SSH never enters this writer; its channel adapter has
 * a separate output path and joins only at terminal_application.
 */
struct connection_writer {
    enum connection_transport_kind transport;
    int fd;
    SSL *ssl;
    audit_log *audit;
    const char *peer;
    int failed;
};

static volatile sig_atomic_t stop_requested = 0;

static void request_stop(int signal_number)
{
    (void)signal_number;
    stop_requested = 1;
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

static void print_startup_openssl_errors(const char *message)
{
    fprintf(stderr, "%s\n", message);
    ERR_print_errors_fp(stderr);
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

static int runtime_is_stopping(struct server_runtime *runtime)
{
    int stopping;

    pthread_mutex_lock(&runtime->mutex);
    stopping = runtime->stopping;
    pthread_mutex_unlock(&runtime->mutex);

    return stopping;
}

static int runtime_reserve_connection(
    struct server_runtime *runtime
)
{
    int allowed = 0;

    pthread_mutex_lock(&runtime->mutex);

    if (!runtime->stopping &&
        runtime->active_connections <
            MAX_ACTIVE_CONNECTIONS) {
        ++runtime->active_connections;
        allowed = 1;
    }

    pthread_mutex_unlock(&runtime->mutex);
    return allowed;
}

static void runtime_release_connection(
    struct server_runtime *runtime
)
{
    pthread_mutex_lock(&runtime->mutex);

    if (runtime->active_connections > 0) {
        --runtime->active_connections;
    }

    pthread_cond_broadcast(&runtime->condition);
    pthread_mutex_unlock(&runtime->mutex);
}

static void runtime_begin_shutdown(
    struct server_runtime *runtime
)
{
    pthread_mutex_lock(&runtime->mutex);
    runtime->stopping = 1;
    pthread_cond_broadcast(&runtime->condition);
    pthread_mutex_unlock(&runtime->mutex);
}

static void runtime_wait_for_workers(
    struct server_runtime *runtime
)
{
    pthread_mutex_lock(&runtime->mutex);

    while (runtime->active_connections > 0) {
        pthread_cond_wait(
            &runtime->condition,
            &runtime->mutex
        );
    }

    pthread_mutex_unlock(&runtime->mutex);
}


static const char *transport_label(enum connection_transport_kind transport)
{
    switch (transport) {
    case CONNECTION_TRANSPORT_TELNET:
        return "telnet";
    case CONNECTION_TRANSPORT_TELNET_TLS:
        return "telnet-tls";
    case CONNECTION_TRANSPORT_SSH:
        return "ssh";
    default:
        return "unknown";
    }
}

static void connection_write(
    void *context,
    const unsigned char *data,
    size_t length
)
{
    struct connection_writer *writer = context;
    size_t offset = 0;
    uint64_t started;

    if (writer == NULL || writer->failed) {
        return;
    }

    started = monotonic_milliseconds();

    while (offset < length) {
        if (writer->transport == CONNECTION_TRANSPORT_TELNET_TLS) {
            size_t written = 0;
            int result;
            int error;
            int socket_errno;

            if (writer->ssl == NULL) {
                writer->failed = 1;
                return;
            }

            ERR_clear_error();
            errno = 0;
            result = SSL_write_ex(
                writer->ssl,
                data + offset,
                length - offset,
                &written
            );
            socket_errno = errno;

            if (result == 1 && written > 0) {
                offset += written;
                continue;
            }

            error = SSL_get_error(writer->ssl, result);
            if (retryable_socket_error(error, socket_errno)) {
                uint64_t now = monotonic_milliseconds();
                if (started != 0 && now != 0 &&
                    now - started < SOCKET_WRITE_TIMEOUT_MS) {
                    continue;
                }
            }
        } else {
            ssize_t written;

            errno = 0;
            written = send(
                writer->fd,
                data + offset,
                length - offset,
                0
            );

            if (written > 0) {
                offset += (size_t)written;
                continue;
            }

            if (written < 0 &&
                (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
                uint64_t now = monotonic_milliseconds();
                if (started != 0 && now != 0 &&
                    now - started < SOCKET_WRITE_TIMEOUT_MS) {
                    continue;
                }
            }
        }

        writer->failed = 1;
        audit_log_event(
            writer->audit,
            "transport_write_failure",
            writer->peer,
            transport_label(writer->transport)
        );
        return;
    }
}

static SSL_CTX *create_tls_context(
    const secure_server_config *config
)
{
    SSL_CTX *context = SSL_CTX_new(TLS_server_method());

    if (context == NULL) {
        print_startup_openssl_errors(
            "Unable to create the TLS context."
        );
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
        print_startup_openssl_errors(
            "Unable to require TLS 1.3."
        );
        SSL_CTX_free(context);
        return NULL;
    }

    /*
     * TLS 1.3 has no renegotiation. OpenSSL's maintained TLS 1.3 cipher
     * defaults are used here instead of maintaining a separate cipher list.
     */
    SSL_CTX_set_mode(context, SSL_MODE_AUTO_RETRY);

    if (SSL_CTX_use_certificate_chain_file(
            context,
            config->certificate_path
        ) != 1) {
        print_startup_openssl_errors(
            "Unable to load the server certificate."
        );
        SSL_CTX_free(context);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(
            context,
            config->private_key_path,
            SSL_FILETYPE_PEM
        ) != 1) {
        print_startup_openssl_errors(
            "Unable to load the server private key."
        );
        SSL_CTX_free(context);
        return NULL;
    }

    if (SSL_CTX_check_private_key(context) != 1) {
        print_startup_openssl_errors(
            "The server certificate and private key do not match."
        );
        SSL_CTX_free(context);
        return NULL;
    }

    return context;
}

static int ipv6_unavailable_error(int error_number)
{
    return error_number == EAFNOSUPPORT ||
           error_number == EPROTONOSUPPORT ||
           error_number == EADDRNOTAVAIL;
}

/*
 * The reference harness listens only on loopback, but it does so on both IP
 * families when the host has IPv6 loopback available. IPv6 is kept V6ONLY so
 * the IPv4 listener remains explicit instead of depending on platform-specific
 * dual-stack defaults.
 */
static int create_loopback_listener(
    int family,
    uint16_t port,
    int optional
)
{
    int listener;
    int enabled = 1;
    struct sockaddr_storage storage;
    socklen_t address_length;

    listener = socket(family, SOCK_STREAM, 0);
    if (listener < 0) {
        if (optional && ipv6_unavailable_error(errno)) {
            return LISTENER_UNAVAILABLE;
        }
        perror("socket");
        return -1;
    }

    if (setsockopt(
            listener,
            SOL_SOCKET,
            SO_REUSEADDR,
            &enabled,
            sizeof(enabled)
        ) != 0 ||
        setsockopt(
            listener,
            SOL_SOCKET,
            SO_KEEPALIVE,
            &enabled,
            sizeof(enabled)
        ) != 0) {
        perror("setsockopt");
        close(listener);
        return -1;
    }

    memset(&storage, 0, sizeof(storage));
    if (family == AF_INET) {
        struct sockaddr_in *address = (struct sockaddr_in *)&storage;
        address->sin_family = AF_INET;
        address->sin_port = htons(port);
        address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address_length = sizeof(*address);
    } else if (family == AF_INET6) {
        struct sockaddr_in6 *address = (struct sockaddr_in6 *)&storage;
        int ipv6_only = 1;

        if (setsockopt(
                listener,
                IPPROTO_IPV6,
                IPV6_V6ONLY,
                &ipv6_only,
                sizeof(ipv6_only)
            ) != 0) {
            int saved_errno = errno;
            close(listener);
            if (optional && ipv6_unavailable_error(saved_errno)) {
                return LISTENER_UNAVAILABLE;
            }
            errno = saved_errno;
            perror("setsockopt(IPV6_V6ONLY)");
            return -1;
        }

        address->sin6_family = AF_INET6;
        address->sin6_port = htons(port);
        address->sin6_addr = in6addr_loopback;
        address_length = sizeof(*address);
    } else {
        close(listener);
        errno = EAFNOSUPPORT;
        return -1;
    }

    if (bind(
            listener,
            (const struct sockaddr *)&storage,
            address_length
        ) != 0) {
        int saved_errno = errno;
        close(listener);
        if (optional && ipv6_unavailable_error(saved_errno)) {
            return LISTENER_UNAVAILABLE;
        }
        errno = saved_errno;
        perror("bind");
        return -1;
    }

    if (listen(listener, 64) != 0) {
        perror("listen");
        close(listener);
        return -1;
    }

    return listener;
}

static int tls_accept_with_deadline(
    struct server_runtime *runtime,
    SSL *ssl,
    const char *peer
)
{
    uint64_t started = monotonic_milliseconds();

    for (;;) {
        uint64_t now;
        int result;
        int error;
        int socket_errno;

        if (runtime_is_stopping(runtime)) {
            return -1;
        }

        ERR_clear_error();
        errno = 0;
        result = SSL_accept(ssl);
        socket_errno = errno;

        if (result == 1) {
            audit_log_event(
                runtime->audit,
                "tls_handshake_success",
                peer,
                "TLS 1.3"
            );
            return 0;
        }

        error = SSL_get_error(ssl, result);
        now = monotonic_milliseconds();

        if (now == 0 ||
            started == 0 ||
            now - started >=
                TLS_HANDSHAKE_TIMEOUT_MS) {
            audit_log_event(
                runtime->audit,
                "tls_handshake_timeout",
                peer,
                "handshake deadline exceeded"
            );
            return -1;
        }

        if (retryable_socket_error(error, socket_errno)) {
            continue;
        }

        audit_log_event(
            runtime->audit,
            "tls_handshake_failure",
            peer,
            "TLS handshake rejected"
        );
        return -1;
    }
}

static void tls_shutdown_bounded(
    SSL *ssl,
    int fd,
    uint64_t timeout_ms
)
{
    uint64_t started;

    if (ssl == NULL) {
        return;
    }

    (void)set_socket_timeout(
        fd,
        SO_RCVTIMEO,
        1000U
    );
    (void)set_socket_timeout(
        fd,
        SO_SNDTIMEO,
        1000U
    );

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
            now - started >= timeout_ms) {
            return;
        }

        /*
         * OpenSSL is fussy about shutdown state. Zero is progress: our
         * close_notify went out and we're still waiting for the peer's.
         */
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

static void *connection_worker(void *opaque)
{
    struct worker_args *args = opaque;
    struct server_runtime *runtime = args->runtime;
    int client_fd = args->client_fd;
    enum connection_transport_kind transport = args->transport;
    char peer[96];
    SSL *ssl = NULL;
    telnet_session *session = NULL;
    struct connection_writer writer;
    uint64_t connected_at;
    uint64_t last_activity;
    int handshake_complete = 0;
    int fatal_tls_error = 0;

    memcpy(peer, args->peer, sizeof(peer));
    free(args);

    memset(&writer, 0, sizeof(writer));
    writer.transport = transport;
    writer.fd = client_fd;
    writer.audit = runtime->audit;
    writer.peer = peer;

    (void)set_socket_timeout(
        client_fd,
        SO_RCVTIMEO,
        SOCKET_READ_TICK_MS
    );
    (void)set_socket_timeout(
        client_fd,
        SO_SNDTIMEO,
        SOCKET_READ_TICK_MS
    );

    if (transport == CONNECTION_TRANSPORT_SSH) {
        ssh_transport_connection_config ssh_config = {
            .client_fd = client_fd,
            .peer = peer,
            .host_key_path = runtime->ssh_host_key_path,
            .store = runtime->store,
            .security = runtime->security,
            .audit = runtime->audit,
            .application = runtime->application.open != NULL
                ? &runtime->application : NULL
        };

        /*
         * libssh owns channel flow control, but the underlying socket still
         * gets a finite write timeout so a dead peer cannot pin this worker
         * forever below the SSH packet layer.
         */
        (void)set_socket_timeout(
            client_fd,
            SO_SNDTIMEO,
            SOCKET_WRITE_TIMEOUT_MS
        );

        audit_log_event(
            runtime->audit,
            "ssh_connection",
            peer,
            "accepted SSH terminal transport"
        );
        (void)ssh_transport_run_connection(&ssh_config);

        /* ssh_transport_run_connection owns client_fd once called. */
        runtime_release_connection(runtime);
        return NULL;
    }

    if (transport == CONNECTION_TRANSPORT_TELNET_TLS) {
        ssl = SSL_new(runtime->tls_context);
        if (ssl == NULL) {
            audit_log_event(
                runtime->audit,
                "tls_allocation_failure",
                peer,
                "SSL_new failed"
            );
            goto cleanup;
        }

        if (SSL_set_fd(ssl, client_fd) != 1) {
            audit_log_event(
                runtime->audit,
                "tls_socket_attach_failure",
                peer,
                "SSL_set_fd failed"
            );
            goto cleanup;
        }

        if (tls_accept_with_deadline(runtime, ssl, peer) != 0) {
            fatal_tls_error = 1;
            goto cleanup;
        }

        handshake_complete = 1;
        writer.ssl = ssl;
    } else {
        audit_log_event(
            runtime->audit,
            "telnet_plain_connection",
            peer,
            "unencrypted compatibility transport"
        );
    }

    (void)set_socket_timeout(
        client_fd,
        SO_SNDTIMEO,
        SOCKET_WRITE_TIMEOUT_MS
    );

    {
        telnet_session_config config = {
            .store = runtime->store,
            .security = runtime->security,
            .audit = runtime->audit,
            .remote_id = peer,
            .writer = connection_write,
            .writer_context = &writer,
            .transport_secure =
                transport == CONNECTION_TRANSPORT_TELNET_TLS,
            .application = runtime->application.open != NULL
                ? &runtime->application : NULL,
            .mssp_query = runtime->mssp_query,
            .mssp_context = runtime->mssp_context
        };

        session = telnet_session_create(&config);
    }

    if (session == NULL) {
        audit_log_event(
            runtime->audit,
            "session_allocation_failure",
            peer,
            "unable to create protocol session"
        );
        goto cleanup;
    }

    telnet_session_start(session);

    connected_at = monotonic_milliseconds();
    last_activity = connected_at;

    while (!writer.failed &&
           !telnet_session_should_close(session)) {
        unsigned char buffer[4096];
        uint64_t now = monotonic_milliseconds();
        size_t received = 0;

        if (runtime_is_stopping(runtime)) {
            audit_log_event(
                runtime->audit,
                "session_server_shutdown",
                peer,
                "server stopping"
            );
            break;
        }

        if (now == 0 || connected_at == 0) {
            break;
        }

        if (now - connected_at >= SESSION_MAX_MS) {
            connection_write(
                &writer,
                (const unsigned char *)
                    "Maximum session time reached.\r\n",
                strlen("Maximum session time reached.\r\n")
            );

            audit_log_event(
                runtime->audit,
                "session_maximum_timeout",
                peer,
                "maximum session lifetime reached"
            );
            break;
        }

        if (!telnet_session_is_in_game(session) &&
            now - connected_at >= LOGIN_TIMEOUT_MS) {
            connection_write(
                &writer,
                (const unsigned char *)"Login timed out.\r\n",
                strlen("Login timed out.\r\n")
            );

            audit_log_event(
                runtime->audit,
                "login_timeout",
                peer,
                "login deadline exceeded"
            );
            break;
        }

        if (telnet_session_is_in_game(session) &&
            now - last_activity >= IDLE_TIMEOUT_MS) {
            connection_write(
                &writer,
                (const unsigned char *)"Idle timeout.\r\n",
                strlen("Idle timeout.\r\n")
            );

            audit_log_event(
                runtime->audit,
                "idle_timeout",
                peer,
                "idle session closed"
            );
            break;
        }

        if (telnet_session_poll(session) != 0) {
            break;
        }

        if (transport == CONNECTION_TRANSPORT_TELNET_TLS) {
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
                if (received > 0) {
                    last_activity = monotonic_milliseconds();
                    if (telnet_session_feed_at(
                            session,
                            buffer,
                            received,
                            last_activity
                        ) != 0) {
                        break;
                    }
                }
                continue;
            }

            error = SSL_get_error(ssl, result);
            if (error == SSL_ERROR_ZERO_RETURN) {
                audit_log_event(
                    runtime->audit,
                    "connection_close",
                    peer,
                    "peer sent TLS close_notify"
                );
                break;
            }

            if (retryable_socket_error(error, socket_errno)) {
                continue;
            }

            fatal_tls_error = 1;
            audit_log_event(
                runtime->audit,
                "tls_read_failure",
                peer,
                "fatal TLS read error or unclean disconnect"
            );
            break;
        } else {
            ssize_t result;

            errno = 0;
            result = recv(client_fd, buffer, sizeof(buffer), 0);

            if (result > 0) {
                received = (size_t)result;
                last_activity = monotonic_milliseconds();
                if (telnet_session_feed_at(
                        session,
                        buffer,
                        received,
                        last_activity
                    ) != 0) {
                    break;
                }
                continue;
            }

            if (result == 0) {
                audit_log_event(
                    runtime->audit,
                    "connection_close",
                    peer,
                    "plain Telnet peer closed connection"
                );
                break;
            }

            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }

            audit_log_event(
                runtime->audit,
                "tcp_read_failure",
                peer,
                "plain Telnet socket read failed"
            );
            break;
        }
    }

cleanup:
    if (session != NULL) {
        telnet_session_destroy(session);
    }

    if (ssl != NULL) {
        if (handshake_complete &&
            !fatal_tls_error &&
            !writer.failed) {
            tls_shutdown_bounded(
                ssl,
                client_fd,
                TLS_SHUTDOWN_TIMEOUT_MS
            );
        }

        SSL_free(ssl);
    }

    close(client_fd);
    runtime_release_connection(runtime);
    return NULL;
}

static int peer_string(
    const struct sockaddr_storage *address,
    char *output,
    size_t output_size
)
{
    const void *source;
    int family;
    char ip[INET6_ADDRSTRLEN];

    if (address == NULL) {
        return -1;
    }

    family = address->ss_family;
    if (family == AF_INET) {
        const struct sockaddr_in *ipv4 =
            (const struct sockaddr_in *)address;
        source = &ipv4->sin_addr;
    } else if (family == AF_INET6) {
        const struct sockaddr_in6 *ipv6 =
            (const struct sockaddr_in6 *)address;
        source = &ipv6->sin6_addr;
    } else {
        return -1;
    }

    if (inet_ntop(family, source, ip, sizeof(ip)) == NULL) {
        return -1;
    }

    if (snprintf(output, output_size, "%s", ip) >= (int)output_size) {
        return -1;
    }

    return 0;
}

static int accept_connection(
    struct server_runtime *runtime,
    int listener,
    enum connection_transport_kind transport
)
{
    struct sockaddr_storage remote_address;
    socklen_t remote_length = sizeof(remote_address);
    struct worker_args *args;
    pthread_t thread;
    char peer[96];
    uint64_t retry_ms = 0;
    uint64_t now_ms;
    int client_fd;

    memset(&remote_address, 0, sizeof(remote_address));
    client_fd = accept(
        listener,
        (struct sockaddr *)&remote_address,
        &remote_length
    );

    if (client_fd < 0) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
    }

    if (peer_string(&remote_address, peer, sizeof(peer)) != 0) {
        memcpy(peer, "unknown", sizeof("unknown"));
    }

    now_ms = monotonic_milliseconds();
    if (now_ms == 0 ||
        !security_policy_allow_connection(
            runtime->security,
            peer,
            now_ms,
            &retry_ms
        )) {
        audit_log_event(
            runtime->audit,
            "connection_rate_limited",
            peer,
            transport_label(transport)
        );
        close(client_fd);
        return 0;
    }

    if (!runtime_reserve_connection(runtime)) {
        audit_log_event(
            runtime->audit,
            "connection_capacity_reached",
            peer,
            "maximum active connections reached"
        );
        close(client_fd);
        return 0;
    }

    args = calloc(1, sizeof(*args));
    if (args == NULL) {
        close(client_fd);
        runtime_release_connection(runtime);
        return 0;
    }

    args->runtime = runtime;
    args->client_fd = client_fd;
    args->transport = transport;
    memcpy(args->peer, peer, strlen(peer) + 1);

    if (pthread_create(
            &thread,
            NULL,
            connection_worker,
            args
        ) != 0) {
        free(args);
        close(client_fd);
        runtime_release_connection(runtime);

        audit_log_event(
            runtime->audit,
            "worker_creation_failure",
            peer,
            "pthread_create failed"
        );
        return 0;
    }

    (void)pthread_detach(thread);
    return 0;
}

int secure_server_run(const secure_server_config *config)
{
    struct server_runtime runtime;
    struct sigaction action;
    SSL_CTX *context = NULL;
    player_store *store = NULL;
    security_policy *security = NULL;
    audit_log *audit = NULL;
    int listener_fds[MAX_LISTENER_SOCKETS];
    enum connection_transport_kind listener_transports[MAX_LISTENER_SOCKETS];
    size_t listener_count = 0;
    int ipv6_enabled = 0;
    int ssh_initialized = 0;
    int exit_status = -1;
    size_t listener_index;

    memset(&runtime, 0, sizeof(runtime));
    memset(&action, 0, sizeof(action));
    for (listener_index = 0; listener_index < MAX_LISTENER_SOCKETS; ++listener_index) {
        listener_fds[listener_index] = -1;
    }

    stop_requested = 0;

    if (config == NULL ||
        config->certificate_path == NULL ||
        config->private_key_path == NULL ||
        config->player_directory_path == NULL ||
        config->audit_log_path == NULL ||
        config->telnet_port == 0 ||
        config->telnet_tls_port == 0 ||
        config->telnet_port == config->telnet_tls_port ||
        (config->ssh_port != 0 &&
         (config->ssh_host_key_path == NULL ||
          config->application == NULL ||
          config->ssh_port == config->telnet_port ||
          config->ssh_port == config->telnet_tls_port))) {
        fprintf(stderr, "Invalid server configuration.\n");
        return -1;
    }

    /* High unprivileged ports let the server keep root out of the trust model. */
    if (geteuid() == 0) {
        fprintf(stderr, "Refusing to run the server as root.\n");
        return -1;
    }

    if (config->ssh_port != 0 &&
        ssh_transport_validate_host_key(config->ssh_host_key_path) != 0) {
        fprintf(
            stderr,
            "SSH host key must be a private regular file owned by this user.\n"
        );
        return -1;
    }

    (void)umask(0077);
    (void)signal(SIGPIPE, SIG_IGN);

    action.sa_handler = request_stop;
    sigemptyset(&action.sa_mask);

    if (sigaction(SIGINT, &action, NULL) != 0 ||
        sigaction(SIGTERM, &action, NULL) != 0) {
        perror("sigaction");
        return -1;
    }

    /* Explicit init happens before any SSH worker thread is created. */
    if (config->ssh_port != 0) {
        if (ssh_transport_global_init() != 0) {
            fprintf(stderr, "Unable to initialize libssh.\n");
            return -1;
        }
        ssh_initialized = 1;
    }

    if (pthread_mutex_init(&runtime.mutex, NULL) != 0) {
        fprintf(stderr, "Unable to initialize server synchronization.\n");
        goto cleanup_ssh;
    }

    if (pthread_cond_init(&runtime.condition, NULL) != 0) {
        fprintf(stderr, "Unable to initialize server synchronization.\n");
        pthread_mutex_destroy(&runtime.mutex);
        goto cleanup_ssh;
    }

    audit = audit_log_open(config->audit_log_path);
    if (audit == NULL) {
        fprintf(stderr, "Unable to open the audit log.\n");
        goto cleanup_runtime;
    }

    security = security_policy_create();
    if (security == NULL) {
        fprintf(stderr, "Unable to initialize security policy.\n");
        goto cleanup;
    }

    store = player_store_open(config->player_directory_path);
    if (store == NULL) {
        fprintf(stderr, "Unable to open the player store.\n");
        goto cleanup;
    }

    context = create_tls_context(config);
    if (context == NULL) {
        goto cleanup;
    }

    listener_fds[listener_count] = create_loopback_listener(
        AF_INET, config->telnet_port, 0
    );
    if (listener_fds[listener_count] < 0) {
        goto cleanup;
    }
    listener_transports[listener_count++] = CONNECTION_TRANSPORT_TELNET;

    listener_fds[listener_count] = create_loopback_listener(
        AF_INET6, config->telnet_port, 1
    );
    if (listener_fds[listener_count] == -1) {
        goto cleanup;
    }
    if (listener_fds[listener_count] >= 0) {
        listener_transports[listener_count++] = CONNECTION_TRANSPORT_TELNET;
        ipv6_enabled = 1;
    }

    listener_fds[listener_count] = create_loopback_listener(
        AF_INET, config->telnet_tls_port, 0
    );
    if (listener_fds[listener_count] < 0) {
        goto cleanup;
    }
    listener_transports[listener_count++] = CONNECTION_TRANSPORT_TELNET_TLS;

    listener_fds[listener_count] = create_loopback_listener(
        AF_INET6, config->telnet_tls_port, 1
    );
    if (listener_fds[listener_count] == -1) {
        goto cleanup;
    }
    if (listener_fds[listener_count] >= 0) {
        listener_transports[listener_count++] = CONNECTION_TRANSPORT_TELNET_TLS;
        ipv6_enabled = 1;
    }

    if (config->ssh_port != 0) {
        listener_fds[listener_count] = create_loopback_listener(
            AF_INET, config->ssh_port, 0
        );
        if (listener_fds[listener_count] < 0) {
            goto cleanup;
        }
        listener_transports[listener_count++] = CONNECTION_TRANSPORT_SSH;

        listener_fds[listener_count] = create_loopback_listener(
            AF_INET6, config->ssh_port, 1
        );
        if (listener_fds[listener_count] == -1) {
            goto cleanup;
        }
        if (listener_fds[listener_count] >= 0) {
            listener_transports[listener_count++] = CONNECTION_TRANSPORT_SSH;
            ipv6_enabled = 1;
        }
    }

    runtime.tls_context = context;
    runtime.store = store;
    if (config->application != NULL) {
        runtime.application = *config->application;
    }
    runtime.mssp_query = config->mssp_query;
    runtime.mssp_context = config->mssp_context;
    runtime.ssh_host_key_path = config->ssh_host_key_path;
    runtime.security = security;
    runtime.audit = audit;

    audit_log_event(
        audit,
        "server_start",
        "local",
        config->ssh_port != 0
            ? "Telnet, TLS Telnet, and SSH listeners started"
            : "plain Telnet and TLS 1.3 Telnet listeners started"
    );

    fprintf(
        stdout,
        "Plain Telnet compatibility listener ready on 127.0.0.1:%u%s.\n",
        (unsigned int)config->telnet_port,
        ipv6_enabled ? " and IPv6 loopback" : ""
    );
    fprintf(
        stdout,
        "Encrypted Telnet listener ready on 127.0.0.1:%u%s using TLS 1.3.\n",
        (unsigned int)config->telnet_tls_port,
        ipv6_enabled ? " and IPv6 loopback" : ""
    );
    if (config->ssh_port != 0) {
        fprintf(
            stdout,
            "SSH terminal listener ready on 127.0.0.1:%u%s.\n",
            (unsigned int)config->ssh_port,
            ipv6_enabled ? " and IPv6 loopback" : ""
        );
    }
    fprintf(
        stdout,
        "Connection policy is shared across all enabled transports.\n"
    );
    fflush(stdout);

    while (!stop_requested) {
        struct pollfd poll_fds[MAX_LISTENER_SOCKETS];
        int result;
        nfds_t i;
        int fatal_listener_error = 0;

        memset(poll_fds, 0, sizeof(poll_fds));
        for (i = 0; i < (nfds_t)listener_count; ++i) {
            poll_fds[i].fd = listener_fds[i];
            poll_fds[i].events = POLLIN;
        }

        result = poll(poll_fds, (nfds_t)listener_count, 1000);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("poll");
            audit_log_event(
                audit,
                "listener_failure",
                "local",
                "poll failed"
            );
            break;
        }

        if (result == 0) {
            continue;
        }

        for (i = 0; i < (nfds_t)listener_count; ++i) {
            enum connection_transport_kind transport = listener_transports[i];

            if (poll_fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                audit_log_event(
                    audit,
                    "listener_failure",
                    "local",
                    transport_label(transport)
                );
                fatal_listener_error = 1;
                break;
            }

            if ((poll_fds[i].revents & POLLIN) != 0 &&
                accept_connection(
                    &runtime,
                    poll_fds[i].fd,
                    transport
                ) != 0) {
                perror("accept");
                audit_log_event(
                    audit,
                    "listener_failure",
                    "local",
                    transport_label(transport)
                );
                fatal_listener_error = 1;
                break;
            }
        }

        if (fatal_listener_error) {
            break;
        }
    }

    exit_status = stop_requested ? 0 : -1;
    runtime_begin_shutdown(&runtime);

    for (listener_index = 0; listener_index < listener_count; ++listener_index) {
        if (listener_fds[listener_index] >= 0) {
            close(listener_fds[listener_index]);
            listener_fds[listener_index] = -1;
        }
    }

    runtime_wait_for_workers(&runtime);

    audit_log_event(
        audit,
        "server_stop",
        "local",
        "listeners stopped"
    );

cleanup:
    for (listener_index = 0; listener_index < listener_count; ++listener_index) {
        if (listener_fds[listener_index] >= 0) {
            close(listener_fds[listener_index]);
            listener_fds[listener_index] = -1;
        }
    }

    SSL_CTX_free(context);
    player_store_close(store);
    security_policy_destroy(security);
    audit_log_close(audit);

cleanup_runtime:
    pthread_cond_destroy(&runtime.condition);
    pthread_mutex_destroy(&runtime.mutex);

cleanup_ssh:
    if (ssh_initialized) {
        ssh_transport_global_cleanup();
    }

    return exit_status;
}
