// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

/*
 * telnet_protocol.c
 *
 * Telnet/NVT owner for the standalone C MUD connection slice. This file turns
 * an arbitrary stream of transport bytes into line-oriented application input,
 * owns Telnet option/subnegotiation handling and terminal capability discovery,
 * and encodes application output back onto the Telnet stream. It does not own
 * sockets or TLS; those arrive through the writer/feed boundary.
 *
 * Telnet still owns the small account dialogue used by the runnable reference.
 * After authentication it can attach terminal_application, which is also where
 * SSH arrives. That keeps the example useful by itself without making Telnet
 * framing the application's permanent account/session architecture.
 */

#define _POSIX_C_SOURCE 200809L

#include "telnet_protocol.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sodium.h>

#include "telnet_internal.h"
#include "terminal_text.h"

/* Authentication/application phases for one connected session. */
enum login_state {
    LOGIN_NAME = 0,
    LOGIN_PASSWORD,
    LOGIN_NEW_PASSWORD,
    LOGIN_CONFIRM_PASSWORD,
    LOGIN_IN_GAME
};

/* Raw-byte parser states for Telnet commands and subnegotiation. */
enum parser_state {
    PARSER_DATA = 0,
    PARSER_IAC,
    PARSER_OPTION,
    PARSER_SB_OPTION,
    PARSER_SB_DATA,
    PARSER_SB_IAC
};

enum {
    TERMINAL_TYPE_IS = 0,
    TERMINAL_TYPE_SEND = 1,

    CHARSET_REQUEST = 1,
    CHARSET_ACCEPTED = 2,
    CHARSET_REJECTED = 3,

    NEW_ENVIRON_IS = 0,
    NEW_ENVIRON_SEND = 1,
    NEW_ENVIRON_INFO = 2,
    NEW_ENVIRON_VAR = 0,
    NEW_ENVIRON_VAL = 1,
    NEW_ENVIRON_ESC = 2,
    NEW_ENVIRON_USERVAR = 3
};

/* Per-session fixed window used for byte, line, and command ceilings. */
struct rate_window {
    uint64_t started_ms;
    size_t used;
};

#define GMCP_PACKAGE_MAX_BYTES 96U
#define GMCP_JSON_MAX_BYTES 3968U

/*
 * GMCP Core.Hello/Supports are normally sent before a player has authenticated.
 * The application seam opens after authentication, so keep a tiny bounded queue
 * rather than silently throwing that early client handshake away.
 */
#define PENDING_GMCP_CORE_MAX 4U
struct pending_gmcp_core_message {
    char package_name[GMCP_PACKAGE_MAX_BYTES + 1];
    char json_payload[GMCP_JSON_MAX_BYTES + 1];
    size_t json_length;
};

/* Complete mutable state owned by one Telnet connection. */
struct telnet_session {
    player_store *store;
    security_policy *security;
    audit_log *audit;
    char remote_id[96];

    telnet_write_fn writer;
    void *writer_context;

    terminal_application_hooks application;
    terminal_output application_output;
    void *application_session;

    telnet_mssp_query_fn mssp_query;
    void *mssp_context;
    int mssp_sent;

    struct pending_gmcp_core_message pending_gmcp_core[PENDING_GMCP_CORE_MAX];
    size_t pending_gmcp_core_count;

    enum login_state login;
    enum parser_state parser;
    unsigned char pending_telnet_command;

    telnet_q options;
    int echo_desired;

    /* Capability probes are bounded and never gate login. */
    unsigned int terminal_type_requests_sent;
    int terminal_type_waiting;
    char last_terminal_type[TELNET_TERMINAL_TYPE_MAX + 1];
    int charset_request_sent;
    int charset_utf8;
    int new_environ_requested;
    int mnes_observed;
    int insecure_warning_shown;

    unsigned char subnegotiation_option;
    unsigned char subnegotiation[4096];
    size_t subnegotiation_length;

    int started;
    int close_requested;
    unsigned int protocol_violations;
    int pending_cr;

    char line[513];
    size_t line_length;
    int line_overflow;

    char player_name[PLAYER_NAME_MAX + 1];
    player_password_token pending_password;

    telnet_terminal_info terminal;

    struct rate_window byte_window;
    struct rate_window line_window;
    struct rate_window command_window;
};

/* Session-local resource limits. Shared peer/account limits live in security_policy. */
#define INPUT_BYTES_PER_WINDOW 65536U
#define INPUT_BYTES_WINDOW_MS 5000ULL
#define INPUT_LINES_PER_WINDOW 30U
#define INPUT_LINES_WINDOW_MS 10000ULL
#define COMMANDS_PER_WINDOW 25U
#define COMMANDS_WINDOW_MS 5000ULL
#define SUBNEGOTIATION_MAX_BYTES 4096U
#define APPLICATION_LINE_MAX 512U
#define MSSP_PAYLOAD_MAX_BYTES 2048U
#define PROTOCOL_VIOLATION_LIMIT 8U
#define TERMINAL_TYPE_REQUEST_LIMIT 4U

#define DEFAULT_TERMINAL_WIDTH 80U
#define DEFAULT_TERMINAL_HEIGHT 24U
#define MIN_TERMINAL_WIDTH 20U
#define MAX_TERMINAL_WIDTH 500U
#define MIN_TERMINAL_HEIGHT 5U
#define MAX_TERMINAL_HEIGHT 200U

static void request_close(
    telnet_session *session,
    const char *event,
    const char *message
);

static uint64_t monotonic_milliseconds(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 1;
    }

    return ((uint64_t)now.tv_sec * 1000ULL) +
           ((uint64_t)now.tv_nsec / 1000000ULL);
}

static int rate_consume(
    struct rate_window *window,
    size_t amount,
    size_t limit,
    uint64_t window_ms,
    uint64_t now_ms
)
{
    if (window->started_ms == 0 ||
        now_ms < window->started_ms ||
        now_ms - window->started_ms >= window_ms) {
        window->started_ms = now_ms;
        window->used = 0;
    }

    if (amount > limit || window->used > limit - amount) {
        return 0;
    }

    window->used += amount;
    return 1;
}

static void audit(
    telnet_session *session,
    const char *event,
    const char *detail
)
{
    audit_log_event(
        session->audit,
        event,
        session->remote_id,
        detail
    );
}

static void write_raw(
    telnet_session *session,
    const unsigned char *data,
    size_t length
)
{
    if (session != NULL &&
        session->writer != NULL &&
        length > 0 &&
        !session->close_requested) {
        session->writer(session->writer_context, data, length);
    }
}

/*
 * Application data always quotes IAC, including BINARY mode. Protocol
 * command sequences use write_raw().
 */
static void write_telnet_data(
    telnet_session *session,
    const unsigned char *data,
    size_t length
)
{
    size_t start = 0;
    size_t i;

    for (i = 0; i < length; ++i) {
        if (data[i] != TELNET_IAC) {
            continue;
        }

        if (i > start) {
            write_raw(session, data + start, i - start);
        }

        {
            const unsigned char escaped[2] = {
                TELNET_IAC,
                TELNET_IAC
            };
            write_raw(session, escaped, sizeof(escaped));
        }

        start = i + 1;
    }

    if (start < length) {
        write_raw(session, data + start, length - start);
    }
}

static void write_text(telnet_session *session, const char *text)
{
    write_telnet_data(
        session,
        (const unsigned char *)text,
        strlen(text)
    );
}


/*
 * Prompts intentionally lack CRLF, so mark their boundary when the peer has a
 * Telnet mechanism for it. EOR is preferred. Before SGA is agreed (or when it
 * is refused), ordinary Telnet GA remains the standards-compatible fallback.
 */
static void write_prompt_text(telnet_session *session, const char *text)
{
    write_text(session, text);

    if (session->terminal.local_eor) {
        const unsigned char marker[2] = {
            TELNET_IAC,
            TELNET_EOR
        };
        write_raw(session, marker, sizeof(marker));
    } else if (!session->terminal.local_suppress_go_ahead) {
        const unsigned char marker[2] = {
            TELNET_IAC,
            TELNET_GA
        };
        write_raw(session, marker, sizeof(marker));
    }
}

static void warn_insecure_password_once(telnet_session *session)
{
    if (session->terminal.secure_transport ||
        session->insecure_warning_shown) {
        return;
    }

    session->insecure_warning_shown = 1;
    write_text(
        session,
        "\r\n"
        "[Notice: plain Telnet is not encrypted; use the TLS endpoint "
        "when available.]\r\n"
    );
}

static void write_untrusted_text(
    telnet_session *session,
    const char *text
)
{
    char safe[256];

    terminal_text_sanitize(
        (const unsigned char *)text,
        strlen(text),
        safe,
        sizeof(safe)
    );

    write_text(session, safe);
}

static void write_telnet_option_raw(
    telnet_session *session,
    unsigned char command,
    unsigned char option
)
{
    const unsigned char bytes[3] = {
        TELNET_IAC,
        command,
        option
    };

    write_raw(session, bytes, sizeof(bytes));
}

static void q_send_callback(
    void *context,
    unsigned char command,
    unsigned char option
)
{
    write_telnet_option_raw(
        (telnet_session *)context,
        command,
        option
    );
}

static int q_accept_callback(
    void *context,
    telnet_q_direction direction,
    unsigned char option
)
{
    telnet_session *session = context;

    if (direction == TELNET_Q_LOCAL) {
        switch (option) {
            case TELNET_OPT_BINARY:
            case TELNET_OPT_SUPPRESS_GO_AHEAD:
            case TELNET_OPT_END_OF_RECORD:
            case TELNET_OPT_CHARSET:
            case TELNET_OPT_GMCP:
                return 1;

            case TELNET_OPT_MSSP:
                return session->mssp_query != NULL;

            case TELNET_OPT_ECHO:
                return session->echo_desired;

            default:
                return 0;
        }
    }

    switch (option) {
        case TELNET_OPT_BINARY:
        case TELNET_OPT_SUPPRESS_GO_AHEAD:
        case TELNET_OPT_TERMINAL_TYPE:
        case TELNET_OPT_NAWS:
        case TELNET_OPT_NEW_ENVIRON:
        case TELNET_OPT_CHARSET:
            return 1;

        /* LINEMODE and every unknown option remain explicitly unsupported. */
        default:
            return 0;
    }
}

static void send_subnegotiation(
    telnet_session *session,
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

    write_raw(session, begin, sizeof(begin));

    for (i = 0; i < payload_length; ++i) {
        if (payload[i] == TELNET_IAC) {
            const unsigned char escaped[2] = {
                TELNET_IAC,
                TELNET_IAC
            };
            write_raw(session, escaped, sizeof(escaped));
        } else {
            write_raw(session, payload + i, 1);
        }
    }

    write_raw(session, end, sizeof(end));
}

static int mssp_append_pair(
    unsigned char *payload,
    size_t payload_size,
    size_t *used,
    const char *name,
    const char *value
)
{
    size_t name_length;
    size_t value_length;
    size_t i;

    if (payload == NULL || used == NULL || name == NULL || value == NULL) {
        return -1;
    }
    name_length = strlen(name);
    value_length = strlen(value);
    if (name_length == 0 ||
        *used + 2U + name_length + value_length > payload_size) {
        return -1;
    }

    for (i = 0; i < name_length; ++i) {
        unsigned char ch = (unsigned char)name[i];
        if (!((ch >= 'A' && ch <= 'Z') || ch == ' ')) {
            return -1;
        }
    }
    for (i = 0; i < value_length; ++i) {
        unsigned char ch = (unsigned char)value[i];
        if (ch == 0 || ch == 1 || ch == 2 || ch == TELNET_IAC) {
            return -1;
        }
    }

    payload[(*used)++] = 1; /* MSSP_VAR */
    memcpy(payload + *used, name, name_length);
    *used += name_length;
    payload[(*used)++] = 2; /* MSSP_VAL */
    memcpy(payload + *used, value, value_length);
    *used += value_length;
    return 0;
}

static void send_mssp_status(telnet_session *session)
{
    unsigned char payload[MSSP_PAYLOAD_MAX_BYTES];
    telnet_mssp_status status;
    char players[32];
    char uptime[32];
    char plain_port[16];
    char tls_port[16];
    size_t used = 0;

    if (session == NULL || session->mssp_sent || session->mssp_query == NULL ||
        !telnet_q_enabled(
            &session->options,
            TELNET_Q_LOCAL,
            TELNET_OPT_MSSP
        )) {
        return;
    }

    memset(&status, 0, sizeof(status));
    session->mssp_query(session->mssp_context, &status);
    if (status.name[0] == '\0') {
        memcpy(status.name, "mud-terminal-core", sizeof("mud-terminal-core"));
    }
    if (status.codebase[0] == '\0') {
        memcpy(status.codebase, "mud-terminal-core", sizeof("mud-terminal-core"));
    }

    (void)snprintf(players, sizeof(players), "%u", status.players);
    (void)snprintf(uptime, sizeof(uptime), "%llu",
                   (unsigned long long)status.uptime);
    (void)snprintf(plain_port, sizeof(plain_port), "%u",
                   (unsigned int)status.telnet_port);
    (void)snprintf(tls_port, sizeof(tls_port), "%u",
                   (unsigned int)status.telnet_tls_port);

    if (mssp_append_pair(payload, sizeof(payload), &used, "NAME", status.name) != 0 ||
        mssp_append_pair(payload, sizeof(payload), &used, "PLAYERS", players) != 0 ||
        mssp_append_pair(payload, sizeof(payload), &used, "UPTIME", uptime) != 0 ||
        mssp_append_pair(payload, sizeof(payload), &used, "CHARSET", "UTF-8") != 0 ||
        mssp_append_pair(payload, sizeof(payload), &used, "CODEBASE", status.codebase) != 0) {
        audit(session, "mssp_status_error", "unable to encode MSSP snapshot");
        return;
    }

    if (status.telnet_port != 0 &&
        mssp_append_pair(payload, sizeof(payload), &used, "PORT", plain_port) != 0) {
        return;
    }
    if (status.telnet_tls_port != 0 &&
        mssp_append_pair(payload, sizeof(payload), &used, "SSL", tls_port) != 0) {
        return;
    }

    session->mssp_sent = 1;
    send_subnegotiation(session, TELNET_OPT_MSSP, payload, used);
}

static int gmcp_package_valid(const char *package_name)
{
    size_t length;
    size_t i;

    if (package_name == NULL) {
        return 0;
    }
    length = strlen(package_name);
    if (length == 0 || length > GMCP_PACKAGE_MAX_BYTES) {
        return 0;
    }

    for (i = 0; i < length; ++i) {
        unsigned char ch = (unsigned char)package_name[i];
        int letter =
            (ch >= 'A' && ch <= 'Z') ||
            (ch >= 'a' && ch <= 'z');
        int digit = ch >= '0' && ch <= '9';
        if (!letter && !digit && ch != '.' && ch != '_' && ch != '-') {
            return 0;
        }
    }
    return 1;
}

static int send_gmcp_message(
    telnet_session *session,
    const char *package_name,
    const char *json_payload
)
{
    unsigned char payload[SUBNEGOTIATION_MAX_BYTES];
    size_t package_length;
    size_t json_length = 0;
    size_t used = 0;

    if (session == NULL ||
        !session->terminal.gmcp ||
        !gmcp_package_valid(package_name)) {
        return -1;
    }

    package_length = strlen(package_name);
    if (json_payload != NULL && json_payload[0] != '\0') {
        json_length = strlen(json_payload);
        if (json_length > GMCP_JSON_MAX_BYTES ||
            !terminal_text_utf8_valid(
                (const unsigned char *)json_payload,
                json_length
            )) {
            return -1;
        }
    }

    if (package_length + (json_length != 0 ? 1U + json_length : 0U) >
        sizeof(payload)) {
        return -1;
    }

    memcpy(payload + used, package_name, package_length);
    used += package_length;
    if (json_length != 0) {
        payload[used++] = ' ';
        memcpy(payload + used, json_payload, json_length);
        used += json_length;
    }

    send_subnegotiation(session, TELNET_OPT_GMCP, payload, used);
    return 0;
}

static int gmcp_package_equal(const char *left, const char *right)
{
    while (*left != '\0' && *right != '\0') {
        unsigned char a = (unsigned char)*left;
        unsigned char b = (unsigned char)*right;
        if (a >= 'A' && a <= 'Z') a = (unsigned char)(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z') b = (unsigned char)(b + ('a' - 'A'));
        if (a != b) return 0;
        ++left;
        ++right;
    }
    return *left == '\0' && *right == '\0';
}

static int gmcp_core_handshake_package(const char *package_name)
{
    return gmcp_package_equal(package_name, "Core.Hello") ||
           gmcp_package_equal(package_name, "Core.Supports.Set") ||
           gmcp_package_equal(package_name, "Core.Supports.Add") ||
           gmcp_package_equal(package_name, "Core.Supports.Remove");
}

static void queue_pre_auth_gmcp_core(
    telnet_session *session,
    const char *package_name,
    const char *json_payload,
    size_t json_length
)
{
    struct pending_gmcp_core_message *message;

    if (session->application.gmcp == NULL ||
        !gmcp_core_handshake_package(package_name)) {
        return;
    }

    if (session->pending_gmcp_core_count >= PENDING_GMCP_CORE_MAX) {
        audit(session, "gmcp_core_queue_full", "early Core handshake message dropped");
        return;
    }

    message = &session->pending_gmcp_core[session->pending_gmcp_core_count++];
    memcpy(message->package_name, package_name, strlen(package_name) + 1);
    memcpy(message->json_payload, json_payload, json_length);
    message->json_payload[json_length] = '\0';
    message->json_length = json_length;
}

static void replay_pre_auth_gmcp_core(telnet_session *session)
{
    size_t index;

    if (session->application_session == NULL || session->application.gmcp == NULL) {
        session->pending_gmcp_core_count = 0;
        return;
    }

    for (index = 0; index < session->pending_gmcp_core_count; ++index) {
        const struct pending_gmcp_core_message *message =
            &session->pending_gmcp_core[index];
        session->application.gmcp(
            session->application_session,
            message->package_name,
            message->json_payload,
            message->json_length
        );
    }

    session->pending_gmcp_core_count = 0;
}

static void handle_gmcp(telnet_session *session)
{
    char package_name[GMCP_PACKAGE_MAX_BYTES + 1];
    char json_payload[GMCP_JSON_MAX_BYTES + 1];
    size_t package_length = 0;
    size_t json_length = 0;
    size_t i = 0;

    if (!telnet_q_enabled(
            &session->options,
            TELNET_Q_LOCAL,
            TELNET_OPT_GMCP
        ) || session->subnegotiation_length == 0) {
        return;
    }

    while (i < session->subnegotiation_length &&
           session->subnegotiation[i] != ' ') {
        if (package_length >= GMCP_PACKAGE_MAX_BYTES) {
            audit(session, "gmcp_invalid_message", "package name too long");
            return;
        }
        package_name[package_length++] = (char)session->subnegotiation[i++];
    }
    package_name[package_length] = '\0';
    if (!gmcp_package_valid(package_name)) {
        audit(session, "gmcp_invalid_message", "invalid package name");
        return;
    }

    if (i < session->subnegotiation_length && session->subnegotiation[i] == ' ') {
        ++i;
        json_length = session->subnegotiation_length - i;
        if (json_length > GMCP_JSON_MAX_BYTES ||
            !terminal_text_utf8_valid(session->subnegotiation + i, json_length)) {
            audit(session, "gmcp_invalid_message", "invalid or oversized UTF-8 body");
            return;
        }
        memcpy(json_payload, session->subnegotiation + i, json_length);
    }
    json_payload[json_length] = '\0';

    /* Core.Ping has a protocol-defined no-body echo response. */
    if (gmcp_package_equal(package_name, "Core.Ping")) {
        (void)send_gmcp_message(session, "Core.Ping", NULL);
    }

    if (session->application_session != NULL && session->application.gmcp != NULL) {
        session->application.gmcp(
            session->application_session,
            package_name,
            json_payload,
            json_length
        );
    } else {
        queue_pre_auth_gmcp_core(
            session,
            package_name,
            json_payload,
            json_length
        );
    }
}

static int osc_uri_safe(const char *uri)
{
    size_t i;
    size_t length;

    if (uri == NULL || uri[0] == '\0') {
        return 0;
    }
    length = strlen(uri);
    if (length > 1024 ||
        !terminal_text_utf8_valid((const unsigned char *)uri, length)) {
        return 0;
    }
    for (i = 0; i < length; ++i) {
        unsigned char ch = (unsigned char)uri[i];
        if (ch < 0x20 || ch == 0x7f || ch == 0x1b) {
            return 0;
        }
    }
    return 1;
}

static void write_application_text(telnet_session *session, const char *text)
{
    const char *start = text;
    const char *cursor = text;

    if (session == NULL || text == NULL) {
        return;
    }

    while (*cursor != '\0') {
        if (*cursor == '\n' && (cursor == text || cursor[-1] != '\r')) {
            if (cursor > start) {
                write_telnet_data(
                    session,
                    (const unsigned char *)start,
                    (size_t)(cursor - start)
                );
            }
            write_telnet_data(session, (const unsigned char *)"\r\n", 2);
            start = cursor + 1;
        }
        ++cursor;
    }
    if (cursor > start) {
        write_telnet_data(
            session,
            (const unsigned char *)start,
            (size_t)(cursor - start)
        );
    }
}

static void application_write_text(void *context, const char *text)
{
    telnet_session *session = context;
    if (session != NULL && text != NULL) {
        write_application_text(session, text);
    }
}

static void application_write_prompt(void *context, const char *text)
{
    telnet_session *session = context;
    if (session != NULL && text != NULL) {
        write_application_text(session, text);
        if (session->terminal.local_eor) {
            const unsigned char marker[2] = {TELNET_IAC, TELNET_EOR};
            write_raw(session, marker, sizeof(marker));
        } else if (!session->terminal.local_suppress_go_ahead) {
            const unsigned char marker[2] = {TELNET_IAC, TELNET_GA};
            write_raw(session, marker, sizeof(marker));
        }
    }
}

static void application_request_close(void *context, const char *message)
{
    telnet_session *session = context;
    if (session != NULL) {
        request_close(session, "application_close", message);
    }
}

static int application_send_gmcp(
    void *context,
    const char *package_name,
    const char *json_payload
)
{
    return send_gmcp_message(
        (telnet_session *)context,
        package_name,
        json_payload
    );
}

static int application_write_link(
    void *context,
    const char *uri,
    const char *label
)
{
    telnet_session *session = context;
    char safe_label[512];
    const unsigned char begin[] = {'\033', ']', '8', ';', ';'};
    const unsigned char end_link[] = {'\033', ']', '8', ';', ';', '\033', '\\'};
    const unsigned char string_terminator[] = {'\033', '\\'};

    if (session == NULL || label == NULL) {
        return -1;
    }

    terminal_text_sanitize(
        (const unsigned char *)label,
        strlen(label),
        safe_label,
        sizeof(safe_label)
    );

    if (!session->terminal.osc8 || !osc_uri_safe(uri) ||
        (strncmp(uri, "send:", 5) == 0 && !session->terminal.osc8_send) ||
        (strncmp(uri, "prompt:", 7) == 0 && !session->terminal.osc8_prompt)) {
        write_text(session, safe_label);
        return 0;
    }

    write_telnet_data(session, begin, sizeof(begin));
    write_telnet_data(
        session,
        (const unsigned char *)uri,
        strlen(uri)
    );
    write_telnet_data(session, string_terminator, sizeof(string_terminator));
    write_text(session, safe_label);
    write_telnet_data(session, end_link, sizeof(end_link));
    return 0;
}

static void copy_terminal_capabilities(
    const telnet_session *session,
    terminal_capabilities *capabilities
)
{
    if (capabilities == NULL) {
        return;
    }
    memset(capabilities, 0, sizeof(*capabilities));
    if (session == NULL) {
        capabilities->width = DEFAULT_TERMINAL_WIDTH;
        capabilities->height = DEFAULT_TERMINAL_HEIGHT;
        memcpy(capabilities->terminal_type, "UNKNOWN", sizeof("UNKNOWN"));
        memcpy(capabilities->client_name, "UNKNOWN", sizeof("UNKNOWN"));
        return;
    }

    capabilities->width = session->terminal.width;
    capabilities->height = session->terminal.height;
    capabilities->utf8 = session->terminal.utf8_enabled;
    capabilities->ansi = session->terminal.ansi;
    capabilities->color_256 = session->terminal.color_256;
    capabilities->truecolor = session->terminal.truecolor;
    capabilities->screen_reader = session->terminal.screen_reader;
    capabilities->secure_transport = session->terminal.secure_transport;
    capabilities->gmcp = session->terminal.gmcp;
    capabilities->osc8 = session->terminal.osc8;
    capabilities->osc8_send = session->terminal.osc8_send;
    capabilities->osc8_prompt = session->terminal.osc8_prompt;
    capabilities->osc8_tooltip = session->terminal.osc8_tooltip;
    memcpy(
        capabilities->terminal_type,
        session->terminal.terminal_type,
        sizeof(capabilities->terminal_type)
    );
    memcpy(
        capabilities->client_name,
        session->terminal.client_name,
        sizeof(capabilities->client_name)
    );
    memcpy(
        capabilities->client_version,
        session->terminal.client_version,
        sizeof(capabilities->client_version)
    );
}

static void notify_application_capabilities(telnet_session *session)
{
    terminal_capabilities capabilities;

    if (session == NULL || session->application_session == NULL ||
        session->application.capabilities_changed == NULL) {
        return;
    }
    copy_terminal_capabilities(session, &capabilities);
    session->application.capabilities_changed(
        session->application_session,
        &capabilities
    );
}

static void apply_mtts_flags(telnet_session *session, uint32_t flags)
{
    session->terminal.mtts_flags = flags;
    session->terminal.ansi = (flags & TELNET_MTTS_ANSI) != 0;
    session->terminal.vt100 = (flags & TELNET_MTTS_VT100) != 0;
    session->terminal.color_256 =
        (flags & TELNET_MTTS_256_COLORS) != 0;
    session->terminal.truecolor =
        (flags & TELNET_MTTS_TRUECOLOR) != 0;
    session->terminal.screen_reader =
        (flags & TELNET_MTTS_SCREEN_READER) != 0;
    session->terminal.mnes = (flags & TELNET_MTTS_MNES) != 0;
}

static void refresh_utf8_metadata(telnet_session *session)
{
    session->terminal.utf8_enabled =
        session->charset_utf8 ||
        (session->terminal.mtts_flags & TELNET_MTTS_UTF8) != 0;
}

static void request_terminal_type(telnet_session *session)
{
    const unsigned char payload[1] = {
        TERMINAL_TYPE_SEND
    };

    if (session->terminal_type_waiting ||
        session->terminal_type_requests_sent >=
            TERMINAL_TYPE_REQUEST_LIMIT ||
        !telnet_q_enabled(
            &session->options,
            TELNET_Q_REMOTE,
            TELNET_OPT_TERMINAL_TYPE
        )) {
        return;
    }

    ++session->terminal_type_requests_sent;
    session->terminal_type_waiting = 1;
    send_subnegotiation(
        session,
        TELNET_OPT_TERMINAL_TYPE,
        payload,
        sizeof(payload)
    );
}

static void request_charset(telnet_session *session)
{
    const unsigned char payload[] = {
        CHARSET_REQUEST,
        ';',
        'U', 'T', 'F', '-', '8'
    };

    /*
     * RFC 2066 permits either side to initiate CHARSET. Supporting both roles
     * avoids depending on one client-specific negotiation ordering.
     */
    if (session->charset_request_sent ||
        !session->terminal.local_binary ||
        !session->terminal.remote_binary ||
        !telnet_q_enabled(
            &session->options,
            TELNET_Q_LOCAL,
            TELNET_OPT_CHARSET
        )) {
        return;
    }

    session->charset_request_sent = 1;
    send_subnegotiation(
        session,
        TELNET_OPT_CHARSET,
        payload,
        sizeof(payload)
    );
}

static void request_new_environ(telnet_session *session)
{
    /*
     * Ask for both the compact MNES VAR vocabulary and the RFC-style USERVAR
     * names used by modern clients. Repeated facts are harmless: whichever
     * report arrives last refreshes the same capability state.
     */
    static const unsigned char payload[] = {
        NEW_ENVIRON_SEND,

        NEW_ENVIRON_VAR,
        'C','L','I','E','N','T','_','N','A','M','E',
        NEW_ENVIRON_VAR,
        'C','L','I','E','N','T','_','V','E','R','S','I','O','N',
        NEW_ENVIRON_VAR,
        'C','H','A','R','S','E','T',
        NEW_ENVIRON_VAR,
        'M','T','T','S',
        NEW_ENVIRON_VAR,
        'T','E','R','M','I','N','A','L','_','T','Y','P','E',

        NEW_ENVIRON_USERVAR,
        'C','L','I','E','N','T','_','N','A','M','E',
        NEW_ENVIRON_USERVAR,
        'C','L','I','E','N','T','_','V','E','R','S','I','O','N',
        NEW_ENVIRON_USERVAR,
        'C','H','A','R','S','E','T',
        NEW_ENVIRON_USERVAR,
        'M','T','T','S',
        NEW_ENVIRON_USERVAR,
        'T','E','R','M','I','N','A','L','_','T','Y','P','E',
        NEW_ENVIRON_USERVAR,
        'S','C','R','E','E','N','_','R','E','A','D','E','R',
        NEW_ENVIRON_USERVAR,
        'O','S','C','_','H','Y','P','E','R','L','I','N','K','S',
        NEW_ENVIRON_USERVAR,
        'O','S','C','_','H','Y','P','E','R','L','I','N','K','S','_','S','E','N','D',
        NEW_ENVIRON_USERVAR,
        'O','S','C','_','H','Y','P','E','R','L','I','N','K','S','_','P','R','O','M','P','T',
        NEW_ENVIRON_USERVAR,
        'O','S','C','_','H','Y','P','E','R','L','I','N','K','S','_','T','O','O','L','T','I','P'
    };

    if (session->new_environ_requested ||
        !telnet_q_enabled(
            &session->options,
            TELNET_Q_REMOTE,
            TELNET_OPT_NEW_ENVIRON
        )) {
        return;
    }

    session->new_environ_requested = 1;
    send_subnegotiation(
        session,
        TELNET_OPT_NEW_ENVIRON,
        payload,
        sizeof(payload)
    );
}

static void update_option_metadata(telnet_session *session)
{
    session->terminal.local_binary = telnet_q_enabled(
        &session->options,
        TELNET_Q_LOCAL,
        TELNET_OPT_BINARY
    );

    session->terminal.remote_binary = telnet_q_enabled(
        &session->options,
        TELNET_Q_REMOTE,
        TELNET_OPT_BINARY
    );

    session->terminal.local_suppress_go_ahead = telnet_q_enabled(
        &session->options,
        TELNET_Q_LOCAL,
        TELNET_OPT_SUPPRESS_GO_AHEAD
    );

    session->terminal.remote_suppress_go_ahead = telnet_q_enabled(
        &session->options,
        TELNET_Q_REMOTE,
        TELNET_OPT_SUPPRESS_GO_AHEAD
    );

    session->terminal.local_eor = telnet_q_enabled(
        &session->options,
        TELNET_Q_LOCAL,
        TELNET_OPT_END_OF_RECORD
    );

    session->terminal.new_environ = telnet_q_enabled(
        &session->options,
        TELNET_Q_REMOTE,
        TELNET_OPT_NEW_ENVIRON
    );

    session->terminal.mssp = telnet_q_enabled(
        &session->options,
        TELNET_Q_LOCAL,
        TELNET_OPT_MSSP
    );
    session->terminal.gmcp = telnet_q_enabled(
        &session->options,
        TELNET_Q_LOCAL,
        TELNET_OPT_GMCP
    );

    /* NEW-ENVIRON is the carrier; MNES is the MUD-specific vocabulary. */
    session->terminal.mnes =
        (session->terminal.mtts_flags & TELNET_MTTS_MNES) != 0 ||
        session->mnes_observed;

    refresh_utf8_metadata(session);
    request_terminal_type(session);
    request_charset(session);
    request_new_environ(session);
    notify_application_capabilities(session);
}

static void negotiate_operational_options(telnet_session *session)
{
    /*
     * A MUD must remain playable when every request below is refused. These
     * negotiations only improve terminal behavior; login is never delayed for
     * capability discovery.
     */
    telnet_q_request(
        &session->options,
        TELNET_Q_LOCAL,
        TELNET_OPT_BINARY,
        1,
        q_send_callback,
        session
    );
    telnet_q_request(
        &session->options,
        TELNET_Q_REMOTE,
        TELNET_OPT_BINARY,
        1,
        q_send_callback,
        session
    );
    telnet_q_request(
        &session->options,
        TELNET_Q_LOCAL,
        TELNET_OPT_SUPPRESS_GO_AHEAD,
        1,
        q_send_callback,
        session
    );
    telnet_q_request(
        &session->options,
        TELNET_Q_REMOTE,
        TELNET_OPT_SUPPRESS_GO_AHEAD,
        1,
        q_send_callback,
        session
    );

    /* EOR gives MUD clients an explicit boundary for prompts without newlines. */
    telnet_q_request(
        &session->options,
        TELNET_Q_LOCAL,
        TELNET_OPT_END_OF_RECORD,
        1,
        q_send_callback,
        session
    );

    telnet_q_request(
        &session->options,
        TELNET_Q_REMOTE,
        TELNET_OPT_NAWS,
        1,
        q_send_callback,
        session
    );
    telnet_q_request(
        &session->options,
        TELNET_Q_REMOTE,
        TELNET_OPT_TERMINAL_TYPE,
        1,
        q_send_callback,
        session
    );

    /*
     * CHARSET is offered in both directions. Some clients initiate the request;
     * others expect the server to do it after accepting WILL CHARSET.
     */
    telnet_q_request(
        &session->options,
        TELNET_Q_LOCAL,
        TELNET_OPT_CHARSET,
        1,
        q_send_callback,
        session
    );
    telnet_q_request(
        &session->options,
        TELNET_Q_REMOTE,
        TELNET_OPT_CHARSET,
        1,
        q_send_callback,
        session
    );

    /* MNES/NEW-ENVIRON supplements MTTS with updateable client metadata. */
    telnet_q_request(
        &session->options,
        TELNET_Q_REMOTE,
        TELNET_OPT_NEW_ENVIRON,
        1,
        q_send_callback,
        session
    );

    /* MSSP is only advertised when the host can supply a coherent snapshot. */
    if (session->mssp_query != NULL) {
        telnet_q_request(
            &session->options,
            TELNET_Q_LOCAL,
            TELNET_OPT_MSSP,
            1,
            q_send_callback,
            session
        );
    }

    /* GMCP framing/Core support is generic; game packages remain application-owned. */
    telnet_q_request(
        &session->options,
        TELNET_Q_LOCAL,
        TELNET_OPT_GMCP,
        1,
        q_send_callback,
        session
    );
}

static void request_close(
    telnet_session *session,
    const char *event,
    const char *message
)
{
    if (session->close_requested) {
        return;
    }

    if (message != NULL) {
        write_text(session, message);
    }

    session->close_requested = 1;

    if (event != NULL) {
        audit(session, event, "session close requested");
    }
}

static void password_echo_off(telnet_session *session)
{
    session->echo_desired = 1;

    telnet_q_request(
        &session->options,
        TELNET_Q_LOCAL,
        TELNET_OPT_ECHO,
        1,
        q_send_callback,
        session
    );
}

static void password_echo_on(telnet_session *session)
{
    session->echo_desired = 0;

    telnet_q_request(
        &session->options,
        TELNET_Q_LOCAL,
        TELNET_OPT_ECHO,
        0,
        q_send_callback,
        session
    );
}

static unsigned char ascii_lower(unsigned char ch)
{
    if (ch >= 'A' && ch <= 'Z') {
        return (unsigned char)(ch + ('a' - 'A'));
    }

    return ch;
}

static int ascii_equal_ignore_case(
    const char *left,
    const char *right
)
{
    while (*left != '\0' && *right != '\0') {
        unsigned char a = (unsigned char)*left;
        unsigned char b = (unsigned char)*right;

        if (ascii_lower(a) != ascii_lower(b)) {
            return 0;
        }

        ++left;
        ++right;
    }

    return *left == '\0' && *right == '\0';
}

static int bytes_equal_ignore_case(
    const unsigned char *bytes,
    size_t length,
    const char *text
)
{
    size_t text_length = strlen(text);
    size_t i;

    if (length != text_length) {
        return 0;
    }

    for (i = 0; i < length; ++i) {
        if (ascii_lower(bytes[i]) !=
            ascii_lower((unsigned char)text[i])) {
            return 0;
        }
    }

    return 1;
}

static void audit_player_event(
    telnet_session *session,
    const char *event
)
{
    char detail[96];

    if (snprintf(
            detail,
            sizeof(detail),
            "player=%s",
            session->player_name[0] != '\0'
                ? session->player_name
                : "-"
        ) >= (int)sizeof(detail)) {
        memcpy(detail, "player=truncated", sizeof("player=truncated"));
    }

    audit(session, event, detail);
}

static void enter_game(telnet_session *session)
{
    session->login = LOGIN_IN_GAME;

    audit_player_event(session, "login_success");

    if (session->application.open != NULL) {
        terminal_capabilities capabilities;
        copy_terminal_capabilities(session, &capabilities);
        session->application_session = session->application.open(
            session->application.manager_context,
            session->player_name,
            &session->application_output,
            &capabilities
        );
        if (session->application_session == NULL) {
            request_close(session, "application_open_rejected", NULL);
        } else {
            replay_pre_auth_gmcp_core(session);
        }
        return;
    }

    /* Standalone fallback retained for protocol-focused harnesses and tests. */
    write_text(session, "\r\nWelcome, ");
    write_untrusted_text(session, session->player_name);
    write_text(
        session,
        ". You are now in game.\r\n"
        "Type PING to test the command loop.\r\n"
    );
    write_prompt_text(session, "> ");
}

static void process_player_name(telnet_session *session)
{
    int exists;

    if (!player_store_name_valid(session->line)) {
        write_text(
            session,
            "\r\n"
            "New player names must be 3-15 characters and use only "
            "letters, numbers, '_' or '-'.\r\n"
        );
        write_prompt_text(session, "Player name: ");
        return;
    }

    memcpy(
        session->player_name,
        session->line,
        strlen(session->line) + 1
    );

    exists = player_store_exists(
        session->store,
        session->player_name
    );

    if (exists < 0) {
        audit_player_event(session, "player_record_rejected");
        session->player_name[0] = '\0';

        write_text(
            session,
            "\r\n"
            "That player record could not be read safely.\r\n"
        );
        write_prompt_text(session, "Player name: ");
        return;
    }

    if (exists == 1) {
        session->login = LOGIN_PASSWORD;
        password_echo_off(session);
        warn_insecure_password_once(session);
        write_prompt_text(session, "Password: ");
        return;
    }

    session->login = LOGIN_NEW_PASSWORD;
    password_echo_off(session);
    warn_insecure_password_once(session);

    write_text(session, "New player. ");
    write_prompt_text(
        session,
        "Create a password (8-128 characters): "
    );
}

static void process_existing_password(
    telnet_session *session,
    uint64_t now_ms
)
{
    uint64_t retry_ms = 0;
    int rehashed = 0;
    int verified;

    if (!security_policy_allow_auth_attempt(
            session->security,
            session->remote_id,
            session->player_name,
            now_ms,
            &retry_ms
        )) {
        sodium_memzero(session->line, sizeof(session->line));
        session->line_length = 0;

        audit_player_event(session, "login_throttled");

        write_text(
            session,
            "\r\nLogin is temporarily locked. Try again later.\r\n"
        );
        write_prompt_text(session, "Password: ");
        return;
    }

    verified = player_store_verify_password(
        session->store,
        session->player_name,
        session->line,
        session->line_length,
        &rehashed
    );

    sodium_memzero(session->line, sizeof(session->line));
    session->line_length = 0;

    if (verified == 1) {
        security_policy_note_auth_success(
            session->security,
            session->remote_id,
            session->player_name,
            now_ms
        );

        if (rehashed) {
            audit_player_event(session, "password_hash_upgraded");
        }

        password_echo_on(session);
        enter_game(session);
        return;
    }

    security_policy_note_auth_failure(
        session->security,
        session->remote_id,
        session->player_name,
        now_ms
    );

    audit_player_event(session, "login_failure");
    /* The third bad password starts the account cooldown immediately. */
    if (!security_policy_allow_auth_attempt(
            session->security,
            session->remote_id,
            session->player_name,
            now_ms,
            &retry_ms
        )) {
        request_close(
            session,
            "login_lockout",
            "\r\nIncorrect password.\r\n"
            "Too many failed passwords. Try again in 5 minutes.\r\n"
        );
        return;
    }

    write_text(session, "\r\nIncorrect password.\r\n");
    write_prompt_text(session, "Password: ");
}

static void process_new_password(telnet_session *session)
{
    int allowed;

    if (session->line_length < PLAYER_PASSWORD_MIN) {
        sodium_memzero(session->line, sizeof(session->line));
        session->line_length = 0;

        write_text(
            session,
            "\r\nPassword must contain at least 8 characters.\r\n"
        );
        write_prompt_text(session, "Create password: ");
        return;
    }

    allowed = player_store_password_allowed(
        session->player_name,
        session->line,
        session->line_length
    );

    if (allowed != 1) {
        sodium_memzero(session->line, sizeof(session->line));
        session->line_length = 0;

        audit_player_event(session, "weak_password_rejected");

        write_text(
            session,
            "\r\nChoose a less common password.\r\n"
        );
        write_prompt_text(session, "Create password: ");
        return;
    }

    if (player_store_prepare_password(
            session->line,
            session->line_length,
            &session->pending_password
        ) != 0) {
        sodium_memzero(session->line, sizeof(session->line));
        session->line_length = 0;

        password_echo_on(session);
        session->login = LOGIN_NAME;
        session->player_name[0] = '\0';

        write_text(
            session,
            "\r\nUnable to prepare the password securely.\r\n"
        );
        write_prompt_text(session, "Player name: ");
        return;
    }

    sodium_memzero(session->line, sizeof(session->line));
    session->line_length = 0;

    session->login = LOGIN_CONFIRM_PASSWORD;
    write_text(session, "\r\n");
    write_prompt_text(session, "Confirm password: ");
}

static void process_password_confirmation(
    telnet_session *session,
    uint64_t now_ms
)
{
    uint64_t retry_ms = 0;
    int matched = player_store_password_matches(
        &session->pending_password,
        session->line,
        session->line_length
    );

    sodium_memzero(session->line, sizeof(session->line));
    session->line_length = 0;

    if (matched != 1) {
        player_store_password_clear(&session->pending_password);
        session->login = LOGIN_NEW_PASSWORD;

        write_text(
            session,
            "\r\nPasswords did not match.\r\n"
        );
        write_prompt_text(session, "Create password: ");
        return;
    }

    if (!security_policy_allow_account_creation(
            session->security,
            session->remote_id,
            now_ms,
            &retry_ms
        )) {
        player_store_password_clear(&session->pending_password);

        password_echo_on(session);
        session->login = LOGIN_NAME;
        session->player_name[0] = '\0';

        audit(
            session,
            "account_creation_throttled",
            "new account rate limit"
        );

        write_text(
            session,
            "\r\nAccount creation is temporarily limited.\r\n"
        );
        write_prompt_text(session, "Player name: ");
        return;
    }

    {
        int created = player_store_create(
            session->store,
            session->player_name,
            &session->pending_password
        );

        player_store_password_clear(&session->pending_password);

        if (created != 0) {
            password_echo_on(session);
            session->login = LOGIN_NAME;

            audit_player_event(session, "account_creation_failed");

            session->player_name[0] = '\0';

            write_text(
                session,
                "\r\n"
                "The player account could not be created. "
                "It may already exist.\r\n"
            );
            write_prompt_text(session, "Player name: ");
            return;
        }
    }

    audit_player_event(session, "account_created");

    security_policy_note_auth_success(
        session->security,
        session->remote_id,
        session->player_name,
        now_ms
    );

    password_echo_on(session);
    enter_game(session);
}

static void process_command(
    telnet_session *session,
    uint64_t now_ms
)
{
    if (!rate_consume(
            &session->command_window,
            1,
            COMMANDS_PER_WINDOW,
            COMMANDS_WINDOW_MS,
            now_ms
        )) {
        request_close(
            session,
            "command_flood",
            "Command rate limit exceeded.\r\n"
        );
        return;
    }

    if (session->application_session != NULL && session->application.line != NULL) {
        if (session->application.line(
                session->application_session,
                session->line,
                session->line_length
            ) != 0) {
            request_close(session, "application_line_close", NULL);
        }
        return;
    }

    if (session->line[0] == '\0') {
        write_prompt_text(session, "> ");
        return;
    }

    if (ascii_equal_ignore_case(session->line, "PING")) {
        write_text(session, "PONG\r\n");
        write_prompt_text(session, "> ");
        return;
    }

    write_text(session, "Unknown command.\r\n");
    write_prompt_text(session, "> ");
}

static void process_complete_line(
    telnet_session *session,
    uint64_t now_ms
)
{
    if (!rate_consume(
            &session->line_window,
            1,
            INPUT_LINES_PER_WINDOW,
            INPUT_LINES_WINDOW_MS,
            now_ms
        )) {
        sodium_memzero(session->line, sizeof(session->line));
        session->line_length = 0;

        request_close(
            session,
            "line_flood",
            "Input rate limit exceeded.\r\n"
        );
        return;
    }

    if (session->line_overflow) {
        int password_state =
            session->login == LOGIN_PASSWORD ||
            session->login == LOGIN_NEW_PASSWORD ||
            session->login == LOGIN_CONFIRM_PASSWORD;

        sodium_memzero(session->line, sizeof(session->line));
        session->line_length = 0;
        session->line_overflow = 0;

        if (password_state) {
            write_text(session, "\r\nPassword input is too long.\r\n");

            if (session->login == LOGIN_PASSWORD) {
                write_prompt_text(session, "Password: ");
            } else {
                player_store_password_clear(&session->pending_password);
                session->login = LOGIN_NEW_PASSWORD;
                write_prompt_text(session, "Create password: ");
            }

            return;
        }

        if (session->application_session != NULL) {
            request_close(
                session,
                "application_input_overflow",
                "Input is too long.\r\n"
            );
            return;
        }

        write_text(session, "Input is too long.\r\n");
        write_prompt_text(session, "> ");
        return;
    }

    session->line[session->line_length] = '\0';

    switch (session->login) {
        case LOGIN_NAME:
            process_player_name(session);
            break;

        case LOGIN_PASSWORD:
            process_existing_password(session, now_ms);
            break;

        case LOGIN_NEW_PASSWORD:
            process_new_password(session);
            break;

        case LOGIN_CONFIRM_PASSWORD:
            process_password_confirmation(session, now_ms);
            break;

        case LOGIN_IN_GAME:
            process_command(session, now_ms);
            break;
    }

    sodium_memzero(session->line, sizeof(session->line));
    session->line_length = 0;
    session->line_overflow = 0;
}

static void note_protocol_violation(
    telnet_session *session,
    const char *detail
)
{
    ++session->protocol_violations;
    audit(session, "telnet_protocol_violation", detail);

    if (session->protocol_violations >= PROTOCOL_VIOLATION_LIMIT) {
        request_close(
            session,
            "telnet_protocol_abuse",
            "Protocol error.\r\n"
        );
    }
}

static void append_line_byte(
    telnet_session *session,
    unsigned char byte
)
{
    if (byte == 8 || byte == 127) {
        if (session->line_length > 0) {
            --session->line_length;
            session->line[session->line_length] = '\0';
        }
        return;
    }

    if (byte < 32) {
        /*
         * Real terminal clients can emit local C0 controls while editing.
         * They aren't command text, so discard them quietly here.
         * Malformed Telnet IAC/subnegotiation is still handled strictly.
         */
        return;
    }

    /*
     * Strict NVT peers negotiate BINARY before sending 8-bit data, but many
     * real terminal tools don't. The line buffer is bounded and higher layers
     * still validate names/passwords, so accept opaque high bytes here instead
     * of treating a harmless compatibility quirk as protocol abuse.
     */
    {
        size_t limit =
            session->login == LOGIN_PASSWORD ||
            session->login == LOGIN_NEW_PASSWORD ||
            session->login == LOGIN_CONFIRM_PASSWORD
                ? PLAYER_PASSWORD_MAX
                : APPLICATION_LINE_MAX;

        if (session->line_length >= limit) {
            session->line_overflow = 1;
            return;
        }
    }

    session->line[session->line_length++] = (char)byte;
}

/*
 * Telnet is picky here: CR isn't complete until the next byte arrives.
 * CR LF ends a line. CR NUL carries a literal carriage return in NVT mode.
 * In BINARY mode this application still treats CR LF as its line delimiter.
 */
static void receive_data_byte(
    telnet_session *session,
    unsigned char byte,
    uint64_t now_ms
)
{
    if (session->pending_cr) {
        session->pending_cr = 0;

        if (byte == '\n') {
            process_complete_line(session, now_ms);
            return;
        }

        if (byte == '\0') {
            append_line_byte(session, '\r');
            return;
        }

        /*
         * Some terminal clients are loose about NVT CR framing. Preserve
         * the carriage return and continue without counting it as abuse.
         */
        append_line_byte(session, '\r');
        if (session->close_requested) {
            return;
        }
    }

    if (byte == '\r') {
        session->pending_cr = 1;
        return;
    }

    if (byte == '\n') {
        /* Bare LF is common in terminal tools and is safe as a line end. */
        process_complete_line(session, now_ms);
        return;
    }

    if (byte == '\0') {
        return;
    }

    append_line_byte(session, byte);
}

static void clear_current_input(telnet_session *session)
{
    sodium_memzero(session->line, sizeof(session->line));
    session->line_length = 0;
    session->line_overflow = 0;
    session->pending_cr = 0;
}

static void write_current_prompt(telnet_session *session)
{
    switch (session->login) {
        case LOGIN_NAME:
            write_prompt_text(session, "Player name: ");
            break;

        case LOGIN_PASSWORD:
            write_prompt_text(session, "Password: ");
            break;

        case LOGIN_NEW_PASSWORD:
            write_prompt_text(session, "Create password: ");
            break;

        case LOGIN_CONFIRM_PASSWORD:
            write_prompt_text(session, "Confirm password: ");
            break;

        case LOGIN_IN_GAME:
            write_prompt_text(session, "> ");
            break;
    }
}

static void interrupt_current_input(telnet_session *session)
{
    clear_current_input(session);

    if (session->login == LOGIN_CONFIRM_PASSWORD) {
        player_store_password_clear(&session->pending_password);
        session->login = LOGIN_NEW_PASSWORD;
    }

    write_text(session, "\r\n");
    write_current_prompt(session);
}

static void handle_control_command(
    telnet_session *session,
    unsigned char command
)
{
    switch (command) {
        case TELNET_NOP:
        case TELNET_DM:
        case TELNET_AO:
        case TELNET_GA:
        case TELNET_EOR:
            /*
             * These commands are valid and there is no queued work for them.
             * Peer GA/EOR markers do not delimit application input here.
             */
            return;

        case TELNET_AYT:
            write_text(session, "\r\n[Server is here]\r\n");
            write_current_prompt(session);
            return;

        case TELNET_IP:
        case TELNET_BRK:
            interrupt_current_input(session);
            return;

        case TELNET_EC:
            if (session->line_length > 0) {
                --session->line_length;
                session->line[session->line_length] = '\0';
            }
            return;

        case TELNET_EL:
            clear_current_input(session);
            return;

        case TELNET_SE:
            note_protocol_violation(
                session,
                "SE received outside subnegotiation"
            );
            return;

        default:
            /* Unknown but well-framed commands are optional Telnet surface. */
            return;
    }
}

static uint16_t clamp_dimension(
    uint16_t value,
    uint16_t minimum,
    uint16_t maximum,
    uint16_t fallback
)
{
    if (value == 0) {
        return fallback;
    }

    if (value < minimum) {
        return minimum;
    }

    if (value > maximum) {
        return maximum;
    }

    return value;
}

static void handle_naws(telnet_session *session)
{
    uint16_t width;
    uint16_t height;

    if (!telnet_q_enabled(
            &session->options,
            TELNET_Q_REMOTE,
            TELNET_OPT_NAWS
        )) {
        /* Some clients eagerly report size before negotiation completes. */
        return;
    }

    if (session->subnegotiation_length != 4) {
        note_protocol_violation(session, "malformed NAWS payload");
        return;
    }

    width = (uint16_t)(
        ((uint16_t)session->subnegotiation[0] << 8) |
        session->subnegotiation[1]
    );
    height = (uint16_t)(
        ((uint16_t)session->subnegotiation[2] << 8) |
        session->subnegotiation[3]
    );

    session->terminal.width = clamp_dimension(
        width,
        MIN_TERMINAL_WIDTH,
        MAX_TERMINAL_WIDTH,
        DEFAULT_TERMINAL_WIDTH
    );
    session->terminal.height = clamp_dimension(
        height,
        MIN_TERMINAL_HEIGHT,
        MAX_TERMINAL_HEIGHT,
        DEFAULT_TERMINAL_HEIGHT
    );
}

static int copy_printable_ascii(
    char *output,
    size_t output_size,
    const unsigned char *input,
    size_t input_length
)
{
    size_t i;

    if (output == NULL || output_size == 0 ||
        input_length >= output_size) {
        return 0;
    }

    for (i = 0; i < input_length; ++i) {
        if (input[i] < 32 || input[i] > 126) {
            return 0;
        }
        output[i] = (char)input[i];
    }

    output[input_length] = '\0';
    return 1;
}

static int parse_decimal_u32(
    const unsigned char *bytes,
    size_t length,
    uint32_t *value
)
{
    uint32_t parsed = 0;
    size_t i;

    if (length == 0 || value == NULL) {
        return 0;
    }

    for (i = 0; i < length; ++i) {
        unsigned int digit;

        if (bytes[i] < '0' || bytes[i] > '9') {
            return 0;
        }

        digit = (unsigned int)(bytes[i] - '0');
        if (parsed > (UINT32_MAX - digit) / 10U) {
            return 0;
        }
        parsed = parsed * 10U + digit;
    }

    *value = parsed;
    return 1;
}

static void infer_terminal_type_capabilities(
    telnet_session *session,
    const char *terminal_type
)
{
    size_t length = strlen(terminal_type);

    if (ascii_equal_ignore_case(terminal_type, "ANSI")) {
        session->terminal.ansi = 1;
    } else if (ascii_equal_ignore_case(terminal_type, "VT100")) {
        session->terminal.ansi = 1;
        session->terminal.vt100 = 1;
    } else if (ascii_equal_ignore_case(terminal_type, "XTERM")) {
        session->terminal.ansi = 1;
        session->terminal.vt100 = 1;
    }

    if (length >= strlen("-256COLOR") &&
        ascii_equal_ignore_case(
            terminal_type + length - strlen("-256COLOR"),
            "-256COLOR"
        )) {
        session->terminal.color_256 = 1;
    }

    if (length >= strlen("-TRUECOLOR") &&
        ascii_equal_ignore_case(
            terminal_type + length - strlen("-TRUECOLOR"),
            "-TRUECOLOR"
        )) {
        session->terminal.color_256 = 1;
        session->terminal.truecolor = 1;
    }
}

static int parse_mtts_report(
    telnet_session *session,
    const unsigned char *bytes,
    size_t length
)
{
    uint32_t flags;

    if (length > 5 &&
        bytes_equal_ignore_case(bytes, 5, "MTTS ") &&
        parse_decimal_u32(bytes + 5, length - 5, &flags)) {
        apply_mtts_flags(session, flags);
        refresh_utf8_metadata(session);
        return 1;
    }

    return 0;
}

static void handle_terminal_type(telnet_session *session)
{
    size_t type_length;
    char reported[TELNET_TERMINAL_TYPE_MAX + 1];
    int repeated;

    if (!telnet_q_enabled(
            &session->options,
            TELNET_Q_REMOTE,
            TELNET_OPT_TERMINAL_TYPE
        )) {
        return;
    }

    session->terminal_type_waiting = 0;

    if (session->subnegotiation_length < 2 ||
        session->subnegotiation[0] != TERMINAL_TYPE_IS) {
        note_protocol_violation(
            session,
            "malformed terminal type payload"
        );
        return;
    }

    type_length = session->subnegotiation_length - 1;

    if (type_length > TELNET_TERMINAL_TYPE_MAX ||
        !copy_printable_ascii(
            reported,
            sizeof(reported),
            session->subnegotiation + 1,
            type_length
        )) {
        note_protocol_violation(
            session,
            "invalid terminal type payload"
        );
        return;
    }

    if (reported[0] == '\0') {
        memcpy(reported, "UNKNOWN", sizeof("UNKNOWN"));
    }

    repeated = session->last_terminal_type[0] != '\0' &&
        ascii_equal_ignore_case(
            session->last_terminal_type,
            reported
        );

    if (!parse_mtts_report(
            session,
            (const unsigned char *)reported,
            strlen(reported)
        )) {
        /*
         * MTTS defines response one as client name and response two as the
         * terminal type. A legacy client may simply repeat one terminal type,
         * so the first response is also kept as a useful fallback.
         */
        if (session->terminal_type_requests_sent == 1) {
            memcpy(
                session->terminal.client_name,
                reported,
                strlen(reported) + 1
            );
            memcpy(
                session->terminal.terminal_type,
                reported,
                strlen(reported) + 1
            );
            infer_terminal_type_capabilities(session, reported);
        } else if (session->terminal_type_requests_sent == 2) {
            memcpy(
                session->terminal.terminal_type,
                reported,
                strlen(reported) + 1
            );
            infer_terminal_type_capabilities(session, reported);
        }
    }

    memcpy(
        session->last_terminal_type,
        reported,
        strlen(reported) + 1
    );

    /*
     * A bare ANSI response is a common legacy-terminal signature. Stop after
     * one probe rather than risking old clients that mishandle TTYPE cycling.
     */
    if (session->terminal_type_requests_sent == 1 &&
        ascii_equal_ignore_case(reported, "ANSI")) {
        return;
    }

    if (!repeated) {
        request_terminal_type(session);
    }
}

static int charset_list_contains_utf8(
    const unsigned char *payload,
    size_t length
)
{
    unsigned char separator;
    size_t start;
    size_t i;

    if (length < 3 || payload[0] != CHARSET_REQUEST) {
        return 0;
    }

    separator = payload[1];

    if (separator == TELNET_IAC || separator < 32) {
        return 0;
    }

    start = 2;

    for (i = 2; i <= length; ++i) {
        if (i == length || payload[i] == separator) {
            if (i > start &&
                bytes_equal_ignore_case(
                    payload + start,
                    i - start,
                    "UTF-8"
                )) {
                return 1;
            }
            start = i + 1;
        } else if (payload[i] < 32 || payload[i] > 126) {
            return 0;
        }
    }

    return 0;
}

static void handle_charset(telnet_session *session)
{
    unsigned char kind;

    if (!telnet_q_enabled(
            &session->options,
            TELNET_Q_REMOTE,
            TELNET_OPT_CHARSET
        ) &&
        !telnet_q_enabled(
            &session->options,
            TELNET_Q_LOCAL,
            TELNET_OPT_CHARSET
        )) {
        return;
    }

    if (session->subnegotiation_length == 0) {
        note_protocol_violation(session, "empty CHARSET payload");
        return;
    }

    kind = session->subnegotiation[0];

    if (kind == CHARSET_REQUEST) {
        if (!telnet_q_enabled(
                &session->options,
                TELNET_Q_REMOTE,
                TELNET_OPT_CHARSET
            )) {
            return;
        }

        if (session->terminal.local_binary &&
            session->terminal.remote_binary &&
            charset_list_contains_utf8(
                session->subnegotiation,
                session->subnegotiation_length
            )) {
            const unsigned char accepted[] = {
                CHARSET_ACCEPTED,
                'U', 'T', 'F', '-', '8'
            };

            send_subnegotiation(
                session,
                TELNET_OPT_CHARSET,
                accepted,
                sizeof(accepted)
            );
            session->charset_utf8 = 1;
            refresh_utf8_metadata(session);
            audit(session, "telnet_charset", "UTF-8 accepted");
        } else {
            const unsigned char rejected[1] = {
                CHARSET_REJECTED
            };

            send_subnegotiation(
                session,
                TELNET_OPT_CHARSET,
                rejected,
                sizeof(rejected)
            );
        }
        return;
    }

    if (!telnet_q_enabled(
            &session->options,
            TELNET_Q_LOCAL,
            TELNET_OPT_CHARSET
        ) || !session->charset_request_sent) {
        return;
    }

    if (kind == CHARSET_ACCEPTED &&
        session->subnegotiation_length == 6 &&
        bytes_equal_ignore_case(
            session->subnegotiation + 1,
            5,
            "UTF-8"
        )) {
        session->charset_utf8 = 1;
        refresh_utf8_metadata(session);
        audit(session, "telnet_charset", "UTF-8 accepted");
        return;
    }

    if (kind == CHARSET_REJECTED) {
        session->charset_utf8 = 0;
        refresh_utf8_metadata(session);
        return;
    }

    /* A negotiated but malformed response is different from an unknown option. */
    note_protocol_violation(session, "malformed CHARSET response");
}

static int env_name_equals(
    const unsigned char *name,
    size_t length,
    const char *expected
)
{
    return bytes_equal_ignore_case(name, length, expected);
}

static int env_value_enabled(const unsigned char *value, size_t value_length)
{
    if (value_length == 1 && value[0] == '1') {
        return 1;
    }
    if (bytes_equal_ignore_case(value, value_length, "TRUE") ||
        bytes_equal_ignore_case(value, value_length, "YES") ||
        bytes_equal_ignore_case(value, value_length, "ON")) {
        return 1;
    }
    return 0;
}

static void apply_new_environ_value(
    telnet_session *session,
    unsigned char token,
    const unsigned char *name,
    size_t name_length,
    const unsigned char *value,
    size_t value_length
)
{
    int is_mnes_var = token == NEW_ENVIRON_VAR;

    /* The five VAR names are the compact MNES vocabulary. */
    if (env_name_equals(name, name_length, "CLIENT_NAME")) {
        if (is_mnes_var) session->mnes_observed = 1;
        (void)copy_printable_ascii(
            session->terminal.client_name,
            sizeof(session->terminal.client_name),
            value,
            value_length
        );
        return;
    }

    if (env_name_equals(name, name_length, "CLIENT_VERSION")) {
        if (is_mnes_var) session->mnes_observed = 1;
        (void)copy_printable_ascii(
            session->terminal.client_version,
            sizeof(session->terminal.client_version),
            value,
            value_length
        );
        return;
    }

    if (env_name_equals(name, name_length, "TERMINAL_TYPE")) {
        if (is_mnes_var) session->mnes_observed = 1;
        if (copy_printable_ascii(
                session->terminal.terminal_type,
                sizeof(session->terminal.terminal_type),
                value,
                value_length
            )) {
            infer_terminal_type_capabilities(
                session,
                session->terminal.terminal_type
            );
        }
        return;
    }

    if (env_name_equals(name, name_length, "CHARSET")) {
        if (is_mnes_var) session->mnes_observed = 1;
        if (bytes_equal_ignore_case(value, value_length, "UTF-8")) {
            session->charset_utf8 = 1;
            refresh_utf8_metadata(session);
        }
        return;
    }

    if (env_name_equals(name, name_length, "MTTS")) {
        uint32_t flags;
        if (is_mnes_var) session->mnes_observed = 1;
        if (parse_decimal_u32(value, value_length, &flags)) {
            apply_mtts_flags(session, flags);
            refresh_utf8_metadata(session);
        }
        return;
    }

    /* The remaining capabilities are modern NEW-ENVIRON USERVAR values. */
    if (token != NEW_ENVIRON_USERVAR) {
        return;
    }

    if (env_name_equals(name, name_length, "SCREEN_READER")) {
        session->terminal.screen_reader = env_value_enabled(value, value_length);
    } else if (env_name_equals(name, name_length, "OSC_HYPERLINKS")) {
        session->terminal.osc8 = env_value_enabled(value, value_length);
    } else if (env_name_equals(name, name_length, "OSC_HYPERLINKS_SEND")) {
        session->terminal.osc8_send = env_value_enabled(value, value_length);
    } else if (env_name_equals(name, name_length, "OSC_HYPERLINKS_PROMPT")) {
        session->terminal.osc8_prompt = env_value_enabled(value, value_length);
    } else if (env_name_equals(name, name_length, "OSC_HYPERLINKS_TOOLTIP")) {
        session->terminal.osc8_tooltip = env_value_enabled(value, value_length);
    }
}

static void handle_new_environ(telnet_session *session)
{
    size_t i = 1;
    unsigned char command;

    if (!telnet_q_enabled(
            &session->options,
            TELNET_Q_REMOTE,
            TELNET_OPT_NEW_ENVIRON
        )) {
        return;
    }

    if (session->subnegotiation_length == 0) {
        return;
    }

    command = session->subnegotiation[0];
    if (command != NEW_ENVIRON_IS && command != NEW_ENVIRON_INFO) {
        return;
    }

    while (i < session->subnegotiation_length) {
        unsigned char name[64];
        unsigned char value[128];
        size_t name_length = 0;
        size_t value_length = 0;
        unsigned char token = session->subnegotiation[i++];
        int has_value = 0;

        if (token != NEW_ENVIRON_VAR &&
            token != NEW_ENVIRON_USERVAR) {
            /* Unknown layout is harmless capability noise, not abuse. */
            return;
        }

        /*
         * RFC 1572 reserves VAR/VAL/ESC/USERVAR inside a field. ESC quotes the
         * following byte, so decode into bounded scratch buffers before using
         * any value. This avoids accepting a truncated prefix from an escaped
         * or malformed environment report.
         */
        while (i < session->subnegotiation_length) {
            unsigned char byte = session->subnegotiation[i];

            if (byte == NEW_ENVIRON_ESC) {
                ++i;
                if (i >= session->subnegotiation_length ||
                    name_length >= sizeof(name)) {
                    return;
                }
                name[name_length++] = session->subnegotiation[i++];
                continue;
            }

            if (byte == NEW_ENVIRON_VAL) {
                has_value = 1;
                ++i;
                break;
            }

            if (byte == NEW_ENVIRON_VAR ||
                byte == NEW_ENVIRON_USERVAR) {
                break;
            }

            if (name_length >= sizeof(name)) {
                return;
            }
            name[name_length++] = byte;
            ++i;
        }

        if (has_value) {
            while (i < session->subnegotiation_length) {
                unsigned char byte = session->subnegotiation[i];

                if (byte == NEW_ENVIRON_ESC) {
                    ++i;
                    if (i >= session->subnegotiation_length ||
                        value_length >= sizeof(value)) {
                        return;
                    }
                    value[value_length++] = session->subnegotiation[i++];
                    continue;
                }

                if (byte == NEW_ENVIRON_VAR ||
                    byte == NEW_ENVIRON_USERVAR) {
                    break;
                }

                /* A second unescaped VAL inside a value is malformed. */
                if (byte == NEW_ENVIRON_VAL ||
                    value_length >= sizeof(value)) {
                    return;
                }

                value[value_length++] = byte;
                ++i;
            }
        }

        if (name_length > 0) {
            apply_new_environ_value(
                session,
                token,
                name,
                name_length,
                value,
                value_length
            );
        }
    }

    update_option_metadata(session);
}

static void finish_subnegotiation(telnet_session *session)
{
    switch (session->subnegotiation_option) {
        case TELNET_OPT_NAWS:
            handle_naws(session);
            break;

        case TELNET_OPT_TERMINAL_TYPE:
            handle_terminal_type(session);
            break;

        case TELNET_OPT_CHARSET:
            handle_charset(session);
            break;

        case TELNET_OPT_NEW_ENVIRON:
            handle_new_environ(session);
            break;

        case TELNET_OPT_GMCP:
            handle_gmcp(session);
            break;

        default:
            /* Unknown subnegotiations already passed the size cap. Ignore them. */
            break;
    }

    session->subnegotiation_length = 0;
}

static void receive_telnet_option(
    telnet_session *session,
    unsigned char command,
    unsigned char option
)
{
    int was_terminal_type = telnet_q_enabled(
        &session->options,
        TELNET_Q_REMOTE,
        TELNET_OPT_TERMINAL_TYPE
    );
    int was_local_charset = telnet_q_enabled(
        &session->options,
        TELNET_Q_LOCAL,
        TELNET_OPT_CHARSET
    );
    int was_new_environ = telnet_q_enabled(
        &session->options,
        TELNET_Q_REMOTE,
        TELNET_OPT_NEW_ENVIRON
    );
    int was_mssp = telnet_q_enabled(
        &session->options,
        TELNET_Q_LOCAL,
        TELNET_OPT_MSSP
    );

    telnet_q_receive(
        &session->options,
        command,
        option,
        q_accept_callback,
        session,
        q_send_callback,
        session
    );

    if (was_terminal_type &&
        !telnet_q_enabled(
            &session->options,
            TELNET_Q_REMOTE,
            TELNET_OPT_TERMINAL_TYPE
        )) {
        session->terminal_type_requests_sent = 0;
        session->terminal_type_waiting = 0;
        session->last_terminal_type[0] = '\0';
        memcpy(
            session->terminal.terminal_type,
            "UNKNOWN",
            sizeof("UNKNOWN")
        );
    }

    if (was_local_charset &&
        !telnet_q_enabled(
            &session->options,
            TELNET_Q_LOCAL,
            TELNET_OPT_CHARSET
        )) {
        session->charset_request_sent = 0;
    }

    if (was_new_environ &&
        !telnet_q_enabled(
            &session->options,
            TELNET_Q_REMOTE,
            TELNET_OPT_NEW_ENVIRON
        )) {
        session->new_environ_requested = 0;
        session->mnes_observed = 0;
        session->terminal.osc8 = 0;
        session->terminal.osc8_send = 0;
        session->terminal.osc8_prompt = 0;
        session->terminal.osc8_tooltip = 0;
    }

    if (was_mssp &&
        !telnet_q_enabled(
            &session->options,
            TELNET_Q_LOCAL,
            TELNET_OPT_MSSP
        )) {
        session->mssp_sent = 0;
    }

    if (!telnet_q_enabled(
            &session->options,
            TELNET_Q_LOCAL,
            TELNET_OPT_CHARSET
        ) &&
        !telnet_q_enabled(
            &session->options,
            TELNET_Q_REMOTE,
            TELNET_OPT_CHARSET
        )) {
        session->charset_utf8 = 0;
    }

    update_option_metadata(session);

    if (!was_mssp && session->terminal.mssp) {
        send_mssp_status(session);
    }
}

int telnet_protocol_init(void)
{
    return sodium_init() < 0 ? -1 : 0;
}

telnet_session *telnet_session_create(
    const telnet_session_config *config
)
{
    telnet_session *session;

    if (config == NULL ||
        config->store == NULL ||
        config->security == NULL ||
        config->writer == NULL ||
        config->remote_id == NULL ||
        telnet_protocol_init() != 0) {
        return NULL;
    }

    session = calloc(1, sizeof(*session));
    if (session == NULL) {
        return NULL;
    }

    session->store = config->store;
    session->security = config->security;
    session->audit = config->audit;
    session->writer = config->writer;
    session->writer_context = config->writer_context;
    if (config->application != NULL) {
        session->application = *config->application;
    }
    session->application_output.context = session;
    session->application_output.write_text = application_write_text;
    session->application_output.write_prompt = application_write_prompt;
    session->application_output.request_close = application_request_close;
    session->application_output.send_gmcp = application_send_gmcp;
    session->application_output.write_link = application_write_link;
    session->mssp_query = config->mssp_query;
    session->mssp_context = config->mssp_context;
    session->login = LOGIN_NAME;
    session->parser = PARSER_DATA;
    session->terminal.width = DEFAULT_TERMINAL_WIDTH;
    session->terminal.height = DEFAULT_TERMINAL_HEIGHT;
    session->terminal.secure_transport = config->transport_secure != 0;
    memcpy(
        session->terminal.terminal_type,
        "UNKNOWN",
        sizeof("UNKNOWN")
    );
    memcpy(
        session->terminal.client_name,
        "UNKNOWN",
        sizeof("UNKNOWN")
    );
    telnet_q_init(&session->options);

    if (strlen(config->remote_id) >= sizeof(session->remote_id)) {
        free(session);
        return NULL;
    }

    memcpy(
        session->remote_id,
        config->remote_id,
        strlen(config->remote_id) + 1
    );

    return session;
}

void telnet_session_destroy(telnet_session *session)
{
    if (session == NULL) {
        return;
    }

    if (session->application_session != NULL && session->application.close != NULL) {
        session->application.close(session->application_session);
        session->application_session = NULL;
    }
    player_store_password_clear(&session->pending_password);
    sodium_memzero(session, sizeof(*session));
    free(session);
}

void telnet_session_start(telnet_session *session)
{
    if (session == NULL || session->started) {
        return;
    }

    session->started = 1;

    negotiate_operational_options(session);

    write_text(
        session,
        "\r\n"
        "========================================\r\n"
        "        Welcome, traveler.\r\n"
        "========================================\r\n"
        "\r\n"
    );
    write_prompt_text(session, "Player name: ");
}

int telnet_session_feed_at(
    telnet_session *session,
    const unsigned char *data,
    size_t length,
    uint64_t now_ms
)
{
    size_t i;

    if (session == NULL || data == NULL) {
        return -1;
    }

    if (session->close_requested) {
        return -1;
    }

    if (!rate_consume(
            &session->byte_window,
            length,
            INPUT_BYTES_PER_WINDOW,
            INPUT_BYTES_WINDOW_MS,
            now_ms
        )) {
        request_close(
            session,
            "byte_flood",
            "Input rate limit exceeded.\r\n"
        );
        return -1;
    }

    for (i = 0;
         i < length && !session->close_requested;
         ++i) {
        unsigned char byte = data[i];

        switch (session->parser) {
            case PARSER_DATA:
                if (byte == TELNET_IAC) {
                    session->parser = PARSER_IAC;
                } else {
                    receive_data_byte(session, byte, now_ms);
                }
                break;

            case PARSER_IAC:
                if (byte == TELNET_IAC) {
                    receive_data_byte(
                        session,
                        TELNET_IAC,
                        now_ms
                    );
                    session->parser = PARSER_DATA;
                } else if (byte == TELNET_WILL ||
                           byte == TELNET_WONT ||
                           byte == TELNET_DO ||
                           byte == TELNET_DONT) {
                    session->pending_telnet_command = byte;
                    session->parser = PARSER_OPTION;
                } else if (byte == TELNET_SB) {
                    session->parser = PARSER_SB_OPTION;
                } else {
                    handle_control_command(session, byte);
                    session->parser = PARSER_DATA;
                }
                break;

            case PARSER_OPTION:
                receive_telnet_option(
                    session,
                    session->pending_telnet_command,
                    byte
                );
                session->parser = PARSER_DATA;
                break;

            case PARSER_SB_OPTION:
                session->subnegotiation_option = byte;
                session->subnegotiation_length = 0;
                session->parser = PARSER_SB_DATA;
                break;

            case PARSER_SB_DATA:
                if (byte == TELNET_IAC) {
                    session->parser = PARSER_SB_IAC;
                } else if (session->subnegotiation_length >=
                           SUBNEGOTIATION_MAX_BYTES) {
                    request_close(
                        session,
                        "telnet_subnegotiation_overflow",
                        "Protocol error.\r\n"
                    );
                } else {
                    session->subnegotiation[
                        session->subnegotiation_length++
                    ] = byte;
                }
                break;

            case PARSER_SB_IAC:
                if (byte == TELNET_SE) {
                    finish_subnegotiation(session);
                    session->parser = PARSER_DATA;
                } else if (byte == TELNET_IAC) {
                    if (session->subnegotiation_length >=
                        SUBNEGOTIATION_MAX_BYTES) {
                        request_close(
                            session,
                            "telnet_subnegotiation_overflow",
                            "Protocol error.\r\n"
                        );
                    } else {
                        session->subnegotiation[
                            session->subnegotiation_length++
                        ] = TELNET_IAC;
                        session->parser = PARSER_SB_DATA;
                    }
                } else {
                    note_protocol_violation(
                        session,
                        "malformed subnegotiation"
                    );
                    session->parser = PARSER_SB_DATA;
                }
                break;
        }
    }

    return session->close_requested ? -1 : 0;
}

int telnet_session_feed(
    telnet_session *session,
    const unsigned char *data,
    size_t length
)
{
    return telnet_session_feed_at(
        session,
        data,
        length,
        monotonic_milliseconds()
    );
}

int telnet_session_is_in_game(const telnet_session *session)
{
    return session != NULL && session->login == LOGIN_IN_GAME;
}

int telnet_session_should_close(const telnet_session *session)
{
    return session == NULL || session->close_requested;
}

const char *telnet_session_player_name(
    const telnet_session *session
)
{
    if (session == NULL || session->login != LOGIN_IN_GAME) {
        return "";
    }

    return session->player_name;
}

void telnet_session_get_terminal_info(
    const telnet_session *session,
    telnet_terminal_info *info
)
{
    if (info == NULL) {
        return;
    }

    memset(info, 0, sizeof(*info));

    if (session == NULL) {
        info->width = DEFAULT_TERMINAL_WIDTH;
        info->height = DEFAULT_TERMINAL_HEIGHT;
        memcpy(
            info->terminal_type,
            "UNKNOWN",
            sizeof("UNKNOWN")
        );
        memcpy(
            info->client_name,
            "UNKNOWN",
            sizeof("UNKNOWN")
        );
        return;
    }

    *info = session->terminal;
}
