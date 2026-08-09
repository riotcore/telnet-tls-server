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
 * The small login and command loop also lives here today so this repository is
 * independently runnable and testable. That is a packaging decision, not a
 * requirement that MUD authentication forever belong to Telnet. When the game
 * grows multiple transports, account and game-session ownership should move
 * above this adapter while this parser/capability layer remains unchanged.
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

/* Complete mutable state owned by one Telnet connection. */
struct telnet_session {
    player_store *store;
    security_policy *security;
    audit_log *audit;
    char remote_id[96];

    telnet_write_fn writer;
    void *writer_context;

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
    unsigned char subnegotiation[256];
    size_t subnegotiation_length;

    int started;
    int close_requested;
    unsigned int protocol_violations;
    int pending_cr;

    char line[PLAYER_PASSWORD_MAX + 1];
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
#define SUBNEGOTIATION_MAX_BYTES 256U
#define PROTOCOL_VIOLATION_LIMIT 8U
#define TERMINAL_TYPE_REQUEST_LIMIT 4U

#define DEFAULT_TERMINAL_WIDTH 80U
#define DEFAULT_TERMINAL_HEIGHT 24U
#define MIN_TERMINAL_WIDTH 20U
#define MAX_TERMINAL_WIDTH 500U
#define MIN_TERMINAL_HEIGHT 5U
#define MAX_TERMINAL_HEIGHT 200U

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
                return 1;

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
        'T','E','R','M','I','N','A','L','_','T','Y','P','E'
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

    /* NEW-ENVIRON is the carrier; MNES is the MUD-specific vocabulary. */
    session->terminal.mnes =
        (session->terminal.mtts_flags & TELNET_MTTS_MNES) != 0 ||
        session->mnes_observed;

    refresh_utf8_metadata(session);
    request_terminal_type(session);
    request_charset(session);
    request_new_environ(session);
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
    if (session->line_length >= sizeof(session->line) - 1) {
        session->line_overflow = 1;
        return;
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

static void apply_new_environ_value(
    telnet_session *session,
    const unsigned char *name,
    size_t name_length,
    const unsigned char *value,
    size_t value_length
)
{
    /* The requested names below are the MNES extension vocabulary. */
    if (env_name_equals(name, name_length, "CLIENT_NAME")) {
        session->mnes_observed = 1;
        (void)copy_printable_ascii(
            session->terminal.client_name,
            sizeof(session->terminal.client_name),
            value,
            value_length
        );
        return;
    }

    if (env_name_equals(name, name_length, "CLIENT_VERSION")) {
        session->mnes_observed = 1;
        (void)copy_printable_ascii(
            session->terminal.client_version,
            sizeof(session->terminal.client_version),
            value,
            value_length
        );
        return;
    }

    if (env_name_equals(name, name_length, "TERMINAL_TYPE")) {
        session->mnes_observed = 1;
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
        session->mnes_observed = 1;
        session->charset_utf8 =
            bytes_equal_ignore_case(value, value_length, "UTF-8");
        refresh_utf8_metadata(session);
        return;
    }

    if (env_name_equals(name, name_length, "MTTS")) {
        session->mnes_observed = 1;
        uint32_t flags;
        if (parse_decimal_u32(value, value_length, &flags)) {
            apply_mtts_flags(session, flags);
            refresh_utf8_metadata(session);
        }
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

        if (token == NEW_ENVIRON_VAR && name_length > 0) {
            apply_new_environ_value(
                session,
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
