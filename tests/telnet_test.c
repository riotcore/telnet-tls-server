// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

#define _POSIX_C_SOURCE 200809L

/*
 * telnet_test.c
 *
 * Collects the Telnet regression suite in one executable. The sections cover
 * option state, login/session behavior, operational negotiations, control
 * functions, NVT line rules, and hostile byte streams.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#define CHECK(expression) \
    do { \
        if (!(expression)) { \
            fprintf( \
                stderr, \
                "%s:%d: check failed: %s\n", \
                __FILE__, \
                __LINE__, \
                #expression \
            ); \
            exit(EXIT_FAILURE); \
        } \
    } while (0)

#include "player_store.h"
#include "security_policy.h"
#include "telnet_internal.h"
#include "telnet_protocol.h"

struct output_capture {
    unsigned char bytes[32768];
    size_t length;
};

struct fixture {
    char root[64];
    char player_directory[512];
    player_store *store;
    security_policy *security;
};

static void capture_write(
    void *context,
    const unsigned char *data,
    size_t length
)
{
    struct output_capture *capture = context;
    size_t room = sizeof(capture->bytes) - capture->length;

    if (length > room) {
        length = room;
    }

    memcpy(capture->bytes + capture->length, data, length);
    capture->length += length;
}

static void discard_write(
    void *context,
    const unsigned char *data,
    size_t length
)
{
    (void)context;
    (void)data;
    (void)length;
}

static void clear_capture(struct output_capture *capture)
{
    memset(capture, 0, sizeof(*capture));
}

static int capture_contains_bytes(
    const struct output_capture *capture,
    const unsigned char *needle,
    size_t needle_length
)
{
    size_t i;

    if (needle_length == 0 || needle_length > capture->length) {
        return 0;
    }

    for (i = 0; i + needle_length <= capture->length; ++i) {
        if (memcmp(capture->bytes + i, needle, needle_length) == 0) {
            return 1;
        }
    }

    return 0;
}

static int capture_contains_text(
    const struct output_capture *capture,
    const char *text
)
{
    return capture_contains_bytes(
        capture,
        (const unsigned char *)text,
        strlen(text)
    );
}

static void fixture_open(struct fixture *fixture, const char *template_text)
{
    int written;

    memset(fixture, 0, sizeof(*fixture));
    CHECK(strlen(template_text) < sizeof(fixture->root));
    memcpy(fixture->root, template_text, strlen(template_text) + 1);
    CHECK(mkdtemp(fixture->root) != NULL);

    written = snprintf(
        fixture->player_directory,
        sizeof(fixture->player_directory),
        "%s/players",
        fixture->root
    );
    CHECK(written >= 0);
    CHECK((size_t)written < sizeof(fixture->player_directory));

    fixture->store = player_store_open(fixture->player_directory);
    fixture->security = security_policy_create();
    CHECK(fixture->store != NULL);
    CHECK(fixture->security != NULL);
}

static void fixture_close(struct fixture *fixture, const char *player_leaf)
{
    if (fixture->store != NULL) {
        player_store_close(fixture->store);
        fixture->store = NULL;
    }

    if (fixture->security != NULL) {
        security_policy_destroy(fixture->security);
        fixture->security = NULL;
    }

    if (player_leaf != NULL) {
        char path[768];
        int written = snprintf(
            path,
            sizeof(path),
            "%s/%s",
            fixture->player_directory,
            player_leaf
        );

        CHECK(written >= 0);
        CHECK((size_t)written < sizeof(path));
        CHECK(unlink(path) == 0);
    }

    CHECK(rmdir(fixture->player_directory) == 0);
    CHECK(rmdir(fixture->root) == 0);
}

static telnet_session *make_session(
    struct fixture *fixture,
    const char *remote_id,
    telnet_write_fn writer,
    void *writer_context
)
{
    telnet_session_config config = {
        .store = fixture->store,
        .security = fixture->security,
        .audit = NULL,
        .remote_id = remote_id,
        .writer = writer,
        .writer_context = writer_context
    };

    return telnet_session_create(&config);
}

static void feed_text(
    telnet_session *session,
    const char *text,
    uint64_t now_ms
)
{
    CHECK(telnet_session_feed_at(
        session,
        (const unsigned char *)text,
        strlen(text),
        now_ms
    ) == 0);
}

/* ---------- Option state machine ---------- */

struct sent_commands {
    unsigned char bytes[128][2];
    size_t count;
};

static void capture_option_send(
    void *context,
    unsigned char command,
    unsigned char option
)
{
    struct sent_commands *sent = context;

    CHECK(sent->count < 128);
    sent->bytes[sent->count][0] = command;
    sent->bytes[sent->count][1] = option;
    ++sent->count;
}

static int accept_binary_only(
    void *context,
    telnet_q_direction direction,
    unsigned char option
)
{
    (void)context;
    (void)direction;
    return option == TELNET_OPT_BINARY;
}

static void test_option_state(void)
{
    telnet_q q;
    struct sent_commands sent;

    memset(&sent, 0, sizeof(sent));
    telnet_q_init(&q);

    /* Remote BINARY activation begins with DO and completes on WILL. */
    telnet_q_request(
        &q,
        TELNET_Q_REMOTE,
        TELNET_OPT_BINARY,
        1,
        capture_option_send,
        &sent
    );
    CHECK(sent.count == 1);
    CHECK(sent.bytes[0][0] == TELNET_DO);
    CHECK(sent.bytes[0][1] == TELNET_OPT_BINARY);
    CHECK(!telnet_q_enabled(&q, TELNET_Q_REMOTE, TELNET_OPT_BINARY));

    telnet_q_receive(
        &q,
        TELNET_WILL,
        TELNET_OPT_BINARY,
        accept_binary_only,
        NULL,
        capture_option_send,
        &sent
    );
    CHECK(telnet_q_enabled(&q, TELNET_Q_REMOTE, TELNET_OPT_BINARY));
    CHECK(sent.count == 1);

    /* Duplicate acknowledgements keep the established state stable. */
    telnet_q_receive(
        &q,
        TELNET_WILL,
        TELNET_OPT_BINARY,
        accept_binary_only,
        NULL,
        capture_option_send,
        &sent
    );
    CHECK(sent.count == 1);

    /* A queued enable request is sent after the active disable completes. */
    telnet_q_request(
        &q,
        TELNET_Q_REMOTE,
        TELNET_OPT_BINARY,
        0,
        capture_option_send,
        &sent
    );
    CHECK(sent.count == 2);
    CHECK(sent.bytes[1][0] == TELNET_DONT);

    telnet_q_request(
        &q,
        TELNET_Q_REMOTE,
        TELNET_OPT_BINARY,
        1,
        capture_option_send,
        &sent
    );
    CHECK(sent.count == 2);

    telnet_q_receive(
        &q,
        TELNET_WONT,
        TELNET_OPT_BINARY,
        accept_binary_only,
        NULL,
        capture_option_send,
        &sent
    );
    CHECK(sent.count == 3);
    CHECK(sent.bytes[2][0] == TELNET_DO);

    telnet_q_receive(
        &q,
        TELNET_WILL,
        TELNET_OPT_BINARY,
        accept_binary_only,
        NULL,
        capture_option_send,
        &sent
    );
    CHECK(telnet_q_enabled(&q, TELNET_Q_REMOTE, TELNET_OPT_BINARY));

    /* Unsolicited unsupported options receive one explicit refusal. */
    telnet_q_receive(
        &q,
        TELNET_WILL,
        99,
        accept_binary_only,
        NULL,
        capture_option_send,
        &sent
    );
    CHECK(sent.bytes[sent.count - 1][0] == TELNET_DONT);
    CHECK(sent.bytes[sent.count - 1][1] == 99);

    /* Local BINARY follows the same state model with WILL/DO commands. */
    telnet_q_request(
        &q,
        TELNET_Q_LOCAL,
        TELNET_OPT_BINARY,
        1,
        capture_option_send,
        &sent
    );
    CHECK(sent.bytes[sent.count - 1][0] == TELNET_WILL);

    telnet_q_receive(
        &q,
        TELNET_DO,
        TELNET_OPT_BINARY,
        accept_binary_only,
        NULL,
        capture_option_send,
        &sent
    );
    CHECK(telnet_q_enabled(&q, TELNET_Q_LOCAL, TELNET_OPT_BINARY));
}

/* ---------- Login, persistence, and command limits ---------- */

static void test_login_and_commands(void)
{
    struct fixture fixture;
    struct output_capture first_output = {0};
    struct output_capture second_output = {0};
    telnet_session *first;
    telnet_session *second;
    telnet_session *third;
    size_t banner_length;

    fixture_open(&fixture, "/tmp/telnet-login-test-XXXXXX");

    first = make_session(
        &fixture,
        "127.0.0.1",
        capture_write,
        &first_output
    );
    CHECK(first != NULL);

    telnet_session_start(first);
    CHECK(capture_contains_text(&first_output, "Welcome, traveler."));

    /* A session may emit its startup banner once. */
    banner_length = first_output.length;
    telnet_session_start(first);
    CHECK(first_output.length == banner_length);

    clear_capture(&first_output);
    feed_text(first, "TestUser\r\n", 1000);
    CHECK(capture_contains_text(&first_output, "8-128 characters"));

    clear_capture(&first_output);
    feed_text(first, "12345678\r\n", 1100);
    CHECK(capture_contains_text(&first_output, "less common password"));

    clear_capture(&first_output);
    feed_text(first, "R!ot2026\r\n", 1200);
    CHECK(capture_contains_text(&first_output, "Confirm password:"));

    clear_capture(&first_output);
    feed_text(first, "R!ot2026\r\n", 1300);
    CHECK(telnet_session_is_in_game(first));

    clear_capture(&first_output);
    feed_text(first, "PING\r\n", 1400);
    CHECK(capture_contains_text(&first_output, "PONG"));

    telnet_session_destroy(first);
    player_store_close(fixture.store);
    fixture.store = player_store_open(fixture.player_directory);
    CHECK(fixture.store != NULL);

    /* Reopening the store proves the account came from persistent storage. */
    second = make_session(
        &fixture,
        "127.0.0.1",
        capture_write,
        &second_output
    );
    CHECK(second != NULL);

    telnet_session_start(second);
    clear_capture(&second_output);
    feed_text(second, "testuser\r\n", 2000);
    CHECK(capture_contains_text(&second_output, "Password:"));

    clear_capture(&second_output);
    feed_text(second, "R!ot2026\r\n", 2100);
    CHECK(telnet_session_is_in_game(second));
    telnet_session_destroy(second);

    third = make_session(
        &fixture,
        "127.0.0.1",
        capture_write,
        &second_output
    );
    CHECK(third != NULL);

    clear_capture(&second_output);
    telnet_session_start(third);
    feed_text(third, "TestUser\r\n", 3000);
    feed_text(third, "R!ot2026\r\n", 3100);
    CHECK(telnet_session_is_in_game(third));

    /* Twenty-five commands fit in one command-rate window. */
    {
        unsigned int i;

        for (i = 0; i < 25; ++i) {
            CHECK(telnet_session_feed_at(
                third,
                (const unsigned char *)"PING\r\n",
                strlen("PING\r\n"),
                3200
            ) == 0);
        }

        CHECK(telnet_session_feed_at(
            third,
            (const unsigned char *)"PING\r\n",
            strlen("PING\r\n"),
            3200
        ) == -1);
        CHECK(telnet_session_should_close(third));
    }

    telnet_session_destroy(third);
    fixture_close(&fixture, "testuser.player");
}

/* ---------- Operational negotiation and NVT controls ---------- */

static void test_operational_telnet(void)
{
    struct fixture fixture;
    struct output_capture output = {0};
    telnet_session *session;
    telnet_terminal_info info;

    const unsigned char will_binary[] = {
        TELNET_IAC, TELNET_WILL, TELNET_OPT_BINARY
    };
    const unsigned char do_binary[] = {
        TELNET_IAC, TELNET_DO, TELNET_OPT_BINARY
    };
    const unsigned char will_sga[] = {
        TELNET_IAC, TELNET_WILL, TELNET_OPT_SUPPRESS_GO_AHEAD
    };
    const unsigned char do_sga[] = {
        TELNET_IAC, TELNET_DO, TELNET_OPT_SUPPRESS_GO_AHEAD
    };
    const unsigned char will_eor[] = {
        TELNET_IAC, TELNET_WILL, TELNET_OPT_END_OF_RECORD
    };
    const unsigned char do_naws[] = {
        TELNET_IAC, TELNET_DO, TELNET_OPT_NAWS
    };
    const unsigned char do_ttype[] = {
        TELNET_IAC, TELNET_DO, TELNET_OPT_TERMINAL_TYPE
    };
    const unsigned char will_charset[] = {
        TELNET_IAC, TELNET_WILL, TELNET_OPT_CHARSET
    };
    const unsigned char do_charset[] = {
        TELNET_IAC, TELNET_DO, TELNET_OPT_CHARSET
    };
    const unsigned char do_new_environ[] = {
        TELNET_IAC, TELNET_DO, TELNET_OPT_NEW_ENVIRON
    };
    const unsigned char ga[] = {
        TELNET_IAC, TELNET_GA
    };

    fixture_open(&fixture, "/tmp/telnet-ops-test-XXXXXX");

    session = make_session(
        &fixture,
        "127.0.0.1",
        capture_write,
        &output
    );
    CHECK(session != NULL);

    telnet_session_start(session);

    CHECK(capture_contains_bytes(&output, will_binary, sizeof(will_binary)));
    CHECK(capture_contains_bytes(&output, do_binary, sizeof(do_binary)));
    CHECK(capture_contains_bytes(&output, will_sga, sizeof(will_sga)));
    CHECK(capture_contains_bytes(&output, do_sga, sizeof(do_sga)));
    CHECK(capture_contains_bytes(&output, will_eor, sizeof(will_eor)));
    CHECK(capture_contains_bytes(&output, do_naws, sizeof(do_naws)));
    CHECK(capture_contains_bytes(&output, do_ttype, sizeof(do_ttype)));
    CHECK(capture_contains_bytes(&output, will_charset, sizeof(will_charset)));
    CHECK(capture_contains_bytes(&output, do_charset, sizeof(do_charset)));
    CHECK(capture_contains_bytes(
        &output,
        do_new_environ,
        sizeof(do_new_environ)
    ));
    /* Before SGA/EOR is agreed, the first prompt uses ordinary Telnet GA. */
    CHECK(capture_contains_bytes(&output, ga, sizeof(ga)));

    /* Complete the server-initiated capability negotiations. */
    clear_capture(&output);
    {
        const unsigned char replies[] = {
            TELNET_IAC, TELNET_DO, TELNET_OPT_BINARY,
            TELNET_IAC, TELNET_WILL, TELNET_OPT_BINARY,
            TELNET_IAC, TELNET_DO, TELNET_OPT_SUPPRESS_GO_AHEAD,
            TELNET_IAC, TELNET_WILL, TELNET_OPT_SUPPRESS_GO_AHEAD,
            TELNET_IAC, TELNET_DO, TELNET_OPT_END_OF_RECORD,
            TELNET_IAC, TELNET_WILL, TELNET_OPT_NAWS,
            TELNET_IAC, TELNET_WILL, TELNET_OPT_TERMINAL_TYPE,
            TELNET_IAC, TELNET_DO, TELNET_OPT_CHARSET,
            TELNET_IAC, TELNET_WILL, TELNET_OPT_CHARSET,
            TELNET_IAC, TELNET_WILL, TELNET_OPT_NEW_ENVIRON
        };

        CHECK(telnet_session_feed_at(
            session,
            replies,
            sizeof(replies),
            1000
        ) == 0);
    }

    {
        const unsigned char ttype_send[] = {
            TELNET_IAC, TELNET_SB, TELNET_OPT_TERMINAL_TYPE,
            1, TELNET_IAC, TELNET_SE
        };
        const unsigned char charset_request[] = {
            TELNET_IAC, TELNET_SB, TELNET_OPT_CHARSET,
            1, ';', 'U', 'T', 'F', '-', '8',
            TELNET_IAC, TELNET_SE
        };
        const unsigned char environ_request_prefix[] = {
            TELNET_IAC, TELNET_SB, TELNET_OPT_NEW_ENVIRON,
            1, 0, 'C', 'L', 'I', 'E', 'N', 'T', '_', 'N', 'A', 'M', 'E'
        };

        CHECK(capture_contains_bytes(
            &output,
            ttype_send,
            sizeof(ttype_send)
        ));
        CHECK(capture_contains_bytes(
            &output,
            charset_request,
            sizeof(charset_request)
        ));
        CHECK(capture_contains_bytes(
            &output,
            environ_request_prefix,
            sizeof(environ_request_prefix)
        ));
    }

    /* MTTS discovery is deliberately bounded to the standard four responses. */
    {
        const unsigned char reports[][32] = {
            {TELNET_IAC, TELNET_SB, TELNET_OPT_TERMINAL_TYPE,
             0, 'M','U','D','L','E','T', TELNET_IAC, TELNET_SE},
            {TELNET_IAC, TELNET_SB, TELNET_OPT_TERMINAL_TYPE,
             0, 'X','T','E','R','M', TELNET_IAC, TELNET_SE},
            {TELNET_IAC, TELNET_SB, TELNET_OPT_TERMINAL_TYPE,
             0, 'M','T','T','S',' ','8','4','7', TELNET_IAC, TELNET_SE},
            {TELNET_IAC, TELNET_SB, TELNET_OPT_TERMINAL_TYPE,
             0, 'M','T','T','S',' ','8','4','7', TELNET_IAC, TELNET_SE}
        };
        const size_t report_lengths[] = {12, 11, 14, 14};
        const unsigned char ttype_send[] = {
            TELNET_IAC, TELNET_SB, TELNET_OPT_TERMINAL_TYPE,
            1, TELNET_IAC, TELNET_SE
        };
        size_t i;

        for (i = 0; i < 4; ++i) {
            clear_capture(&output);
            CHECK(telnet_session_feed_at(
                session,
                reports[i],
                report_lengths[i],
                1100 + (uint64_t)i
            ) == 0);

            if (i < 3) {
                CHECK(capture_contains_bytes(
                    &output,
                    ttype_send,
                    sizeof(ttype_send)
                ));
            } else {
                CHECK(!capture_contains_bytes(
                    &output,
                    ttype_send,
                    sizeof(ttype_send)
                ));
            }
        }
    }

    /* Report a 120-column by 40-row terminal. */
    {
        const unsigned char naws[] = {
            TELNET_IAC, TELNET_SB, TELNET_OPT_NAWS,
            0, 120, 0, 40,
            TELNET_IAC, TELNET_SE
        };
        CHECK(telnet_session_feed_at(
            session,
            naws,
            sizeof(naws),
            1200
        ) == 0);
    }

    /* Accept the server-originated UTF-8 request. */
    {
        const unsigned char charset_accepted[] = {
            TELNET_IAC, TELNET_SB, TELNET_OPT_CHARSET,
            2, 'U', 'T', 'F', '-', '8',
            TELNET_IAC, TELNET_SE
        };
        CHECK(telnet_session_feed_at(
            session,
            charset_accepted,
            sizeof(charset_accepted),
            1300
        ) == 0);
    }

    /* The opposite RFC 2066 role remains supported too. */
    clear_capture(&output);
    {
        const unsigned char charset_request[] = {
            TELNET_IAC, TELNET_SB, TELNET_OPT_CHARSET,
            1, ';', 'U', 'T', 'F', '-', '8',
            TELNET_IAC, TELNET_SE
        };
        const unsigned char accepted[] = {
            TELNET_IAC, TELNET_SB, TELNET_OPT_CHARSET,
            2, 'U', 'T', 'F', '-', '8',
            TELNET_IAC, TELNET_SE
        };

        CHECK(telnet_session_feed_at(
            session,
            charset_request,
            sizeof(charset_request),
            1301
        ) == 0);
        CHECK(capture_contains_bytes(&output, accepted, sizeof(accepted)));
    }

    /* MNES can fill/update client metadata independently of TTYPE. */
    {
        const unsigned char environ[] = {
            TELNET_IAC, TELNET_SB, TELNET_OPT_NEW_ENVIRON,
            0,
            /* Unknown variables and RFC 1572 escaping must not desync parsing. */
            0, 'X', 1, 'A', 2, 1, 'B',
            0, 'C','L','I','E','N','T','_','N','A','M','E',
            1, 'M','u','d','l','e','t',
            0, 'C','L','I','E','N','T','_','V','E','R','S','I','O','N',
            1, '4','.','1','9',
            TELNET_IAC, TELNET_SE
        };
        CHECK(telnet_session_feed_at(
            session,
            environ,
            sizeof(environ),
            1350
        ) == 0);
    }

    telnet_session_get_terminal_info(session, &info);
    CHECK(info.width == 120);
    CHECK(info.height == 40);
    CHECK(info.local_binary);
    CHECK(info.remote_binary);
    CHECK(info.local_suppress_go_ahead);
    CHECK(info.remote_suppress_go_ahead);
    CHECK(info.local_eor);
    CHECK(info.new_environ);
    CHECK(info.utf8_enabled);
    CHECK(info.ansi);
    CHECK(info.vt100);
    CHECK(info.color_256);
    CHECK(info.truecolor);
    CHECK(info.screen_reader);
    CHECK(info.mnes);
    CHECK(info.mtts_flags == 847U);
    CHECK(strcmp(info.terminal_type, "XTERM") == 0);
    CHECK(strcmp(info.client_name, "Mudlet") == 0);
    CHECK(strcmp(info.client_version, "4.19") == 0);

    /* AYT produces a prompt response and EOR marks that prompt boundary. */
    clear_capture(&output);
    {
        const unsigned char ayt[] = {TELNET_IAC, TELNET_AYT};
        const unsigned char eor[] = {TELNET_IAC, TELNET_EOR};
        const unsigned char prompt_ga[] = {TELNET_IAC, TELNET_GA};
        CHECK(telnet_session_feed_at(
            session,
            ayt,
            sizeof(ayt),
            1400
        ) == 0);
        CHECK(capture_contains_text(&output, "Server is here"));
        CHECK(capture_contains_bytes(&output, eor, sizeof(eor)));
        CHECK(!capture_contains_bytes(&output, prompt_ga, sizeof(prompt_ga)));
    }

    /* CR is held until the following NVT byte defines its meaning. */
    clear_capture(&output);
    CHECK(telnet_session_feed_at(
        session,
        (const unsigned char *)"TestUser\r",
        strlen("TestUser\r"),
        1500
    ) == 0);
    CHECK(!capture_contains_text(&output, "password"));
    CHECK(!capture_contains_text(&output, "New player"));

    CHECK(telnet_session_feed_at(
        session,
        (const unsigned char *)"\n",
        1,
        1501
    ) == 0);
    CHECK(capture_contains_text(&output, "New player"));

    /* IP clears the active password line and restores the current prompt. */
    clear_capture(&output);
    {
        const unsigned char partial_and_ip[] = {
            's', 'e', 'c', 'r', 'e', 't',
            TELNET_IAC, TELNET_IP
        };
        CHECK(telnet_session_feed_at(
            session,
            partial_and_ip,
            sizeof(partial_and_ip),
            1600
        ) == 0);
        CHECK(capture_contains_text(&output, "Create password:"));
    }

    telnet_session_destroy(session);

    /* CR NUL carries a literal carriage return in NVT input. */
    clear_capture(&output);
    session = make_session(
        &fixture,
        "127.0.0.1",
        capture_write,
        &output
    );
    CHECK(session != NULL);
    telnet_session_start(session);
    clear_capture(&output);
    {
        const unsigned char cr_nul[] = {
            'A', 'b', 'c', '\r', '\0'
        };
        CHECK(telnet_session_feed_at(
            session,
            cr_nul,
            sizeof(cr_nul),
            1700
        ) == 0);
        CHECK(!capture_contains_text(&output, "New player"));
        CHECK(!capture_contains_text(&output, "Password:"));
    }

    telnet_session_destroy(session);
    fixture_close(&fixture, NULL);
}

/* ---------- Older TLS/Telnet client compatibility ---------- */

static void test_old_client_controls(void)
{
    struct fixture fixture;
    struct output_capture output = {0};
    telnet_session *session;

    fixture_open(&fixture, "/tmp/telnet-old-client-test-XXXXXX");
    session = make_session(
        &fixture,
        "127.0.0.1",
        capture_write,
        &output
    );
    CHECK(session != NULL);

    telnet_session_start(session);
    clear_capture(&output);

    {
        const unsigned char old_client_controls[] = {
            'J', 'o', 'h', 'n',
            3, 3, 3, 21, 12, 3, 3,
            '\r', '\n'
        };

        CHECK(telnet_session_feed_at(
            session,
            old_client_controls,
            sizeof(old_client_controls),
            1800
        ) == 0);
    }

    CHECK(!telnet_session_should_close(session));
    CHECK(!capture_contains_text(&output, "Protocol error"));
    CHECK(capture_contains_text(&output, "New player"));

    telnet_session_destroy(session);
    fixture_close(&fixture, NULL);
}

static void test_plain_telnet_warning(void)
{
    struct fixture fixture;
    struct output_capture output = {0};
    telnet_session *session;

    fixture_open(&fixture, "/tmp/telnet-plain-warning-test-XXXXXX");
    session = make_session(
        &fixture,
        "127.0.0.1",
        capture_write,
        &output
    );
    CHECK(session != NULL);

    telnet_session_start(session);
    clear_capture(&output);
    feed_text(session, "TestUser\r\n", 1850);
    CHECK(capture_contains_text(&output, "plain Telnet is not encrypted"));

    clear_capture(&output);
    feed_text(session, "12345678\r\n", 1851);
    CHECK(!capture_contains_text(&output, "plain Telnet is not encrypted"));

    telnet_session_destroy(session);
    fixture_close(&fixture, NULL);
}

static void test_new_account_name_limit(void)
{
    struct fixture fixture;
    struct output_capture output = {0};
    telnet_session *session;

    fixture_open(&fixture, "/tmp/telnet-name-limit-test-XXXXXX");
    session = make_session(
        &fixture,
        "127.0.0.1",
        capture_write,
        &output
    );
    CHECK(session != NULL);
    telnet_session_start(session);
    clear_capture(&output);
    feed_text(session, "SixteenCharsHere\r\n", 1900);
    CHECK(capture_contains_text(&output, "3-15 characters"));
    CHECK(!capture_contains_text(&output, "Create a password"));

    telnet_session_destroy(session);
    fixture_close(&fixture, NULL);
}

/* ---------- Hostile and malformed input ---------- */

static void test_malformed_input(void)
{
    struct fixture fixture;
    telnet_session *session;
    unsigned int seed = 0xC0FFEEU;
    unsigned int iteration;

    fixture_open(&fixture, "/tmp/telnet-hostile-test-XXXXXX");

    session = make_session(
        &fixture,
        "fuzz-test",
        discard_write,
        NULL
    );
    CHECK(session != NULL);
    telnet_session_start(session);

    /*
     * Deterministic hostile bytes run during every CTest execution. The
     * coverage-guided fuzz target provides a second, independent parser test.
     */
    for (iteration = 0; iteration < 5000U; ++iteration) {
        unsigned char bytes[32];
        size_t i;
        int result;

        for (i = 0; i < sizeof(bytes); ++i) {
            seed = seed * 1103515245U + 12345U;
            bytes[i] = (unsigned char)(seed >> 16);
        }

        result = telnet_session_feed_at(
            session,
            bytes,
            sizeof(bytes),
            1000ULL + (uint64_t)iteration * 100ULL
        );

        if (result != 0) {
            telnet_session_destroy(session);
            session = make_session(
                &fixture,
                "fuzz-test",
                discard_write,
                NULL
            );
            CHECK(session != NULL);
            telnet_session_start(session);
        }
    }

    /* Unknown but well-framed Telnet commands are compatibility noise, not abuse. */
    {
        const unsigned char unknown_command[] = {
            TELNET_IAC, 200
        };
        unsigned int i;

        for (i = 0; i < 20; ++i) {
            CHECK(telnet_session_feed_at(
                session,
                unknown_command,
                sizeof(unknown_command),
                850000 + i
            ) == 0);
        }
        CHECK(!telnet_session_should_close(session));
    }

    /* Eager NAWS reports before WILL NAWS are harmless and ignored. */
    {
        const unsigned char early_naws[] = {
            TELNET_IAC, TELNET_SB, TELNET_OPT_NAWS,
            0, 100, 0, 30,
            TELNET_IAC, TELNET_SE
        };
        unsigned int i;

        for (i = 0; i < 12; ++i) {
            CHECK(telnet_session_feed_at(
                session,
                early_naws,
                sizeof(early_naws),
                860000 + i
            ) == 0);
        }
        CHECK(!telnet_session_should_close(session));
    }

    /* Repeated unsupported WILL requests remain bounded and stable. */
    {
        const unsigned char will_unknown[] = {
            TELNET_IAC, TELNET_WILL, 99
        };

        CHECK(telnet_session_feed_at(
            session,
            will_unknown,
            sizeof(will_unknown),
            900000
        ) == 0);
        CHECK(telnet_session_feed_at(
            session,
            will_unknown,
            sizeof(will_unknown),
            900001
        ) == 0);
    }

    telnet_session_destroy(session);
    session = make_session(
        &fixture,
        "fuzz-test",
        discard_write,
        NULL
    );
    CHECK(session != NULL);
    telnet_session_start(session);

    /* The fixed subnegotiation cap closes a session that exceeds 4096 bytes. */
    {
        const unsigned char prefix[] = {
            TELNET_IAC, TELNET_SB, TELNET_OPT_CHARSET
        };
        unsigned char payload[4097];

        memset(payload, 'A', sizeof(payload));

        CHECK(telnet_session_feed_at(
            session,
            prefix,
            sizeof(prefix),
            910000
        ) == 0);
        CHECK(telnet_session_feed_at(
            session,
            payload,
            sizeof(payload),
            910001
        ) == -1);
    }

    telnet_session_destroy(session);
    fixture_close(&fixture, NULL);
}

int main(void)
{
    test_option_state();
    test_login_and_commands();
    test_operational_telnet();
    test_old_client_controls();
    test_plain_telnet_warning();
    test_new_account_name_limit();
    test_malformed_input();

    puts("telnet test passed");
    return 0;
}
