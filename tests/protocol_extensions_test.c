// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "player_store.h"
#include "security_policy.h"
#include "telnet_internal.h"
#include "telnet_protocol.h"

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #expr); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

struct capture {
    unsigned char bytes[65536];
    size_t length;
};

struct application_probe {
    int opened;
    int closed;
    int link_result;
    int send_link_result;
    int gmcp_result;
    int poll_calls;
    size_t gmcp_count;
    char gmcp_packages[4][64];
    char gmcp_payloads[4][256];
    terminal_capabilities capabilities;
};

static void *application_open(
    void *manager_context,
    const char *account_name,
    const terminal_output *output,
    const terminal_capabilities *capabilities
)
{
    struct application_probe *probe = manager_context;

    CHECK(strcmp(account_name, "ProtoUser") == 0);
    CHECK(output != NULL && capabilities != NULL);
    probe->opened = 1;
    probe->capabilities = *capabilities;
    probe->link_result = output->write_link(
        output->context,
        "https://example.invalid/help",
        "help"
    );
    probe->send_link_result = output->write_link(
        output->context,
        "send:north",
        "north"
    );
    probe->gmcp_result = output->send_gmcp(
        output->context,
        "Test.Message",
        "{\"ok\":true}"
    );
    return probe;
}

static int application_line(void *session_context, const char *line, size_t length)
{
    (void)session_context;
    (void)line;
    (void)length;
    return 0;
}

static void application_capabilities_changed(
    void *session_context,
    const terminal_capabilities *capabilities
)
{
    struct application_probe *probe = session_context;
    probe->capabilities = *capabilities;
}

static void application_gmcp(
    void *session_context,
    const char *package_name,
    const char *json_payload,
    size_t json_length
)
{
    struct application_probe *probe = session_context;
    size_t index = probe->gmcp_count;

    CHECK(index < 4);
    CHECK(strlen(package_name) < sizeof(probe->gmcp_packages[index]));
    CHECK(json_length < sizeof(probe->gmcp_payloads[index]));

    memcpy(
        probe->gmcp_packages[index],
        package_name,
        strlen(package_name) + 1
    );
    memcpy(probe->gmcp_payloads[index], json_payload, json_length);
    probe->gmcp_payloads[index][json_length] = '\0';
    ++probe->gmcp_count;
}

static int application_poll(void *session_context)
{
    struct application_probe *probe = session_context;
    ++probe->poll_calls;
    return 0;
}

static void application_close(void *session_context)
{
    struct application_probe *probe = session_context;
    probe->closed = 1;
}

static void write_capture(void *context, const unsigned char *data, size_t length)
{
    struct capture *capture = context;
    CHECK(capture->length + length <= sizeof(capture->bytes));
    memcpy(capture->bytes + capture->length, data, length);
    capture->length += length;
}

static int contains(
    const struct capture *capture,
    const unsigned char *needle,
    size_t needle_length
)
{
    size_t i;
    if (needle_length == 0 || needle_length > capture->length) return 0;
    for (i = 0; i + needle_length <= capture->length; ++i) {
        if (memcmp(capture->bytes + i, needle, needle_length) == 0) return 1;
    }
    return 0;
}

static void status_snapshot(void *context, telnet_mssp_status *status)
{
    (void)context;
    memcpy(status->name, "Protocol Test", sizeof("Protocol Test"));
    status->players = 7;
    status->uptime = 1700000000ULL;
    status->telnet_port = 3333;
    status->telnet_tls_port = 3334;
    memcpy(status->codebase, "mud-terminal-core", sizeof("mud-terminal-core"));
}

static void feed(telnet_session *session, const unsigned char *data, size_t length)
{
    CHECK(telnet_session_feed_at(session, data, length, 1000) == 0);
}

int main(void)
{
    char root[] = "/tmp/telnet-protocol-ext-test-XXXXXX";
    char players[512];
    player_store *store;
    security_policy *security;
    telnet_session *session;
    telnet_session_config config;
    telnet_terminal_info info;
    terminal_application_hooks application;
    player_password_token password_token;
    struct capture capture;
    struct application_probe probe;
    const unsigned char will_mssp[] = {TELNET_IAC, TELNET_WILL, TELNET_OPT_MSSP};
    const unsigned char will_gmcp[] = {TELNET_IAC, TELNET_WILL, TELNET_OPT_GMCP};

    CHECK(mkdtemp(root) != NULL);
    CHECK(snprintf(players, sizeof(players), "%s/players", root) > 0);
    store = player_store_open(players);
    security = security_policy_create();
    CHECK(store != NULL && security != NULL);
    CHECK(player_store_prepare_password(
        "TestPass!123",
        strlen("TestPass!123"),
        &password_token
    ) == 0);
    CHECK(player_store_create(store, "ProtoUser", &password_token) == 0);
    player_store_password_clear(&password_token);

    memset(&probe, 0, sizeof(probe));
    memset(&application, 0, sizeof(application));
    application.manager_context = &probe;
    application.open = application_open;
    application.line = application_line;
    application.capabilities_changed = application_capabilities_changed;
    application.gmcp = application_gmcp;
    application.poll = application_poll;
    application.close = application_close;

    memset(&capture, 0, sizeof(capture));
    memset(&config, 0, sizeof(config));
    config.store = store;
    config.security = security;
    config.remote_id = "127.0.0.1";
    config.writer = write_capture;
    config.writer_context = &capture;
    config.application = &application;
    config.mssp_query = status_snapshot;

    session = telnet_session_create(&config);
    CHECK(session != NULL);
    telnet_session_start(session);
    CHECK(contains(&capture, will_mssp, sizeof(will_mssp)));
    CHECK(contains(&capture, will_gmcp, sizeof(will_gmcp)));

    memset(&capture, 0, sizeof(capture));
    {
        const unsigned char replies[] = {
            TELNET_IAC, TELNET_DO, TELNET_OPT_MSSP,
            TELNET_IAC, TELNET_DO, TELNET_OPT_GMCP,
            TELNET_IAC, TELNET_WILL, TELNET_OPT_NEW_ENVIRON
        };
        feed(session, replies, sizeof(replies));
    }

    /* MSSP is one bounded snapshot once DO MSSP establishes server WILL MSSP. */
    {
        const unsigned char name_pair[] = {1,'N','A','M','E',2,'P','r','o','t','o','c','o','l',' ','T','e','s','t'};
        const unsigned char players_pair[] = {1,'P','L','A','Y','E','R','S',2,'7'};
        const unsigned char uptime_pair[] = {1,'U','P','T','I','M','E',2,'1','7','0','0','0','0','0','0','0','0'};
        const unsigned char port_pair[] = {1,'P','O','R','T',2,'3','3','3','3'};
        const unsigned char ssl_pair[] = {1,'S','S','L',2,'3','3','3','4'};
        CHECK(contains(&capture, name_pair, sizeof(name_pair)));
        CHECK(contains(&capture, players_pair, sizeof(players_pair)));
        CHECK(contains(&capture, uptime_pair, sizeof(uptime_pair)));
        CHECK(contains(&capture, port_pair, sizeof(port_pair)));
        CHECK(contains(&capture, ssl_pair, sizeof(ssl_pair)));
    }

    telnet_session_get_terminal_info(session, &info);
    CHECK(info.mssp);
    CHECK(info.gmcp);

    /* Core.Ping receives the protocol-defined no-body echo. */
    memset(&capture, 0, sizeof(capture));
    {
        const unsigned char ping[] = {
            TELNET_IAC, TELNET_SB, TELNET_OPT_GMCP,
            'C','o','r','e','.','P','i','n','g',' ','1','2','3',
            TELNET_IAC, TELNET_SE
        };
        const unsigned char pong[] = {
            TELNET_IAC, TELNET_SB, TELNET_OPT_GMCP,
            'C','o','r','e','.','P','i','n','g',
            TELNET_IAC, TELNET_SE
        };
        feed(session, ping, sizeof(ping));
        CHECK(contains(&capture, pong, sizeof(pong)));
    }

    /*
     * Core.Hello and Core.Supports normally arrive before account login. Keep
     * that bounded handshake until the post-auth application seam exists.
     */
    {
        const unsigned char hello[] = {
            TELNET_IAC, TELNET_SB, TELNET_OPT_GMCP,
            'C','o','r','e','.','H','e','l','l','o',' ',
            '{','"','C','l','i','e','n','t','"',':','"','T','e','s','t','C','l','i','e','n','t','"',',',
            '"','V','e','r','s','i','o','n','"',':','"','1','.','0','"','}',
            TELNET_IAC, TELNET_SE
        };
        const unsigned char supports[] = {
            TELNET_IAC, TELNET_SB, TELNET_OPT_GMCP,
            'C','o','r','e','.','S','u','p','p','o','r','t','s','.','S','e','t',' ',
            '[','"','C','o','r','e',' ','1','"',',','"','R','o','o','m',' ','1','"',']',
            TELNET_IAC, TELNET_SE
        };
        feed(session, hello, sizeof(hello));
        feed(session, supports, sizeof(supports));
        CHECK(probe.gmcp_count == 0);
    }

    /* Modern NEW-ENVIRON USERVARs populate OSC 8 capability facts. */
    {
        const unsigned char environ[] = {
            TELNET_IAC, TELNET_SB, TELNET_OPT_NEW_ENVIRON,
            0,
            3,'O','S','C','_','H','Y','P','E','R','L','I','N','K','S',1,'1',
            3,'O','S','C','_','H','Y','P','E','R','L','I','N','K','S','_','S','E','N','D',1,'T','R','U','E',
            3,'O','S','C','_','H','Y','P','E','R','L','I','N','K','S','_','P','R','O','M','P','T',1,'1',
            3,'O','S','C','_','H','Y','P','E','R','L','I','N','K','S','_','T','O','O','L','T','I','P',1,'Y','E','S',
            TELNET_IAC, TELNET_SE
        };
        feed(session, environ, sizeof(environ));
        telnet_session_get_terminal_info(session, &info);
        CHECK(info.osc8 && info.osc8_send && info.osc8_prompt && info.osc8_tooltip);
    }

    /* INFO updates are live rather than connect-time-only facts. */
    {
        const unsigned char info_update[] = {
            TELNET_IAC, TELNET_SB, TELNET_OPT_NEW_ENVIRON,
            2,
            3,'O','S','C','_','H','Y','P','E','R','L','I','N','K','S','_','S','E','N','D',1,'0',
            TELNET_IAC, TELNET_SE
        };
        feed(session, info_update, sizeof(info_update));
        telnet_session_get_terminal_info(session, &info);
        CHECK(info.osc8);
        CHECK(!info.osc8_send);
    }

    /* Restore SEND and authenticate into the generic application seam. */
    {
        const unsigned char send_restore[] = {
            TELNET_IAC, TELNET_SB, TELNET_OPT_NEW_ENVIRON,
            2,
            3,'O','S','C','_','H','Y','P','E','R','L','I','N','K','S','_','S','E','N','D',1,'1',
            TELNET_IAC, TELNET_SE
        };
        feed(session, send_restore, sizeof(send_restore));
    }

    memset(&capture, 0, sizeof(capture));
    feed(session, (const unsigned char *)"ProtoUser\r\n", strlen("ProtoUser\r\n"));
    memset(&capture, 0, sizeof(capture));
    feed(session, (const unsigned char *)"TestPass!123\r\n", strlen("TestPass!123\r\n"));
    CHECK(probe.opened);
    CHECK(probe.capabilities.gmcp);
    CHECK(probe.capabilities.osc8);
    CHECK(probe.capabilities.osc8_send);
    CHECK(probe.link_result == 0);
    CHECK(probe.send_link_result == 0);
    CHECK(probe.gmcp_result == 0);
    CHECK(probe.gmcp_count == 2);
    CHECK(strcmp(probe.gmcp_packages[0], "Core.Hello") == 0);
    CHECK(strcmp(
        probe.gmcp_payloads[0],
        "{\"Client\":\"TestClient\",\"Version\":\"1.0\"}"
    ) == 0);
    CHECK(strcmp(probe.gmcp_packages[1], "Core.Supports.Set") == 0);
    CHECK(strcmp(probe.gmcp_payloads[1], "[\"Core 1\",\"Room 1\"]") == 0);
    CHECK(telnet_session_poll(session) == 0);
    CHECK(probe.poll_calls == 1);

    {
        static const unsigned char link_frame[] =
            "\033]8;;https://example.invalid/help\033\\help\033]8;;\033\\";
        static const unsigned char send_frame[] =
            "\033]8;;send:north\033\\north\033]8;;\033\\";
        const unsigned char gmcp_frame[] = {
            TELNET_IAC, TELNET_SB, TELNET_OPT_GMCP,
            'T','e','s','t','.','M','e','s','s','a','g','e',' ',
            '{','"','o','k','"',':','t','r','u','e','}',
            TELNET_IAC, TELNET_SE
        };
        CHECK(contains(&capture, link_frame, sizeof(link_frame) - 1));
        CHECK(contains(&capture, send_frame, sizeof(send_frame) - 1));
        CHECK(contains(&capture, gmcp_frame, sizeof(gmcp_frame)));
    }

    telnet_session_destroy(session);
    CHECK(probe.closed);
    player_store_close(store);
    security_policy_destroy(security);
    {
        char player_path[640];
        CHECK(snprintf(
            player_path,
            sizeof(player_path),
            "%s/protouser.player",
            players
        ) > 0);
        CHECK(unlink(player_path) == 0);
    }
    CHECK(rmdir(players) == 0);
    CHECK(rmdir(root) == 0);

    puts("protocol extensions test passed");
    return 0;
}
