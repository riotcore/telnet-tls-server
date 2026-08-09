// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

#ifndef TELNET_PROTOCOL_H
#define TELNET_PROTOCOL_H

/*
 * Application-facing Telnet adapter for a C MUD server.
 *
 * Raw Telnet framing, NVT input rules, option negotiation, subnegotiation,
 * session-local input limits, and negotiated terminal capabilities stay behind
 * this interface. Socket/TLS ownership stays in secure_server; credential
 * storage stays in player_store; cross-connection abuse policy stays in
 * security_policy. Keeping those concerns separate makes the Telnet adapter
 * reusable when the surrounding game architecture changes.
 *
 * This standalone repository currently keeps a minimal account/login and
 * command loop in the Telnet session so the public slice can run and be tested
 * by itself. A complete MUD should eventually place account/game-session
 * ownership above this adapter, which is the same seam a future SSH transport
 * will use. Higher layers should consume negotiated capabilities rather than
 * branch on a particular MUD client name.
 */

#include <stddef.h>
#include <stdint.h>

#include "audit_log.h"
#include "player_store.h"
#include "security_policy.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TELNET_TERMINAL_TYPE_MAX 40
#define TELNET_CLIENT_NAME_MAX 40
#define TELNET_CLIENT_VERSION_MAX 40

/* MTTS bit values are exposed so presentation code can make capability choices. */
enum telnet_mtts_capability {
    TELNET_MTTS_ANSI = 1U,
    TELNET_MTTS_VT100 = 2U,
    TELNET_MTTS_UTF8 = 4U,
    TELNET_MTTS_256_COLORS = 8U,
    TELNET_MTTS_MOUSE_TRACKING = 16U,
    TELNET_MTTS_OSC_COLOR_PALETTE = 32U,
    TELNET_MTTS_SCREEN_READER = 64U,
    TELNET_MTTS_PROXY = 128U,
    TELNET_MTTS_TRUECOLOR = 256U,
    TELNET_MTTS_MNES = 512U,
    TELNET_MTTS_MSLP = 1024U,
    TELNET_MTTS_TLS = 2048U
};

typedef void (*telnet_write_fn)(
    void *context,
    const unsigned char *data,
    size_t length
);

typedef struct telnet_session telnet_session;

typedef struct telnet_session_config {
    player_store *store;
    security_policy *security;
    audit_log *audit;
    const char *remote_id;
    telnet_write_fn writer;
    void *writer_context;

    /* Used only for security-aware presentation; Telnet itself is unchanged. */
    int transport_secure;
} telnet_session_config;

/*
 * Negotiated/reported terminal capabilities exposed to future application
 * systems. Defaults remain conservative so a client that negotiates nothing is
 * still fully usable as a basic line-oriented terminal.
 */
typedef struct telnet_terminal_info {
    uint16_t width;
    uint16_t height;

    int local_binary;
    int remote_binary;
    int local_suppress_go_ahead;
    int remote_suppress_go_ahead;
    int local_eor;
    int new_environ;
    int utf8_enabled;
    int secure_transport;

    uint32_t mtts_flags;
    int ansi;
    int vt100;
    int color_256;
    int truecolor;
    int screen_reader;
    int mnes;

    char terminal_type[TELNET_TERMINAL_TYPE_MAX + 1];
    char client_name[TELNET_CLIENT_NAME_MAX + 1];
    char client_version[TELNET_CLIENT_VERSION_MAX + 1];
} telnet_terminal_info;

/* Initializes protocol dependencies. Safe to call more than once. */
int telnet_protocol_init(void);

/*
 * Creates one session. The referenced store, security policy, audit logger,
 * writer context, and remote identifier must remain valid for session life.
 */
telnet_session *telnet_session_create(
    const telnet_session_config *config
);

/* Securely clears session state and releases the session. NULL is accepted. */
void telnet_session_destroy(telnet_session *session);

/*
 * Starts capability negotiation and writes the welcome banner. Negotiation is
 * deliberately asynchronous: a peer can ignore every optional Telnet feature
 * and still continue directly to the login prompt.
 */
void telnet_session_start(telnet_session *session);

/*
 * Feeds raw Telnet bytes using a caller-supplied monotonic timestamp.
 *
 * Returns 0 while the session remains usable. Returns -1 after a protocol,
 * input, or command limit requests transport closure.
 */
int telnet_session_feed_at(
    telnet_session *session,
    const unsigned char *data,
    size_t length,
    uint64_t now_ms
);

/* Convenience form that reads CLOCK_MONOTONIC internally. */
int telnet_session_feed(
    telnet_session *session,
    const unsigned char *data,
    size_t length
);

/* Session state queries used by the transport and future application layer. */
int telnet_session_is_in_game(const telnet_session *session);
int telnet_session_should_close(const telnet_session *session);
const char *telnet_session_player_name(const telnet_session *session);

/*
 * Copies terminal metadata into caller-owned storage.
 * Defaults are 80x24, terminal/client type UNKNOWN, and optional capabilities
 * disabled until the peer negotiates or reports them.
 */
void telnet_session_get_terminal_info(
    const telnet_session *session,
    telnet_terminal_info *info
);

#ifdef __cplusplus
}
#endif

#endif
