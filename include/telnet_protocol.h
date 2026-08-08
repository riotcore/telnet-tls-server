// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

#ifndef TELNET_PROTOCOL_H
#define TELNET_PROTOCOL_H

/*
 * Application-facing Telnet session API.
 *
 * Raw Telnet parsing, negotiation, login state, input limits, and terminal
 * capabilities stay behind this interface. Higher-level code shouldn't need to
 * know what an IAC byte is.
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
} telnet_session_config;

/* Negotiated terminal capabilities exposed to future application systems. */
typedef struct telnet_terminal_info {
    uint16_t width;
    uint16_t height;
    int local_binary;
    int remote_binary;
    int local_suppress_go_ahead;
    int remote_suppress_go_ahead;
    int utf8_enabled;
    char terminal_type[TELNET_TERMINAL_TYPE_MAX + 1];
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
 * Starts capability negotiation and writes the welcome banner.
 * The call is idempotent for a session.
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
 * Defaults are 80x24, terminal type UNKNOWN, and UTF-8 disabled.
 */
void telnet_session_get_terminal_info(
    const telnet_session *session,
    telnet_terminal_info *info
);

#ifdef __cplusplus
}
#endif

#endif
