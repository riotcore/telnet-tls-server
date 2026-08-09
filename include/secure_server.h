// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

#ifndef SECURE_SERVER_H
#define SECURE_SERVER_H

/*
 * Network transport and connection lifecycle for the C MUD boundary.
 *
 * This layer owns bind/listen/accept, TLS setup, worker lifetime, transport
 * deadlines, and shared connection admission. It deliberately does not own
 * Telnet framing or game commands: accepted byte streams are handed to the
 * Telnet session API in telnet_protocol.h.
 *
 * Plain TCP exists because traditional MUD clients and basic Telnet remain a
 * compatibility target. TLS 1.3 is the preferred protected transport. Keeping
 * them as separate listeners avoids protocol sniffing and makes the security
 * properties of each endpoint explicit. A future SSH listener belongs beside
 * these transports and should feed the same higher-level account/game session,
 * not tunnel through this Telnet path.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct secure_server_config {
    const char *certificate_path;
    const char *private_key_path;
    const char *player_directory_path;
    const char *audit_log_path;

    /* Plain Telnet is the compatibility endpoint; TLS Telnet is preferred. */
    uint16_t telnet_port;
    uint16_t telnet_tls_port;
} secure_server_config;

/*
 * Runs both blocking listeners until SIGINT, SIGTERM, or a fatal listener
 * error. Runtime safeguards are shared across transports so opening a second
 * port does not double connection or authentication limits.
 */
int secure_server_run(const secure_server_config *config);

#ifdef __cplusplus
}
#endif

#endif
