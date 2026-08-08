// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

#ifndef SECURE_SERVER_H
#define SECURE_SERVER_H

/*
 * TLS transport and connection lifecycle.
 *
 * The server binds to IPv4 loopback, accepts TLS 1.3 clients, applies connection
 * policy, gives each accepted session a worker, and feeds decrypted bytes into
 * the Telnet session API.
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
    uint16_t port;
} secure_server_config;

/*
 * Runs the blocking listener until SIGINT, SIGTERM, or a fatal listener error.
 *
 * Runtime safeguards include connection limits, handshake/login/idle/session
 * deadlines, bounded TLS writes, coordinated worker shutdown, and clean TLS
 * close notifications. An orderly stop returns 0.
 */
int secure_server_run(const secure_server_config *config);

#ifdef __cplusplus
}
#endif

#endif
