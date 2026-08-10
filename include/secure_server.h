// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

#ifndef SECURE_SERVER_H
#define SECURE_SERVER_H

/*
 * Listener and connection-lifecycle owner for the reference server.
 *
 * This is where sockets, TLS setup, SSH handoff, worker slots, and transport
 * deadlines live. Telnet framing belongs to telnet_protocol; SSH packet and
 * channel mechanics belong to libssh through ssh_transport.c. Once either side
 * has an authenticated terminal session, both meet at terminal_application.
 *
 * The three development endpoint types are separate on purpose. Plain Telnet
 * keeps the traditional compatibility path, TLS makes the protected Telnet
 * endpoint explicit, and SSH is a sibling terminal transport rather than
 * Telnet hidden inside an SSH channel. The harness opens matching IPv4 and,
 * when available, IPv6 loopback sockets for each endpoint.
 */

#include <stdint.h>

#include "telnet_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct secure_server_config {
    const char *certificate_path;
    const char *private_key_path;
    const char *ssh_host_key_path;
    const char *player_directory_path;
    const char *audit_log_path;

    /* Optional owner called after Telnet or SSH has authenticated an account. */
    const terminal_application_hooks *application;

    /* Optional generic MSSP snapshot source for Telnet clients. */
    telnet_mssp_query_fn mssp_query;
    void *mssp_context;

    uint16_t telnet_port;
    uint16_t telnet_tls_port;

    /* Set to zero to disable SSH. The standalone harness enables it on 3335. */
    uint16_t ssh_port;
} secure_server_config;

/*
 * Runs the configured blocking listeners until SIGINT, SIGTERM, or a fatal
 * listener error. The accept loop polls only listener sockets; accepted clients
 * run in bounded detached workers so a stalled terminal does not stall accept().
 * Shared connection/authentication policy spans every enabled transport.
 */
int secure_server_run(const secure_server_config *config);

#ifdef __cplusplus
}
#endif

#endif
