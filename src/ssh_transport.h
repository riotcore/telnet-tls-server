// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

#ifndef SSH_TRANSPORT_H
#define SSH_TRANSPORT_H

#include "audit_log.h"
#include "player_store.h"
#include "security_policy.h"
#include "terminal_application.h"

/*
 * Internal SSH adapter used by secure_server.c.
 *
 * secure_server owns the TCP listener and worker slot. Once it has accepted a
 * socket, this adapter lets libssh own the SSH protocol and turns the resulting
 * authenticated terminal channel into terminal_application callbacks.
 */
typedef struct ssh_transport_connection_config {
    int client_fd;
    const char *peer;
    const char *host_key_path;
    player_store *store;
    security_policy *security;
    audit_log *audit;
    const terminal_application_hooks *application;
} ssh_transport_connection_config;

/* Refuse symlinked, foreign-owned, or group/world-readable host keys. */
int ssh_transport_validate_host_key(const char *path);

/* libssh global setup/teardown for the lifetime of secure_server_run(). */
int ssh_transport_global_init(void);
void ssh_transport_global_cleanup(void);

/* Takes ownership of client_fd for the duration of the SSH session. */
int ssh_transport_run_connection(
    const ssh_transport_connection_config *config
);

#endif
