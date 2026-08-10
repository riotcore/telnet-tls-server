// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

/*
 * mud-terminal-core
 * C17 networking and terminal-protocol foundation for MUD servers.
 *
 * Original project and implementation by Riot / riotcore.
 * https://github.com/riotcore/mud-terminal-core
 *
 * This code is meant to be shared, modified, and folded into other MUDs.
 * Use what is useful, change what you need, and pass it along. Please keep
 * the original project credit and MIT license notice intact when redistributing
 * substantial portions of the code.
 *
 * This code is meant to be shared, modified, and folded into other MUDs.
 * Use what is useful, change what you need, and pass it along. Please keep
 * the original project credit and MIT license notice intact when redistributing
 * substantial portions of the code.
 */

/*
 * Runnable example configuration. It supplies localhost ports, development
 * credential paths, a small MSSP snapshot, and the harness application.
 * A MUD can keep mud_terminal_core and replace this file with its own startup
 * and configuration code.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "harness_application.h"
#include "secure_server.h"

struct harness_status {
    uint64_t started_at;
    uint16_t telnet_port;
    uint16_t telnet_tls_port;
};

static void mssp_snapshot(void *context, telnet_mssp_status *status)
{
    const struct harness_status *harness = context;

    if (status == NULL || harness == NULL) {
        return;
    }

    (void)snprintf(
        status->name,
        sizeof(status->name),
        "%s",
        "mud-terminal-core reference"
    );
    status->players = 0;
    status->uptime = harness->started_at;
    status->telnet_port = harness->telnet_port;
    status->telnet_tls_port = harness->telnet_tls_port;
    (void)snprintf(
        status->codebase,
        sizeof(status->codebase),
        "%s",
        "mud-terminal-core"
    );
}

int main(int argc, char **argv)
{
    struct harness_status status = {
        .started_at = (uint64_t)time(NULL),
        .telnet_port = 3333,
        .telnet_tls_port = 3334
    };
    secure_server_config config = {
        .certificate_path = "local_tls/server.crt",
        .private_key_path = "local_tls/server.key",
        .ssh_host_key_path = "local_ssh/ssh_host_ed25519_key",
        .player_directory_path = "data/players",
        .audit_log_path = "logs/security.log",
        .application = NULL,
        .mssp_query = mssp_snapshot,
        .mssp_context = &status,
        .telnet_port = 3333,
        .telnet_tls_port = 3334,
        .ssh_port = 3335
    };

    config.application = harness_application_hooks();

    /*
     * Existing local workflows can still replace just the TLS paths. A third
     * argument optionally replaces the SSH host-key path as well.
     */
    if (argc == 3 || argc == 4) {
        config.certificate_path = argv[1];
        config.private_key_path = argv[2];
        if (argc == 4) {
            config.ssh_host_key_path = argv[3];
        }
    } else if (argc != 1) {
        fprintf(
            stderr,
            "usage: %s [certificate private-key [ssh-host-key]]\n",
            argv[0]
        );
        return EXIT_FAILURE;
    }

    return secure_server_run(&config) == 0
        ? EXIT_SUCCESS
        : EXIT_FAILURE;
}
