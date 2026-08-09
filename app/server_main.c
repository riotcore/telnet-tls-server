// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

/*
 * server_main.c
 *
 * Local executable harness, not the intended MUD architecture. The reusable
 * connection code lives in telnetcore; this file only supplies development
 * paths/ports and starts it. An integrating C MUD would normally replace this
 * entry point with its own configuration, process lifecycle, and game startup.
 * Plain Telnet and TLS Telnet still reach the same account/session path.
 */

#include <stdlib.h>

#include "secure_server.h"

int main(int argc, char **argv)
{
    /* Default paths are resolved from the repository root at launch. */
    secure_server_config config = {
        .certificate_path = "local_tls/server.crt",
        .private_key_path = "local_tls/server.key",
        .player_directory_path = "data/players",
        .audit_log_path = "logs/security.log",
        .telnet_port = 3333,
        .telnet_tls_port = 3334
    };

    /* Optional paths make local certificate swaps painless. */
    if (argc == 3) {
        config.certificate_path = argv[1];
        config.private_key_path = argv[2];
    } else if (argc != 1) {
        return EXIT_FAILURE;
    }

    return secure_server_run(&config) == 0
        ? EXIT_SUCCESS
        : EXIT_FAILURE;
}
