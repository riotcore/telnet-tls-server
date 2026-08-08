// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

/*
 * server_main.c
 *
 * Tiny executable entry point. The library owns the server behavior; this file
 * only supplies paths, the development port, and process exit status.
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
        .port = 3333
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
