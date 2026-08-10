// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

/*
 * telnet_fuzz.c
 *
 * Coverage-guided parser harness for Clang libFuzzer. Every generated input gets
 * a fresh Telnet session and fresh abuse-control state. A private temporary
 * player store lasts for the fuzz process. Protocol output is discarded so
 * fuzzing can focus on parser and session-state behavior.
 */

#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "player_store.h"
#include "security_policy.h"
#include "telnet_protocol.h"

static player_store *store;
static char fuzz_directory[256];

static void discard_write(
    void *context,
    const unsigned char *data,
    size_t length
)
{
    (void)context;
    (void)data;
    (void)length;
}

static void cleanup_fuzz_store(void)
{
    DIR *directory;
    struct dirent *entry;

    if (store != NULL) {
        player_store_close(store);
        store = NULL;
    }

    if (fuzz_directory[0] == '\0') {
        return;
    }

    directory = opendir(fuzz_directory);
    if (directory != NULL) {
        while ((entry = readdir(directory)) != NULL) {
            char path[512];
            int written;

            if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0) {
                continue;
            }

            written = snprintf(
                path,
                sizeof(path),
                "%s/%s",
                fuzz_directory,
                entry->d_name
            );

            if (written >= 0 && (size_t)written < sizeof(path)) {
                (void)unlink(path);
            }
        }

        closedir(directory);
    }

    (void)rmdir(fuzz_directory);
    fuzz_directory[0] = '\0';
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    const char template_text[] = "/tmp/telnet-fuzz-store-XXXXXX";

    (void)argc;
    (void)argv;

    memcpy(fuzz_directory, template_text, sizeof(template_text));

    if (mkdtemp(fuzz_directory) == NULL) {
        fuzz_directory[0] = '\0';
        return -1;
    }

    store = player_store_open(fuzz_directory);
    if (store == NULL) {
        cleanup_fuzz_store();
        return -1;
    }

    if (atexit(cleanup_fuzz_store) != 0) {
        cleanup_fuzz_store();
        return -1;
    }

    return 0;
}

int LLVMFuzzerTestOneInput(
    const uint8_t *data,
    size_t size
)
{
    telnet_session_config config;
    security_policy *input_security;
    telnet_session *session;

    if (store == NULL) {
        return 0;
    }

    input_security = security_policy_create();
    if (input_security == NULL) {
        return 0;
    }

    config.store = store;
    config.security = input_security;
    config.audit = NULL;
    config.remote_id = "libfuzzer";
    config.writer = discard_write;
    config.writer_context = NULL;

    session = telnet_session_create(&config);
    if (session != NULL) {
        telnet_session_start(session);
        (void)telnet_session_feed_at(
            session,
            data,
            size,
            1000
        );
        telnet_session_destroy(session);
    }

    security_policy_destroy(input_security);
    return 0;
}
