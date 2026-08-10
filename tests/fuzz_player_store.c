// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

/*
 * Lightweight player-store stand-in used only by the libFuzzer target.
 *
 * The Telnet fuzzer is meant to spend its budget exploring byte framing,
 * option state, subnegotiation, NVT line handling, and session transitions.
 * Running real Argon2id work when random input happens to look like a new
 * account password makes that coverage crawl without teaching us anything
 * about the parser. Normal builds and deterministic tests still link the real
 * player_store.c and exercise the actual filesystem and password boundary.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "player_store.h"

struct player_store {
    unsigned int marker;
};

player_store *player_store_open(const char *directory_path)
{
    player_store *store;

    if (directory_path == NULL) {
        return NULL;
    }

    store = calloc(1, sizeof(*store));
    if (store != NULL) {
        store->marker = 0x46555a5aU; /* "FUZZ" */
    }
    return store;
}

void player_store_close(player_store *store)
{
    free(store);
}

int player_store_name_valid(const char *name)
{
    size_t length;
    size_t index;

    if (name == NULL) {
        return 0;
    }

    length = strlen(name);
    if (length < PLAYER_NAME_MIN || length > PLAYER_NAME_MAX) {
        return 0;
    }

    for (index = 0; index < length; ++index) {
        unsigned char ch = (unsigned char)name[index];
        int alpha = (ch >= (unsigned char)'A' && ch <= (unsigned char)'Z') ||
                    (ch >= (unsigned char)'a' && ch <= (unsigned char)'z');
        int digit = ch >= (unsigned char)'0' && ch <= (unsigned char)'9';

        if (!alpha && !digit && ch != (unsigned char)'_' &&
            ch != (unsigned char)'-') {
            return 0;
        }
    }

    return 1;
}

int player_store_password_allowed(
    const char *player_name,
    const char *password,
    size_t password_length
)
{
    if (player_name == NULL || password == NULL) {
        return -1;
    }

    return password_length >= PLAYER_PASSWORD_MIN &&
           password_length <= PLAYER_PASSWORD_MAX;
}

int player_store_exists(player_store *store, const char *name)
{
    if (store == NULL || name == NULL) {
        return -1;
    }

    /* Keep fuzz sessions deterministic and filesystem-free. */
    return 0;
}

int player_store_prepare_password(
    const char *password,
    size_t password_length,
    player_password_token *prepared
)
{
    if (password == NULL || prepared == NULL ||
        password_length < PLAYER_PASSWORD_MIN ||
        password_length > PLAYER_PASSWORD_MAX ||
        password_length + 2U > sizeof(prepared->bytes)) {
        return -1;
    }

    memset(prepared->bytes, 0, sizeof(prepared->bytes));
    prepared->bytes[0] = (unsigned char)(password_length & 0xffU);
    prepared->bytes[1] = (unsigned char)((password_length >> 8U) & 0xffU);
    memcpy(prepared->bytes + 2U, password, password_length);
    return 0;
}

int player_store_password_matches(
    const player_password_token *prepared,
    const char *password,
    size_t password_length
)
{
    size_t prepared_length;

    if (prepared == NULL || password == NULL) {
        return -1;
    }

    prepared_length = (size_t)prepared->bytes[0] |
                      ((size_t)prepared->bytes[1] << 8U);

    if (prepared_length != password_length ||
        prepared_length > PLAYER_PASSWORD_MAX ||
        prepared_length + 2U > sizeof(prepared->bytes)) {
        return 0;
    }

    return memcmp(prepared->bytes + 2U, password, password_length) == 0;
}

void player_store_password_clear(player_password_token *prepared)
{
    if (prepared != NULL) {
        volatile unsigned char *bytes = prepared->bytes;
        size_t index;

        for (index = 0; index < sizeof(prepared->bytes); ++index) {
            bytes[index] = 0;
        }
    }
}

int player_store_create(
    player_store *store,
    const char *name,
    const player_password_token *prepared
)
{
    if (store == NULL || name == NULL || prepared == NULL) {
        return -1;
    }

    return 0;
}

int player_store_verify_password(
    player_store *store,
    const char *name,
    const char *password,
    size_t password_length,
    int *rehashed
)
{
    (void)password_length;

    if (store == NULL || name == NULL || password == NULL) {
        return -1;
    }

    if (rehashed != NULL) {
        *rehashed = 0;
    }

    return 0;
}
