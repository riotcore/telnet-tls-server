// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

#ifndef PLAYER_STORE_H
#define PLAYER_STORE_H

/*
 * Persistent player credentials.
 *
 * Name rules, password policy, Argon2id verifiers, private account files, atomic
 * writes, and hash upgrades live here. The Telnet layer doesn't need to know the
 * record format.
 */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLAYER_NAME_MIN 3
#define PLAYER_NAME_MAX 24
#define PLAYER_PASSWORD_MIN 8
#define PLAYER_PASSWORD_MAX 128
#define PLAYER_PASSWORD_TOKEN_BYTES 256

/* Temporary one-way password verifier used during account confirmation. */
typedef struct player_password_token {
    unsigned char bytes[PLAYER_PASSWORD_TOKEN_BYTES];
} player_password_token;

typedef struct player_store player_store;

/*
 * Opens or creates the private player directory.
 *
 * The directory is held at mode 0700. Player records are held at mode 0600.
 * Returns NULL when the directory cannot be prepared safely.
 */
player_store *player_store_open(const char *directory_path);

/* Releases store resources. NULL is accepted. */
void player_store_close(player_store *store);

/*
 * Validates a player identifier.
 *
 * Accepted form: 3-24 ASCII letters, digits, '_' or '-'.
 * This check runs before a name is used to construct a filesystem path.
 */
int player_store_name_valid(const char *name);

/*
 * Applies the local password-quality rules.
 *
 * Returns 1 for an accepted password, 0 for a blocked password, and -1 for
 * invalid arguments. Password length is checked here and during preparation.
 */
int player_store_password_allowed(
    const char *player_name,
    const char *password,
    size_t password_length
);

/* Returns 1 when a valid record exists, 0 when absent, and -1 on record error. */
int player_store_exists(player_store *store, const char *name);

/*
 * Builds an Argon2id verification string for a new password.
 *
 * The prepared token can survive the confirmation prompt without retaining
 * the original plaintext password. Call player_store_password_clear() after
 * the token is no longer needed.
 */
int player_store_prepare_password(
    const char *password,
    size_t password_length,
    player_password_token *prepared
);

/* Returns 1 for a match, 0 for a mismatch, and -1 for invalid arguments. */
int player_store_password_matches(
    const player_password_token *prepared,
    const char *password,
    size_t password_length
);

/* Securely erases a prepared token. NULL is accepted. */
void player_store_password_clear(player_password_token *prepared);

/*
 * Atomically creates a player record from a prepared verifier.
 *
 * Returns 0 on success, 1 when the player already exists, and -1 on error.
 * Existing records are never replaced by account creation.
 */
int player_store_create(
    player_store *store,
    const char *name,
    const player_password_token *prepared
);

/*
 * Verifies a stored password and upgrades old Argon2id work parameters after a
 * successful login when an upgrade is required.
 *
 * Returns 1 for a valid password, 0 for a mismatch, and -1 for record errors.
 * rehashed may be NULL. A non-NULL value receives 1 after a completed upgrade.
 */
int player_store_verify_password(
    player_store *store,
    const char *name,
    const char *password,
    size_t password_length,
    int *rehashed
);

#ifdef __cplusplus
}
#endif

#endif
