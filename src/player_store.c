// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

/*
 * player_store.c
 *
 * Implements persistent player credentials with private filesystem objects and
 * Argon2id verification strings. Record creation and hash upgrades publish a
 * complete synchronized file atomically. Player names are validated before any
 * path construction.
 */

#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700

#include "player_store.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <sodium.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif

/* Stable on-disk record format identifiers. */
#define PLAYER_FILE_SUFFIX ".player"
#define RECORD_VERSION "player-record-v1"

_Static_assert(
    PLAYER_PASSWORD_TOKEN_BYTES >= crypto_pwhash_STRBYTES,
    "Prepared password token is too small for libsodium."
);

/* Store paths are canonicalized once and reused for validated player names. */
struct player_store {
    char directory[PATH_MAX];
};

/* Parsed record held only long enough for verification or update work. */
struct loaded_record {
    char name[PLAYER_NAME_MAX + 1];
    char password_hash[crypto_pwhash_STRBYTES];
};

/*
 * This is a starter denylist, not a comprehensive password database.
 * It catches a few painfully obvious choices and gives the policy a clear
 * extension point if a breached-password source is added later.
 */
static const char *const blocked_passwords[] = {
    "password",
    "password1",
    "12345678",
    "qwerty123",
    "letmein123",
    "changeme"
};

static unsigned char ascii_lower(unsigned char ch)
{
    if (ch >= 'A' && ch <= 'Z') {
        return (unsigned char)(ch + ('a' - 'A'));
    }

    return ch;
}

static int ascii_equal_ignore_case(const char *left, const char *right)
{
    while (*left != '\0' && *right != '\0') {
        unsigned char a = ascii_lower((unsigned char)*left);
        unsigned char b = ascii_lower((unsigned char)*right);

        if (a != b) {
            return 0;
        }

        ++left;
        ++right;
    }

    return *left == '\0' && *right == '\0';
}

int player_store_name_valid(const char *name)
{
    size_t length;
    size_t i;

    if (name == NULL) {
        return 0;
    }

    length = strlen(name);

    if (length < PLAYER_NAME_MIN || length > PLAYER_NAME_MAX) {
        return 0;
    }

    for (i = 0; i < length; ++i) {
        unsigned char ch = (unsigned char)name[i];

        int letter =
            (ch >= 'A' && ch <= 'Z') ||
            (ch >= 'a' && ch <= 'z');
        int digit = ch >= '0' && ch <= '9';

        if (!letter && !digit && ch != '_' && ch != '-') {
            return 0;
        }
    }

    return 1;
}

static int password_is_repeated_character(
    const char *password,
    size_t length
)
{
    size_t i;

    if (length == 0) {
        return 0;
    }

    for (i = 1; i < length; ++i) {
        if (password[i] != password[0]) {
            return 0;
        }
    }

    return 1;
}

static int password_is_digit_sequence(
    const char *password,
    size_t length
)
{
    size_t i;
    int ascending = 1;
    int descending = 1;

    if (length < PLAYER_PASSWORD_MIN) {
        return 0;
    }

    for (i = 0; i < length; ++i) {
        if (password[i] < '0' || password[i] > '9') {
            return 0;
        }

        if (i > 0) {
            int previous = password[i - 1] - '0';
            int current = password[i] - '0';

            if (current != (previous + 1) % 10) {
                ascending = 0;
            }

            if (current != (previous + 9) % 10) {
                descending = 0;
            }
        }
    }

    return ascending || descending;
}

int player_store_password_allowed(
    const char *player_name,
    const char *password,
    size_t password_length
)
{
    char lowered[PLAYER_PASSWORD_MAX + 1];
    size_t i;

    if (player_name == NULL ||
        password == NULL ||
        password_length > PLAYER_PASSWORD_MAX) {
        return -1;
    }

    if (password_length < PLAYER_PASSWORD_MIN) {
        return 0;
    }

    for (i = 0; i < password_length; ++i) {
        lowered[i] = (char)ascii_lower((unsigned char)password[i]);
    }
    lowered[password_length] = '\0';

    if (ascii_equal_ignore_case(lowered, player_name) ||
        password_is_repeated_character(password, password_length) ||
        password_is_digit_sequence(password, password_length)) {
        sodium_memzero(lowered, sizeof(lowered));
        return 0;
    }

    for (i = 0;
         i < sizeof(blocked_passwords) / sizeof(blocked_passwords[0]);
         ++i) {
        if (strcmp(lowered, blocked_passwords[i]) == 0) {
            sodium_memzero(lowered, sizeof(lowered));
            return 0;
        }
    }

    sodium_memzero(lowered, sizeof(lowered));
    return 1;
}

static int ensure_private_directory(const char *path)
{
    char working[PATH_MAX];
    size_t length;
    size_t i;

    if (path == NULL || *path == '\0') {
        return -1;
    }

    length = strlen(path);
    if (length >= sizeof(working)) {
        return -1;
    }

    memcpy(working, path, length + 1);

    for (i = 1; i <= length; ++i) {
        struct stat info;
        char saved;

        if (working[i] != '/' && working[i] != '\0') {
            continue;
        }

        saved = working[i];
        working[i] = '\0';

        if (working[0] != '\0') {
            if (mkdir(working, 0700) != 0 && errno != EEXIST) {
                return -1;
            }

            if (lstat(working, &info) != 0 ||
                !S_ISDIR(info.st_mode) ||
                S_ISLNK(info.st_mode)) {
                return -1;
            }
        }

        working[i] = saved;
    }

    if (chmod(path, 0700) != 0) {
        return -1;
    }

    return 0;
}

static int build_player_path(
    const player_store *store,
    const char *name,
    char *path,
    size_t path_size
)
{
    char normalized[PLAYER_NAME_MAX + 1];
    size_t length;
    size_t i;
    int written;

    if (store == NULL ||
        !player_store_name_valid(name) ||
        path == NULL ||
        path_size == 0) {
        return -1;
    }

    length = strlen(name);

    for (i = 0; i < length; ++i) {
        normalized[i] = (char)ascii_lower((unsigned char)name[i]);
    }
    normalized[length] = '\0';

    written = snprintf(
        path,
        path_size,
        "%s/%s%s",
        store->directory,
        normalized,
        PLAYER_FILE_SUFFIX
    );

    if (written < 0 || (size_t)written >= path_size) {
        return -1;
    }

    return 0;
}

player_store *player_store_open(const char *directory_path)
{
    player_store *store;
    char resolved[PATH_MAX];

    if (directory_path == NULL || sodium_init() < 0) {
        return NULL;
    }

    if (ensure_private_directory(directory_path) != 0) {
        return NULL;
    }

    if (realpath(directory_path, resolved) == NULL) {
        return NULL;
    }

    store = calloc(1, sizeof(*store));
    if (store == NULL) {
        return NULL;
    }

    if (strlen(resolved) >= sizeof(store->directory)) {
        free(store);
        return NULL;
    }

    memcpy(store->directory, resolved, strlen(resolved) + 1);
    return store;
}

void player_store_close(player_store *store)
{
    if (store == NULL) {
        return;
    }

    sodium_memzero(store, sizeof(*store));
    free(store);
}

static void strip_line_ending(char *line)
{
    size_t length;

    if (line == NULL) {
        return;
    }

    length = strlen(line);

    while (length > 0 &&
           (line[length - 1] == '\n' ||
            line[length - 1] == '\r')) {
        line[--length] = '\0';
    }
}

static int load_record(
    player_store *store,
    const char *name,
    struct loaded_record *record
)
{
    char path[PATH_MAX];
    int fd;
    struct stat info;
    FILE *file = NULL;
    char version_line[64];
    char name_line[64];
    char hash_line[crypto_pwhash_STRBYTES + 16];
    int result = -1;

    if (record == NULL ||
        build_player_path(store, name, path, sizeof(path)) != 0) {
        return -1;
    }

    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return errno == ENOENT ? 1 : -1;
    }

    if (fstat(fd, &info) != 0 ||
        !S_ISREG(info.st_mode) ||
        info.st_uid != geteuid() ||
        (info.st_mode & 0077) != 0) {
        close(fd);
        return -1;
    }

    file = fdopen(fd, "r");
    if (file == NULL) {
        close(fd);
        return -1;
    }

    if (fgets(version_line, sizeof(version_line), file) == NULL ||
        fgets(name_line, sizeof(name_line), file) == NULL ||
        fgets(hash_line, sizeof(hash_line), file) == NULL) {
        goto cleanup;
    }

    strip_line_ending(version_line);
    strip_line_ending(name_line);
    strip_line_ending(hash_line);

    if (strcmp(version_line, RECORD_VERSION) != 0 ||
        strncmp(name_line, "name=", 5) != 0 ||
        strncmp(hash_line, "hash=", 5) != 0) {
        goto cleanup;
    }

    if (!player_store_name_valid(name_line + 5) ||
        !ascii_equal_ignore_case(name_line + 5, name)) {
        goto cleanup;
    }

    if (strlen(hash_line + 5) >= sizeof(record->password_hash)) {
        goto cleanup;
    }

    memcpy(
        record->name,
        name_line + 5,
        strlen(name_line + 5) + 1
    );

    memcpy(
        record->password_hash,
        hash_line + 5,
        strlen(hash_line + 5) + 1
    );

    result = 0;

cleanup:
    if (fclose(file) != 0 && result == 0) {
        result = -1;
    }

    if (result != 0) {
        sodium_memzero(record, sizeof(*record));
    }

    return result;
}

int player_store_exists(player_store *store, const char *name)
{
    struct loaded_record record;
    int result;

    memset(&record, 0, sizeof(record));
    result = load_record(store, name, &record);

    if (result == 0) {
        sodium_memzero(&record, sizeof(record));
        return 1;
    }

    return result == 1 ? 0 : -1;
}

int player_store_prepare_password(
    const char *password,
    size_t password_length,
    player_password_token *prepared
)
{
    char *hash;

    if (password == NULL ||
        prepared == NULL ||
        password_length < PLAYER_PASSWORD_MIN ||
        password_length > PLAYER_PASSWORD_MAX) {
        return -1;
    }

    sodium_memzero(prepared, sizeof(*prepared));
    hash = (char *)prepared->bytes;

    if (crypto_pwhash_str_alg(
            hash,
            password,
            (unsigned long long)password_length,
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_ARGON2ID13
        ) != 0) {
        sodium_memzero(prepared, sizeof(*prepared));
        return -1;
    }

    return 0;
}

int player_store_password_matches(
    const player_password_token *prepared,
    const char *password,
    size_t password_length
)
{
    const char *hash;

    if (prepared == NULL ||
        password == NULL ||
        password_length > PLAYER_PASSWORD_MAX) {
        return -1;
    }

    hash = (const char *)prepared->bytes;

    if (hash[0] == '\0' ||
        memchr(
            hash,
            '\0',
            PLAYER_PASSWORD_TOKEN_BYTES
        ) == NULL) {
        return -1;
    }

    return crypto_pwhash_str_verify(
        hash,
        password,
        (unsigned long long)password_length
    ) == 0 ? 1 : 0;
}

void player_store_password_clear(player_password_token *prepared)
{
    if (prepared != NULL) {
        sodium_memzero(prepared, sizeof(*prepared));
    }
}

static int write_all(int fd, const char *data, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        ssize_t written = write(fd, data + offset, length - offset);

        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }

        if (written == 0) {
            return -1;
        }

        offset += (size_t)written;
    }

    return 0;
}

static int build_record_text(
    char *record_text,
    size_t record_size,
    const char *name,
    const char *hash
)
{
    int length = snprintf(
        record_text,
        record_size,
        "%s\nname=%s\nhash=%s\n",
        RECORD_VERSION,
        name,
        hash
    );

    if (length < 0 || (size_t)length >= record_size) {
        return -1;
    }

    return length;
}

static int sync_directory(const player_store *store)
{
    int directory_fd = open(
        store->directory,
        O_RDONLY | O_CLOEXEC | O_DIRECTORY
    );
    int result;

    if (directory_fd < 0) {
        return -1;
    }

    result = fsync(directory_fd);
    close(directory_fd);

    return result == 0 ? 0 : -1;
}

static int write_new_record_atomic(
    player_store *store,
    const char *name,
    const char *hash
)
{
    char final_path[PATH_MAX];
    char temp_path[PATH_MAX];
    char record_text[512];
    int record_length;
    int fd = -1;
    int linked = 0;
    int result = -1;

    if (build_player_path(
            store,
            name,
            final_path,
            sizeof(final_path)
        ) != 0) {
        return -1;
    }

    if (snprintf(
            temp_path,
            sizeof(temp_path),
            "%s/.player-write-XXXXXX",
            store->directory
        ) >= (int)sizeof(temp_path)) {
        return -1;
    }

    record_length = build_record_text(
        record_text,
        sizeof(record_text),
        name,
        hash
    );

    if (record_length < 0) {
        return -1;
    }

    fd = mkstemp(temp_path);
    if (fd < 0) {
        sodium_memzero(record_text, sizeof(record_text));
        return -1;
    }

    if (fchmod(fd, 0600) != 0 ||
        write_all(fd, record_text, (size_t)record_length) != 0 ||
        fsync(fd) != 0) {
        goto cleanup;
    }

    if (close(fd) != 0) {
        fd = -1;
        goto cleanup;
    }
    fd = -1;

    if (link(temp_path, final_path) != 0) {
        if (errno == EEXIST) {
            result = 1;
        }
        goto cleanup;
    }
    linked = 1;

    if (sync_directory(store) != 0) {
        goto cleanup;
    }

    result = 0;

cleanup:
    sodium_memzero(record_text, sizeof(record_text));

    if (fd >= 0) {
        close(fd);
    }

    if (result != 0 && linked) {
        (void)unlink(final_path);
    }

    (void)unlink(temp_path);
    return result;
}

static int replace_record_atomic(
    player_store *store,
    const char *name,
    const char *hash
)
{
    char final_path[PATH_MAX];
    char temp_path[PATH_MAX];
    char record_text[512];
    int record_length;
    int fd = -1;
    int result = -1;

    if (build_player_path(
            store,
            name,
            final_path,
            sizeof(final_path)
        ) != 0) {
        return -1;
    }

    if (snprintf(
            temp_path,
            sizeof(temp_path),
            "%s/.player-rehash-XXXXXX",
            store->directory
        ) >= (int)sizeof(temp_path)) {
        return -1;
    }

    record_length = build_record_text(
        record_text,
        sizeof(record_text),
        name,
        hash
    );

    if (record_length < 0) {
        return -1;
    }

    fd = mkstemp(temp_path);
    if (fd < 0) {
        sodium_memzero(record_text, sizeof(record_text));
        return -1;
    }

    if (fchmod(fd, 0600) != 0 ||
        write_all(fd, record_text, (size_t)record_length) != 0 ||
        fsync(fd) != 0) {
        goto cleanup;
    }

    if (close(fd) != 0) {
        fd = -1;
        goto cleanup;
    }
    fd = -1;

    /*
     * The directory is private and the existing record was validated before
     * reaching this path. rename() publishes the complete replacement
     * atomically so readers see either the old valid hash or the new one.
     */
    if (rename(temp_path, final_path) != 0) {
        goto cleanup;
    }

    if (sync_directory(store) != 0) {
        goto cleanup;
    }

    result = 0;

cleanup:
    sodium_memzero(record_text, sizeof(record_text));

    if (fd >= 0) {
        close(fd);
    }

    (void)unlink(temp_path);
    return result;
}

int player_store_create(
    player_store *store,
    const char *name,
    const player_password_token *prepared
)
{
    const char *hash;

    if (store == NULL ||
        !player_store_name_valid(name) ||
        prepared == NULL) {
        return -1;
    }

    hash = (const char *)prepared->bytes;

    if (hash[0] == '\0' ||
        memchr(
            hash,
            '\0',
            PLAYER_PASSWORD_TOKEN_BYTES
        ) == NULL ||
        strlen(hash) >= crypto_pwhash_STRBYTES) {
        return -1;
    }

    return write_new_record_atomic(store, name, hash);
}

int player_store_verify_password(
    player_store *store,
    const char *name,
    const char *password,
    size_t password_length,
    int *rehashed
)
{
    struct loaded_record record;
    int loaded;
    int verified;

    if (rehashed != NULL) {
        *rehashed = 0;
    }

    if (store == NULL ||
        password == NULL ||
        password_length > PLAYER_PASSWORD_MAX) {
        return -1;
    }

    memset(&record, 0, sizeof(record));

    loaded = load_record(store, name, &record);
    if (loaded != 0) {
        sodium_memzero(&record, sizeof(record));
        return -1;
    }

    verified = crypto_pwhash_str_verify(
        record.password_hash,
        password,
        (unsigned long long)password_length
    ) == 0;

    if (verified &&
        crypto_pwhash_str_needs_rehash(
            record.password_hash,
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE
        ) == 1) {
        char updated_hash[crypto_pwhash_STRBYTES];

        memset(updated_hash, 0, sizeof(updated_hash));

        if (crypto_pwhash_str_alg(
                updated_hash,
                password,
                (unsigned long long)password_length,
                crypto_pwhash_OPSLIMIT_INTERACTIVE,
                crypto_pwhash_MEMLIMIT_INTERACTIVE,
                crypto_pwhash_ALG_ARGON2ID13
            ) == 0 &&
            replace_record_atomic(
                store,
                record.name,
                updated_hash
            ) == 0) {
            if (rehashed != NULL) {
                *rehashed = 1;
            }
        }

        sodium_memzero(
            updated_hash,
            sizeof(updated_hash)
        );
    }

    sodium_memzero(&record, sizeof(record));
    return verified ? 1 : 0;
}
