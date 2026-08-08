// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

/*
 * player_store_test.c
 *
 * Verifies account-name rules, password policy, private permissions, atomic
 * account creation, persistent reopen, password verification, and case-folded
 * identity behavior.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>


#define CHECK(expression) \
    do { \
        if (!(expression)) { \
            fprintf( \
                stderr, \
                "%s:%d: check failed: %s\n", \
                __FILE__, \
                __LINE__, \
                #expression \
            ); \
            exit(EXIT_FAILURE); \
        } \
    } while (0)

#include "player_store.h"

static void build_path(
    char *destination,
    size_t destination_size,
    const char *directory,
    const char *leaf
)
{
    int written = snprintf(
        destination,
        destination_size,
        "%s/%s",
        directory,
        leaf
    );

    CHECK(written >= 0);
    CHECK((size_t)written < destination_size);
}

int main(void)
{
    char temporary_root[] = "/tmp/player-store-test-XXXXXX";
    char player_directory[512];
    char player_file[512];
    struct stat info;
    player_password_token prepared;
    player_store *store;
    int rehashed = 0;

    CHECK(mkdtemp(temporary_root) != NULL);

    build_path(
        player_directory,
        sizeof(player_directory),
        temporary_root,
        "players"
    );

    store = player_store_open(player_directory);
    CHECK(store != NULL);

    /* Identifier validation runs before path construction. */
    CHECK(player_store_name_valid("TestUser"));
    CHECK(player_store_name_valid("abc"));

    CHECK(player_store_name_valid("123456789012345"));
    CHECK(PLAYER_NAME_MAX == 15);
    CHECK(!player_store_name_valid("1234567890123456"));
    CHECK(!player_store_name_valid("ab"));
    CHECK(!player_store_name_valid("../bad"));

    /* Password policy accepts a reasonable test password. */
    CHECK(player_store_password_allowed(
        "TestUser",
        "Example!42",
        strlen("Example!42")
    ) == 1);

    CHECK(player_store_password_allowed(
        "TestUser",
        "12345678",
        strlen("12345678")
    ) == 0);

    CHECK(player_store_password_allowed(
        "TestUser",
        "password1",
        strlen("password1")
    ) == 0);

    CHECK(player_store_password_allowed(
        "TestUser",
        "TestUser",
        strlen("TestUser")
    ) == 0);

    CHECK(player_store_password_allowed(
        "TestUser",
        "short7",
        strlen("short7")
    ) == 0);

    /* Preparation creates a one-way verifier used for account creation. */
    CHECK(player_store_prepare_password(
        "Example!42",
        strlen("Example!42"),
        &prepared
    ) == 0);

    CHECK(player_store_prepare_password(
        "short7",
        strlen("short7"),
        &prepared
    ) == -1);

    CHECK(player_store_prepare_password(
        "Example!42",
        strlen("Example!42"),
        &prepared
    ) == 0);

    /* Account creation publishes one private record and rejects duplicates. */
    CHECK(player_store_create(
        store,
        "TestUser",
        &prepared
    ) == 0);

    CHECK(player_store_create(
        store,
        "testuser",
        &prepared
    ) == 1);

    player_store_password_clear(&prepared);
    player_store_close(store);

    /* Reopen from disk to exercise persistence and verification. */
    store = player_store_open(player_directory);
    CHECK(store != NULL);

    CHECK(player_store_exists(store, "TESTUSER") == 1);

    CHECK(player_store_verify_password(
        store,
        "TestUser",
        "Example!42",
        strlen("Example!42"),
        &rehashed
    ) == 1);

    CHECK(player_store_verify_password(
        store,
        "TestUser",
        "Wrong!42",
        strlen("Wrong!42"),
        NULL
    ) == 0);

    build_path(
        player_file,
        sizeof(player_file),
        player_directory,
        "testuser.player"
    );

    CHECK(stat(player_directory, &info) == 0);
    CHECK((info.st_mode & 0777) == 0700);

    CHECK(stat(player_file, &info) == 0);
    CHECK((info.st_mode & 0777) == 0600);

    player_store_close(store);

    CHECK(unlink(player_file) == 0);
    CHECK(rmdir(player_directory) == 0);
    CHECK(rmdir(temporary_root) == 0);

    puts("player store test passed");
    return 0;
}
