// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

#define _POSIX_C_SOURCE 200809L

/*
 * security_test.c
 *
 * Exercises the shared connection/authentication policy, audit logger, and
 * terminal-text sanitizers. These are small boundaries with a lot of security
 * responsibility, so the checks stay direct and always-on.
 */

#include <stdint.h>
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

#include "audit_log.h"
#include "security_policy.h"
#include "terminal_text.h"

static void test_security_policy(void)
{
    security_policy *policy;
    uint64_t retry = 0;
    int i;

    policy = security_policy_create();
    CHECK(policy != NULL);

    /* Five peer connection starts are permitted inside the active window. */
    for (i = 0; i < 5; ++i) {
        CHECK(security_policy_allow_connection(
            policy,
            "127.0.0.1",
            1000U + (uint64_t)i,
            &retry
        ) == 1);
    }

    /* The next start is delayed until the rolling window releases capacity. */
    CHECK(security_policy_allow_connection(
        policy,
        "127.0.0.1",
        1006,
        &retry
    ) == 0);
    CHECK(retry > 0);

    CHECK(security_policy_allow_connection(
        policy,
        "127.0.0.1",
        12000,
        &retry
    ) == 1);

    /* Long peer identifiers keep one stable limiter key after truncation. */
    {
        const char *long_peer =
            "peer-address-that-is-deliberately-longer-than-the-policy-key-buffer-"
            "and-keeps-going-for-a-while";

        for (i = 0; i < 5; ++i) {
            CHECK(security_policy_allow_connection(
                policy,
                long_peer,
                13000U + (uint64_t)i,
                &retry
            ) == 1);
        }

        CHECK(security_policy_allow_connection(
            policy,
            long_peer,
            13006,
            &retry
        ) == 0);
    }

    /* Three failed passwords activate temporary authentication backoff. */
    security_policy_note_auth_failure(policy, "127.0.0.1", "TestUser", 20000);
    security_policy_note_auth_failure(policy, "127.0.0.1", "TestUser", 20001);
    security_policy_note_auth_failure(policy, "127.0.0.1", "TestUser", 20002);

    CHECK(security_policy_allow_auth_attempt(
        policy,
        "127.0.0.1",
        "TestUser",
        20003,
        &retry
    ) == 0);
    CHECK(retry > 0);

    CHECK(security_policy_allow_auth_attempt(
        policy,
        "127.0.0.1",
        "TestUser",
        22000,
        &retry
    ) == 1);

    security_policy_note_auth_success(
        policy,
        "127.0.0.1",
        "TestUser",
        22000
    );

    CHECK(security_policy_allow_auth_attempt(
        policy,
        "127.0.0.1",
        "TestUser",
        22001,
        &retry
    ) == 1);

    /* Account creation has an independent peer limit. */
    for (i = 0; i < 10; ++i) {
        CHECK(security_policy_allow_account_creation(
            policy,
            "127.0.0.2",
            30000U + (uint64_t)i,
            &retry
        ) == 1);
    }

    CHECK(security_policy_allow_account_creation(
        policy,
        "127.0.0.2",
        30020,
        &retry
    ) == 0);

    security_policy_destroy(policy);
}

static void test_audit_log(void)
{
    char root[] = "/tmp/audit-log-test-XXXXXX";
    char log_directory[256];
    char log_path[320];
    char contents[1024];
    struct stat info;
    audit_log *log;
    FILE *file;
    size_t length;
    int written;

    CHECK(mkdtemp(root) != NULL);

    written = snprintf(
        log_directory,
        sizeof(log_directory),
        "%s/logs",
        root
    );
    CHECK(written >= 0);
    CHECK((size_t)written < sizeof(log_directory));

    written = snprintf(
        log_path,
        sizeof(log_path),
        "%s/security.log",
        log_directory
    );
    CHECK(written >= 0);
    CHECK((size_t)written < sizeof(log_path));

    log = audit_log_open(log_path);
    CHECK(log != NULL);

    /* Newlines and control bytes can't manufacture extra audit records. */
    audit_log_event(
        log,
        "login\nforged",
        "peer\rname",
        "detail\nwith\tcontrols"
    );
    audit_log_close(log);

    CHECK(stat(log_directory, &info) == 0);
    CHECK((info.st_mode & 0777) == 0700);
    CHECK(stat(log_path, &info) == 0);
    CHECK((info.st_mode & 0777) == 0600);

    file = fopen(log_path, "rb");
    CHECK(file != NULL);
    length = fread(contents, 1, sizeof(contents) - 1, file);
    CHECK(ferror(file) == 0);
    CHECK(fclose(file) == 0);
    contents[length] = '\0';

    CHECK(strstr(contents, "event=login_forged") != NULL);
    CHECK(strstr(contents, "peer=peer_name") != NULL);
    CHECK(strstr(contents, "detail=detail_with_controls") != NULL);

    {
        size_t i;
        size_t newlines = 0;

        for (i = 0; i < length; ++i) {
            if (contents[i] == '\n') {
                ++newlines;
            }
        }

        CHECK(newlines == 1);
    }

    CHECK(unlink(log_path) == 0);
    CHECK(rmdir(log_directory) == 0);
    CHECK(rmdir(root) == 0);
}

static void test_terminal_text(void)
{
    const unsigned char hostile[] = {
        'H', 'i', ' ',
        27, '[', '3', '1', 'm',
        'X',
        255,
        '\n',
        7,
        '\0'
    };
    const unsigned char utf8_good[] = {
        'C', 'a', 'f', 0xc3, 0xa9
    };
    const unsigned char utf8_bad[] = {
        0xc0, 0xaf
    };
    const unsigned char bidi_override[] = {
        'A', 0xe2, 0x80, 0xae, 'B'
    };
    char output[128];

    /* Terminal control bytes are replaced before untrusted text is rendered. */
    terminal_text_sanitize(
        hostile,
        sizeof(hostile) - 1,
        output,
        sizeof(output)
    );

    CHECK(strstr(output, "Hi ?[31mX?") != NULL);
    CHECK(strchr(output, 27) == NULL);
    CHECK(strchr(output, 7) == NULL);

    CHECK(terminal_text_utf8_valid(utf8_good, sizeof(utf8_good)));
    CHECK(!terminal_text_utf8_valid(utf8_bad, sizeof(utf8_bad)));

    terminal_text_sanitize_utf8(
        utf8_good,
        sizeof(utf8_good),
        output,
        sizeof(output)
    );
    CHECK(memcmp(output, utf8_good, sizeof(utf8_good)) == 0);

    /* Bidi override controls are replaced to reduce terminal spoofing risk. */
    terminal_text_sanitize_utf8(
        bidi_override,
        sizeof(bidi_override),
        output,
        sizeof(output)
    );
    CHECK(strcmp(output, "A?B") == 0);
}

int main(void)
{
    test_security_policy();
    test_audit_log();
    test_terminal_text();

    puts("security test passed");
    return 0;
}
