// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

/*
 * security_policy.c
 *
 * Implements shared abuse-control state for connections, authentication, and
 * account creation. Fixed-size peer/account tables bound memory use. Rolling
 * event windows and temporary backoff use monotonic timestamps supplied by the
 * caller. A mutex protects all shared records.
 */

#include "security_policy.h"

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Fixed capacities bound policy memory independently of connection volume. */
#define MAX_PEER_RECORDS 128
#define MAX_ACCOUNT_RECORDS 256
#define PEER_KEY_BYTES 96
#define ACCOUNT_KEY_BYTES 32

/* Connection-start windows protect TLS setup and worker allocation. */
#define PEER_CONNECTION_LIMIT 5
#define PEER_CONNECTION_WINDOW_MS 10000ULL
#define GLOBAL_CONNECTION_LIMIT 30
#define GLOBAL_CONNECTION_WINDOW_MS 10000ULL

/* Three bad passwords pause an account for five minutes. */
#define ACCOUNT_AUTH_FAILURE_LIMIT 3U
#define ACCOUNT_AUTH_LOCK_MS 300000ULL

/* Account-creation windows protect password hashing and filesystem work. */
#define PEER_CREATION_LIMIT 10
#define PEER_CREATION_WINDOW_MS 600000ULL
#define GLOBAL_CREATION_LIMIT 50
#define GLOBAL_CREATION_WINDOW_MS 600000ULL

/* Sliding timestamps for one bounded rolling event window. */
struct event_window {
    uint64_t times[64];
    size_t count;
};

struct peer_record {
    char key[PEER_KEY_BYTES];
    uint64_t last_seen_ms;
    struct event_window connections;
    struct event_window creations;
    unsigned int auth_failures;
    uint64_t auth_blocked_until_ms;
};

struct account_record {
    char key[ACCOUNT_KEY_BYTES];
    uint64_t last_seen_ms;
    unsigned int auth_failures;
    uint64_t auth_blocked_until_ms;
};

/* Shared process-wide policy state. Every access is mutex protected. */
struct security_policy {
    pthread_mutex_t mutex;
    struct peer_record peers[MAX_PEER_RECORDS];
    struct account_record accounts[MAX_ACCOUNT_RECORDS];
    struct event_window global_connections;
    struct event_window global_creations;
};

static unsigned char ascii_lower(unsigned char ch)
{
    if (ch >= 'A' && ch <= 'Z') {
        return (unsigned char)(ch + ('a' - 'A'));
    }

    return ch;
}

static void copy_key(char *destination, size_t size, const char *source)
{
    size_t length;

    if (size == 0) {
        return;
    }

    if (source == NULL || *source == '\0') {
        source = "unknown";
    }

    length = strlen(source);
    if (length >= size) {
        length = size - 1;
    }

    memcpy(destination, source, length);
    destination[length] = '\0';
}

static void normalize_account(
    char *destination,
    size_t size,
    const char *source
)
{
    size_t i = 0;

    if (size == 0) {
        return;
    }

    if (source == NULL) {
        source = "";
    }

    while (source[i] != '\0' && i + 1 < size) {
        destination[i] = (char)ascii_lower((unsigned char)source[i]);
        ++i;
    }

    destination[i] = '\0';
}

static void prune_window(
    struct event_window *window,
    uint64_t now_ms,
    uint64_t window_ms
)
{
    size_t read_index;
    size_t write_index = 0;

    for (read_index = 0;
         read_index < window->count;
         ++read_index) {
        uint64_t then = window->times[read_index];

        if (now_ms >= then &&
            now_ms - then < window_ms) {
            window->times[write_index++] = then;
        }
    }

    window->count = write_index;
}

static int window_allow(
    struct event_window *window,
    size_t limit,
    uint64_t window_ms,
    uint64_t now_ms,
    uint64_t *retry_after_ms
)
{
    prune_window(window, now_ms, window_ms);

    if (window->count >= limit) {
        uint64_t oldest = window->times[0];
        uint64_t age = now_ms >= oldest ? now_ms - oldest : 0;

        if (retry_after_ms != NULL) {
            *retry_after_ms =
                age >= window_ms ? 0 : window_ms - age;
        }

        return 0;
    }

    window->times[window->count++] = now_ms;

    if (retry_after_ms != NULL) {
        *retry_after_ms = 0;
    }

    return 1;
}

static struct peer_record *peer_record_for(
    security_policy *policy,
    const char *peer,
    uint64_t now_ms
)
{
    char peer_key[PEER_KEY_BYTES];
    size_t index;
    size_t empty_index = MAX_PEER_RECORDS;
    size_t oldest_index = 0;
    uint64_t oldest_seen = UINT64_MAX;

    copy_key(peer_key, sizeof(peer_key), peer);

    for (index = 0; index < MAX_PEER_RECORDS; ++index) {
        struct peer_record *record = &policy->peers[index];

        if (record->key[0] == '\0') {
            if (empty_index == MAX_PEER_RECORDS) {
                empty_index = index;
            }
            continue;
        }

        if (strcmp(record->key, peer_key) == 0) {
            record->last_seen_ms = now_ms;
            return record;
        }

        if (record->last_seen_ms < oldest_seen) {
            oldest_seen = record->last_seen_ms;
            oldest_index = index;
        }
    }

    index = empty_index != MAX_PEER_RECORDS
        ? empty_index
        : oldest_index;

    memset(&policy->peers[index], 0, sizeof(policy->peers[index]));
    copy_key(
        policy->peers[index].key,
        sizeof(policy->peers[index].key),
        peer_key
    );
    policy->peers[index].last_seen_ms = now_ms;

    return &policy->peers[index];
}

static struct account_record *account_record_for(
    security_policy *policy,
    const char *player_name,
    uint64_t now_ms
)
{
    char normalized[ACCOUNT_KEY_BYTES];
    size_t index;
    size_t empty_index = MAX_ACCOUNT_RECORDS;
    size_t oldest_index = 0;
    uint64_t oldest_seen = UINT64_MAX;

    normalize_account(
        normalized,
        sizeof(normalized),
        player_name
    );

    for (index = 0; index < MAX_ACCOUNT_RECORDS; ++index) {
        struct account_record *record = &policy->accounts[index];

        if (record->key[0] == '\0') {
            if (empty_index == MAX_ACCOUNT_RECORDS) {
                empty_index = index;
            }
            continue;
        }

        if (strcmp(record->key, normalized) == 0) {
            record->last_seen_ms = now_ms;
            return record;
        }

        if (record->last_seen_ms < oldest_seen) {
            oldest_seen = record->last_seen_ms;
            oldest_index = index;
        }
    }

    index = empty_index != MAX_ACCOUNT_RECORDS
        ? empty_index
        : oldest_index;

    memset(
        &policy->accounts[index],
        0,
        sizeof(policy->accounts[index])
    );

    copy_key(
        policy->accounts[index].key,
        sizeof(policy->accounts[index].key),
        normalized
    );
    policy->accounts[index].last_seen_ms = now_ms;

    return &policy->accounts[index];
}

static uint64_t peer_backoff_ms(unsigned int failures)
{
    unsigned int shift;
    uint64_t delay;

    if (failures < 3) {
        return 0;
    }

    shift = failures - 3;
    if (shift > 6) {
        shift = 6;
    }

    delay = 1000ULL << shift;
    return delay > 60000ULL ? 60000ULL : delay;
}

static uint64_t account_backoff_ms(unsigned int failures)
{
    return failures >= ACCOUNT_AUTH_FAILURE_LIMIT
        ? ACCOUNT_AUTH_LOCK_MS
        : 0;
}
security_policy *security_policy_create(void)
{
    security_policy *policy = calloc(1, sizeof(*policy));

    if (policy == NULL) {
        return NULL;
    }

    if (pthread_mutex_init(&policy->mutex, NULL) != 0) {
        free(policy);
        return NULL;
    }

    return policy;
}

void security_policy_destroy(security_policy *policy)
{
    if (policy == NULL) {
        return;
    }

    pthread_mutex_destroy(&policy->mutex);
    free(policy);
}

int security_policy_allow_connection(
    security_policy *policy,
    const char *peer,
    uint64_t now_ms,
    uint64_t *retry_after_ms
)
{
    if (retry_after_ms != NULL) {
        *retry_after_ms = 0;
    }

    struct peer_record *record;
    uint64_t peer_retry = 0;
    uint64_t global_retry = 0;
    int peer_allowed;
    int global_allowed;

    if (policy == NULL || peer == NULL) {
        return 0;
    }

    pthread_mutex_lock(&policy->mutex);

    record = peer_record_for(policy, peer, now_ms);

    peer_allowed = window_allow(
        &record->connections,
        PEER_CONNECTION_LIMIT,
        PEER_CONNECTION_WINDOW_MS,
        now_ms,
        &peer_retry
    );

    /*
     * Only consume a global slot when the peer-specific limiter accepted the
     * connection. This avoids rejected peer floods exhausting the global pool.
     */
    if (peer_allowed) {
        global_allowed = window_allow(
            &policy->global_connections,
            GLOBAL_CONNECTION_LIMIT,
            GLOBAL_CONNECTION_WINDOW_MS,
            now_ms,
            &global_retry
        );
    } else {
        global_allowed = 0;
    }

    if (retry_after_ms != NULL) {
        *retry_after_ms = peer_retry > global_retry
            ? peer_retry
            : global_retry;
    }

    pthread_mutex_unlock(&policy->mutex);
    return peer_allowed && global_allowed;
}

int security_policy_allow_auth_attempt(
    security_policy *policy,
    const char *peer,
    const char *player_name,
    uint64_t now_ms,
    uint64_t *retry_after_ms
)
{
    if (retry_after_ms != NULL) {
        *retry_after_ms = 0;
    }

    struct peer_record *peer_record;
    struct account_record *account_record;
    uint64_t peer_wait = 0;
    uint64_t account_wait = 0;

    if (policy == NULL || peer == NULL || player_name == NULL) {
        return 0;
    }

    pthread_mutex_lock(&policy->mutex);

    peer_record = peer_record_for(policy, peer, now_ms);
    account_record = account_record_for(
        policy,
        player_name,
        now_ms
    );

    /* A completed cooldown starts a fresh set of attempts. */
    if (peer_record->auth_blocked_until_ms != 0 &&
        peer_record->auth_blocked_until_ms <= now_ms) {
        peer_record->auth_failures = 0;
        peer_record->auth_blocked_until_ms = 0;
    }

    if (account_record->auth_blocked_until_ms != 0 &&
        account_record->auth_blocked_until_ms <= now_ms) {
        account_record->auth_failures = 0;
        account_record->auth_blocked_until_ms = 0;
    }

    if (peer_record->auth_blocked_until_ms > now_ms) {
        peer_wait =
            peer_record->auth_blocked_until_ms - now_ms;
    }

    if (account_record->auth_blocked_until_ms > now_ms) {
        account_wait =
            account_record->auth_blocked_until_ms - now_ms;
    }

    if (retry_after_ms != NULL) {
        *retry_after_ms = peer_wait > account_wait
            ? peer_wait
            : account_wait;
    }

    pthread_mutex_unlock(&policy->mutex);
    return peer_wait == 0 && account_wait == 0;
}

void security_policy_note_auth_failure(
    security_policy *policy,
    const char *peer,
    const char *player_name,
    uint64_t now_ms
)
{
    struct peer_record *peer_record;
    struct account_record *account_record;
    uint64_t peer_delay;
    uint64_t account_delay;

    if (policy == NULL || peer == NULL || player_name == NULL) {
        return;
    }

    pthread_mutex_lock(&policy->mutex);

    peer_record = peer_record_for(policy, peer, now_ms);
    account_record = account_record_for(
        policy,
        player_name,
        now_ms
    );

    if (peer_record->auth_failures < 1000000U) {
        ++peer_record->auth_failures;
    }

    if (account_record->auth_failures < 1000000U) {
        ++account_record->auth_failures;
    }

    peer_delay = peer_backoff_ms(peer_record->auth_failures);
    account_delay =
        account_backoff_ms(account_record->auth_failures);

    if (peer_delay > 0) {
        peer_record->auth_blocked_until_ms =
            now_ms + peer_delay;
    }

    if (account_delay > 0) {
        account_record->auth_blocked_until_ms =
            now_ms + account_delay;
    }

    pthread_mutex_unlock(&policy->mutex);
}

void security_policy_note_auth_success(
    security_policy *policy,
    const char *peer,
    const char *player_name,
    uint64_t now_ms
)
{
    struct peer_record *peer_record;
    struct account_record *account_record;

    if (policy == NULL || peer == NULL || player_name == NULL) {
        return;
    }

    pthread_mutex_lock(&policy->mutex);

    peer_record = peer_record_for(policy, peer, now_ms);
    account_record = account_record_for(
        policy,
        player_name,
        now_ms
    );

    peer_record->auth_failures = 0;
    peer_record->auth_blocked_until_ms = 0;
    account_record->auth_failures = 0;
    account_record->auth_blocked_until_ms = 0;

    pthread_mutex_unlock(&policy->mutex);
}

int security_policy_allow_account_creation(
    security_policy *policy,
    const char *peer,
    uint64_t now_ms,
    uint64_t *retry_after_ms
)
{
    if (retry_after_ms != NULL) {
        *retry_after_ms = 0;
    }

    struct peer_record *record;
    uint64_t peer_retry = 0;
    uint64_t global_retry = 0;
    int peer_allowed;
    int global_allowed;

    if (policy == NULL || peer == NULL) {
        return 0;
    }

    pthread_mutex_lock(&policy->mutex);

    record = peer_record_for(policy, peer, now_ms);

    peer_allowed = window_allow(
        &record->creations,
        PEER_CREATION_LIMIT,
        PEER_CREATION_WINDOW_MS,
        now_ms,
        &peer_retry
    );

    if (peer_allowed) {
        global_allowed = window_allow(
            &policy->global_creations,
            GLOBAL_CREATION_LIMIT,
            GLOBAL_CREATION_WINDOW_MS,
            now_ms,
            &global_retry
        );
    } else {
        global_allowed = 0;
    }

    if (retry_after_ms != NULL) {
        *retry_after_ms = peer_retry > global_retry
            ? peer_retry
            : global_retry;
    }

    pthread_mutex_unlock(&policy->mutex);
    return peer_allowed && global_allowed;
}
