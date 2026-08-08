// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

#ifndef SECURITY_POLICY_H
#define SECURITY_POLICY_H

/*
 * Shared abuse-control policy.
 *
 * Connection workers share one policy object. Its mutex protects peer/account
 * records and global windows. Timestamps are monotonic milliseconds supplied by
 * the caller. Destroy it after all workers have stopped using it.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct security_policy security_policy;

/* Creates an empty thread-safe policy state. */
security_policy *security_policy_create(void);

/* Releases the policy state. NULL is accepted. */
void security_policy_destroy(security_policy *policy);

/*
 * Checks peer and global connection-start windows before TLS work begins.
 *
 * Returns 1 when accepted and 0 when delayed. retry_after_ms may be NULL.
 */
int security_policy_allow_connection(
    security_policy *policy,
    const char *peer,
    uint64_t now_ms,
    uint64_t *retry_after_ms
);

/*
 * Checks temporary peer/account login backoff before password verification.
 * Returns 1 when the attempt may proceed and 0 during an active delay.
 */
int security_policy_allow_auth_attempt(
    security_policy *policy,
    const char *peer,
    const char *player_name,
    uint64_t now_ms,
    uint64_t *retry_after_ms
);

/* Records one failed password attempt and updates temporary backoff state. */
void security_policy_note_auth_failure(
    security_policy *policy,
    const char *peer,
    const char *player_name,
    uint64_t now_ms
);

/* Clears applicable temporary login backoff after successful authentication. */
void security_policy_note_auth_success(
    security_policy *policy,
    const char *peer,
    const char *player_name,
    uint64_t now_ms
);

/*
 * Checks the peer and global account-creation windows.
 * Returns 1 when creation may proceed and 0 when delayed.
 */
int security_policy_allow_account_creation(
    security_policy *policy,
    const char *peer,
    uint64_t now_ms,
    uint64_t *retry_after_ms
);

#ifdef __cplusplus
}
#endif

#endif
