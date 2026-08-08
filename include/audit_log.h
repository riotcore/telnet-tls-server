// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

#ifndef AUDIT_LOG_H
#define AUDIT_LOG_H

/*
 * Security audit logging.
 *
 * The logger owns file creation, rotation, field cleanup, and serialized writes.
 * Callers give it short event metadata. Passwords, password hashes, private keys,
 * and raw command text don't belong here.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct audit_log audit_log;

/*
 * Opens the active audit log and creates its parent directory when needed.
 *
 * Directory mode: 0700
 * Active file mode: 0600
 *
 * Returns NULL when the path cannot be prepared safely.
 */
audit_log *audit_log_open(const char *path);

/* Flushes, closes, and releases the logger. NULL is accepted. */
void audit_log_close(audit_log *log);

/*
 * Appends one event record.
 *
 * event is a stable machine-readable event name.
 * peer identifies the remote endpoint or local subsystem.
 * detail contains short sanitized context.
 *
 * The logger strips line-breaking and control bytes from peer and detail so a
 * single call always creates a single logical audit record.
 */
void audit_log_event(
    audit_log *log,
    const char *event,
    const char *peer,
    const char *detail
);

#ifdef __cplusplus
}
#endif

#endif
