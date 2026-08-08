// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

/*
 * audit_log.c
 *
 * Security audit log with bounded rotation and private file permissions. The
 * logger also scrubs control bytes from fields so one event can't forge extra
 * log lines. Its mutex keeps worker-thread writes together.
 */

#define _POSIX_C_SOURCE 200809L

#include "audit_log.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

/* Active log rotation policy. */
#define AUDIT_MAX_BYTES (5ULL * 1024ULL * 1024ULL)
#define AUDIT_ARCHIVES 4

/* Rotation and writes share one lock; mixing those two would get ugly fast. */
struct audit_log {
    pthread_mutex_t mutex;
    int fd;
    char path[PATH_MAX];
};

static int ensure_private_parent(const char *path)
{
    char parent[PATH_MAX];
    char *slash;
    struct stat info;

    if (path == NULL || strlen(path) >= sizeof(parent)) {
        return -1;
    }

    memcpy(parent, path, strlen(path) + 1);
    slash = strrchr(parent, '/');

    if (slash == NULL) {
        return 0;
    }

    if (slash == parent) {
        return 0;
    }

    *slash = '\0';

    if (mkdir(parent, 0700) != 0 && errno != EEXIST) {
        return -1;
    }

    if (lstat(parent, &info) != 0 ||
        !S_ISDIR(info.st_mode) ||
        S_ISLNK(info.st_mode)) {
        return -1;
    }

    if (chmod(parent, 0700) != 0) {
        return -1;
    }

    return 0;
}

static int open_active_file(const char *path)
{
    int fd = open(
        path,
        O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
        0600
    );

    if (fd < 0) {
        return -1;
    }

    if (fchmod(fd, 0600) != 0) {
        close(fd);
        return -1;
    }

    return fd;
}

static void sanitize_field(
    const char *input,
    char *output,
    size_t output_size
)
{
    size_t used = 0;

    if (output_size == 0) {
        return;
    }

    if (input == NULL) {
        input = "-";
    }

    while (*input != '\0' && used + 1 < output_size) {
        unsigned char ch = (unsigned char)*input++;

        if (ch >= 32 && ch <= 126 && ch != '|') {
            output[used++] = (char)ch;
        } else {
            output[used++] = '_';
        }
    }

    output[used] = '\0';
}

static int reopen_active_after_rotation_error(audit_log *log)
{
    if (log->fd >= 0) {
        return -1;
    }

    log->fd = open_active_file(log->path);
    return -1;
}

static int rotate_if_needed(audit_log *log)
{
    struct stat info;
    int index;

    if (fstat(log->fd, &info) != 0) {
        return -1;
    }

    if ((unsigned long long)info.st_size < AUDIT_MAX_BYTES) {
        return 0;
    }

    close(log->fd);
    log->fd = -1;

    for (index = AUDIT_ARCHIVES; index >= 1; --index) {
        char from[PATH_MAX + 16];
        char to[PATH_MAX + 16];

        if (index == AUDIT_ARCHIVES) {
            if (snprintf(
                    to,
                    sizeof(to),
                    "%s.%d",
                    log->path,
                    index
                ) < (int)sizeof(to)) {
                (void)unlink(to);
            }
        }

        if (index == 1) {
            if (snprintf(
                    from,
                    sizeof(from),
                    "%s",
                    log->path
                ) >= (int)sizeof(from)) {
                return reopen_active_after_rotation_error(log);
            }
        } else {
            if (snprintf(
                    from,
                    sizeof(from),
                    "%s.%d",
                    log->path,
                    index - 1
                ) >= (int)sizeof(from)) {
                return reopen_active_after_rotation_error(log);
            }
        }

        if (snprintf(
                to,
                sizeof(to),
                "%s.%d",
                log->path,
                index
            ) >= (int)sizeof(to)) {
            return reopen_active_after_rotation_error(log);
        }

        if (rename(from, to) != 0 && errno != ENOENT) {
            return reopen_active_after_rotation_error(log);
        }
    }

    log->fd = open_active_file(log->path);
    return log->fd >= 0 ? 0 : -1;
}

audit_log *audit_log_open(const char *path)
{
    audit_log *log;

    if (path == NULL ||
        *path == '\0' ||
        strlen(path) >= PATH_MAX ||
        ensure_private_parent(path) != 0) {
        return NULL;
    }

    log = calloc(1, sizeof(*log));
    if (log == NULL) {
        return NULL;
    }

    log->fd = -1;
    memcpy(log->path, path, strlen(path) + 1);

    if (pthread_mutex_init(&log->mutex, NULL) != 0) {
        free(log);
        return NULL;
    }

    log->fd = open_active_file(log->path);
    if (log->fd < 0) {
        pthread_mutex_destroy(&log->mutex);
        free(log);
        return NULL;
    }

    return log;
}

void audit_log_close(audit_log *log)
{
    if (log == NULL) {
        return;
    }

    pthread_mutex_lock(&log->mutex);

    if (log->fd >= 0) {
        (void)fsync(log->fd);
        close(log->fd);
        log->fd = -1;
    }

    pthread_mutex_unlock(&log->mutex);
    pthread_mutex_destroy(&log->mutex);
    free(log);
}

void audit_log_event(
    audit_log *log,
    const char *event,
    const char *peer,
    const char *detail
)
{
    char safe_event[64];
    char safe_peer[96];
    char safe_detail[256];
    char timestamp[32];
    char line[512];
    struct timespec now;
    struct tm utc;
    int length;

    if (log == NULL || event == NULL) {
        return;
    }

    sanitize_field(event, safe_event, sizeof(safe_event));
    sanitize_field(peer, safe_peer, sizeof(safe_peer));
    sanitize_field(detail, safe_detail, sizeof(safe_detail));

    if (clock_gettime(CLOCK_REALTIME, &now) != 0 ||
        gmtime_r(&now.tv_sec, &utc) == NULL ||
        strftime(
            timestamp,
            sizeof(timestamp),
            "%Y-%m-%dT%H:%M:%SZ",
            &utc
        ) == 0) {
        memcpy(timestamp, "unknown-time", sizeof("unknown-time"));
    }

    length = snprintf(
        line,
        sizeof(line),
        "%s event=%s peer=%s detail=%s\n",
        timestamp,
        safe_event,
        safe_peer,
        safe_detail
    );

    if (length <= 0 || (size_t)length >= sizeof(line)) {
        return;
    }

    pthread_mutex_lock(&log->mutex);

    if (log->fd >= 0) {
        (void)rotate_if_needed(log);

        if (log->fd >= 0) {
            size_t offset = 0;

            while (offset < (size_t)length) {
                ssize_t written = write(
                    log->fd,
                    line + offset,
                    (size_t)length - offset
                );

                if (written < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    break;
                }

                if (written == 0) {
                    break;
                }

                offset += (size_t)written;
            }
        }
    }

    pthread_mutex_unlock(&log->mutex);
}
