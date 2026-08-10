// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ssh_transport.h"

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "%s:%d: check failed: %s (errno=%d)\n", \
            __FILE__, __LINE__, #expr, errno); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

static void write_dummy_key(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    const char content[] = "not-a-real-key\n";

    CHECK(fd >= 0);
    CHECK(write(fd, content, sizeof(content) - 1U) ==
        (ssize_t)(sizeof(content) - 1U));
    CHECK(close(fd) == 0);
}

int main(void)
{
    char directory[] = "/tmp/telnet-ssh-key-test-XXXXXX";
    char key_path[512];
    char link_path[512];

    CHECK(mkdtemp(directory) != NULL);
    CHECK(snprintf(key_path, sizeof(key_path), "%s/host_key", directory) > 0);
    CHECK(snprintf(link_path, sizeof(link_path), "%s/host_key_link", directory) > 0);

    write_dummy_key(key_path);

    /* Validation is about filesystem ownership/mode; parsing happens in libssh. */
    CHECK(ssh_transport_validate_host_key(key_path) == 0);

    CHECK(chmod(key_path, 0640) == 0);
    CHECK(ssh_transport_validate_host_key(key_path) == -1);

    CHECK(chmod(key_path, 0600) == 0);
    CHECK(symlink(key_path, link_path) == 0);
    CHECK(ssh_transport_validate_host_key(link_path) == -1);

    CHECK(unlink(link_path) == 0);
    CHECK(unlink(key_path) == 0);
    CHECK(rmdir(directory) == 0);

    puts("ssh transport test passed");
    return EXIT_SUCCESS;
}
