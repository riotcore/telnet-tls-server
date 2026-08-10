// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

#ifndef TERMINAL_APPLICATION_H
#define TERMINAL_APPLICATION_H

/*
 * Small seam between a terminal transport and whatever the MUD does next.
 *
 * Telnet and SSH arrive here by very different routes, but the application
 * should not need to care about IAC bytes, TLS records, SSH packets, or PTY
 * request messages. It gets a line-oriented session, a set of capabilities,
 * and a trusted output surface instead.
 *
 * The interface keeps transport details out of the application so an existing
 * C MUD can retain its own account, character, command, and world code above
 * the connection layer.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TERMINAL_CLIENT_NAME_MAX 40
#define TERMINAL_CLIENT_VERSION_MAX 40
#define TERMINAL_TYPE_MAX 40

typedef struct terminal_capabilities {
    uint16_t width;
    uint16_t height;

    int utf8;
    int ansi;
    int color_256;
    int truecolor;
    int screen_reader;
    int secure_transport;

    /* Telnet-specific enhancements stay false on transports that lack them. */
    int gmcp;
    int osc8;
    int osc8_send;
    int osc8_prompt;
    int osc8_tooltip;

    char terminal_type[TERMINAL_TYPE_MAX + 1];
    char client_name[TERMINAL_CLIENT_NAME_MAX + 1];
    char client_version[TERMINAL_CLIENT_VERSION_MAX + 1];
} terminal_capabilities;

typedef struct terminal_output {
    void *context;

    /* Trusted server-authored text. The adapter does transport quoting. */
    void (*write_text)(void *context, const char *text);
    void (*write_prompt)(void *context, const char *text);

    /* Ask the adapter for an orderly close, optionally after a final message. */
    void (*request_close)(void *context, const char *message);

    /*
     * Progressive enhancements. A transport can return -1 when the mechanism
     * does not exist there. write_link still emits the visible label as a
     * plain-text fallback when OSC 8 is unavailable.
     */
    int (*send_gmcp)(
        void *context,
        const char *package_name,
        const char *json_payload
    );
    int (*write_link)(
        void *context,
        const char *uri,
        const char *label
    );
} terminal_output;

typedef struct terminal_application_hooks {
    void *manager_context;

    /*
     * Called once the transport has authenticated an account. Return a
     * per-session application pointer, or NULL to reject the attachment.
     */
    void *(*open)(
        void *manager_context,
        const char *account_name,
        const terminal_output *output,
        const terminal_capabilities *capabilities
    );

    /* One complete, bounded input line. Non-zero asks the transport to close. */
    int (*line)(
        void *session_context,
        const char *line,
        size_t length
    );

    /* Width, terminal type, or another capability can change after login. */
    void (*capabilities_changed)(
        void *session_context,
        const terminal_capabilities *capabilities
    );

    /* Telnet GMCP after IAC/SB framing and bounds checks have been removed. */
    void (*gmcp)(
        void *session_context,
        const char *package_name,
        const char *json_payload,
        size_t json_length
    );

    /*
     * Runs only from the connection's owning worker thread. Applications can
     * drain queued asynchronous output here without writing another session's
     * socket, TLS object, or SSH channel from a publisher thread.
     */
    int (*poll)(void *session_context);

    void (*close)(void *session_context);
} terminal_application_hooks;

#ifdef __cplusplus
}
#endif

#endif
