// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

/*
 * harness_application.c
 *
 * The standalone server provides a small command set after authentication so
 * Telnet and SSH both exercise the same terminal_application interface. Game
 * systems such as rooms, characters, and combat are outside this harness.
 */

#include "harness_application.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "player_store.h"

struct harness_session {
    char account_name[PLAYER_NAME_MAX + 1];
    terminal_output output;
    terminal_capabilities capabilities;
};

static int line_equals(const char *line, size_t length, const char *word)
{
    size_t word_length;
    size_t i;

    if (line == NULL || word == NULL) {
        return 0;
    }

    word_length = strlen(word);
    if (length != word_length) {
        return 0;
    }

    for (i = 0; i < length; ++i) {
        unsigned char left = (unsigned char)line[i];
        unsigned char right = (unsigned char)word[i];

        if (left >= 'A' && left <= 'Z') {
            left = (unsigned char)(left + ('a' - 'A'));
        }
        if (right >= 'A' && right <= 'Z') {
            right = (unsigned char)(right + ('a' - 'A'));
        }
        if (left != right) {
            return 0;
        }
    }

    return 1;
}

static void write_prompt(struct harness_session *session)
{
    if (session != NULL && session->output.write_prompt != NULL) {
        session->output.write_prompt(session->output.context, "> ");
    }
}

static void *application_open(
    void *manager_context,
    const char *account_name,
    const terminal_output *output,
    const terminal_capabilities *capabilities
)
{
    struct harness_session *session;

    (void)manager_context;

    if (account_name == NULL || output == NULL || capabilities == NULL) {
        return NULL;
    }

    session = calloc(1, sizeof(*session));
    if (session == NULL) {
        return NULL;
    }

    if (snprintf(
            session->account_name,
            sizeof(session->account_name),
            "%s",
            account_name
        ) >= (int)sizeof(session->account_name)) {
        free(session);
        return NULL;
    }

    session->output = *output;
    session->capabilities = *capabilities;

    if (session->output.write_text != NULL) {
        session->output.write_text(
            session->output.context,
            "\nAuthenticated terminal session.\n"
            "Type HELP for the small reference-harness command set.\n"
        );
    }
    write_prompt(session);
    return session;
}

static void write_capabilities(struct harness_session *session)
{
    char buffer[512];

    if (session == NULL || session->output.write_text == NULL) {
        return;
    }

    if (snprintf(
            buffer,
            sizeof(buffer),
            "transport=%s terminal=%s size=%ux%u utf8=%s ansi=%s "
            "256color=%s truecolor=%s screen_reader=%s gmcp=%s osc8=%s\n",
            session->capabilities.secure_transport ? "secure" : "plain",
            session->capabilities.terminal_type[0] != '\0'
                ? session->capabilities.terminal_type : "UNKNOWN",
            (unsigned int)session->capabilities.width,
            (unsigned int)session->capabilities.height,
            session->capabilities.utf8 ? "yes" : "no",
            session->capabilities.ansi ? "yes" : "no",
            session->capabilities.color_256 ? "yes" : "no",
            session->capabilities.truecolor ? "yes" : "no",
            session->capabilities.screen_reader ? "yes" : "no",
            session->capabilities.gmcp ? "yes" : "no",
            session->capabilities.osc8 ? "yes" : "no"
        ) >= (int)sizeof(buffer)) {
        session->output.write_text(
            session->output.context,
            "Capability summary is too large to display.\n"
        );
        return;
    }

    session->output.write_text(session->output.context, buffer);
}

static int application_line(void *session_context, const char *line, size_t length)
{
    struct harness_session *session = session_context;

    if (session == NULL || line == NULL) {
        return 1;
    }

    if (line_equals(line, length, "PING")) {
        session->output.write_text(session->output.context, "PONG\n");
    } else if (line_equals(line, length, "WHOAMI")) {
        char buffer[64];
        if (snprintf(
                buffer,
                sizeof(buffer),
                "%s\n",
                session->account_name
            ) < (int)sizeof(buffer)) {
            session->output.write_text(session->output.context, buffer);
        }
    } else if (line_equals(line, length, "CAPS")) {
        write_capabilities(session);
    } else if (line_equals(line, length, "LINK")) {
        if (session->output.write_link != NULL) {
            (void)session->output.write_link(
                session->output.context,
                "https://github.com/riotcore/mud-terminal-core",
                "project repository"
            );
            session->output.write_text(session->output.context, "\n");
        }
    } else if (line_equals(line, length, "HELP")) {
        session->output.write_text(
            session->output.context,
            "Commands: HELP, PING, WHOAMI, CAPS, LINK, QUIT\n"
        );
    } else if (line_equals(line, length, "QUIT")) {
        if (session->output.request_close != NULL) {
            session->output.request_close(
                session->output.context,
                "Goodbye.\n"
            );
        }
        return 1;
    } else if (length != 0) {
        session->output.write_text(
            session->output.context,
            "Unknown harness command. Type HELP.\n"
        );
    }

    write_prompt(session);
    return 0;
}

static void application_capabilities_changed(
    void *session_context,
    const terminal_capabilities *capabilities
)
{
    struct harness_session *session = session_context;

    if (session != NULL && capabilities != NULL) {
        session->capabilities = *capabilities;
    }
}

static void application_gmcp(
    void *session_context,
    const char *package_name,
    const char *json_payload,
    size_t json_length
)
{
    /*
     * Framing belongs to the connection layer; game-specific packages do not.
     * The harness deliberately ignores application GMCP after proving delivery.
     */
    (void)session_context;
    (void)package_name;
    (void)json_payload;
    (void)json_length;
}

static void application_close(void *session_context)
{
    free(session_context);
}

const terminal_application_hooks *harness_application_hooks(void)
{
    static const terminal_application_hooks hooks = {
        .manager_context = NULL,
        .open = application_open,
        .line = application_line,
        .capabilities_changed = application_capabilities_changed,
        .gmcp = application_gmcp,
        .close = application_close
    };

    return &hooks;
}
