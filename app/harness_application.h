// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

#ifndef HARNESS_APPLICATION_H
#define HARNESS_APPLICATION_H

#include "terminal_application.h"

/*
 * Small application used by the standalone executable.
 *
 * Telnet and SSH both call these hooks after authentication. A MUD can replace
 * them with its own account, session, and command handling.
 */
const terminal_application_hooks *harness_application_hooks(void);

#endif
