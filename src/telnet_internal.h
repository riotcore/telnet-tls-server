// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

#ifndef TELNET_INTERNAL_H
#define TELNET_INTERNAL_H

/*
 * Private Telnet wire definitions and option state.
 *
 * The server, development client, and Telnet tests share these definitions.
 * Application code doesn't get this header; wire details stay on this side of
 * the protocol boundary.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum telnet_command_code {
    TELNET_EOR = 239,
    TELNET_SE = 240,
    TELNET_NOP = 241,
    TELNET_DM = 242,
    TELNET_BRK = 243,
    TELNET_IP = 244,
    TELNET_AO = 245,
    TELNET_AYT = 246,
    TELNET_EC = 247,
    TELNET_EL = 248,
    TELNET_GA = 249,
    TELNET_SB = 250,
    TELNET_WILL = 251,
    TELNET_WONT = 252,
    TELNET_DO = 253,
    TELNET_DONT = 254,
    TELNET_IAC = 255
};

enum telnet_option_code {
    TELNET_OPT_BINARY = 0,
    TELNET_OPT_ECHO = 1,
    TELNET_OPT_SUPPRESS_GO_AHEAD = 3,
    TELNET_OPT_TERMINAL_TYPE = 24,
    TELNET_OPT_END_OF_RECORD = 25,
    TELNET_OPT_NAWS = 31,
    TELNET_OPT_LINEMODE = 34,
    TELNET_OPT_NEW_ENVIRON = 39,
    TELNET_OPT_CHARSET = 42,
    TELNET_OPT_MSSP = 70,
    TELNET_OPT_GMCP = 201
};

typedef enum telnet_q_direction {
    TELNET_Q_LOCAL = 0,
    TELNET_Q_REMOTE = 1
} telnet_q_direction;

typedef enum telnet_q_state_id {
    TELNET_Q_NO = 0,
    TELNET_Q_YES,
    TELNET_Q_WANTNO,
    TELNET_Q_WANTYES
} telnet_q_state_id;

typedef struct telnet_q_side {
    unsigned char state;
    unsigned char queued_opposite;
} telnet_q_side;

typedef struct telnet_q {
    telnet_q_side local[256];
    telnet_q_side remote[256];
} telnet_q;

typedef void (*telnet_q_send_fn)(
    void *context,
    unsigned char command,
    unsigned char option
);

typedef int (*telnet_q_accept_fn)(
    void *context,
    telnet_q_direction direction,
    unsigned char option
);

/* Every option starts disabled in both directions. */
void telnet_q_init(telnet_q *negotiator);

/* Returns 1 once this side of the option has reached YES. */
int telnet_q_enabled(
    const telnet_q *negotiator,
    telnet_q_direction direction,
    unsigned char option
);

/* Requests a local or remote option-state change. */
void telnet_q_request(
    telnet_q *negotiator,
    telnet_q_direction direction,
    unsigned char option,
    int enable,
    telnet_q_send_fn send_fn,
    void *send_context
);

/* Applies one received WILL/WONT/DO/DONT command to the option state machine. */
void telnet_q_receive(
    telnet_q *negotiator,
    unsigned char command,
    unsigned char option,
    telnet_q_accept_fn accept_fn,
    void *accept_context,
    telnet_q_send_fn send_fn,
    void *send_context
);

#ifdef __cplusplus
}
#endif

#endif
