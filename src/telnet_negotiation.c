// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

/*
 * telnet_negotiation.c
 *
 * RFC 1143 option negotiation lives here. Each direction has its own state,
 * and the queue bit remembers when we change our mind mid-negotiation. That
 * little bit of bookkeeping keeps Telnet from arguing with itself forever.
 */

#include "telnet_internal.h"

#include <stddef.h>
#include <string.h>

/* Pick the state slot for this option and direction. */
static telnet_q_side *select_side(
    telnet_q *negotiator,
    telnet_q_direction direction,
    unsigned char option
)
{
    return direction == TELNET_Q_LOCAL
        ? &negotiator->local[option]
        : &negotiator->remote[option];
}

static const telnet_q_side *select_side_const(
    const telnet_q *negotiator,
    telnet_q_direction direction,
    unsigned char option
)
{
    return direction == TELNET_Q_LOCAL
        ? &negotiator->local[option]
        : &negotiator->remote[option];
}

static unsigned char enable_command(
    telnet_q_direction direction
)
{
    return direction == TELNET_Q_LOCAL
        ? TELNET_WILL
        : TELNET_DO;
}

static unsigned char disable_command(
    telnet_q_direction direction
)
{
    return direction == TELNET_Q_LOCAL
        ? TELNET_WONT
        : TELNET_DONT;
}

void telnet_q_init(telnet_q *negotiator)
{
    if (negotiator != NULL) {
        memset(negotiator, 0, sizeof(*negotiator));
    }
}

int telnet_q_enabled(
    const telnet_q *negotiator,
    telnet_q_direction direction,
    unsigned char option
)
{
    const telnet_q_side *side;

    if (negotiator == NULL) {
        return 0;
    }

    side = select_side_const(
        negotiator,
        direction,
        option
    );

    return side->state == TELNET_Q_YES;
}

void telnet_q_request(
    telnet_q *negotiator,
    telnet_q_direction direction,
    unsigned char option,
    int enable,
    telnet_q_send_fn send_fn,
    void *send_context
)
{
    telnet_q_side *side;

    if (negotiator == NULL || send_fn == NULL) {
        return;
    }

    side = select_side(
        negotiator,
        direction,
        option
    );

    if (enable) {
        switch ((telnet_q_state_id)side->state) {
            case TELNET_Q_NO:
                side->state = TELNET_Q_WANTYES;
                side->queued_opposite = 0;
                send_fn(
                    send_context,
                    enable_command(direction),
                    option
                );
                break;

            case TELNET_Q_YES:
                break;

            case TELNET_Q_WANTNO:
                if (!side->queued_opposite) {
                    side->queued_opposite = 1;
                }
                break;

            case TELNET_Q_WANTYES:
                if (side->queued_opposite) {
                    side->queued_opposite = 0;
                }
                break;
        }
    } else {
        switch ((telnet_q_state_id)side->state) {
            case TELNET_Q_NO:
                break;

            case TELNET_Q_YES:
                side->state = TELNET_Q_WANTNO;
                side->queued_opposite = 0;
                send_fn(
                    send_context,
                    disable_command(direction),
                    option
                );
                break;

            case TELNET_Q_WANTNO:
                if (side->queued_opposite) {
                    side->queued_opposite = 0;
                }
                break;

            case TELNET_Q_WANTYES:
                if (!side->queued_opposite) {
                    side->queued_opposite = 1;
                }
                break;
        }
    }
}

static void receive_positive(
    telnet_q *negotiator,
    telnet_q_direction direction,
    unsigned char option,
    int allow_enable,
    telnet_q_send_fn send_fn,
    void *send_context
)
{
    telnet_q_side *side = select_side(
        negotiator,
        direction,
        option
    );

    switch ((telnet_q_state_id)side->state) {
        case TELNET_Q_NO:
            if (allow_enable) {
                side->state = TELNET_Q_YES;
                side->queued_opposite = 0;
                send_fn(
                    send_context,
                    enable_command(direction),
                    option
                );
            } else {
                send_fn(
                    send_context,
                    disable_command(direction),
                    option
                );
            }
            break;

        case TELNET_Q_YES:
            break;

        case TELNET_Q_WANTNO:
            if (!side->queued_opposite) {
                side->state = TELNET_Q_NO;
            } else {
                side->state = TELNET_Q_YES;
                side->queued_opposite = 0;
            }
            break;

        case TELNET_Q_WANTYES:
            if (!side->queued_opposite) {
                side->state = TELNET_Q_YES;
            } else {
                side->state = TELNET_Q_WANTNO;
                side->queued_opposite = 0;
                send_fn(
                    send_context,
                    disable_command(direction),
                    option
                );
            }
            break;
    }
}

static void receive_negative(
    telnet_q *negotiator,
    telnet_q_direction direction,
    unsigned char option,
    telnet_q_send_fn send_fn,
    void *send_context
)
{
    telnet_q_side *side = select_side(
        negotiator,
        direction,
        option
    );

    switch ((telnet_q_state_id)side->state) {
        case TELNET_Q_NO:
            break;

        case TELNET_Q_YES:
            side->state = TELNET_Q_NO;
            side->queued_opposite = 0;
            send_fn(
                send_context,
                disable_command(direction),
                option
            );
            break;

        case TELNET_Q_WANTNO:
            if (!side->queued_opposite) {
                side->state = TELNET_Q_NO;
            } else {
                side->state = TELNET_Q_WANTYES;
                side->queued_opposite = 0;
                send_fn(
                    send_context,
                    enable_command(direction),
                    option
                );
            }
            break;

        case TELNET_Q_WANTYES:
            side->state = TELNET_Q_NO;
            side->queued_opposite = 0;
            break;
    }
}

void telnet_q_receive(
    telnet_q *negotiator,
    unsigned char command,
    unsigned char option,
    telnet_q_accept_fn accept_fn,
    void *accept_context,
    telnet_q_send_fn send_fn,
    void *send_context
)
{
    telnet_q_direction direction;
    int positive;
    int allow_enable = 0;

    if (negotiator == NULL || send_fn == NULL) {
        return;
    }

    switch (command) {
        case TELNET_WILL:
            direction = TELNET_Q_REMOTE;
            positive = 1;
            break;

        case TELNET_WONT:
            direction = TELNET_Q_REMOTE;
            positive = 0;
            break;

        case TELNET_DO:
            direction = TELNET_Q_LOCAL;
            positive = 1;
            break;

        case TELNET_DONT:
            direction = TELNET_Q_LOCAL;
            positive = 0;
            break;

        default:
            return;
    }

    if (positive && accept_fn != NULL) {
        allow_enable = accept_fn(
            accept_context,
            direction,
            option
        );
    }

    if (positive) {
        receive_positive(
            negotiator,
            direction,
            option,
            allow_enable,
            send_fn,
            send_context
        );
    } else {
        receive_negative(
            negotiator,
            direction,
            option,
            send_fn,
            send_context
        );
    }
}
