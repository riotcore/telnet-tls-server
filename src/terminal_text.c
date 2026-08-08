// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

/*
 * terminal_text.c
 *
 * Terminal text reaches a real terminal eventually, so this file is strict on
 * purpose. It validates UTF-8 and filters control bytes that can change terminal
 * behavior or make text visually misleading.
 */

#include "terminal_text.h"

#include <stddef.h>
#include <stdint.h>

/* Decodes one RFC 3629 scalar value and rejects overlong/surrogate forms. */
static int decode_utf8(
    const unsigned char *input,
    size_t input_length,
    size_t *consumed,
    uint32_t *codepoint
)
{
    unsigned char first;

    if (input == NULL || input_length == 0 ||
        consumed == NULL || codepoint == NULL) {
        return 0;
    }

    first = input[0];

    if (first <= 0x7f) {
        *consumed = 1;
        *codepoint = first;
        return 1;
    }

    if (first >= 0xc2 && first <= 0xdf) {
        if (input_length < 2 ||
            (input[1] & 0xc0) != 0x80) {
            return 0;
        }

        *consumed = 2;
        *codepoint =
            ((uint32_t)(first & 0x1f) << 6) |
            (uint32_t)(input[1] & 0x3f);
        return 1;
    }

    if (first >= 0xe0 && first <= 0xef) {
        if (input_length < 3 ||
            (input[1] & 0xc0) != 0x80 ||
            (input[2] & 0xc0) != 0x80) {
            return 0;
        }

        if ((first == 0xe0 && input[1] < 0xa0) ||
            (first == 0xed && input[1] >= 0xa0)) {
            return 0;
        }

        *consumed = 3;
        *codepoint =
            ((uint32_t)(first & 0x0f) << 12) |
            ((uint32_t)(input[1] & 0x3f) << 6) |
            (uint32_t)(input[2] & 0x3f);
        return 1;
    }

    if (first >= 0xf0 && first <= 0xf4) {
        if (input_length < 4 ||
            (input[1] & 0xc0) != 0x80 ||
            (input[2] & 0xc0) != 0x80 ||
            (input[3] & 0xc0) != 0x80) {
            return 0;
        }

        if ((first == 0xf0 && input[1] < 0x90) ||
            (first == 0xf4 && input[1] > 0x8f)) {
            return 0;
        }

        *consumed = 4;
        *codepoint =
            ((uint32_t)(first & 0x07) << 18) |
            ((uint32_t)(input[1] & 0x3f) << 12) |
            ((uint32_t)(input[2] & 0x3f) << 6) |
            (uint32_t)(input[3] & 0x3f);
        return 1;
    }

    return 0;
}

/* Keep controls with useful text semantics and reject display-control tricks. */
static int codepoint_safe(uint32_t codepoint)
{
    if (codepoint == '\r' ||
        codepoint == '\n' ||
        codepoint == '\t') {
        return 1;
    }

    if (codepoint < 0x20 ||
        (codepoint >= 0x7f && codepoint <= 0x9f)) {
        return 0;
    }

    /* Unicode line/paragraph separators can forge terminal layout. */
    if (codepoint == 0x2028 || codepoint == 0x2029) {
        return 0;
    }

    /* Bidi embedding/override and isolate controls can visually spoof text. */
    if ((codepoint >= 0x202a && codepoint <= 0x202e) ||
        (codepoint >= 0x2066 && codepoint <= 0x2069)) {
        return 0;
    }

    return 1;
}

size_t terminal_text_sanitize(
    const unsigned char *input,
    size_t input_length,
    char *output,
    size_t output_size
)
{
    size_t input_index;
    size_t output_index = 0;

    if (output == NULL || output_size == 0) {
        return 0;
    }

    if (input == NULL) {
        output[0] = '\0';
        return 0;
    }

    for (input_index = 0;
         input_index < input_length &&
         output_index + 1 < output_size;
         ++input_index) {
        unsigned char ch = input[input_index];

        if ((ch >= 32 && ch <= 126) ||
            ch == '\r' ||
            ch == '\n' ||
            ch == '\t') {
            output[output_index++] = (char)ch;
        } else {
            output[output_index++] = '?';
        }
    }

    output[output_index] = '\0';
    return output_index;
}

int terminal_text_utf8_valid(
    const unsigned char *input,
    size_t input_length
)
{
    size_t offset = 0;

    if (input == NULL && input_length != 0) {
        return 0;
    }

    while (offset < input_length) {
        size_t consumed = 0;
        uint32_t codepoint = 0;

        if (!decode_utf8(
                input + offset,
                input_length - offset,
                &consumed,
                &codepoint
            )) {
            return 0;
        }

        offset += consumed;
    }

    return 1;
}

size_t terminal_text_sanitize_utf8(
    const unsigned char *input,
    size_t input_length,
    char *output,
    size_t output_size
)
{
    size_t input_index = 0;
    size_t output_index = 0;

    if (output == NULL || output_size == 0) {
        return 0;
    }

    if (input == NULL) {
        output[0] = '\0';
        return 0;
    }

    while (input_index < input_length &&
           output_index + 1 < output_size) {
        size_t consumed = 0;
        uint32_t codepoint = 0;
        size_t copy_index;

        if (!decode_utf8(
                input + input_index,
                input_length - input_index,
                &consumed,
                &codepoint
            )) {
            output[output_index++] = '?';
            ++input_index;
            continue;
        }

        if (!codepoint_safe(codepoint)) {
            output[output_index++] = '?';
            input_index += consumed;
            continue;
        }

        if (output_index + consumed >= output_size) {
            break;
        }

        for (copy_index = 0;
             copy_index < consumed;
             ++copy_index) {
            output[output_index++] =
                (char)input[input_index + copy_index];
        }

        input_index += consumed;
    }

    output[output_index] = '\0';
    return output_index;
}
