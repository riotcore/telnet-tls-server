// SPDX-FileCopyrightText: 2026 riotcore
// SPDX-License-Identifier: MIT

#ifndef TERMINAL_TEXT_H
#define TERMINAL_TEXT_H

/*
 * Terminal-safe text validation and sanitization.
 *
 * Anything untrusted that may reach a user's terminal should pass through here.
 * ANSI escapes, Telnet command bytes, unsafe controls, malformed UTF-8, and a
 * small set of Unicode display controls are filtered.
 */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Sanitizes ASCII/NVT-oriented text.
 *
 * Printable ASCII, CR, LF, and TAB are retained. Other bytes become '?'.
 * Returns the number of output bytes written, excluding the terminating NUL.
 */
size_t terminal_text_sanitize(
    const unsigned char *input,
    size_t input_length,
    char *output,
    size_t output_size
);

/* Returns 1 when the complete input is valid RFC 3629 UTF-8. */
int terminal_text_utf8_valid(
    const unsigned char *input,
    size_t input_length
);

/*
 * Sanitizes negotiated UTF-8 terminal text.
 *
 * Valid printable Unicode is preserved. Unsafe controls, bidi override/isolate
 * characters, Unicode line/paragraph separators, malformed sequences, ESC,
 * DEL, and Telnet IAC are replaced with '?'.
 *
 * Unicode normalization belongs to the persistent field that owns the text.
 * Future free-form fields should define an NFC policy before storage.
 */
size_t terminal_text_sanitize_utf8(
    const unsigned char *input,
    size_t input_length,
    char *output,
    size_t output_size
);

#ifdef __cplusplus
}
#endif

#endif
