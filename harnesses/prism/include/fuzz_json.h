#ifndef PRISM_FUZZ_JSON_H
#define PRISM_FUZZ_JSON_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/**
 * Return the byte length (2..4) of a valid UTF-8 multibyte sequence starting at
 * `u[0]` within `[0, rem)`, or 0 if `u[0]` does not begin a valid UTF-8 sequence.
 */
static inline size_t fuzz_json_utf8_seq_len(const uint8_t *u, size_t rem) {
    if (rem < 2) {
        return 0;
    }
    uint8_t b0 = u[0];
    if (b0 >= 0xC2 && b0 <= 0xDF) {
        return (u[1] & 0xC0) == 0x80 ? 2u : 0u;
    }
    if (rem < 3) {
        return 0;
    }
    if (b0 == 0xE0) {
        return (u[1] >= 0xA0 && u[1] <= 0xBF && (u[2] & 0xC0) == 0x80) ? 3u : 0u;
    }
    if ((b0 >= 0xE1 && b0 <= 0xEC) || (b0 >= 0xEE && b0 <= 0xEF)) {
        return ((u[1] & 0xC0) == 0x80 && (u[2] & 0xC0) == 0x80) ? 3u : 0u;
    }
    if (b0 == 0xED) {
        return (u[1] >= 0x80 && u[1] <= 0x9F && (u[2] & 0xC0) == 0x80) ? 3u : 0u;
    }
    if (rem < 4) {
        return 0;
    }
    if (b0 == 0xF0) {
        return (u[1] >= 0x90 && u[1] <= 0xBF && (u[2] & 0xC0) == 0x80 && (u[3] & 0xC0) == 0x80) ? 4u : 0u;
    }
    if (b0 >= 0xF1 && b0 <= 0xF3) {
        return ((u[1] & 0xC0) == 0x80 && (u[2] & 0xC0) == 0x80 && (u[3] & 0xC0) == 0x80) ? 4u : 0u;
    }
    if (b0 == 0xF4) {
        return (u[1] >= 0x80 && u[1] <= 0x8F && (u[2] & 0xC0) == 0x80 && (u[3] & 0xC0) == 0x80) ? 4u : 0u;
    }
    return 0;
}

/**
 * Write a JSON-quoted string of `len` bytes to `out`, preserving valid UTF-8
 * sequences verbatim while escaping ASCII control chars, DEL, and invalid bytes.
 */
static inline void fuzz_json_write_string(FILE *out, const char *s, size_t len) {
    fputc('"', out);
    if (s != NULL) {
        const uint8_t *u = (const uint8_t *) s;
        for (size_t i = 0; i < len; i++) {
            uint8_t c = u[i];
            switch (c) {
                case '"':  fputs("\\\"", out); break;
                case '\\': fputs("\\\\", out); break;
                case '\b': fputs("\\b", out); break;
                case '\f': fputs("\\f", out); break;
                case '\n': fputs("\\n", out); break;
                case '\r': fputs("\\r", out); break;
                case '\t': fputs("\\t", out); break;
                default:
                    if (c < 0x20 || c == 0x7f) {
                        fprintf(out, "\\u%04x", (unsigned) c);
                    } else if (c >= 0x80) {
                        size_t ulen = fuzz_json_utf8_seq_len(u + i, len - i);
                        if (ulen > 0) {
                            fwrite(u + i, 1, ulen, out);
                            i += ulen - 1;
                        } else {
                            fprintf(out, "\\u%04x", (unsigned) c);
                        }
                    } else {
                        fputc((int) c, out);
                    }
                    break;
            }
        }
    }
    fputc('"', out);
}

#endif
