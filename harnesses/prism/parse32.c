#define _GNU_SOURCE
#include <assert.h>
#include <prism.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define PRISM_FUZZ_ALLOW_STREAM_WITH_IJON 1
#include "include/fuzz_options.h"
#include "include/fuzz_serialize_scan.h"
#ifdef PRISM_FUZZ_IJON
#include "include/prism_ijon.h"
#endif

#define ORACLE32_MAGIC 0x504D3634U /* "PM64" little-endian */
#define ORACLE32_STR_INNER(x) #x
#define ORACLE32_STR(x) ORACLE32_STR_INNER(x)

#ifndef FUZZ_ORACLE_NAMESPACE
#define FUZZ_ORACLE_NAMESPACE "oracle_arm32"
#endif

#ifndef FUZZ_ORACLE_LEN_KEY
#define FUZZ_ORACLE_LEN_KEY "arm32_len"
#endif

#ifndef FUZZ_MAX_INPUT_SIZE
#define FUZZ_MAX_INPUT_SIZE 1024
#endif

#ifndef FUZZ_MAX_ALLOCATED
#define FUZZ_MAX_ALLOCATED 128
#endif

#ifndef FUZZ_HARD_RSS_LIMIT
#define FUZZ_HARD_RSS_LIMIT (FUZZ_MAX_ALLOCATED * 16)
#endif

#ifdef PRISM_OSS_FUZZ
__attribute__((visibility("default"))) extern const char *__asan_default_options(void);
__attribute__((visibility("default"))) extern const char *__ubsan_default_options(void);

__attribute__((visibility("default")))
const char *__asan_default_options(void) {
    return "detect_leaks=0:abort_on_error=1:handle_abort=1:symbolize=0:max_allocation_size_mb="
           ORACLE32_STR(FUZZ_MAX_ALLOCATED) ":hard_rss_limit_mb=" ORACLE32_STR(FUZZ_HARD_RSS_LIMIT);
}

__attribute__((visibility("default")))
const char *__ubsan_default_options(void) {
    return "abort_on_error=1:print_stacktrace=1";
}
#endif

__attribute__((noreturn, noinline, format(printf, 1, 2)))
static void fuzz_oracle32_fail(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fflush(stderr);
    abort();
}

static bool has_oracle64_envelope(
    const uint8_t *input,
    size_t size,
    const uint8_t **oracle_out,
    size_t *oracle_len_out,
    const uint8_t **raw_out,
    size_t *raw_len_out
) {
    if (input == NULL || size < 17) return false;

    uint32_t magic = fuzz_read_u32_le(input);
    uint32_t olen = fuzz_read_u32_le(input + 4);
    if (magic != ORACLE32_MAGIC) return false;
    if (olen < 9 || (size_t) olen > size - 8) return false;
    if (memcmp(input + 8, "PRISM", 5) != 0) return false;

    *oracle_out = input + 8;
    *oracle_len_out = (size_t) olen;
    *raw_out = input + 8 + olen;
    *raw_len_out = size - 8 - olen;
    return true;
}

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
static inline uint32_t oracle_read_u32_be(const uint8_t *p) {
    return (((uint32_t) p[0]) << 24) |
           (((uint32_t) p[1]) << 16) |
           (((uint32_t) p[2]) << 8) |
           ((uint32_t) p[3]);
}

static inline void oracle_swap_u32(uint8_t *p) {
    uint8_t b0 = p[0];
    uint8_t b1 = p[1];
    p[0] = p[3];
    p[1] = p[2];
    p[2] = b1;
    p[3] = b0;
}

static inline void oracle_swap_u64(uint8_t *p) {
    for (size_t i = 0; i < 4; i++) {
        uint8_t tmp = p[i];
        p[i] = p[7 - i];
        p[7 - i] = tmp;
    }
}

static bool oracle_read_varuint(const uint8_t *buf, size_t limit, size_t *pos, uint32_t *out) {
    uint32_t val = 0;
    uint32_t shift = 0;
    for (;;) {
        if (*pos >= limit) return false;
        uint8_t byte = buf[(*pos)++];
        if (shift >= 28 && (byte & 0x7fU) > 0x0fU) return false;
        val |= ((uint32_t) (byte & 0x7fU)) << shift;
        if ((byte & 0x80U) == 0) break;
        shift += 7;
    }
    if (out != NULL) *out = val;
    return true;
}

static bool oracle_skip_bytes_prefixed(const uint8_t *buf, size_t limit, size_t *pos) {
    uint32_t n = 0;
    if (!oracle_read_varuint(buf, limit, pos, &n)) return false;
    if ((size_t) n > limit - *pos) return false;
    *pos += (size_t) n;
    return true;
}

static bool oracle_skip_loc(const uint8_t *buf, size_t limit, size_t *pos) {
    return oracle_read_varuint(buf, limit, pos, NULL) &&
           oracle_read_varuint(buf, limit, pos, NULL);
}

static bool oracle_skip_opt_loc(const uint8_t *buf, size_t limit, size_t *pos) {
    if (*pos >= limit) return false;
    uint8_t present = buf[(*pos)++];
    return present == 0 || oracle_skip_loc(buf, limit, pos);
}

static bool oracle_skip_diag_list(const uint8_t *buf, size_t limit, size_t *pos) {
    uint32_t count = 0;
    if (!oracle_read_varuint(buf, limit, pos, &count)) return false;
    for (uint32_t i = 0; i < count; i++) {
        if (!oracle_read_varuint(buf, limit, pos, NULL) ||
            !oracle_skip_bytes_prefixed(buf, limit, pos) ||
            !oracle_skip_loc(buf, limit, pos) ||
            *pos >= limit) {
            return false;
        }
        (*pos)++;
    }
    return true;
}

#define SERIALIZE_WALK_FAIL() do { *fail_pos = pos; return false; } while (0)
#define SERIALIZE_WALK_U8() do { if (pos >= cpool_offset) SERIALIZE_WALK_FAIL(); pos++; } while (0)
#define SERIALIZE_WALK_VARUINT() do { if (!oracle_read_varuint(buf, cpool_offset, &pos, NULL)) SERIALIZE_WALK_FAIL(); } while (0)
#define SERIALIZE_WALK_LOC() do { if (!oracle_skip_loc(buf, cpool_offset, &pos)) SERIALIZE_WALK_FAIL(); } while (0)
#define SERIALIZE_WALK_OPT_LOC() do { if (!oracle_skip_opt_loc(buf, cpool_offset, &pos)) SERIALIZE_WALK_FAIL(); } while (0)
#define SERIALIZE_WALK_STRING() do { if (!oracle_skip_bytes_prefixed(buf, cpool_offset, &pos)) SERIALIZE_WALK_FAIL(); } while (0)
#define SERIALIZE_WALK_CONST_LIST() do { \
    uint32_t cl_n = 0; \
    if (!oracle_read_varuint(buf, cpool_offset, &pos, &cl_n)) SERIALIZE_WALK_FAIL(); \
    for (uint32_t cl_i = 0; cl_i < cl_n; cl_i++) { \
        if (!oracle_read_varuint(buf, cpool_offset, &pos, NULL)) SERIALIZE_WALK_FAIL(); \
    } \
} while (0)
#define SERIALIZE_WALK_INTEGER() do { \
    SERIALIZE_WALK_U8(); \
    uint32_t int_n = 0; \
    if (!oracle_read_varuint(buf, cpool_offset, &pos, &int_n)) SERIALIZE_WALK_FAIL(); \
    for (uint32_t int_i = 0; int_i < int_n; int_i++) { \
        if (!oracle_read_varuint(buf, cpool_offset, &pos, NULL)) SERIALIZE_WALK_FAIL(); \
    } \
} while (0)
#define SERIALIZE_WALK_SWAP_U64() do { \
    if ((size_t) cpool_offset - pos < 8U) SERIALIZE_WALK_FAIL(); \
    oracle_swap_u64(buf + pos); \
    pos += 8U; \
} while (0)

static inline size_t oracle_first_diff(const uint8_t *a, const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) return i;
    }
    return n;
}

/*
 * Canonicalize big-endian native fields in a pm_serialize buffer to little-endian
 * so the serialized AST can be compared against the 64-bit LE oracle.
 */
static bool oracle_canonicalize_be_to_le(
    uint8_t *buf,
    size_t len,
    size_t *out_cpool_offset,
    uint32_t *out_cpool_size,
    size_t *fail_pos
) {
    size_t pos = 0;
    *out_cpool_offset = 0;
    *out_cpool_size = 0;
    *fail_pos = 0;

    if (buf == NULL || len < 10 || memcmp(buf, "PRISM", 5) != 0) {
        return false;
    }
    uint8_t only_semantics = buf[8];
    pos = 9;

    /* encoding + start_line */
    if (!oracle_skip_bytes_prefixed(buf, len, &pos) ||
        !oracle_read_varuint(buf, len, &pos, NULL)) {
        *fail_pos = pos;
        return false;
    }

    /* 8-byte native-endian checksum */
    if (len - pos < 8U) {
        *fail_pos = pos;
        return false;
    }
    oracle_swap_u64(buf + pos);
    pos += 8U;

    /* line_offsets */
    uint32_t line_cnt = 0;
    if (!oracle_read_varuint(buf, len, &pos, &line_cnt)) {
        *fail_pos = pos;
        return false;
    }
    for (uint32_t i = 0; i < line_cnt; i++) {
        if (!oracle_read_varuint(buf, len, &pos, NULL)) {
            *fail_pos = pos;
            return false;
        }
    }

    if (only_semantics == 0) {
        /* comments */
        uint32_t com_cnt = 0;
        if (!oracle_read_varuint(buf, len, &pos, &com_cnt)) {
            *fail_pos = pos;
            return false;
        }
        for (uint32_t i = 0; i < com_cnt; i++) {
            if (pos >= len) { *fail_pos = pos; return false; }
            pos++;
            if (!oracle_skip_loc(buf, len, &pos)) { *fail_pos = pos; return false; }
        }

        /* comment_attachments */
        uint32_t att_cnt = 0;
        if (!oracle_read_varuint(buf, len, &pos, &att_cnt)) {
            *fail_pos = pos;
            return false;
        }
        for (uint32_t i = 0; i < att_cnt; i++) {
            uint32_t idx_cnt = 0;
            if (!oracle_read_varuint(buf, len, &pos, NULL) ||
                !oracle_read_varuint(buf, len, &pos, &idx_cnt)) {
                *fail_pos = pos;
                return false;
            }
            for (uint32_t j = 0; j < idx_cnt; j++) {
                if (!oracle_read_varuint(buf, len, &pos, NULL)) { *fail_pos = pos; return false; }
            }
        }
    }

    /* magic_comments */
    uint32_t mc_cnt = 0;
    if (!oracle_read_varuint(buf, len, &pos, &mc_cnt)) {
        *fail_pos = pos;
        return false;
    }
    for (uint32_t i = 0; i < mc_cnt; i++) {
        if (!oracle_skip_loc(buf, len, &pos) || !oracle_skip_loc(buf, len, &pos)) {
            *fail_pos = pos;
            return false;
        }
    }

    /* data_loc + errors + warnings + continuable */
    if (!oracle_skip_opt_loc(buf, len, &pos) ||
        !oracle_skip_diag_list(buf, len, &pos) ||
        !oracle_skip_diag_list(buf, len, &pos) ||
        pos >= len) {
        *fail_pos = pos;
        return false;
    }
    pos++; /* continuable */

    /* 4-byte native-endian constant pool offset followed by varuint pool size */
    if (len - pos < 4U) {
        *fail_pos = pos;
        return false;
    }
    uint32_t cpool_offset_u32 = oracle_read_u32_be(buf + pos);
    oracle_swap_u32(buf + pos);
    pos += 4U;

    uint32_t cpool_size = 0;
    if (!oracle_read_varuint(buf, len, &pos, &cpool_size)) {
        *fail_pos = pos;
        return false;
    }

    size_t cpool_offset = (size_t) cpool_offset_u32;
    if (cpool_offset < pos || cpool_offset > len) {
        *fail_pos = pos;
        return false;
    }

    /* Post-order node stream up to cpool_offset */
    while (pos < cpool_offset) {
        uint8_t tag = buf[pos++];
        if (tag == 0) continue;
        if (tag == 255) {
            if (cpool_offset - pos < 8U) { *fail_pos = pos; return false; }
            oracle_swap_u32(buf + pos);
            oracle_swap_u32(buf + pos + 4);
            pos += 8U;
            continue;
        }

#if !PRISM_SERIALIZE_ONLY_SEMANTICS_FIELDS
        SERIALIZE_WALK_VARUINT(); /* node_id */
        SERIALIZE_WALK_LOC();     /* location */
#endif
        switch ((int) tag) {
        case PM_SCOPE_NODE:
            break;
#include <node_serialize_walk.inc>
        default:
            SERIALIZE_WALK_FAIL();
        }
    }

    if (pos != cpool_offset) {
        *fail_pos = pos;
        return false;
    }

    /* Constant pool table: cpool_size * (4B content_offset + 4B constant_length) */
    if ((size_t) cpool_size > (len - pos) / 8U) {
        *fail_pos = pos;
        return false;
    }
    for (uint32_t i = 0; i < cpool_size; i++) {
        oracle_swap_u32(buf + pos);
        oracle_swap_u32(buf + pos + 4);
        pos += 8U;
    }

    *out_cpool_offset = cpool_offset;
    *out_cpool_size = cpool_size;
    return true;
}

static bool oracle_compare_be_against_le(
    const uint8_t *buf32,
    size_t len32,
    size_t cpool_offset,
    uint32_t cpool_size,
    const uint8_t *oracle,
    size_t oracle_len,
    size_t *diff32_out,
    size_t *diff64_out
) {
    if (len32 != oracle_len) {
        size_t min_len = len32 < oracle_len ? len32 : oracle_len;
        size_t diff = oracle_first_diff(buf32, oracle, min_len);
        *diff32_out = diff;
        *diff64_out = diff;
        return false;
    }
    if (len32 == 0) return true;

    if (cpool_offset > 0 && memcmp(buf32, oracle, cpool_offset) != 0) {
        size_t diff = oracle_first_diff(buf32, oracle, cpool_offset);
        *diff32_out = diff;
        *diff64_out = diff;
        return false;
    }

    size_t table_bytes = (size_t) cpool_size * 8U;
    size_t str_start = cpool_offset + table_bytes;
    if (str_start >= len32 || table_bytes / 8U != (size_t) cpool_size) {
        *diff32_out = cpool_offset;
        *diff64_out = cpool_offset;
        return false;
    }
    if (buf32[len32 - 1U] != oracle[len32 - 1U]) {
        *diff32_out = len32 - 1U;
        *diff64_out = len32 - 1U;
        return false;
    }

    /*
     * pm_constant_pool_hash uses host-endian word reads while pm_serialize_content
     * appends constant strings in hash-bucket order, so identical constants appear
     * at different string offsets on BE vs LE; compare table lengths + bytes per ID.
     */
    size_t total_str_bytes = 0;
    for (uint32_t i = 0; i < cpool_size; i++) {
        size_t entry = cpool_offset + (size_t) i * 8U;
        uint32_t off32 = fuzz_read_u32_le(buf32 + entry);
        uint32_t clen32 = fuzz_read_u32_le(buf32 + entry + 4U);
        uint32_t off64 = fuzz_read_u32_le(oracle + entry);
        uint32_t clen64 = fuzz_read_u32_le(oracle + entry + 4U);

        if (clen32 != clen64) {
            size_t d = oracle_first_diff(buf32 + entry + 4U, oracle + entry + 4U, 4U);
            *diff32_out = entry + 4U + d;
            *diff64_out = entry + 4U + d;
            return false;
        }
        if ((size_t) off32 < str_start || (size_t) clen32 > (len32 - 1U) - (size_t) off32 ||
            (size_t) off64 < str_start || (size_t) clen64 > (oracle_len - 1U) - (size_t) off64) {
            *diff32_out = entry;
            *diff64_out = entry;
            return false;
        }
        if (clen32 > 0U && memcmp(buf32 + off32, oracle + off64, clen32) != 0) {
            size_t d = oracle_first_diff(buf32 + off32, oracle + off64, clen32);
            *diff32_out = (size_t) off32 + d;
            *diff64_out = (size_t) off64 + d;
            return false;
        }
        total_str_bytes += (size_t) clen32;
    }

    if (total_str_bytes != (len32 - 1U) - str_start) {
        *diff32_out = str_start;
        *diff64_out = str_start;
        return false;
    }

    return true;
}

#undef SERIALIZE_WALK_FAIL
#undef SERIALIZE_WALK_U8
#undef SERIALIZE_WALK_VARUINT
#undef SERIALIZE_WALK_LOC
#undef SERIALIZE_WALK_OPT_LOC
#undef SERIALIZE_WALK_STRING
#undef SERIALIZE_WALK_CONST_LIST
#undef SERIALIZE_WALK_INTEGER
#undef SERIALIZE_WALK_SWAP_U64
#endif

__attribute__((noinline)) void harness(const uint8_t *input, size_t size) {
    if (input == NULL || size == 0) return;

    const uint8_t *oracle = NULL;
    size_t oracle_len = 0;
    const uint8_t *raw = input;
    size_t raw_len = size;
    bool has_oracle = has_oracle64_envelope(input, size, &oracle, &oracle_len, &raw, &raw_len);

    if (raw_len < 4 || (raw_len - 4) > (size_t) FUZZ_MAX_INPUT_SIZE) return;

    fuzz_options_t opts;
    fuzz_options_decode(raw, &opts);

    const uint8_t *src = raw + 4;
    size_t src_len = raw_len - 4;
    uint8_t *source = malloc(src_len);
    if (src_len > 0) {
        assert(source != NULL);
        memcpy(source, src, src_len);
    }
    const uint8_t *source_buf = (src_len == 0 && source == NULL) ? (const uint8_t *) "" : source;

    pm_options_t *options = pm_options_new();
    fuzz_options_populate(options, &opts, source_buf, src_len, true);

    pm_arena_t *arena = pm_arena_new();
    pm_source_t *stream_src = NULL;
    pm_parser_t *parser = NULL;
    pm_node_t *node = NULL;
    size_t parsed_size = src_len;

    if (opts.stream_mode) {
        fuzz_stream_t stream_state = {
            .data = source_buf,
            .size = src_len,
            .pos = 0,
            .eof = false,
        };
        stream_src = pm_source_stream_new(&stream_state, fuzz_stream_fgets, fuzz_stream_feof);
        node = pm_parse_stream(&parser, arena, stream_src, options);
        parsed_size = pm_source_length(stream_src);
        if (parsed_size > src_len) {
            fuzz_oracle32_fail(
                "INVARIANT[" FUZZ_ORACLE_NAMESPACE "]: kind=stream_parsed_size_oob [detail: parsed_size=%zu size=%zu]\n",
                parsed_size,
                src_len
            );
        }
    } else {
        parser = pm_parser_new(arena, source_buf, src_len, options);
#ifdef PRISM_FUZZ_IJON
        fuzz_ijon_state_t ijon_state;
        fuzz_ijon_attach(parser, &ijon_state, 0U);
#endif
        node = pm_parse(parser);
    }

    pm_buffer_t *ast_buf = pm_buffer_new();
    pm_serialize(parser, node, ast_buf);

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    if (has_oracle) {
        size_t canon_cpool_offset = 0;
        uint32_t canon_cpool_size = 0;
        size_t canon_fail_pos = 0;
        uint8_t *buf32_mut = (uint8_t *) pm_buffer_value(ast_buf);
        size_t len32 = pm_buffer_length(ast_buf);
        if (!oracle_canonicalize_be_to_le(buf32_mut, len32, &canon_cpool_offset, &canon_cpool_size, &canon_fail_pos)) {
            fuzz_oracle32_fail(
                "INVARIANT[" FUZZ_ORACLE_NAMESPACE "]: kind=be_canonicalize_error stream=%d [detail: " FUZZ_ORACLE_LEN_KEY "=%zu pos=%zu]\n",
                opts.stream_mode ? 1 : 0,
                len32,
                canon_fail_pos
            );
        }
        size_t diff32 = 0;
        size_t diff64 = 0;
        if (!oracle_compare_be_against_le(buf32_mut, len32, canon_cpool_offset, canon_cpool_size, oracle, oracle_len, &diff32, &diff64)) {
            const char *kind = (len32 != oracle_len) ? "ast_size_mismatch" : "ast_byte_mismatch";
            char section[32];
            char node_type[64];
            size_t eff32 = diff32;
            size_t eff64 = diff64;
            fuzz_classify_serialize_diff(
                buf32_mut, len32, false,
                oracle, oracle_len, false,
                diff32,
                section, sizeof(section),
                node_type, sizeof(node_type),
                &eff32, &eff64
            );
            if (node_type[0] != '\0') {
                fuzz_oracle32_fail(
                    "INVARIANT[" FUZZ_ORACLE_NAMESPACE "]: kind=%s section=%s type=%s stream=%d [detail: " FUZZ_ORACLE_LEN_KEY "=%zu oracle64_len=%zu first_diff=%zu eff_diff=%zu byte32=0x%02x byte64=0x%02x]\n",
                    kind,
                    section,
                    node_type,
                    opts.stream_mode ? 1 : 0,
                    len32,
                    oracle_len,
                    diff32,
                    eff32,
                    eff32 < len32 ? buf32_mut[eff32] : 0U,
                    eff64 < oracle_len ? oracle[eff64] : 0U
                );
            }
            fuzz_oracle32_fail(
                "INVARIANT[" FUZZ_ORACLE_NAMESPACE "]: kind=%s section=%s stream=%d [detail: " FUZZ_ORACLE_LEN_KEY "=%zu oracle64_len=%zu first_diff=%zu byte32=0x%02x byte64=0x%02x]\n",
                kind,
                section,
                opts.stream_mode ? 1 : 0,
                len32,
                oracle_len,
                diff32,
                diff32 < len32 ? buf32_mut[diff32] : 0U,
                diff64 < oracle_len ? oracle[diff64] : 0U
            );
        }
    }
#else
    if (has_oracle) {
        size_t len32 = pm_buffer_length(ast_buf);
        const uint8_t *buf32 = (const uint8_t *) pm_buffer_value(ast_buf);
        if (len32 != oracle_len || (len32 > 0 && memcmp(buf32, oracle, len32) != 0)) {
            size_t min_len = len32 < oracle_len ? len32 : oracle_len;
            size_t diff_off = min_len;
            for (size_t i = 0; i < min_len; i++) {
                if (buf32[i] != oracle[i]) {
                    diff_off = i;
                    break;
                }
            }
            const char *kind = (len32 != oracle_len) ? "ast_size_mismatch" : "ast_byte_mismatch";
            char section[32];
            char node_type[64];
            size_t eff32 = diff_off;
            size_t eff64 = diff_off;
            fuzz_classify_serialize_diff(
                buf32, len32, false,
                oracle, oracle_len, false,
                diff_off,
                section, sizeof(section),
                node_type, sizeof(node_type),
                &eff32, &eff64
            );
            if (node_type[0] != '\0') {
                fuzz_oracle32_fail(
                    "INVARIANT[" FUZZ_ORACLE_NAMESPACE "]: kind=%s section=%s type=%s stream=%d [detail: " FUZZ_ORACLE_LEN_KEY "=%zu oracle64_len=%zu first_diff=%zu eff_diff=%zu byte32=0x%02x byte64=0x%02x]\n",
                    kind,
                    section,
                    node_type,
                    opts.stream_mode ? 1 : 0,
                    len32,
                    oracle_len,
                    diff_off,
                    eff32,
                    eff32 < len32 ? buf32[eff32] : 0U,
                    eff64 < oracle_len ? oracle[eff64] : 0U
                );
            }
            fuzz_oracle32_fail(
                "INVARIANT[" FUZZ_ORACLE_NAMESPACE "]: kind=%s section=%s stream=%d [detail: " FUZZ_ORACLE_LEN_KEY "=%zu oracle64_len=%zu first_diff=%zu byte32=0x%02x byte64=0x%02x]\n",
                kind,
                section,
                opts.stream_mode ? 1 : 0,
                len32,
                oracle_len,
                diff_off,
                diff_off < len32 ? buf32[diff_off] : 0U,
                diff_off < oracle_len ? oracle[diff_off] : 0U
            );
        }
    }
#endif

    pm_buffer_free(ast_buf);
    if (stream_src != NULL) {
        pm_source_free(stream_src);
    }
    pm_parser_free(parser);
    pm_arena_free(arena);
    pm_options_free(options);
    free(source);
}
