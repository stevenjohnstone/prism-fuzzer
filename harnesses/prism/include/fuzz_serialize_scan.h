#ifndef PRISM_FUZZER_SERIALIZE_SCAN_H
#define PRISM_FUZZER_SERIALIZE_SCAN_H

#include <prism.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    bool valid;
    size_t meta_end;
    size_t ast_start;
    size_t cpool_offset;
    uint32_t cpool_size;
    size_t cpool_str_start;
} fuzz_serialize_layout_t;

static inline uint32_t fuzz_scan_read_u32(const uint8_t *p, bool host_endian) {
    if (host_endian) {
        uint32_t v = 0;
        memcpy(&v, p, sizeof(v));
        return v;
    }
    return ((uint32_t) p[0]) |
           (((uint32_t) p[1]) << 8U) |
           (((uint32_t) p[2]) << 16U) |
           (((uint32_t) p[3]) << 24U);
}

static inline bool fuzz_scan_read_varuint(const uint8_t *buf, size_t limit, size_t *pos, uint32_t *out) {
    uint32_t val = 0;
    uint32_t shift = 0;
    for (;;) {
        if (*pos >= limit) return false;
        uint8_t byte = buf[(*pos)++];
        if (shift >= 28U && (byte & 0x7fU) > 0x0fU) return false;
        val |= ((uint32_t) (byte & 0x7fU)) << shift;
        if ((byte & 0x80U) == 0U) break;
        shift += 7U;
    }
    if (out != NULL) *out = val;
    return true;
}

static inline bool fuzz_scan_skip_bytes_prefixed(const uint8_t *buf, size_t limit, size_t *pos) {
    uint32_t n = 0;
    if (!fuzz_scan_read_varuint(buf, limit, pos, &n)) return false;
    if ((size_t) n > limit - *pos) return false;
    *pos += (size_t) n;
    return true;
}

static inline bool fuzz_scan_skip_loc(const uint8_t *buf, size_t limit, size_t *pos) {
    return fuzz_scan_read_varuint(buf, limit, pos, NULL) &&
           fuzz_scan_read_varuint(buf, limit, pos, NULL);
}

static inline bool fuzz_scan_skip_opt_loc(const uint8_t *buf, size_t limit, size_t *pos) {
    if (*pos >= limit) return false;
    uint8_t present = buf[(*pos)++];
    return present == 0U || fuzz_scan_skip_loc(buf, limit, pos);
}

static inline bool fuzz_scan_skip_diag_list(const uint8_t *buf, size_t limit, size_t *pos) {
    uint32_t count = 0;
    if (!fuzz_scan_read_varuint(buf, limit, pos, &count)) return false;
    for (uint32_t i = 0; i < count; i++) {
        if (!fuzz_scan_read_varuint(buf, limit, pos, NULL) ||
            !fuzz_scan_skip_bytes_prefixed(buf, limit, pos) ||
            !fuzz_scan_skip_loc(buf, limit, pos) ||
            *pos >= limit) {
            return false;
        }
        (*pos)++;
    }
    return true;
}

static inline const char *fuzz_scan_node_type_name(uint8_t tag) {
#if defined(PRISM_FUZZ_NO_NODE_TYPE_NAME)
    (void) tag;
    return NULL;
#elif defined(PRISM_FUZZ_NODE_TYPE_TO_STR)
    return pm_node_type_to_str((pm_node_type_t) tag);
#else
    return pm_node_type((pm_node_type_t) tag);
#endif
}

static inline void fuzz_scan_copy_str(char *dst, size_t cap, const char *src) {
    if (dst == NULL || cap == 0) return;
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }
    snprintf(dst, cap, "%s", src);
}

#if !defined(PRISM_FUZZ_NO_SERIALIZE_SCAN)
#define SERIALIZE_WALK_FAIL() do { return false; } while (0)
#define SERIALIZE_WALK_U8() do { if (pos >= cpool_offset) SERIALIZE_WALK_FAIL(); pos++; } while (0)
#define SERIALIZE_WALK_VARUINT() do { if (!fuzz_scan_read_varuint(buf, cpool_offset, &pos, NULL)) SERIALIZE_WALK_FAIL(); } while (0)
#define SERIALIZE_WALK_LOC() do { if (!fuzz_scan_skip_loc(buf, cpool_offset, &pos)) SERIALIZE_WALK_FAIL(); } while (0)
#define SERIALIZE_WALK_OPT_LOC() do { if (!fuzz_scan_skip_opt_loc(buf, cpool_offset, &pos)) SERIALIZE_WALK_FAIL(); } while (0)
#define SERIALIZE_WALK_STRING() do { if (!fuzz_scan_skip_bytes_prefixed(buf, cpool_offset, &pos)) SERIALIZE_WALK_FAIL(); } while (0)
#define SERIALIZE_WALK_CONST_LIST() do { \
    uint32_t cl_n = 0; \
    if (!fuzz_scan_read_varuint(buf, cpool_offset, &pos, &cl_n)) SERIALIZE_WALK_FAIL(); \
    for (uint32_t cl_i = 0; cl_i < cl_n; cl_i++) { \
        if (!fuzz_scan_read_varuint(buf, cpool_offset, &pos, NULL)) SERIALIZE_WALK_FAIL(); \
    } \
} while (0)
#define SERIALIZE_WALK_INTEGER() do { \
    SERIALIZE_WALK_U8(); \
    uint32_t int_n = 0; \
    if (!fuzz_scan_read_varuint(buf, cpool_offset, &pos, &int_n)) SERIALIZE_WALK_FAIL(); \
    for (uint32_t int_i = 0; int_i < int_n; int_i++) { \
        if (!fuzz_scan_read_varuint(buf, cpool_offset, &pos, NULL)) SERIALIZE_WALK_FAIL(); \
    } \
} while (0)
#define SERIALIZE_WALK_SWAP_U64() do { \
    if (cpool_offset - pos < 8U) SERIALIZE_WALK_FAIL(); \
    pos += 8U; \
} while (0)

static inline bool fuzz_scan_ast_locate(
    const uint8_t *buf,
    size_t ast_start,
    size_t cpool_offset,
    size_t query_off,
    char *type_out,
    size_t type_cap
) {
    size_t pos = ast_start;
    while (pos < cpool_offset) {
        size_t rec_start = pos;
        uint8_t tag = buf[pos++];
        if (tag == 0U) {
            if (query_off == rec_start) {
                fuzz_scan_copy_str(type_out, type_cap, "");
            }
            continue;
        }
        if (tag == 255U) {
            if (cpool_offset - pos < 8U) return false;
            pos += 8U;
            if (query_off >= rec_start && query_off < pos) {
                fuzz_scan_copy_str(type_out, type_cap, "LAZY_HEADER");
            }
            continue;
        }

#if !PRISM_SERIALIZE_ONLY_SEMANTICS_FIELDS
        SERIALIZE_WALK_VARUINT();
        SERIALIZE_WALK_LOC();
#endif
        switch ((int) tag) {
        case PM_SCOPE_NODE:
            break;
#include <node_serialize_walk.inc>
        default:
            SERIALIZE_WALK_FAIL();
        }
        if (query_off >= rec_start && query_off < pos) {
            const char *tname = fuzz_scan_node_type_name(tag);
            if (tname != NULL && tname[0] != '\0') {
                fuzz_scan_copy_str(type_out, type_cap, tname);
            } else if (type_out != NULL && type_cap > 0) {
                snprintf(type_out, type_cap, "TAG_%u", (unsigned) tag);
            }
        }
    }
    return pos == cpool_offset;
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

static inline bool fuzz_serialize_locate_offset(
    const uint8_t *buf,
    size_t len,
    bool host_endian_u32,
    size_t query_off,
    fuzz_serialize_layout_t *layout_out,
    char *section_out,
    size_t sec_cap,
    char *type_out,
    size_t type_cap
) {
    fuzz_serialize_layout_t layout;
    memset(&layout, 0, sizeof(layout));
    fuzz_scan_copy_str(section_out, sec_cap, "unknown");
    fuzz_scan_copy_str(type_out, type_cap, "");

    if (buf == NULL || len < 10U || memcmp(buf, "PRISM", 5U) != 0) {
        if (query_off < 9U) fuzz_scan_copy_str(section_out, sec_cap, "header");
        if (layout_out != NULL) *layout_out = layout;
        return false;
    }

    uint8_t only_semantics = buf[8];
    size_t pos = 9U;
    if (query_off < pos) fuzz_scan_copy_str(section_out, sec_cap, "header");

    size_t sec_start = pos;
    if (!fuzz_scan_skip_bytes_prefixed(buf, len, &pos)) {
        if (query_off >= sec_start) fuzz_scan_copy_str(section_out, sec_cap, "encoding");
        if (layout_out != NULL) *layout_out = layout;
        return false;
    }
    if (query_off >= sec_start && query_off < pos) fuzz_scan_copy_str(section_out, sec_cap, "encoding");

    sec_start = pos;
    if (!fuzz_scan_read_varuint(buf, len, &pos, NULL)) {
        if (query_off >= sec_start) fuzz_scan_copy_str(section_out, sec_cap, "start_line");
        if (layout_out != NULL) *layout_out = layout;
        return false;
    }
    if (query_off >= sec_start && query_off < pos) fuzz_scan_copy_str(section_out, sec_cap, "start_line");

    sec_start = pos;
    if (len - pos < 8U) {
        if (query_off >= sec_start) fuzz_scan_copy_str(section_out, sec_cap, "checksum");
        if (layout_out != NULL) *layout_out = layout;
        return false;
    }
    pos += 8U;
    if (query_off >= sec_start && query_off < pos) fuzz_scan_copy_str(section_out, sec_cap, "checksum");

    sec_start = pos;
    uint32_t line_cnt = 0;
    if (!fuzz_scan_read_varuint(buf, len, &pos, &line_cnt)) {
        if (query_off >= sec_start) fuzz_scan_copy_str(section_out, sec_cap, "line_offsets");
        if (layout_out != NULL) *layout_out = layout;
        return false;
    }
    for (uint32_t i = 0; i < line_cnt; i++) {
        if (!fuzz_scan_read_varuint(buf, len, &pos, NULL)) {
            if (query_off >= sec_start) fuzz_scan_copy_str(section_out, sec_cap, "line_offsets");
            if (layout_out != NULL) *layout_out = layout;
            return false;
        }
    }
    if (query_off >= sec_start && query_off < pos) fuzz_scan_copy_str(section_out, sec_cap, "line_offsets");

    if (only_semantics == 0U) {
        sec_start = pos;
        uint32_t com_cnt = 0;
        if (!fuzz_scan_read_varuint(buf, len, &pos, &com_cnt)) {
            if (query_off >= sec_start) fuzz_scan_copy_str(section_out, sec_cap, "comments");
            if (layout_out != NULL) *layout_out = layout;
            return false;
        }
        for (uint32_t i = 0; i < com_cnt; i++) {
            if (pos >= len) {
                if (query_off >= sec_start) fuzz_scan_copy_str(section_out, sec_cap, "comments");
                if (layout_out != NULL) *layout_out = layout;
                return false;
            }
            pos++;
            if (!fuzz_scan_skip_loc(buf, len, &pos)) {
                if (query_off >= sec_start) fuzz_scan_copy_str(section_out, sec_cap, "comments");
                if (layout_out != NULL) *layout_out = layout;
                return false;
            }
        }
        if (query_off >= sec_start && query_off < pos) fuzz_scan_copy_str(section_out, sec_cap, "comments");

        sec_start = pos;
        uint32_t att_cnt = 0;
        if (!fuzz_scan_read_varuint(buf, len, &pos, &att_cnt)) {
            if (query_off >= sec_start) fuzz_scan_copy_str(section_out, sec_cap, "comment_attachments");
            if (layout_out != NULL) *layout_out = layout;
            return false;
        }
        for (uint32_t i = 0; i < att_cnt; i++) {
            uint32_t idx_cnt = 0;
            if (!fuzz_scan_read_varuint(buf, len, &pos, NULL) ||
                !fuzz_scan_read_varuint(buf, len, &pos, &idx_cnt)) {
                if (query_off >= sec_start) fuzz_scan_copy_str(section_out, sec_cap, "comment_attachments");
                if (layout_out != NULL) *layout_out = layout;
                return false;
            }
            for (uint32_t j = 0; j < idx_cnt; j++) {
                if (!fuzz_scan_read_varuint(buf, len, &pos, NULL)) {
                    if (query_off >= sec_start) fuzz_scan_copy_str(section_out, sec_cap, "comment_attachments");
                    if (layout_out != NULL) *layout_out = layout;
                    return false;
                }
            }
        }
        if (query_off >= sec_start && query_off < pos) fuzz_scan_copy_str(section_out, sec_cap, "comment_attachments");
    }

    sec_start = pos;
    uint32_t mc_cnt = 0;
    if (!fuzz_scan_read_varuint(buf, len, &pos, &mc_cnt)) {
        if (query_off >= sec_start) fuzz_scan_copy_str(section_out, sec_cap, "magic_comments");
        if (layout_out != NULL) *layout_out = layout;
        return false;
    }
    for (uint32_t i = 0; i < mc_cnt; i++) {
        if (!fuzz_scan_skip_loc(buf, len, &pos) || !fuzz_scan_skip_loc(buf, len, &pos)) {
            if (query_off >= sec_start) fuzz_scan_copy_str(section_out, sec_cap, "magic_comments");
            if (layout_out != NULL) *layout_out = layout;
            return false;
        }
    }
    if (query_off >= sec_start && query_off < pos) fuzz_scan_copy_str(section_out, sec_cap, "magic_comments");

    sec_start = pos;
    if (!fuzz_scan_skip_opt_loc(buf, len, &pos)) {
        if (query_off >= sec_start) fuzz_scan_copy_str(section_out, sec_cap, "data_loc");
        if (layout_out != NULL) *layout_out = layout;
        return false;
    }
    if (query_off >= sec_start && query_off < pos) fuzz_scan_copy_str(section_out, sec_cap, "data_loc");

    sec_start = pos;
    if (!fuzz_scan_skip_diag_list(buf, len, &pos)) {
        if (query_off >= sec_start) fuzz_scan_copy_str(section_out, sec_cap, "errors");
        if (layout_out != NULL) *layout_out = layout;
        return false;
    }
    if (query_off >= sec_start && query_off < pos) fuzz_scan_copy_str(section_out, sec_cap, "errors");

    sec_start = pos;
    if (!fuzz_scan_skip_diag_list(buf, len, &pos)) {
        if (query_off >= sec_start) fuzz_scan_copy_str(section_out, sec_cap, "warnings");
        if (layout_out != NULL) *layout_out = layout;
        return false;
    }
    if (query_off >= sec_start && query_off < pos) fuzz_scan_copy_str(section_out, sec_cap, "warnings");

    sec_start = pos;
    if (pos >= len) {
        if (query_off >= sec_start) fuzz_scan_copy_str(section_out, sec_cap, "continuable");
        if (layout_out != NULL) *layout_out = layout;
        return false;
    }
    pos++;
    if (query_off >= sec_start && query_off < pos) fuzz_scan_copy_str(section_out, sec_cap, "continuable");

    layout.meta_end = pos;
    sec_start = pos;
    if (len - pos < 4U) {
        if (query_off >= sec_start) fuzz_scan_copy_str(section_out, sec_cap, "cpool_header");
        if (layout_out != NULL) *layout_out = layout;
        return false;
    }
    uint32_t cpool_off_u32 = fuzz_scan_read_u32(buf + pos, host_endian_u32);
    pos += 4U;

    uint32_t cpool_size = 0;
    if (!fuzz_scan_read_varuint(buf, len, &pos, &cpool_size)) {
        if (query_off >= sec_start) fuzz_scan_copy_str(section_out, sec_cap, "cpool_header");
        if (layout_out != NULL) *layout_out = layout;
        return false;
    }
    if (query_off >= sec_start && query_off < pos) fuzz_scan_copy_str(section_out, sec_cap, "cpool_header");

    size_t cpool_offset = (size_t) cpool_off_u32;
    if (cpool_offset < pos || cpool_offset > len) {
        if (layout_out != NULL) *layout_out = layout;
        return false;
    }

    size_t table_bytes = (size_t) cpool_size * 8U;
    if (table_bytes / 8U != (size_t) cpool_size || table_bytes > len - cpool_offset) {
        if (layout_out != NULL) *layout_out = layout;
        return false;
    }

    layout.valid = true;
    layout.ast_start = pos;
    layout.cpool_offset = cpool_offset;
    layout.cpool_size = cpool_size;
    layout.cpool_str_start = cpool_offset + table_bytes;

    if (query_off >= layout.ast_start && query_off < layout.cpool_offset) {
        fuzz_scan_copy_str(section_out, sec_cap, "ast");
#if !defined(PRISM_FUZZ_NO_SERIALIZE_SCAN)
        (void) fuzz_scan_ast_locate(buf, layout.ast_start, layout.cpool_offset, query_off, type_out, type_cap);
#endif
    } else if (query_off >= layout.cpool_offset && query_off < layout.cpool_str_start) {
        fuzz_scan_copy_str(section_out, sec_cap, "cpool_table");
    } else if (query_off >= layout.cpool_str_start && query_off < len) {
        if (len > layout.cpool_str_start && query_off == len - 1U && buf[len - 1U] == 0U) {
            fuzz_scan_copy_str(section_out, sec_cap, "trailer");
        } else {
            fuzz_scan_copy_str(section_out, sec_cap, "cpool_strings");
        }
    } else if (query_off >= len) {
        fuzz_scan_copy_str(section_out, sec_cap, "eof");
    }

    if (layout_out != NULL) *layout_out = layout;
    return true;
}

static inline void fuzz_classify_serialize_diff(
    const uint8_t *buf_a,
    size_t len_a,
    bool host_endian_a,
    const uint8_t *buf_b,
    size_t len_b,
    bool host_endian_b,
    size_t hint_diff_a,
    char *section_out,
    size_t sec_cap,
    char *type_out,
    size_t type_cap,
    size_t *eff_diff_a_out,
    size_t *eff_diff_b_out
) {
    size_t min_len = len_a < len_b ? len_a : len_b;
    size_t raw_diff = min_len;
    for (size_t i = 0; i < min_len; i++) {
        if (buf_a[i] != buf_b[i]) {
            raw_diff = i;
            break;
        }
    }

    fuzz_serialize_layout_t la;
    fuzz_serialize_layout_t lb;
    char sec_a[32];
    char sec_b[32];
    char typ_a[64];
    char typ_b[64];

    bool ok_a = fuzz_serialize_locate_offset(buf_a, len_a, host_endian_a, raw_diff, &la, sec_a, sizeof(sec_a), typ_a, sizeof(typ_a));
    bool ok_b = fuzz_serialize_locate_offset(buf_b, len_b, host_endian_b, raw_diff, &lb, sec_b, sizeof(sec_b), typ_b, sizeof(typ_b));

    if (eff_diff_a_out != NULL) *eff_diff_a_out = raw_diff;
    if (eff_diff_b_out != NULL) *eff_diff_b_out = raw_diff;

    if (!ok_a || !ok_b || raw_diff < la.meta_end) {
        fuzz_scan_copy_str(section_out, sec_cap, strcmp(sec_a, "unknown") != 0 ? sec_a : sec_b);
        fuzz_scan_copy_str(type_out, type_cap, typ_a[0] != '\0' ? typ_a : typ_b);
        return;
    }

    size_t ast_len_a = la.cpool_offset - la.ast_start;
    size_t ast_len_b = lb.cpool_offset - lb.ast_start;
    size_t min_ast = ast_len_a < ast_len_b ? ast_len_a : ast_len_b;
    size_t ast_rel = min_ast;
    for (size_t i = 0; i < min_ast; i++) {
        if (buf_a[la.ast_start + i] != buf_b[lb.ast_start + i]) {
            ast_rel = i;
            break;
        }
    }

    if (ast_rel < min_ast || ast_len_a != ast_len_b) {
        size_t qa = la.ast_start + ast_rel;
        size_t qb = lb.ast_start + ast_rel;
        if (eff_diff_a_out != NULL) *eff_diff_a_out = qa;
        if (eff_diff_b_out != NULL) *eff_diff_b_out = qb;

        typ_a[0] = '\0';
        typ_b[0] = '\0';
        if (ast_rel < ast_len_a) {
            (void) fuzz_serialize_locate_offset(buf_a, len_a, host_endian_a, qa, NULL, sec_a, sizeof(sec_a), typ_a, sizeof(typ_a));
        }
        if (ast_rel < ast_len_b) {
            (void) fuzz_serialize_locate_offset(buf_b, len_b, host_endian_b, qb, NULL, sec_b, sizeof(sec_b), typ_b, sizeof(typ_b));
        }
        fuzz_scan_copy_str(section_out, sec_cap, "ast");
        if (typ_a[0] != '\0' && strcmp(typ_a, "LAZY_HEADER") != 0) {
            fuzz_scan_copy_str(type_out, type_cap, typ_a);
        } else if (typ_b[0] != '\0') {
            fuzz_scan_copy_str(type_out, type_cap, typ_b);
        } else {
            fuzz_scan_copy_str(type_out, type_cap, typ_a);
        }
        return;
    }

    if (la.cpool_size != lb.cpool_size) {
        fuzz_scan_copy_str(section_out, sec_cap, "cpool_table");
        fuzz_scan_copy_str(type_out, type_cap, "");
        return;
    }

    size_t cpool_q = hint_diff_a < len_a ? hint_diff_a : raw_diff;
    if (eff_diff_a_out != NULL) *eff_diff_a_out = cpool_q;
    (void) fuzz_serialize_locate_offset(buf_a, len_a, host_endian_a, cpool_q, NULL, sec_a, sizeof(sec_a), typ_a, sizeof(typ_a));
    if (strcmp(sec_a, "cpool_header") == 0) {
        fuzz_scan_copy_str(section_out, sec_cap, "cpool_table");
    } else {
        fuzz_scan_copy_str(section_out, sec_cap, sec_a);
    }
    fuzz_scan_copy_str(type_out, type_cap, "");
}

#endif
