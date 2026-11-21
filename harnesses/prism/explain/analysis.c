#define EXPLAIN_NEED_FUZZ_OPTIONS_IMPL 1
#include "explain.h"
#include "../include/fuzz_invariants.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

void explain_decode_options(const uint8_t hdr[4], fuzz_options_t *opts) {
    fuzz_options_decode(hdr, opts);
}

void explain_populate_options(
    pm_options_t *options,
    const fuzz_options_t *opts,
    const uint8_t *src_buf,
    size_t src_len
) {
    fuzz_options_populate(options, opts, src_buf, src_len, false);
}

static int64_t signed_u32(uint32_t v) {
    if (v >= 0x80000000U) {
        return -(int64_t) (0x100000000ULL - (uint64_t) v);
    }
    return (int64_t) v;
}

const char *explain_safe_node_name(pm_node_type_t type) {
    const char *name = pm_node_type(type);
    return (name != NULL && name[0] != '\0') ? name : "UNKNOWN";
}

void explain_node_camel_name(pm_node_type_t type, char *out, size_t cap) {
    const char *raw = explain_safe_node_name(type);
    if (strncmp(raw, "PM_", 3) == 0) {
        raw += 3;
    }
    size_t pos = 0;
    bool upper_next = true;
    for (size_t i = 0; raw[i] != '\0' && pos + 1 < cap; i++) {
        unsigned char c = (unsigned char) raw[i];
        if (c == '_') {
            upper_next = true;
            continue;
        }
        out[pos++] = (char) (upper_next ? toupper(c) : tolower(c));
        upper_next = false;
    }
    out[pos] = '\0';
}

static void format_span_detail(char *buf, size_t cap, uint32_t start, uint32_t length, size_t parsed_size) {
    uint64_t sum = (uint64_t) start + (uint64_t) length;
    uint32_t wrapped = (uint32_t) (sum & 0xffffffffULL);
    if ((uint64_t) parsed_size < 0x80000000ULL && start >= 0x80000000U) {
        snprintf(buf, cap, "start=%u (signed=%lld) len=%u parsed_size=%zu",
            (unsigned) start, (long long) signed_u32(start), (unsigned) length, parsed_size);
    } else if ((uint64_t) parsed_size < 0x80000000ULL && length >= 0x80000000U) {
        snprintf(buf, cap, "start=%u len=%u (signed=%lld) wrapped_end=%u parsed_size=%zu",
            (unsigned) start, (unsigned) length, (long long) signed_u32(length), (unsigned) wrapped, parsed_size);
    } else if (sum >= 0x100000000ULL) {
        snprintf(buf, cap, "start=%u len=%u sum=%llu wrapped_end=%u parsed_size=%zu",
            (unsigned) start, (unsigned) length, (unsigned long long) sum, (unsigned) wrapped, parsed_size);
    } else {
        snprintf(buf, cap, "start=%u len=%u end=%llu parsed_size=%zu",
            (unsigned) start, (unsigned) length, (unsigned long long) sum, parsed_size);
    }
}

bool explain_safe_line_column(
    const pm_line_offset_list_t *lo,
    int32_t start_line,
    bool lo_can_query,
    uint32_t offset,
    pm_line_column_t *out
) {
    if (!lo_can_query || lo == NULL || lo->size == 0 || lo->offsets[0] != 0) {
        return false;
    }
    *out = pm_line_offset_list_line_column(lo, offset, start_line);
    return true;
}

void explain_parse_analysis_free(parse_analysis_t *a) {
    free(a->items);
    free(a->nodes);
    memset(a, 0, sizeof(*a));
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 7, 8)))
#endif
static void add_anomaly(
    parse_analysis_t *a,
    anomaly_scope_t scope,
    size_t node_idx,
    const char *category,
    const char *kind,
    const char *field_name,
    const char *fmt,
    ...
) {
    if (a == NULL || a->oom) return;
    if (a->count == a->cap) {
        size_t next_cap = a->cap == 0 ? 16 : a->cap * 2;
        if (next_cap > SIZE_MAX / sizeof(anomaly_t)) {
            a->oom = true;
            return;
        }
        anomaly_t *grown = realloc(a->items, next_cap * sizeof(anomaly_t));
        if (grown == NULL) {
            a->oom = true;
            return;
        }
        a->items = grown;
        a->cap = next_cap;
    }

    anomaly_t *entry = &a->items[a->count++];
    entry->scope = scope;
    entry->node_idx = node_idx;
    entry->category = category;
    entry->kind = kind;
    entry->field_name = field_name;

    va_list args;
    va_start(args, fmt);
    vsnprintf(entry->detail, sizeof(entry->detail), fmt, args);
    va_end(args);
}

static size_t push_visited_node(parse_analysis_t *a, const visited_node_t *v) {
    if (a->oom) return SIZE_MAX;
    if (a->node_count == a->node_cap) {
        size_t next_cap = a->node_cap == 0 ? 32 : a->node_cap * 2;
        if (next_cap > SIZE_MAX / sizeof(visited_node_t)) {
            a->oom = true;
            return SIZE_MAX;
        }
        visited_node_t *grown = realloc(a->nodes, next_cap * sizeof(visited_node_t));
        if (grown == NULL) {
            a->oom = true;
            return SIZE_MAX;
        }
        a->nodes = grown;
        a->node_cap = next_cap;
    }
    size_t idx = a->node_count++;
    a->nodes[idx] = *v;
    return idx;
}

static bool node_is_heredoc(const pm_node_t *node, const uint8_t *source, size_t parsed_size) {
    pm_location_t open_loc;
    if (!fuzz_heredoc_node_locs(node, &open_loc, NULL)) {
        return false;
    }
    return fuzz_is_heredoc_opening_span(open_loc.start, open_loc.length, source, parsed_size);
}

static bool loc_is_present_closing(pm_location_t loc, size_t parsed_size) {
    if (fuzz_span_violation_kind(loc.start, loc.length, parsed_size, true) != NULL) return false;
    return loc.length > 0 || loc.start > 0;
}

typedef struct {
    bool has_open;
    const char *open_name;
    pm_location_t open_loc;
    bool has_close;
    const char *close_name;
    pm_location_t close_loc;
} loc_pair_state_t;

typedef struct {
    parse_analysis_t *analysis;
    const uint8_t *source;
    size_t parsed_size;
    size_t node_idx;
    const char *node_name;
    bool node_loc_valid;
    bool is_heredoc;
    loc_pair_state_t pairs[2]; /* [0]: general open/close, [1]: lparen/rparen */
} subloc_check_ctx_t;

static void record_delimiter_field(subloc_check_ctx_t *ctx, const char *field_name, pm_location_t raw_loc) {
    if (strcmp(field_name, "opening_loc") == 0 ||
        strcmp(field_name, "begin_keyword_loc") == 0 ||
        strcmp(field_name, "case_keyword_loc") == 0 ||
        strcmp(field_name, "def_keyword_loc") == 0) {
        ctx->pairs[0].has_open = true;
        ctx->pairs[0].open_name = field_name;
        ctx->pairs[0].open_loc = raw_loc;
    } else if (strcmp(field_name, "closing_loc") == 0 ||
               strcmp(field_name, "end_keyword_loc") == 0) {
        ctx->pairs[0].has_close = true;
        ctx->pairs[0].close_name = field_name;
        ctx->pairs[0].close_loc = raw_loc;
    } else if (strcmp(field_name, "lparen_loc") == 0) {
        ctx->pairs[1].has_open = true;
        ctx->pairs[1].open_name = field_name;
        ctx->pairs[1].open_loc = raw_loc;
    } else if (strcmp(field_name, "rparen_loc") == 0) {
        ctx->pairs[1].has_close = true;
        ctx->pairs[1].close_name = field_name;
        ctx->pairs[1].close_loc = raw_loc;
    }
}

static void fuzz_check_sub_location(
    const pm_node_t *node,
    const char *field_name,
    pm_location_t raw_loc,
    subloc_check_ctx_t *ctx
) {
    record_delimiter_field(ctx, field_name, raw_loc);

    const char *kind = fuzz_span_violation_kind(raw_loc.start, raw_loc.length, ctx->parsed_size, true);
    if (kind != NULL) {
        if (raw_loc.length > 0) {
            ctx->analysis->prettyprint_locs_safe = false;
        }
        char span_buf[140];
        format_span_detail(span_buf, sizeof(span_buf), raw_loc.start, raw_loc.length, ctx->parsed_size);
        add_anomaly(ctx->analysis, ANOMALY_SCOPE_SUB_LOC, ctx->node_idx, "sub_location", kind, field_name,
            "%.48s.%s %s", ctx->node_name, field_name, span_buf);
        return;
    }

    if (ctx->node_loc_valid && !ctx->is_heredoc && raw_loc.length > 0) {
        uint64_t fend = (uint64_t) raw_loc.start + (uint64_t) raw_loc.length;
        uint64_t nend = (uint64_t) node->location.start + (uint64_t) node->location.length;
        if (raw_loc.start < node->location.start || fend > nend) {
            add_anomaly(ctx->analysis, ANOMALY_SCOPE_SUB_LOC, ctx->node_idx, "sub_location", "outside_node", field_name,
                "%.48s.%s [%u..%llu) outside node [%u..%llu)",
                ctx->node_name, field_name,
                (unsigned) raw_loc.start, (unsigned long long) fend,
                (unsigned) node->location.start, (unsigned long long) nend);
        }
    }
}

static void check_delimiter_pairs(subloc_check_ctx_t *ctx) {
    for (size_t i = 0; i < 2; i++) {
        loc_pair_state_t *p = &ctx->pairs[i];
        if (!p->has_open || !p->has_close || p->open_loc.length == 0) continue;
        if (fuzz_span_violation_kind(p->open_loc.start, p->open_loc.length, ctx->parsed_size, true) != NULL) continue;
        if (fuzz_span_violation_kind(p->close_loc.start, p->close_loc.length, ctx->parsed_size, true) != NULL) continue;

        uint64_t open_end = (uint64_t) p->open_loc.start + (uint64_t) p->open_loc.length;
        bool bad = (p->close_loc.length > 0 && (uint64_t) p->close_loc.start < open_end) ||
                   (p->close_loc.length == 0 && p->close_loc.start > 0 && p->close_loc.start < p->open_loc.start);
        if (bad) {
            add_anomaly(ctx->analysis, ANOMALY_SCOPE_SUB_LOC, ctx->node_idx, "sub_location", "closing_before_opening",
                p->close_name, "%.48s.%s (%u,%u) starts before %s (%u,%u)",
                ctx->node_name, p->close_name,
                (unsigned) p->close_loc.start, (unsigned) p->close_loc.length,
                p->open_name, (unsigned) p->open_loc.start, (unsigned) p->open_loc.length);
        }
    }
}

static void check_node_sub_locations(
    parse_analysis_t *a,
    const uint8_t *source,
    size_t parsed_size,
    size_t node_idx,
    const pm_node_t *node,
    const char *node_name,
    bool node_loc_valid,
    bool is_heredoc
) {
    subloc_check_ctx_t ctx_val = {
        .analysis = a,
        .source = source,
        .parsed_size = parsed_size,
        .node_idx = node_idx,
        .node_name = node_name,
        .node_loc_valid = node_loc_valid,
        .is_heredoc = is_heredoc,
    };
    subloc_check_ctx_t *ctx = &ctx_val;

    switch (node->type) {
#include <node_locations.inc>
        default:
            break;
    }

    check_delimiter_pairs(ctx);
}

pm_visit_result_t explain_collect_direct_child_cb(const pm_node_t *child, void *data) {
    node_ptr_vec_t *v = (node_ptr_vec_t *) data;
    if (v->oom || PM_NODE_TYPE_P(child, PM_SCOPE_NODE)) return PM_VISIT_SKIP;
    if (v->count == v->cap) {
        size_t next_cap = v->cap == 0 ? 8 : v->cap * 2;
        if (next_cap > SIZE_MAX / sizeof(const pm_node_t *)) {
            v->oom = true;
            return PM_VISIT_STOP;
        }
        const pm_node_t **grown = realloc((void *) v->items, next_cap * sizeof(const pm_node_t *));
        if (grown == NULL) {
            v->oom = true;
            return PM_VISIT_STOP;
        }
        v->items = grown;
        v->cap = next_cap;
    }
    v->items[v->count++] = child;
    return PM_VISIT_SKIP;
}

static bool lookup_direct_child(
    const node_ptr_vec_t *direct,
    const size_t *child_indices,
    const pm_node_t *target,
    size_t *out_idx
) {
    for (size_t i = 0; i < direct->count; i++) {
        if (direct->items[i] == target && child_indices[i] != SIZE_MAX) {
            *out_idx = child_indices[i];
            return true;
        }
    }
    return false;
}

static void check_child_delimiter_bounds(
    parse_analysis_t *a,
    const char *parent_name,
    const pm_node_t *child,
    size_t child_idx,
    pm_location_t opening_loc,
    bool has_open,
    pm_location_t closing_loc,
    bool has_close,
    const char *open_name,
    const char *close_name,
    size_t elem_idx,
    bool has_elem_idx,
    bool is_heredoc,
    size_t parsed_size
) {
    if (is_heredoc || child == NULL || child_idx == SIZE_MAX) return;
    if (!fuzz_span_in_bounds(child->location.start, child->location.length, parsed_size)) return;

    const char *child_name = explain_safe_node_name(child->type);
    uint64_t cstart = (uint64_t) child->location.start;
    uint64_t cend = cstart + (uint64_t) child->location.length;
    char idx_tag[32];
    if (has_elem_idx) {
        snprintf(idx_tag, sizeof(idx_tag), "[%zu]", elem_idx);
    } else {
        idx_tag[0] = '\0';
    }

    if (has_open && opening_loc.length > 0 && fuzz_span_in_bounds(opening_loc.start, opening_loc.length, parsed_size)) {
        uint64_t open_end = (uint64_t) opening_loc.start + (uint64_t) opening_loc.length;
        if (cstart < open_end && !fuzz_node_edge_has_error_recovery(child, cstart, false)) {
            add_anomaly(a, ANOMALY_SCOPE_NODE, child_idx, "node_relation", "child_before_opening", NULL,
                "%.40s%s %.40s start=%llu < %.32s_end=%llu",
                parent_name, idx_tag, child_name,
                (unsigned long long) cstart, open_name, (unsigned long long) open_end);
        }
    }

    if (has_close && loc_is_present_closing(closing_loc, parsed_size)) {
        if (cend > (uint64_t) closing_loc.start && !fuzz_node_edge_has_error_recovery(child, cend, true)) {
            add_anomaly(a, ANOMALY_SCOPE_NODE, child_idx, "node_relation", "child_after_closing", NULL,
                "%.40s%s %.40s end=%llu > %.32s_start=%u",
                parent_name, idx_tag, child_name,
                (unsigned long long) cend, close_name, (unsigned) closing_loc.start);
        }
    }
}

static void check_node_list_spans(
    parse_analysis_t *a,
    const pm_node_t *parent,
    const char *list_name,
    pm_location_t opening_loc,
    bool has_open,
    pm_location_t closing_loc,
    bool has_close,
    const char *open_name,
    const char *close_name,
    const pm_node_list_t *list,
    const node_ptr_vec_t *direct,
    const size_t *child_indices,
    bool is_heredoc,
    size_t parsed_size
) {
    const char *parent_name = explain_safe_node_name(parent->type);
    const pm_node_t *prev = NULL;
    size_t prev_list_i = 0;
    uint32_t prev_start = 0;
    uint32_t prev_len = 0;
    uint64_t prev_end = 0;

    for (size_t i = 0; i < list->size; i++) {
        const pm_node_t *child = list->nodes[i];
        if (child == NULL) continue;
        if (!fuzz_span_in_bounds(child->location.start, child->location.length, parsed_size)) {
            continue;
        }

        size_t child_idx = SIZE_MAX;
        (void) lookup_direct_child(direct, child_indices, child, &child_idx);

        pm_location_t cloc = child->location;
        uint64_t cend = (uint64_t) cloc.start + (uint64_t) cloc.length;
        const char *child_name = explain_safe_node_name(child->type);

        if (prev != NULL && child_idx != SIZE_MAX) {
            bool er_child_start = fuzz_node_edge_has_error_recovery(child, (uint64_t) cloc.start, false);
            bool er_prev_end = fuzz_node_edge_has_error_recovery(prev, prev_end, true);
            bool intersects = (uint64_t) cloc.start < prev_end && cend > (uint64_t) prev_start;

            if (cloc.start == prev_start && cloc.length == prev_len && prev_len > 0) {
                if (!er_prev_end && !er_child_start) {
                    add_anomaly(a, ANOMALY_SCOPE_NODE, child_idx, "node_relation", "duplicate_part", NULL,
                        "%.36s.%s[%zu] %.36s [%u..%llu) duplicates [%zu]",
                        parent_name, list_name, i, child_name,
                        (unsigned) cloc.start, (unsigned long long) cend, prev_list_i);
                }
            } else if (intersects) {
                if ((cloc.start < prev_start && !er_child_start) || (!er_prev_end && !er_child_start)) {
                    uint64_t ov_start = (uint64_t) cloc.start > (uint64_t) prev_start ? (uint64_t) cloc.start : (uint64_t) prev_start;
                    uint64_t ov_end = cend < prev_end ? cend : prev_end;
                    add_anomaly(a, ANOMALY_SCOPE_NODE, child_idx, "node_relation", "sibling_overlap", NULL,
                        "%.36s.%s[%zu] %.36s [%u..%llu) overlaps [%zu] [%u..%llu) by %lluB",
                        parent_name, list_name, i, child_name,
                        (unsigned) cloc.start, (unsigned long long) cend,
                        prev_list_i, (unsigned) prev_start, (unsigned long long) prev_end,
                        (unsigned long long) (ov_end - ov_start));
                }
            } else if (cloc.start < prev_start && !er_child_start) {
                add_anomaly(a, ANOMALY_SCOPE_NODE, child_idx, "node_relation", "sibling_out_of_order", NULL,
                    "%.36s.%s[%zu] %.36s [%u..%llu) starts before [%zu] [%u..%llu)",
                    parent_name, list_name, i, child_name,
                    (unsigned) cloc.start, (unsigned long long) cend,
                    prev_list_i, (unsigned) prev_start, (unsigned long long) prev_end);
            }
        }

        check_child_delimiter_bounds(a, parent_name, child, child_idx,
            opening_loc, has_open, closing_loc, has_close, open_name, close_name,
            i, true, is_heredoc, parsed_size);

        prev = child;
        prev_list_i = i;
        prev_start = cloc.start;
        prev_len = cloc.length;
        prev_end = cend;
    }
}

static void check_container_relations(
    parse_analysis_t *a,
    const pm_node_t *node,
    const node_ptr_vec_t *direct,
    const size_t *child_indices,
    bool is_heredoc,
    size_t parsed_size
) {
    pm_location_t zero = { 0, 0 };
#define CHECK_LIST(field, open_expr, has_o, close_expr, has_c, oname, cname) \
    check_node_list_spans(a, node, #field, (open_expr), (has_o), (close_expr), (has_c), \
        (oname), (cname), &cast->field, direct, child_indices, is_heredoc, parsed_size)
#define CHECK_SINGLE(field, open_expr, has_o, close_expr, has_c, oname, cname) \
    do { \
        size_t cidx = SIZE_MAX; \
        if (cast->field != NULL && lookup_direct_child(direct, child_indices, (const pm_node_t *) cast->field, &cidx)) { \
            check_child_delimiter_bounds(a, explain_safe_node_name(node->type), (const pm_node_t *) cast->field, cidx, \
                (open_expr), (has_o), (close_expr), (has_c), (oname), (cname), 0, false, is_heredoc, parsed_size); \
        } \
    } while (0)

    switch (PM_NODE_TYPE(node)) {
        case PM_ARGUMENTS_NODE: {
            const pm_arguments_node_t *cast = (const pm_arguments_node_t *) node;
            CHECK_LIST(arguments, zero, false, zero, false, "", "");
            break;
        }
        case PM_ARRAY_NODE: {
            const pm_array_node_t *cast = (const pm_array_node_t *) node;
            CHECK_LIST(elements, cast->opening_loc, true, cast->closing_loc, true, "opening_loc", "closing_loc");
            break;
        }
        case PM_ARRAY_PATTERN_NODE: {
            const pm_array_pattern_node_t *cast = (const pm_array_pattern_node_t *) node;
            CHECK_LIST(requireds, cast->opening_loc, true, cast->closing_loc, true, "opening_loc", "closing_loc");
            CHECK_LIST(posts, cast->opening_loc, true, cast->closing_loc, true, "opening_loc", "closing_loc");
            break;
        }
        case PM_BLOCK_PARAMETERS_NODE: {
            const pm_block_parameters_node_t *cast = (const pm_block_parameters_node_t *) node;
            CHECK_LIST(locals, cast->opening_loc, true, cast->closing_loc, true, "opening_loc", "closing_loc");
            break;
        }
        case PM_CASE_MATCH_NODE: {
            const pm_case_match_node_t *cast = (const pm_case_match_node_t *) node;
            CHECK_LIST(conditions, cast->case_keyword_loc, true, cast->end_keyword_loc, true, "case_keyword_loc", "end_keyword_loc");
            break;
        }
        case PM_CASE_NODE: {
            const pm_case_node_t *cast = (const pm_case_node_t *) node;
            CHECK_LIST(conditions, cast->case_keyword_loc, true, cast->end_keyword_loc, true, "case_keyword_loc", "end_keyword_loc");
            break;
        }
        case PM_EMBEDDED_STATEMENTS_NODE: {
            const pm_embedded_statements_node_t *cast = (const pm_embedded_statements_node_t *) node;
            CHECK_SINGLE(statements, cast->opening_loc, true, cast->closing_loc, true, "opening_loc", "closing_loc");
            break;
        }
        case PM_FIND_PATTERN_NODE: {
            const pm_find_pattern_node_t *cast = (const pm_find_pattern_node_t *) node;
            CHECK_LIST(requireds, cast->opening_loc, true, cast->closing_loc, true, "opening_loc", "closing_loc");
            break;
        }
        case PM_HASH_NODE: {
            const pm_hash_node_t *cast = (const pm_hash_node_t *) node;
            CHECK_LIST(elements, cast->opening_loc, true, cast->closing_loc, true, "opening_loc", "closing_loc");
            break;
        }
        case PM_HASH_PATTERN_NODE: {
            const pm_hash_pattern_node_t *cast = (const pm_hash_pattern_node_t *) node;
            CHECK_LIST(elements, cast->opening_loc, true, cast->closing_loc, true, "opening_loc", "closing_loc");
            break;
        }
        case PM_INTERPOLATED_MATCH_LAST_LINE_NODE: {
            const pm_interpolated_match_last_line_node_t *cast = (const pm_interpolated_match_last_line_node_t *) node;
            CHECK_LIST(parts, cast->opening_loc, true, cast->closing_loc, true, "opening_loc", "closing_loc");
            break;
        }
        case PM_INTERPOLATED_REGULAR_EXPRESSION_NODE: {
            const pm_interpolated_regular_expression_node_t *cast = (const pm_interpolated_regular_expression_node_t *) node;
            CHECK_LIST(parts, cast->opening_loc, true, cast->closing_loc, true, "opening_loc", "closing_loc");
            break;
        }
        case PM_INTERPOLATED_STRING_NODE: {
            const pm_interpolated_string_node_t *cast = (const pm_interpolated_string_node_t *) node;
            CHECK_LIST(parts, cast->opening_loc, true, cast->closing_loc, true, "opening_loc", "closing_loc");
            break;
        }
        case PM_INTERPOLATED_SYMBOL_NODE: {
            const pm_interpolated_symbol_node_t *cast = (const pm_interpolated_symbol_node_t *) node;
            CHECK_LIST(parts, cast->opening_loc, true, cast->closing_loc, true, "opening_loc", "closing_loc");
            break;
        }
        case PM_INTERPOLATED_X_STRING_NODE: {
            const pm_interpolated_x_string_node_t *cast = (const pm_interpolated_x_string_node_t *) node;
            CHECK_LIST(parts, cast->opening_loc, true, cast->closing_loc, true, "opening_loc", "closing_loc");
            break;
        }
        case PM_KEYWORD_HASH_NODE: {
            const pm_keyword_hash_node_t *cast = (const pm_keyword_hash_node_t *) node;
            CHECK_LIST(elements, zero, false, zero, false, "", "");
            break;
        }
        case PM_MATCH_WRITE_NODE: {
            const pm_match_write_node_t *cast = (const pm_match_write_node_t *) node;
            CHECK_LIST(targets, zero, false, zero, false, "", "");
            break;
        }
        case PM_MULTI_TARGET_NODE: {
            const pm_multi_target_node_t *cast = (const pm_multi_target_node_t *) node;
            CHECK_LIST(lefts, cast->lparen_loc, true, cast->rparen_loc, true, "lparen_loc", "rparen_loc");
            CHECK_LIST(rights, cast->lparen_loc, true, cast->rparen_loc, true, "lparen_loc", "rparen_loc");
            break;
        }
        case PM_MULTI_WRITE_NODE: {
            const pm_multi_write_node_t *cast = (const pm_multi_write_node_t *) node;
            CHECK_LIST(lefts, cast->lparen_loc, true, cast->rparen_loc, true, "lparen_loc", "rparen_loc");
            CHECK_LIST(rights, cast->lparen_loc, true, cast->rparen_loc, true, "lparen_loc", "rparen_loc");
            break;
        }
        case PM_PARAMETERS_NODE: {
            const pm_parameters_node_t *cast = (const pm_parameters_node_t *) node;
            CHECK_LIST(requireds, zero, false, zero, false, "", "");
            CHECK_LIST(optionals, zero, false, zero, false, "", "");
            CHECK_LIST(posts, zero, false, zero, false, "", "");
            CHECK_LIST(keywords, zero, false, zero, false, "", "");
            break;
        }
        case PM_PARENTHESES_NODE: {
            const pm_parentheses_node_t *cast = (const pm_parentheses_node_t *) node;
            CHECK_SINGLE(body, cast->opening_loc, true, cast->closing_loc, true, "opening_loc", "closing_loc");
            break;
        }
        case PM_POST_EXECUTION_NODE: {
            const pm_post_execution_node_t *cast = (const pm_post_execution_node_t *) node;
            CHECK_SINGLE(statements, cast->opening_loc, true, cast->closing_loc, true, "opening_loc", "closing_loc");
            break;
        }
        case PM_PRE_EXECUTION_NODE: {
            const pm_pre_execution_node_t *cast = (const pm_pre_execution_node_t *) node;
            CHECK_SINGLE(statements, cast->opening_loc, true, cast->closing_loc, true, "opening_loc", "closing_loc");
            break;
        }
        case PM_RESCUE_NODE: {
            const pm_rescue_node_t *cast = (const pm_rescue_node_t *) node;
            CHECK_LIST(exceptions, cast->keyword_loc, true, zero, false, "keyword_loc", "");
            break;
        }
        case PM_STATEMENTS_NODE: {
            const pm_statements_node_t *cast = (const pm_statements_node_t *) node;
            CHECK_LIST(body, zero, false, zero, false, "", "");
            break;
        }
        case PM_UNDEF_NODE: {
            const pm_undef_node_t *cast = (const pm_undef_node_t *) node;
            CHECK_LIST(names, cast->keyword_loc, true, zero, false, "keyword_loc", "");
            break;
        }
        case PM_WHEN_NODE: {
            const pm_when_node_t *cast = (const pm_when_node_t *) node;
            CHECK_LIST(conditions, cast->when_keyword_loc, true, zero, false, "when_keyword_loc", "");
            break;
        }
        default:
            break;
    }

#undef CHECK_SINGLE
#undef CHECK_LIST
}

typedef struct {
    parse_analysis_t *analysis;
    const pm_parser_t *parser;
    const uint8_t *source;
    size_t parsed_size;
    bool has_depth_or_stack_error;
} ast_inspect_ctx_t;

static void inspect_ast_node(
    ast_inspect_ctx_t *ctx,
    const pm_node_t *node,
    pm_node_type_t parent_type,
    size_t raw_depth,
    size_t non_iter_depth,
    size_t *out_idx,
    bool *out_subtree_heredoc
) {
    *out_idx = SIZE_MAX;
    *out_subtree_heredoc = false;
    if (node == NULL || PM_NODE_TYPE_P(node, PM_SCOPE_NODE)) return;

    const char *node_name = explain_safe_node_name(node->type);
    const char *parent_name = parent_type == 0 ? "ROOT" : explain_safe_node_name(parent_type);
    const char *loc_kind = fuzz_span_violation_kind(node->location.start, node->location.length, ctx->parsed_size, true);
    bool loc_valid = (loc_kind == NULL);
    bool is_heredoc = node_is_heredoc(node, ctx->source, ctx->parsed_size);

    visited_node_t v = {
        .node = node,
        .parent_type = parent_type,
        .raw_depth = raw_depth,
        .non_iter_depth = non_iter_depth,
        .loc_valid = loc_valid,
        .is_heredoc = is_heredoc,
        .subtree_has_heredoc = is_heredoc,
    };
    explain_node_camel_name(node->type, v.camel_name, sizeof(v.camel_name));

    size_t my_idx = push_visited_node(ctx->analysis, &v);
    if (my_idx == SIZE_MAX) return;
    *out_idx = my_idx;

    if (!loc_valid) {
        char span_buf[140];
        format_span_detail(span_buf, sizeof(span_buf), node->location.start, node->location.length, ctx->parsed_size);
        add_anomaly(ctx->analysis, ANOMALY_SCOPE_NODE, my_idx, "node_location", loc_kind, NULL,
            "%.48s [parent=%.48s] %s", node_name, parent_name, span_buf);
    }

    if (PM_NODE_TYPE_P(node, PM_ERROR_RECOVERY_NODE) && pm_parser_errors_size(ctx->parser) == 0) {
        add_anomaly(ctx->analysis, ANOMALY_SCOPE_NODE, my_idx, "error_recovery", "zero_errors", NULL,
            "ErrorRecoveryNode present with errors=0 [parent=%.48s start=%u len=%u]",
            parent_name, (unsigned) node->location.start, (unsigned) node->location.length);
    }

    if (non_iter_depth > FUZZ_MAX_NON_ITER_DEPTH && !ctx->has_depth_or_stack_error &&
        !ctx->analysis->reported_non_iter_depth) {
        ctx->analysis->reported_non_iter_depth = true;
        add_anomaly(ctx->analysis, ANOMALY_SCOPE_NODE, my_idx, "recursion_depth", "depth_exceeded", NULL,
            "%.48s non_iter_depth=%zu > limit=%zu (max=%u) without depth/stack error",
            node_name, non_iter_depth, FUZZ_MAX_NON_ITER_DEPTH, (unsigned) (PRISM_DEPTH_MAXIMUM));
    }

    check_node_sub_locations(ctx->analysis, ctx->source, ctx->parsed_size, my_idx, node, node_name, loc_valid, is_heredoc);

    if (raw_depth >= EXPLAIN_MAX_VISIT_DEPTH) {
        if (!ctx->analysis->reported_depth_cap) {
            ctx->analysis->reported_depth_cap = true;
            add_anomaly(ctx->analysis, ANOMALY_SCOPE_NODE, my_idx, "recursion_depth", "visit_depth_cap", NULL,
                "AST depth reached safety cap %u; subtree truncated", (unsigned) EXPLAIN_MAX_VISIT_DEPTH);
        }
        *out_subtree_heredoc = is_heredoc;
        return;
    }

    node_ptr_vec_t direct = { 0 };
    pm_visit_child_nodes(node, explain_collect_direct_child_cb, &direct);
    if (direct.oom) {
        free((void *) direct.items);
        ctx->analysis->oom = true;
        return;
    }

    bool any_child_heredoc = false;
    if (direct.count > 0) {
        size_t *child_indices = malloc(direct.count * sizeof(size_t));
        bool *child_heredocs = malloc(direct.count * sizeof(bool));
        if (child_indices == NULL || child_heredocs == NULL) {
            free(child_indices);
            free(child_heredocs);
            free((void *) direct.items);
            ctx->analysis->oom = true;
            return;
        }

        uint64_t pend = (uint64_t) node->location.start + (uint64_t) node->location.length;
        for (size_t i = 0; i < direct.count; i++) {
            const pm_node_t *child = direct.items[i];
            size_t next_non_iter = non_iter_depth + (fuzz_is_iterative_chain_node(node->type, child->type) ? 0u : 1u);
            inspect_ast_node(ctx, child, node->type, raw_depth + 1u, next_non_iter, &child_indices[i], &child_heredocs[i]);
            if (child_heredocs[i]) any_child_heredoc = true;

            if (loc_valid && !is_heredoc && child_indices[i] != SIZE_MAX && ctx->analysis->nodes[child_indices[i]].loc_valid) {
                uint64_t cstart = (uint64_t) child->location.start;
                uint64_t cend = cstart + (uint64_t) child->location.length;
                const char *child_name = explain_safe_node_name(child->type);

                if (cstart < (uint64_t) node->location.start && !fuzz_node_edge_has_error_recovery(child, cstart, false)) {
                    add_anomaly(ctx->analysis, ANOMALY_SCOPE_NODE, child_indices[i], "node_relation", "child_before_parent", NULL,
                        "%.40s [%llu..%llu) starts before parent %.40s [%u..%llu)",
                        child_name, (unsigned long long) cstart, (unsigned long long) cend,
                        node_name, (unsigned) node->location.start, (unsigned long long) pend);
                }
                if (cend > pend && !child_heredocs[i] && !fuzz_node_edge_has_error_recovery(child, cend, true)) {
                    add_anomaly(ctx->analysis, ANOMALY_SCOPE_NODE, child_indices[i], "node_relation", "child_after_parent", NULL,
                        "%.40s [%llu..%llu) extends past parent %.40s [%u..%llu)",
                        child_name, (unsigned long long) cstart, (unsigned long long) cend,
                        node_name, (unsigned) node->location.start, (unsigned long long) pend);
                }
            }
        }

        check_container_relations(ctx->analysis, node, &direct, child_indices, is_heredoc, ctx->parsed_size);
        free(child_indices);
        free(child_heredocs);
    }

    free((void *) direct.items);
    ctx->analysis->nodes[my_idx].subtree_has_heredoc = (is_heredoc || any_child_heredoc);
    *out_subtree_heredoc = (is_heredoc || any_child_heredoc);
}

static void check_non_ast_invariants(
    parse_analysis_t *a,
    const pm_parser_t *parser,
    const uint8_t *source,
    size_t parsed_size,
    bool check_comment_order,
    bool *out_has_depth_or_stack_error
) {
    a->line_offsets_can_query = true;
    a->prettyprint_locs_safe = true;
    a->errors_locs_safe = true;
    *out_has_depth_or_stack_error = false;

    const pm_location_t *dloc = pm_parser_data_loc(parser);
    if (dloc->length > 0 || dloc->start > 0) {
        const char *dkind = fuzz_span_violation_kind(dloc->start, dloc->length, parsed_size, true);
        if (dkind != NULL) {
            char sbuf[140];
            format_span_detail(sbuf, sizeof(sbuf), dloc->start, dloc->length, parsed_size);
            add_anomaly(a, ANOMALY_SCOPE_GENERAL, SIZE_MAX, "data_loc", dkind, NULL, "%s", sbuf);
        }
    }

    const pm_line_offset_list_t *lo = pm_parser_line_offsets(parser);
    if (lo->size == 0) {
        a->line_offsets_can_query = false;
        a->prettyprint_locs_safe = false;
        a->errors_locs_safe = false;
        add_anomaly(a, ANOMALY_SCOPE_GENERAL, SIZE_MAX, "line_offsets", "empty", NULL,
            "size=0 parsed_size=%zu", parsed_size);
    } else {
        if (lo->offsets[0] != 0) {
            a->line_offsets_can_query = false;
            a->prettyprint_locs_safe = false;
            a->errors_locs_safe = false;
            add_anomaly(a, ANOMALY_SCOPE_GENERAL, SIZE_MAX, "line_offsets", "nonzero_start", NULL,
                "offsets[0]=%u parsed_size=%zu", (unsigned) lo->offsets[0], parsed_size);
        }
        for (size_t i = 1; i < lo->size; i++) {
            uint32_t prev = lo->offsets[i - 1];
            uint32_t curr = lo->offsets[i];
            const char *lo_kind = NULL;
            if ((uint64_t) parsed_size < 0x80000000ULL && curr >= 0x80000000U) {
                lo_kind = "underflow";
            } else if (curr == prev) {
                lo_kind = "duplicate";
            } else if (curr < prev) {
                lo_kind = "rewind";
                a->line_offsets_can_query = false;
                a->prettyprint_locs_safe = false;
                a->errors_locs_safe = false;
            } else if ((size_t) curr > parsed_size) {
                lo_kind = "oob";
                a->errors_locs_safe = false;
            }
            if (lo_kind != NULL) {
                add_anomaly(a, ANOMALY_SCOPE_GENERAL, SIZE_MAX, "line_offsets", lo_kind, NULL,
                    "idx=%zu prev=%u curr=%u parsed_size=%zu", i, (unsigned) prev, (unsigned) curr, parsed_size);
            }
        }
    }

    size_t err_idx = 0;
    for (const pm_diagnostic_t *d = pm_parser_errors_first(parser); d != NULL; d = pm_diagnostic_next(d), err_idx++) {
        pm_location_t loc = pm_diagnostic_location(d);
        const char *dtype = pm_diagnostic_type(d);
        const char *kind = fuzz_span_violation_kind(loc.start, loc.length, parsed_size, true);
        if (dtype != NULL && (strcmp(dtype, "nesting_too_deep") == 0 || strcmp(dtype, "stack_exhausted") == 0)) {
            *out_has_depth_or_stack_error = true;
        }
        if (kind != NULL) {
            a->errors_locs_safe = false;
            char sbuf[140];
            format_span_detail(sbuf, sizeof(sbuf), loc.start, loc.length, parsed_size);
            add_anomaly(a, ANOMALY_SCOPE_GENERAL, SIZE_MAX, "diagnostic", kind, NULL,
                "error[%zu] type=%.48s %s", err_idx, dtype ? dtype : "unknown", sbuf);
        } else if (dtype != NULL) {
            if (strcmp(dtype, "mixed_encoding") == 0) {
                if (loc.length == 0) {
                    add_anomaly(a, ANOMALY_SCOPE_GENERAL, SIZE_MAX, "diagnostic_semantic", "zero_length", NULL,
                        "error[%zu] type=mixed_encoding start=%u len=0", err_idx, (unsigned) loc.start);
                } else {
                    bool has_non_ascii_or_escape = false;
                    for (uint32_t i = 0; i < loc.length; i++) {
                        uint8_t b = source[loc.start + i];
                        if (b >= 0x80 || b == '\\') {
                            has_non_ascii_or_escape = true;
                            break;
                        }
                    }
                    if (!has_non_ascii_or_escape && !fuzz_is_unicode_escape_mixed_encoding_span(source, loc.start, loc.length)) {
                        add_anomaly(a, ANOMALY_SCOPE_GENERAL, SIZE_MAX, "diagnostic_semantic", "wrong_byte", NULL,
                            "error[%zu] type=mixed_encoding byte=0x%02x start=%u len=%u",
                            err_idx, (unsigned) source[loc.start], (unsigned) loc.start, (unsigned) loc.length);
                    }
                }
            } else if (strcmp(dtype, "escape_invalid_unicode_literal") == 0 && loc.length == 0) {
                add_anomaly(a, ANOMALY_SCOPE_GENERAL, SIZE_MAX, "diagnostic_semantic", "zero_length", NULL,
                    "error[%zu] type=escape_invalid_unicode_literal start=%u len=0", err_idx, (unsigned) loc.start);
            }
        }
    }

    size_t warn_idx = 0;
    for (const pm_diagnostic_t *d = pm_parser_warnings_first(parser); d != NULL; d = pm_diagnostic_next(d), warn_idx++) {
        pm_location_t loc = pm_diagnostic_location(d);
        const char *kind = fuzz_span_violation_kind(loc.start, loc.length, parsed_size, true);
        if (kind != NULL) {
            const char *dtype = pm_diagnostic_type(d);
            char sbuf[140];
            format_span_detail(sbuf, sizeof(sbuf), loc.start, loc.length, parsed_size);
            add_anomaly(a, ANOMALY_SCOPE_GENERAL, SIZE_MAX, "diagnostic", kind, NULL,
                "warning[%zu] type=%.48s %s", warn_idx, dtype ? dtype : "unknown", sbuf);
        }
    }

    bool first_comment = true;
    uint32_t prev_comment_start = 0;
    size_t c_idx = 0;
    for (const pm_comment_t *c = pm_parser_comments_first(parser); c != NULL; c = pm_comment_next(c), c_idx++) {
        pm_location_t loc = pm_comment_location(c);
        const char *ctype = pm_comment_type(c) == PM_COMMENT_EMBDOC ? "embdoc" : "inline";
        const char *kind = fuzz_span_violation_kind(loc.start, loc.length, parsed_size, true);
        if (kind != NULL) {
            char sbuf[140];
            format_span_detail(sbuf, sizeof(sbuf), loc.start, loc.length, parsed_size);
            add_anomaly(a, ANOMALY_SCOPE_GENERAL, SIZE_MAX, "comment", kind, NULL,
                "comment[%zu] (%s) %s", c_idx, ctype, sbuf);
        }
        if (check_comment_order && !first_comment && loc.start < prev_comment_start) {
            add_anomaly(a, ANOMALY_SCOPE_GENERAL, SIZE_MAX, "comment", "unsorted", NULL,
                "comment[%zu] (%s) start=%u < prev=%u", c_idx, ctype,
                (unsigned) loc.start, (unsigned) prev_comment_start);
        }
        prev_comment_start = loc.start;
        first_comment = false;
    }

    size_t mc_idx = 0;
    for (const pm_magic_comment_t *mc = pm_parser_magic_comments_first(parser); mc != NULL; mc = pm_magic_comment_next(mc), mc_idx++) {
        pm_location_t k = pm_magic_comment_key(mc);
        const char *k_kind = fuzz_span_violation_kind(k.start, k.length, parsed_size, true);
        if (k_kind != NULL) {
            char sbuf[140];
            format_span_detail(sbuf, sizeof(sbuf), k.start, k.length, parsed_size);
            add_anomaly(a, ANOMALY_SCOPE_GENERAL, SIZE_MAX, "magic_comment", k_kind, "key",
                "magic_comment[%zu].key %s", mc_idx, sbuf);
        }
        pm_location_t v = pm_magic_comment_value(mc);
        const char *v_kind = fuzz_span_violation_kind(v.start, v.length, parsed_size, true);
        if (v_kind != NULL) {
            char sbuf[140];
            format_span_detail(sbuf, sizeof(sbuf), v.start, v.length, parsed_size);
            add_anomaly(a, ANOMALY_SCOPE_GENERAL, SIZE_MAX, "magic_comment", v_kind, "value",
                "magic_comment[%zu].value %s", mc_idx, sbuf);
        }
    }
}

void explain_run_parse_analysis(
    parse_analysis_t *a,
    const pm_parser_t *parser,
    const pm_node_t *node,
    const uint8_t *source,
    size_t parsed_size,
    bool check_comment_order
) {
    memset(a, 0, sizeof(*a));
    a->analyzed = true;
    bool has_depth_or_stack_error = false;
    check_non_ast_invariants(a, parser, source, parsed_size, check_comment_order, &has_depth_or_stack_error);

    if (node != NULL) {
        ast_inspect_ctx_t actx = {
            .analysis = a,
            .parser = parser,
            .source = source,
            .parsed_size = parsed_size,
            .has_depth_or_stack_error = has_depth_or_stack_error,
        };
        size_t root_idx = SIZE_MAX;
        bool root_heredoc = false;
        inspect_ast_node(&actx, node, 0, 0, 1, &root_idx, &root_heredoc);
    }
}

void explain_parsed_run_free(parsed_run_t *run) {
    explain_parse_analysis_free(&run->analysis);
    if (run->errfmt_buf != NULL) pm_buffer_free(run->errfmt_buf);
    if (run->json_buf != NULL) pm_buffer_free(run->json_buf);
    if (run->ser_buf != NULL) pm_buffer_free(run->ser_buf);
    if (run->pretty_buf != NULL) pm_buffer_free(run->pretty_buf);
    if (run->parser != NULL) pm_parser_free(run->parser);
    if (run->stream_src != NULL) pm_source_free(run->stream_src);
    if (run->arena != NULL) pm_arena_free(run->arena);
    memset(run, 0, sizeof(*run));
}

bool explain_run_parse(
    parsed_run_t *out,
    const uint8_t *src_buf,
    size_t src_len,
    const pm_options_t *options,
    bool stream_mode,
    bool check_comment_order,
    bool check_anomalies,
    bool want_ast,
    bool want_ser,
    bool want_json,
    bool want_errfmt
) {
    memset(out, 0, sizeof(*out));
    out->arena = pm_arena_new();
    if (out->arena == NULL) return false;

    if (stream_mode) {
        fuzz_stream_t stream_state = {
            .data = src_buf,
            .size = src_len,
            .pos = 0,
            .eof = false,
        };
        out->stream_src = pm_source_stream_new(&stream_state, fuzz_stream_fgets, fuzz_stream_feof);
        if (out->stream_src == NULL) {
            explain_parsed_run_free(out);
            return false;
        }
        out->node = pm_parse_stream(&out->parser, out->arena, out->stream_src, options);
        out->parsed_size = pm_source_length(out->stream_src);
    } else {
        out->parser = pm_parser_new(out->arena, src_buf, src_len, options);
        if (out->parser == NULL) {
            explain_parsed_run_free(out);
            return false;
        }
        out->node = pm_parse(out->parser);
        const uint8_t *pstart = pm_parser_start(out->parser);
        const uint8_t *pend = pm_parser_end(out->parser);
        out->parsed_size = (pend != NULL && pstart != NULL && pend >= pstart) ? (size_t) (pend - pstart) : src_len;
    }

    if (out->parser == NULL) {
        explain_parsed_run_free(out);
        return false;
    }

    if (check_anomalies || want_ast || want_errfmt) {
        explain_run_parse_analysis(&out->analysis, out->parser, out->node, src_buf, out->parsed_size, check_comment_order);
        if (!check_anomalies) {
            out->analysis.count = 0;
        }
    } else {
        out->analysis.line_offsets_can_query = true;
        out->analysis.prettyprint_locs_safe = true;
        out->analysis.errors_locs_safe = true;
    }

    if (want_ast && out->node != NULL && out->analysis.line_offsets_can_query && out->analysis.prettyprint_locs_safe) {
        out->pretty_buf = pm_buffer_new();
        pm_prettyprint(out->pretty_buf, out->parser, out->node);
    }
    if (want_ser && out->node != NULL) {
        out->ser_buf = pm_buffer_new();
        pm_serialize(out->parser, out->node, out->ser_buf);
    }
    if (want_json && out->node != NULL) {
        out->json_buf = pm_buffer_new();
        pm_dump_json(out->json_buf, out->parser, out->node);
    }
    if (want_errfmt && pm_parser_errors_size(out->parser) > 0 &&
        out->analysis.line_offsets_can_query && out->analysis.errors_locs_safe) {
        out->errfmt_buf = pm_buffer_new();
        (void) pm_errors_format(out->parser, out->errfmt_buf, PM_ERRORS_FORMAT_PLAIN);
    }

    return true;
}

size_t explain_first_buffer_diff(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen) {
    size_t min_len = alen < blen ? alen : blen;
    for (size_t i = 0; i < min_len; i++) {
        if (a[i] != b[i]) return i;
    }
    return min_len;
}
