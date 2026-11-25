#define _GNU_SOURCE
#include <assert.h>
#include <limits.h>
#include <prism.h>
#if defined(__has_include)
#  if __has_include("prism_fuzz_compat.h")
#    include "prism_fuzz_compat.h"
#  endif
#endif
#if defined(SLOW) && !defined(PRISM_FUZZ_NO_INTERNAL_BUFFER)
#include "prism/internal/buffer.h"
#endif
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/fuzz_options.h"
#ifdef PRISM_FUZZ_IJON
#include "include/prism_ijon.h"
#endif

#ifdef PRISM_FUZZ_LEGACY_VISIT_BOOL
typedef bool pm_visit_result_t;
#define PM_VISIT_DESCEND true
#define PM_VISIT_SKIP false
#endif

#include "include/fuzz_invariants.h"

#ifndef PRISM_FUZZ_NO_VISIT_NODE
static inline const char *fuzz_node_type_name(pm_node_type_t type) {
#ifdef PRISM_FUZZ_NODE_TYPE_TO_STR
    return pm_node_type_to_str(type);
#else
    return pm_node_type(type);
#endif
}
#endif

#ifdef PRISM_FUZZ_NODE_TYPE_TO_STR
#define pm_node_type(type) pm_node_type_to_str(type)
#endif

typedef struct {
    uint32_t start;
    uint32_t length;
} fuzz_span_t;

static inline fuzz_span_t fuzz_loc_span(pm_location_t loc, const uint8_t *source) {
#ifdef PRISM_FUZZ_POINTER_LOCATIONS
    if (loc.start == NULL && loc.end == NULL) {
        return (fuzz_span_t) { .start = 0, .length = 0 };
    }
    if (loc.start == NULL || loc.end == NULL || (uintptr_t) loc.start < (uintptr_t) source) {
        return (fuzz_span_t) { .start = UINT32_MAX, .length = 0 };
    }
    uintptr_t s_off = (uintptr_t) loc.start - (uintptr_t) source;
    if ((uintptr_t) loc.end < (uintptr_t) loc.start) {
        return (fuzz_span_t) {
            .start = s_off <= UINT32_MAX ? (uint32_t) s_off : UINT32_MAX,
            .length = UINT32_MAX,
        };
    }
    uintptr_t len = (uintptr_t) loc.end - (uintptr_t) loc.start;
    return (fuzz_span_t) {
        .start = s_off <= UINT32_MAX ? (uint32_t) s_off : UINT32_MAX,
        .length = len <= UINT32_MAX ? (uint32_t) len : UINT32_MAX,
    };
#else
    (void) source;
    return (fuzz_span_t) { .start = loc.start, .length = loc.length };
#endif
}

#ifdef PRISM_FUZZ_LEGACY_MAGIC_COMMENT_START
static inline fuzz_span_t fuzz_raw_ptr_span(const uint8_t *start, uint32_t length, const uint8_t *source) {
    if (start == NULL) {
        return (fuzz_span_t) { .start = 0, .length = 0 };
    }
    if ((uintptr_t) start < (uintptr_t) source) {
        return (fuzz_span_t) { .start = UINT32_MAX, .length = length };
    }
    uintptr_t s_off = (uintptr_t) start - (uintptr_t) source;
    return (fuzz_span_t) {
        .start = s_off <= UINT32_MAX ? (uint32_t) s_off : UINT32_MAX,
        .length = length,
    };
}
#endif

static inline const pm_location_t *fuzz_parser_data_loc(const pm_parser_t *parser) {
#ifdef PRISM_FUZZ_LEGACY_PARSER_DATA_LOC
    return &parser->data_loc;
#else
    return pm_parser_data_loc(parser);
#endif
}

static inline pm_location_t fuzz_diag_location(const pm_diagnostic_t *d) {
#ifdef PRISM_FUZZ_LEGACY_DIAG_FIELDS
    return d->location;
#else
    return pm_diagnostic_location(d);
#endif
}

static inline const char *fuzz_diag_type(const pm_diagnostic_t *d) {
#ifdef PRISM_FUZZ_NO_DIAGNOSTIC_TYPE
    (void) d;
    return "diag";
#else
    return pm_diagnostic_type(d);
#endif
}

static inline unsigned fuzz_diag_error_level(const pm_diagnostic_t *d) {
#ifdef PRISM_FUZZ_LEGACY_DIAG_FIELDS
    return (unsigned) d->level;
#else
    return (unsigned) pm_diagnostic_error_level(d);
#endif
}

static inline unsigned fuzz_diag_warning_level(const pm_diagnostic_t *d) {
#ifdef PRISM_FUZZ_LEGACY_DIAG_FIELDS
    return (unsigned) d->level;
#else
    return (unsigned) pm_diagnostic_warning_level(d);
#endif
}

static inline pm_location_t fuzz_comment_location(const pm_comment_t *c) {
#ifdef PRISM_FUZZ_LEGACY_COMMENT_FIELDS
    return c->location;
#else
    return pm_comment_location(c);
#endif
}

static inline int fuzz_comment_type(const pm_comment_t *c) {
#ifdef PRISM_FUZZ_LEGACY_COMMENT_FIELDS
    return (int) c->type;
#else
    return (int) pm_comment_type(c);
#endif
}

static inline fuzz_span_t fuzz_magic_comment_key_span(const pm_magic_comment_t *mc, const uint8_t *source) {
#ifdef PRISM_FUZZ_LEGACY_MAGIC_COMMENT_START
    return fuzz_raw_ptr_span(mc->key_start, mc->key_length, source);
#elif defined(PRISM_FUZZ_LEGACY_MAGIC_COMMENT_FIELDS)
    return fuzz_loc_span(mc->key, source);
#else
    return fuzz_loc_span(pm_magic_comment_key(mc), source);
#endif
}

static inline fuzz_span_t fuzz_magic_comment_value_span(const pm_magic_comment_t *mc, const uint8_t *source) {
#ifdef PRISM_FUZZ_LEGACY_MAGIC_COMMENT_START
    return fuzz_raw_ptr_span(mc->value_start, mc->value_length, source);
#elif defined(PRISM_FUZZ_LEGACY_MAGIC_COMMENT_FIELDS)
    return fuzz_loc_span(mc->value, source);
#else
    return fuzz_loc_span(pm_magic_comment_value(mc), source);
#endif
}

typedef struct {
    const uint8_t *source;
    size_t parsed_size;
    pm_node_type_t parent_type;
    pm_parser_t *parser;
    size_t depth;
} fuzz_node_check_t;

typedef struct {
    const uint8_t *source;
    size_t parsed_size;
} fuzz_diag_check_ctx_t;

#ifndef PRISM_FUZZ_NO_VISIT_NODE
typedef struct {
    const uint8_t *source;
    size_t parsed_size;
    uint32_t probe;
    const char *ctx;
} fuzz_line_offset_ctx_t;
#endif

__attribute__((noreturn, noinline, format(printf, 1, 2)))
static void fuzz_invariant_fail(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fflush(stderr);
    abort();
}

static bool fuzz_loc_in_bounds(fuzz_span_t loc, size_t parsed_size) {
    return fuzz_span_in_bounds(loc.start, loc.length, parsed_size);
}

#ifndef PRISM_FUZZ_NO_VISIT_NODE
static bool fuzz_heredoc_span_contains(
    const uint8_t *source,
    size_t parsed_size,
    pm_location_t opening_pm_loc,
    pm_location_t closing_pm_loc,
    uint32_t probe
) {
    fuzz_span_t opening_loc = fuzz_loc_span(opening_pm_loc, source);
    fuzz_span_t closing_loc = fuzz_loc_span(closing_pm_loc, source);
    if (!fuzz_is_heredoc_opening_span(opening_loc.start, opening_loc.length, source, parsed_size)) {
        return false;
    }
    size_t end_offset = parsed_size;
    if (closing_loc.length > 0 && fuzz_loc_in_bounds(closing_loc, parsed_size)) {
        end_offset = (size_t) closing_loc.start + (size_t) closing_loc.length;
    }
    return probe >= opening_loc.start && (size_t) probe <= end_offset;
}

static pm_visit_result_t fuzz_line_offset_visit(const pm_node_t *node, void *data) {
    fuzz_line_offset_ctx_t *st = (fuzz_line_offset_ctx_t *) data;
    fuzz_span_t node_loc = fuzz_loc_span(node->location, st->source);
    bool in_node_loc = fuzz_loc_in_bounds(node_loc, st->parsed_size) &&
        st->probe >= node_loc.start &&
        (size_t) st->probe <= (size_t) node_loc.start + (size_t) node_loc.length;

    pm_location_t open_pm_loc;
    pm_location_t close_pm_loc;
    if (fuzz_heredoc_node_locs(node, &open_pm_loc, &close_pm_loc)) {
        if (fuzz_heredoc_span_contains(st->source, st->parsed_size, open_pm_loc, close_pm_loc, st->probe)) {
            st->ctx = "heredoc";
        } else if (in_node_loc) {
            st->ctx = fuzz_node_type_name(node->type);
        }
        return PM_VISIT_DESCEND;
    }

    switch (PM_NODE_TYPE(node)) {
        case PM_SYMBOL_NODE:
        case PM_INTERPOLATED_SYMBOL_NODE:
        case PM_REGULAR_EXPRESSION_NODE:
        case PM_INTERPOLATED_REGULAR_EXPRESSION_NODE:
        case PM_MATCH_LAST_LINE_NODE:
        case PM_INTERPOLATED_MATCH_LAST_LINE_NODE:
            if (in_node_loc) {
                st->ctx = fuzz_node_type_name(node->type);
            }
            break;
        case PM_ARRAY_NODE: {
            const pm_array_node_t *cast = (const pm_array_node_t *) node;
            fuzz_span_t open_loc = fuzz_loc_span(cast->opening_loc, st->source);
            if (in_node_loc && open_loc.length >= 2 &&
                fuzz_loc_in_bounds(open_loc, st->parsed_size) &&
                st->source[open_loc.start] == '%') {
                st->ctx = "percent_array";
            }
            break;
        }
        default:
            break;
    }

    return PM_VISIT_DESCEND;
}
#endif

typedef struct {
    const uint8_t *source;
    size_t parsed_size;
    uint32_t probe;
    const char *found;
} fuzz_line_offset_comment_ctx_t;

static void fuzz_line_offset_check_comment(const pm_comment_t *c, void *data) {
    fuzz_line_offset_comment_ctx_t *st = (fuzz_line_offset_comment_ctx_t *) data;
    if (st->found != NULL) return;
    fuzz_span_t loc = fuzz_loc_span(fuzz_comment_location(c), st->source);
    if (fuzz_loc_in_bounds(loc, st->parsed_size) &&
        st->probe >= loc.start &&
        (size_t) st->probe <= (size_t) loc.start + (size_t) loc.length) {
        st->found = fuzz_comment_type(c) == PM_COMMENT_EMBDOC ? "embdoc" : "inline_comment";
    }
}

static const char *fuzz_line_offset_context(
    const pm_parser_t *parser,
    const pm_node_t *root,
    const uint8_t *source,
    size_t parsed_size,
    uint32_t offset
) {
    uint32_t probe = (size_t) offset <= parsed_size
        ? (offset > 0 ? offset - 1 : 0)
        : (parsed_size > 0 ? (uint32_t) (parsed_size - 1) : 0);

    fuzz_span_t data_loc = fuzz_loc_span(*fuzz_parser_data_loc(parser), source);
    if (data_loc.length > 0 && fuzz_loc_in_bounds(data_loc, parsed_size) &&
        probe >= data_loc.start &&
        (size_t) probe <= (size_t) data_loc.start + (size_t) data_loc.length) {
        return "data";
    }

    fuzz_line_offset_comment_ctx_t comment_ctx = {
        .source = source,
        .parsed_size = parsed_size,
        .probe = probe,
        .found = NULL,
    };
#ifdef PRISM_FUZZ_LIST_ITERATORS
    for (const pm_comment_t *c = (const pm_comment_t *) parser->comment_list.head; c != NULL && comment_ctx.found == NULL; c = (const pm_comment_t *) c->node.next) {
        fuzz_line_offset_check_comment(c, &comment_ctx);
    }
#elif defined(PRISM_FUZZ_ITER_OBJS)
    {
        pm_comments_iter_t *c_iter = pm_parser_comments(parser);
        for (const pm_comment_t *c = pm_comments_iter_next(c_iter); c != NULL && comment_ctx.found == NULL; c = pm_comments_iter_next(c_iter)) {
            fuzz_line_offset_check_comment(c, &comment_ctx);
        }
        pm_comments_iter_free(c_iter);
    }
#elif defined(PRISM_FUZZ_EACH_ITERATORS)
    pm_parser_comments_each(parser, fuzz_line_offset_check_comment, &comment_ctx);
#else
    for (const pm_comment_t *c = pm_parser_comments_first(parser); c != NULL && comment_ctx.found == NULL; c = pm_comment_next(c)) {
        fuzz_line_offset_check_comment(c, &comment_ctx);
    }
#endif
    if (comment_ctx.found != NULL) {
        return comment_ctx.found;
    }

#ifdef PRISM_FUZZ_NO_VISIT_NODE
    (void) root;
    return "default";
#else
    fuzz_line_offset_ctx_t st = {
        .source = source,
        .parsed_size = parsed_size,
        .probe = probe,
        .ctx = "default",
    };
    if (root != NULL) {
        pm_visit_node(root, fuzz_line_offset_visit, &st);
    }
    return st.ctx;
#endif
}

typedef struct {
    const uint8_t *source;
    size_t parsed_size;
    bool check_order;
    uint32_t prev_start;
    const char *prev_type;
    bool first;
} fuzz_comment_check_state_t;

static void fuzz_check_error_diag(const pm_diagnostic_t *d, void *data) {
    const fuzz_diag_check_ctx_t *ctx = (const fuzz_diag_check_ctx_t *) data;
    fuzz_span_t loc = fuzz_loc_span(fuzz_diag_location(d), ctx->source);
    const char *kind = fuzz_span_violation_kind(loc.start, loc.length, ctx->parsed_size, false);
    if (kind != NULL) {
        const char *diag_type = fuzz_diag_type(d);
        fuzz_invariant_fail(
            "INVARIANT[diagnostic]: list=error type=%s kind=%s [detail: level=%u start=%u length=%u parsed_size=%zu]\n",
            diag_type[0] != '\0' ? diag_type : "unknown",
            kind,
            fuzz_diag_error_level(d),
            loc.start,
            loc.length,
            ctx->parsed_size
        );
    }

#ifndef PRISM_FUZZ_NO_DIAGNOSTIC_TYPE
    const char *diag_type = fuzz_diag_type(d);
    if (diag_type != NULL) {
        if (strcmp(diag_type, "mixed_encoding") == 0) {
            if (loc.length == 0) {
                fuzz_invariant_fail(
                    "INVARIANT[diagnostic_semantic]: type=mixed_encoding kind=zero_length [detail: level=%u start=%u length=%u parsed_size=%zu]\n",
                    fuzz_diag_error_level(d),
                    loc.start,
                    loc.length,
                    ctx->parsed_size
                );
            }
            bool has_non_ascii_or_escape = false;
            for (uint32_t i = 0; i < loc.length; i++) {
                uint8_t byte = ctx->source[loc.start + i];
                if (byte >= 0x80 || byte == '\\') {
                    has_non_ascii_or_escape = true;
                    break;
                }
            }
            if (!has_non_ascii_or_escape && !fuzz_is_unicode_escape_mixed_encoding_span(ctx->source, loc.start, loc.length)) {
                fuzz_invariant_fail(
                    "INVARIANT[diagnostic_semantic]: type=mixed_encoding kind=wrong_byte [detail: level=%u byte=0x%02x start=%u length=%u parsed_size=%zu]\n",
                    fuzz_diag_error_level(d),
                    (unsigned) ctx->source[loc.start],
                    loc.start,
                    loc.length,
                    ctx->parsed_size
                );
            }
        } else if (strcmp(diag_type, "escape_invalid_unicode_literal") == 0 && loc.length == 0) {
            fuzz_invariant_fail(
                "INVARIANT[diagnostic_semantic]: type=escape_invalid_unicode_literal kind=zero_length [detail: level=%u start=%u length=%u parsed_size=%zu]\n",
                fuzz_diag_error_level(d),
                loc.start,
                loc.length,
                ctx->parsed_size
            );
        }
    }
#endif
}

static void fuzz_check_warning_diag(const pm_diagnostic_t *d, void *data) {
    const fuzz_diag_check_ctx_t *ctx = (const fuzz_diag_check_ctx_t *) data;
    fuzz_span_t loc = fuzz_loc_span(fuzz_diag_location(d), ctx->source);
    const char *kind = fuzz_span_violation_kind(loc.start, loc.length, ctx->parsed_size, false);
    if (kind != NULL) {
        const char *diag_type = fuzz_diag_type(d);
        fuzz_invariant_fail(
            "INVARIANT[diagnostic]: list=warning type=%s kind=%s [detail: level=%u start=%u length=%u parsed_size=%zu]\n",
            diag_type[0] != '\0' ? diag_type : "unknown",
            kind,
            fuzz_diag_warning_level(d),
            loc.start,
            loc.length,
            ctx->parsed_size
        );
    }
}

static void fuzz_check_comment(const pm_comment_t *c, void *data) {
    fuzz_comment_check_state_t *st = (fuzz_comment_check_state_t *) data;
    fuzz_span_t loc = fuzz_loc_span(fuzz_comment_location(c), st->source);
    const char *comment_type = fuzz_comment_type(c) == PM_COMMENT_EMBDOC ? "embdoc" : "inline";
    const char *kind = fuzz_span_violation_kind(loc.start, loc.length, st->parsed_size, false);
    if (kind != NULL) {
        fuzz_invariant_fail(
            "INVARIANT[comment]: type=%s kind=%s [detail: start=%u length=%u parsed_size=%zu]\n",
            comment_type,
            kind,
            loc.start,
            loc.length,
            st->parsed_size
        );
    }
    if (st->check_order && !st->first && loc.start < st->prev_start) {
        fuzz_invariant_fail(
            "INVARIANT[comment]: type=%s prev_type=%s kind=unsorted [detail: prev_start=%u start=%u parsed_size=%zu]\n",
            comment_type,
            st->prev_type,
            st->prev_start,
            loc.start,
            st->parsed_size
        );
    }
    st->prev_start = loc.start;
    st->prev_type = comment_type;
    st->first = false;
}

static void fuzz_check_magic_comment(const pm_magic_comment_t *mc, void *data) {
    const fuzz_diag_check_ctx_t *ctx = (const fuzz_diag_check_ctx_t *) data;
    fuzz_span_t k = fuzz_magic_comment_key_span(mc, ctx->source);
    const char *k_kind = fuzz_span_violation_kind(k.start, k.length, ctx->parsed_size, false);
    if (k_kind != NULL) {
        fuzz_invariant_fail(
            "INVARIANT[magic_comment]: field=key kind=%s [detail: start=%u length=%u parsed_size=%zu]\n",
            k_kind,
            k.start,
            k.length,
            ctx->parsed_size
        );
    }
    fuzz_span_t v = fuzz_magic_comment_value_span(mc, ctx->source);
    const char *v_kind = fuzz_span_violation_kind(v.start, v.length, ctx->parsed_size, false);
    if (v_kind != NULL) {
        fuzz_invariant_fail(
            "INVARIANT[magic_comment]: field=value kind=%s [detail: start=%u length=%u parsed_size=%zu]\n",
            v_kind,
            v.start,
            v.length,
            ctx->parsed_size
        );
    }
}

static inline const char *fuzz_safe_node_name(pm_node_type_t type) {
    const char *name = pm_node_type(type);
    return (name != NULL && name[0] != '\0') ? name : "UNKNOWN";
}

#if !defined(PRISM_FUZZ_NO_VISIT_NODE) && !defined(PRISM_FUZZ_POINTER_LOCATIONS) && !defined(PRISM_FUZZ_NO_NODE_RELATIONS)
static void fuzz_check_node_list_relations(
    const pm_node_t *parent,
    pm_location_t opening_loc,
    pm_location_t closing_loc,
    const pm_node_list_t *list,
    const uint8_t *source,
    size_t parsed_size
) {
    pm_location_t parent_loc = parent->location;
    bool opening_valid = opening_loc.length > 0 && fuzz_span_violation_kind(opening_loc.start, opening_loc.length, parsed_size, false) == NULL;
    bool closing_valid = closing_loc.length > 0 && fuzz_span_violation_kind(closing_loc.start, closing_loc.length, parsed_size, false) == NULL;
    bool is_heredoc = fuzz_is_heredoc_opening_span(opening_loc.start, opening_loc.length, source, parsed_size);
    const char *parent_name = fuzz_safe_node_name(parent->type);
    uint64_t pend = (uint64_t) parent_loc.start + (uint64_t) parent_loc.length;
    uint64_t opening_end = (uint64_t) opening_loc.start + (uint64_t) opening_loc.length;

    const pm_node_t *prev_node = NULL;
    uint32_t prev_start = 0;
    uint32_t prev_len = 0;
    uint64_t prev_end = 0;

    for (size_t i = 0; i < list->size; i++) {
        const pm_node_t *child = list->nodes[i];
        if (child == NULL) continue;

        pm_location_t cloc = child->location;
        if (fuzz_span_violation_kind(cloc.start, cloc.length, parsed_size, false) != NULL) {
            continue;
        }

        const char *child_name = fuzz_safe_node_name(child->type);
        uint64_t cend = (uint64_t) cloc.start + (uint64_t) cloc.length;

        if (prev_node != NULL && (uint64_t) cloc.start < prev_end &&
            !fuzz_node_edge_has_error_recovery(prev_node, prev_end, true) &&
            !fuzz_node_edge_has_error_recovery(child, (uint64_t) cloc.start, false)) {
            const char *kind = (cloc.start == prev_start && cloc.length == prev_len && prev_len > 0)
                ? "duplicate_part"
                : "sibling_overlap";
            fuzz_invariant_fail(
                "INVARIANT[node_relation]: parent=%s child=%s kind=%s [detail: idx=%zu prev_start=%u prev_len=%u start=%u len=%u]\n",
                parent_name,
                child_name,
                kind,
                i,
                prev_start,
                prev_len,
                cloc.start,
                cloc.length
            );
        }

        if (!is_heredoc) {
            if (cloc.start < parent_loc.start &&
                !fuzz_node_edge_has_error_recovery(child, (uint64_t) cloc.start, false)) {
                fuzz_invariant_fail(
                    "INVARIANT[node_relation]: parent=%s child=%s kind=start_after_child [detail: idx=%zu parent_start=%u child_start=%u]\n",
                    parent_name,
                    child_name,
                    i,
                    parent_loc.start,
                    cloc.start
                );
            }
            if (cend > pend &&
                !fuzz_node_edge_has_error_recovery(child, cend, true)) {
                fuzz_invariant_fail(
                    "INVARIANT[node_relation]: parent=%s child=%s kind=child_oob [detail: idx=%zu parent_end=%llu child_end=%llu]\n",
                    parent_name,
                    child_name,
                    i,
                    (unsigned long long) pend,
                    (unsigned long long) cend
                );
            }
            if (opening_valid && (uint64_t) cloc.start < opening_end &&
                !fuzz_node_edge_has_error_recovery(child, (uint64_t) cloc.start, false)) {
                fuzz_invariant_fail(
                    "INVARIANT[node_relation]: parent=%s child=%s kind=child_before_opening [detail: idx=%zu opening_end=%llu child_start=%u]\n",
                    parent_name,
                    child_name,
                    i,
                    (unsigned long long) opening_end,
                    cloc.start
                );
            }
            if (closing_valid && cend > (uint64_t) closing_loc.start &&
                !fuzz_node_edge_has_error_recovery(child, cend, true)) {
                fuzz_invariant_fail(
                    "INVARIANT[node_relation]: parent=%s child=%s kind=child_after_closing [detail: idx=%zu closing_start=%u child_end=%llu]\n",
                    parent_name,
                    child_name,
                    i,
                    closing_loc.start,
                    (unsigned long long) cend
                );
            }
        }

        prev_node = child;
        prev_start = cloc.start;
        prev_len = cloc.length;
        prev_end = cend;
    }
}

static void fuzz_check_node_relations(const pm_node_t *node, const uint8_t *source, size_t parsed_size) {
    switch (node->type) {
        case PM_ARRAY_NODE: {
            const pm_array_node_t *arr = (const pm_array_node_t *) node;
            fuzz_check_node_list_relations(node, arr->opening_loc, arr->closing_loc, &arr->elements, source, parsed_size);
            break;
        }
        case PM_INTERPOLATED_SYMBOL_NODE: {
            const pm_interpolated_symbol_node_t *sym = (const pm_interpolated_symbol_node_t *) node;
            fuzz_check_node_list_relations(node, sym->opening_loc, sym->closing_loc, &sym->parts, source, parsed_size);
            break;
        }
        case PM_INTERPOLATED_STRING_NODE: {
            const pm_interpolated_string_node_t *str = (const pm_interpolated_string_node_t *) node;
            fuzz_check_node_list_relations(node, str->opening_loc, str->closing_loc, &str->parts, source, parsed_size);
            break;
        }
        case PM_INTERPOLATED_X_STRING_NODE: {
            const pm_interpolated_x_string_node_t *xstr = (const pm_interpolated_x_string_node_t *) node;
            fuzz_check_node_list_relations(node, xstr->opening_loc, xstr->closing_loc, &xstr->parts, source, parsed_size);
            break;
        }
        case PM_INTERPOLATED_REGULAR_EXPRESSION_NODE: {
            const pm_interpolated_regular_expression_node_t *re = (const pm_interpolated_regular_expression_node_t *) node;
            fuzz_check_node_list_relations(node, re->opening_loc, re->closing_loc, &re->parts, source, parsed_size);
            break;
        }
        default:
            break;
    }
}
#endif

#if !defined(PRISM_FUZZ_NO_VISIT_NODE) && !defined(PRISM_FUZZ_NO_SUB_LOCATIONS)
#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static void fuzz_check_sub_location(
    const pm_node_t *node,
    const char *field_name,
    pm_location_t raw_loc,
    const fuzz_node_check_t *ctx
) {
    fuzz_span_t loc = fuzz_loc_span(raw_loc, ctx->source);
    const char *kind = fuzz_span_violation_kind(loc.start, loc.length, ctx->parsed_size, false);
    if (kind != NULL) {
        fuzz_invariant_fail(
            "INVARIANT[node_sub_location]: type=%s field=%s kind=%s [detail: parent=%s start=%u length=%u parsed_size=%zu]\n",
            fuzz_safe_node_name(node->type),
            field_name,
            kind,
            ctx->parent_type == 0 ? "ROOT" : fuzz_safe_node_name(ctx->parent_type),
            loc.start,
            loc.length,
            ctx->parsed_size
        );
    }
}

static void fuzz_check_node_sub_locations(const pm_node_t *node, const fuzz_node_check_t *ctx) {
    switch (node->type) {
#include <node_locations.inc>
        default:
            break;
    }
}
#endif

static void fuzz_for_each_error_diag(pm_parser_t *parser, void (*fn)(const pm_diagnostic_t *, void *), void *ctx) {
#ifdef PRISM_FUZZ_LIST_ITERATORS
    for (const pm_diagnostic_t *d = (const pm_diagnostic_t *) parser->error_list.head; d != NULL; d = (const pm_diagnostic_t *) d->node.next) {
        fn(d, ctx);
    }
#elif defined(PRISM_FUZZ_ITER_OBJS)
    pm_diagnostics_iter_t *err_iter = pm_parser_errors(parser);
    for (const pm_diagnostic_t *d = pm_diagnostics_iter_next(err_iter); d != NULL; d = pm_diagnostics_iter_next(err_iter)) {
        fn(d, ctx);
    }
    pm_diagnostics_iter_free(err_iter);
#elif defined(PRISM_FUZZ_EACH_ITERATORS)
    pm_parser_errors_each(parser, fn, ctx);
#else
    for (const pm_diagnostic_t *d = pm_parser_errors_first(parser); d != NULL; d = pm_diagnostic_next(d)) {
        fn(d, ctx);
    }
#endif
}

#if !defined(PRISM_FUZZ_NO_VISIT_NODE) && !defined(PRISM_FUZZ_POINTER_LOCATIONS) && !defined(PRISM_FUZZ_NO_DIAGNOSTIC_TYPE) && !defined(PRISM_FUZZ_NO_NODE_RELATIONS)
static void fuzz_check_depth_or_stack_cb(const pm_diagnostic_t *d, void *data) {
    bool *found = (bool *) data;
    if (*found) return;
    const char *diag_type = fuzz_diag_type(d);
    if (diag_type != NULL && (strcmp(diag_type, "nesting_too_deep") == 0 || strcmp(diag_type, "stack_exhausted") == 0)) {
        *found = true;
    }
}

static bool fuzz_parser_has_depth_or_stack_error(pm_parser_t *parser) {
    bool found = false;
    fuzz_for_each_error_diag(parser, fuzz_check_depth_or_stack_cb, &found);
    return found;
}
#endif

static pm_visit_result_t check_node_location(const pm_node_t *node, void *data) {
    const fuzz_node_check_t *ctx = (const fuzz_node_check_t *) data;
    fuzz_span_t loc = fuzz_loc_span(node->location, ctx->source);
    const char *kind = fuzz_span_violation_kind(loc.start, loc.length, ctx->parsed_size, false);
    if (kind != NULL) {
        const char *type_name = fuzz_safe_node_name(node->type);
        const char *parent_name = ctx->parent_type == 0 ? "ROOT" : fuzz_safe_node_name(ctx->parent_type);
        fuzz_invariant_fail(
            "INVARIANT[node_location]: type=%s kind=%s [detail: parent=%s start=%u length=%u parsed_size=%zu]\n",
            type_name,
            kind,
            parent_name,
            loc.start,
            loc.length,
            ctx->parsed_size
        );
    }

#if !defined(PRISM_FUZZ_NO_VISIT_NODE) && !defined(PRISM_FUZZ_NO_PARSER_ERRORS_SIZE)
    if (PM_NODE_TYPE_P(node, PM_ERROR_RECOVERY_NODE) && ctx->parser != NULL && pm_parser_errors_size(ctx->parser) == 0) {
        const char *parent_name = ctx->parent_type == 0 ? "ROOT" : fuzz_safe_node_name(ctx->parent_type);
        fuzz_invariant_fail(
            "INVARIANT[error_recovery]: kind=zero_errors [detail: parent=%s start=%u length=%u parsed_size=%zu]\n",
            parent_name,
            loc.start,
            loc.length,
            ctx->parsed_size
        );
    }
#endif

#ifdef PRISM_FUZZ_NO_VISIT_NODE
    (void) node;
    (void) ctx;
#else
#if !defined(PRISM_FUZZ_POINTER_LOCATIONS) && !defined(PRISM_FUZZ_NO_DIAGNOSTIC_TYPE) && !defined(PRISM_FUZZ_NO_NODE_RELATIONS)
    size_t cur_depth = ctx->depth + (fuzz_is_iterative_chain_node(ctx->parent_type, node->type) ? 0u : 1u);
    if (cur_depth > FUZZ_MAX_NON_ITER_DEPTH && ctx->parser != NULL && !fuzz_parser_has_depth_or_stack_error(ctx->parser)) {
        fuzz_invariant_fail(
            "INVARIANT[recursion_depth]: type=%s kind=depth_exceeded [detail: depth=%zu limit=%zu max=%u]\n",
            fuzz_safe_node_name(node->type),
            cur_depth,
            (size_t) FUZZ_MAX_NON_ITER_DEPTH,
            (unsigned) (PRISM_DEPTH_MAXIMUM)
        );
    }
#else
    size_t cur_depth = ctx->depth + 1u;
#endif
    fuzz_node_check_t child_ctx = {
        .source = ctx->source,
        .parsed_size = ctx->parsed_size,
        .parent_type = node->type,
        .parser = ctx->parser,
        .depth = cur_depth,
    };
    pm_visit_child_nodes(node, check_node_location, &child_ctx);
#if !defined(PRISM_FUZZ_NO_SUB_LOCATIONS)
    fuzz_check_node_sub_locations(node, ctx);
#endif
#if !defined(PRISM_FUZZ_POINTER_LOCATIONS) && !defined(PRISM_FUZZ_NO_NODE_RELATIONS)
    /* Check container relations after descendants so child node_location
     * underflows/OOB report before parent list geometry checks. */
    fuzz_check_node_relations(node, ctx->source, ctx->parsed_size);
#endif
#endif
    return PM_VISIT_SKIP;
}

#ifdef SLOW
static inline void fuzz_buffer_reset(pm_buffer_t *buffer) {
#ifdef PRISM_FUZZ_NO_BUFFER_CLEAR
    buffer->length = 0;
#else
    pm_buffer_clear(buffer);
#endif
}

#if PRISM_FUZZ_STREAM_ENABLED && !defined(PRISM_FUZZ_NO_STREAM_DIFF) && \
    !defined(PRISM_FUZZ_LEGACY_NO_ARENA) && !defined(PRISM_FUZZ_LEGACY_ARENA_STRUCT) && !defined(PRISM_FUZZ_LEGACY_PARSER_INIT) && \
    !defined(PRISM_FUZZ_LEGACY_PARSER_DATA_LOC) && !defined(PRISM_FUZZ_LEGACY_BUFFER_STRUCT) && !defined(PRISM_FUZZ_NO_PARSER_ERRORS_SIZE)
static uint64_t fuzz_stream_node_end(const pm_node_t *node, size_t max_size) {
#ifndef PRISM_FUZZ_POINTER_LOCATIONS
    if (node != NULL && fuzz_span_in_bounds(node->location.start, node->location.length, max_size)) {
        return (uint64_t) node->location.start + (uint64_t) node->location.length;
    }
#else
    (void) node;
    (void) max_size;
#endif
    return 0;
}

/* Only treat \0, ^D, ^Z as having halted lexing before __END__ when the byte is
 * at or past the last AST span end; earlier bytes (e.g., #\x00 in a comment)
 * must not mask a spurious __END__ stop later in a string/heredoc. */
static bool fuzz_has_eof_control_byte(const uint8_t *buf, size_t len, uint64_t ast_end) {
    for (size_t i = 0; i < len; i++) {
        uint8_t byte = buf[i];
        if ((byte == '\0' || byte == '\004' || byte == '\032') && (uint64_t) i + 1 >= ast_end) {
            return true;
        }
    }
    return false;
}

static void fuzz_assert_serialized_equal(
    pm_parser_t *stream_parser,
    pm_node_t *stream_node,
    pm_parser_t *ref_parser,
    pm_node_t *ref_node,
    const pm_buffer_t *stream_buf,
    const pm_buffer_t *ref_buf,
    const char *kind,
    const char *ref_label,
    size_t parsed_size,
    size_t size
);

#if !defined(PRISM_FUZZ_NO_VISIT_NODE) && !defined(PRISM_FUZZ_POINTER_LOCATIONS) && \
    !defined(PRISM_FUZZ_LIST_ITERATORS) && !defined(PRISM_FUZZ_ITER_OBJS) && \
    !defined(PRISM_FUZZ_EACH_ITERATORS) && !defined(PRISM_FUZZ_LEGACY_PARSER_LINE_OFFSETS) && \
    !defined(PRISM_FUZZ_PARSER_NEWLINE_LIST)
#define FUZZ_STREAM_DIFF_CLASSIFY_MAX_NODES 2048

typedef struct {
    const pm_node_t *nodes[FUZZ_STREAM_DIFF_CLASSIFY_MAX_NODES];
    size_t count;
    bool truncated;
} fuzz_stream_node_seq_t;

static pm_visit_result_t fuzz_collect_stream_nodes_cb(const pm_node_t *node, void *data) {
    fuzz_stream_node_seq_t *seq = (fuzz_stream_node_seq_t *) data;
    if (seq->count < FUZZ_STREAM_DIFF_CLASSIFY_MAX_NODES) {
        seq->nodes[seq->count++] = node;
        return PM_VISIT_DESCEND;
    }
    seq->truncated = true;
    return PM_VISIT_STOP;
}

static void fuzz_classify_stream_divergence(
    pm_parser_t *stream_parser,
    pm_node_t *stream_node,
    pm_parser_t *ref_parser,
    pm_node_t *ref_node,
    char *sub_buf,
    size_t sub_cap,
    char *type_buf,
    size_t type_cap
) {
    snprintf(sub_buf, sub_cap, "unknown");
    type_buf[0] = '\0';

    if (stream_parser != NULL && ref_parser != NULL) {
        if (pm_parser_continuable(stream_parser) != pm_parser_continuable(ref_parser)) {
            snprintf(sub_buf, sub_cap, "continuable");
            return;
        }

        const pm_location_t *sd = pm_parser_data_loc(stream_parser);
        const pm_location_t *rd = pm_parser_data_loc(ref_parser);
        bool sd_present = sd != NULL && sd->length > 0;
        bool rd_present = rd != NULL && rd->length > 0;
        if (sd_present != rd_present || (sd_present && sd->start != rd->start)) {
            snprintf(sub_buf, sub_cap, "data_loc");
            return;
        }

        if (pm_parser_errors_size(stream_parser) != pm_parser_errors_size(ref_parser)) {
            snprintf(sub_buf, sub_cap, "error_count");
            return;
        }
        const pm_diagnostic_t *se = pm_parser_errors_first(stream_parser);
        const pm_diagnostic_t *re = pm_parser_errors_first(ref_parser);
        while (se != NULL && re != NULL) {
            const char *st = fuzz_diag_type(se);
            const char *rt = fuzz_diag_type(re);
            pm_location_t sl = fuzz_diag_location(se);
            pm_location_t rl = fuzz_diag_location(re);
            if (strcmp(st, rt) != 0) {
                snprintf(sub_buf, sub_cap, "error_type");
                snprintf(type_buf, type_cap, "%s", st[0] != '\0' ? st : "unknown");
                return;
            }
            if (sl.start != rl.start || sl.length != rl.length) {
                snprintf(sub_buf, sub_cap, "error_loc");
                snprintf(type_buf, type_cap, "%s", st[0] != '\0' ? st : "unknown");
                return;
            }
            se = pm_diagnostic_next(se);
            re = pm_diagnostic_next(re);
        }

        if (pm_parser_warnings_size(stream_parser) != pm_parser_warnings_size(ref_parser)) {
            snprintf(sub_buf, sub_cap, "warning_count");
            return;
        }
        const pm_diagnostic_t *sw = pm_parser_warnings_first(stream_parser);
        const pm_diagnostic_t *rw = pm_parser_warnings_first(ref_parser);
        while (sw != NULL && rw != NULL) {
            const char *st = fuzz_diag_type(sw);
            const char *rt = fuzz_diag_type(rw);
            pm_location_t sl = fuzz_diag_location(sw);
            pm_location_t rl = fuzz_diag_location(rw);
            if (strcmp(st, rt) != 0) {
                snprintf(sub_buf, sub_cap, "warning_type");
                snprintf(type_buf, type_cap, "%s", st[0] != '\0' ? st : "unknown");
                return;
            }
            if (sl.start != rl.start || sl.length != rl.length) {
                snprintf(sub_buf, sub_cap, "warning_loc");
                snprintf(type_buf, type_cap, "%s", st[0] != '\0' ? st : "unknown");
                return;
            }
            sw = pm_diagnostic_next(sw);
            rw = pm_diagnostic_next(rw);
        }
    }

    if (stream_node != NULL && ref_node != NULL) {
        fuzz_stream_node_seq_t s_seq = { .count = 0, .truncated = false };
        fuzz_stream_node_seq_t r_seq = { .count = 0, .truncated = false };
        pm_visit_node(stream_node, fuzz_collect_stream_nodes_cb, &s_seq);
        pm_visit_node(ref_node, fuzz_collect_stream_nodes_cb, &r_seq);

        size_t common = s_seq.count < r_seq.count ? s_seq.count : r_seq.count;
        for (size_t i = 0; i < common; i++) {
            const pm_node_t *sn = s_seq.nodes[i];
            const pm_node_t *rn = r_seq.nodes[i];
            if (sn->type != rn->type) {
                snprintf(sub_buf, sub_cap, "node_type");
                snprintf(type_buf, type_cap, "%s", fuzz_safe_node_name(sn->type));
                return;
            }
            if (sn->flags != rn->flags) {
                snprintf(sub_buf, sub_cap, "node_flags");
                snprintf(type_buf, type_cap, "%s", fuzz_safe_node_name(sn->type));
                return;
            }
            /* ProgramNode/StatementsNode outer spans inherit trailing child ends,
             * so continue to the deepest child whose own span diverged first. */
            if (sn->location.start != rn->location.start || sn->location.length != rn->location.length) {
                snprintf(sub_buf, sub_cap, "node_loc");
                snprintf(type_buf, type_cap, "%s", fuzz_safe_node_name(sn->type));
            }
        }
        if (s_seq.count != r_seq.count && !s_seq.truncated && !r_seq.truncated) {
            const pm_node_t *extra = s_seq.count > r_seq.count ? s_seq.nodes[common] : r_seq.nodes[common];
            snprintf(sub_buf, sub_cap, "node_count");
            snprintf(type_buf, type_cap, "%s", fuzz_safe_node_name(extra->type));
            return;
        }
        if (strcmp(sub_buf, "node_loc") == 0) {
            return;
        }
    }

    if (stream_parser != NULL && ref_parser != NULL) {
        const pm_line_offset_list_t *slo = pm_parser_line_offsets(stream_parser);
        const pm_line_offset_list_t *rlo = pm_parser_line_offsets(ref_parser);
        if (slo != NULL && rlo != NULL) {
            if (slo->size != rlo->size ||
                (slo->size > 0 && memcmp(slo->offsets, rlo->offsets, slo->size * sizeof(uint32_t)) != 0)) {
                snprintf(sub_buf, sub_cap, "line_offsets");
                return;
            }
        }
        if (pm_parser_comments_size(stream_parser) != pm_parser_comments_size(ref_parser)) {
            snprintf(sub_buf, sub_cap, "comments");
            return;
        }
        const pm_comment_t *sc = pm_parser_comments_first(stream_parser);
        const pm_comment_t *rc = pm_parser_comments_first(ref_parser);
        while (sc != NULL && rc != NULL) {
            pm_location_t sl = fuzz_comment_location(sc);
            pm_location_t rl = fuzz_comment_location(rc);
            if (fuzz_comment_type(sc) != fuzz_comment_type(rc) || sl.start != rl.start || sl.length != rl.length) {
                snprintf(sub_buf, sub_cap, "comments");
                return;
            }
            sc = pm_comment_next(sc);
            rc = pm_comment_next(rc);
        }
        if (pm_parser_magic_comments_size(stream_parser) != pm_parser_magic_comments_size(ref_parser)) {
            snprintf(sub_buf, sub_cap, "magic_comments");
            return;
        }
    }

    snprintf(sub_buf, sub_cap, "leaf_or_subloc");
}
#endif

static void fuzz_fail_classified_stream_diff(
    const char *kind,
    pm_parser_t *stream_parser,
    pm_node_t *stream_node,
    pm_parser_t *ref_parser,
    pm_node_t *ref_node,
    size_t parsed_size,
    size_t size,
    const char *len_a_label,
    size_t len_a,
    const char *len_b_label,
    size_t len_b
) {
#if !defined(PRISM_FUZZ_NO_VISIT_NODE) && !defined(PRISM_FUZZ_POINTER_LOCATIONS) && \
    !defined(PRISM_FUZZ_LIST_ITERATORS) && !defined(PRISM_FUZZ_ITER_OBJS) && \
    !defined(PRISM_FUZZ_EACH_ITERATORS) && !defined(PRISM_FUZZ_LEGACY_PARSER_LINE_OFFSETS) && \
    !defined(PRISM_FUZZ_PARSER_NEWLINE_LIST)
    char sub_buf[32];
    char type_buf[64];
    fuzz_classify_stream_divergence(stream_parser, stream_node, ref_parser, ref_node, sub_buf, sizeof(sub_buf), type_buf, sizeof(type_buf));
    if (type_buf[0] != '\0') {
        fuzz_invariant_fail(
            "INVARIANT[stream_diff]: kind=%s sub=%s type=%s [detail: parsed_size=%zu size=%zu %s=%zu %s=%zu]\n",
            kind,
            sub_buf,
            type_buf,
            parsed_size,
            size,
            len_a_label,
            len_a,
            len_b_label,
            len_b
        );
    }
    fuzz_invariant_fail(
        "INVARIANT[stream_diff]: kind=%s sub=%s [detail: parsed_size=%zu size=%zu %s=%zu %s=%zu]\n",
        kind,
        sub_buf,
        parsed_size,
        size,
        len_a_label,
        len_a,
        len_b_label,
        len_b
    );
#else
    (void) stream_parser;
    (void) stream_node;
    (void) ref_parser;
    (void) ref_node;
    fuzz_invariant_fail(
        "INVARIANT[stream_diff]: kind=%s [detail: parsed_size=%zu size=%zu %s=%zu %s=%zu]\n",
        kind,
        parsed_size,
        size,
        len_a_label,
        len_a,
        len_b_label,
        len_b
    );
#endif
}

static bool fuzz_ser_read_varuint(const uint8_t *buf, size_t len, size_t *pos, uint32_t *out) {
    uint32_t val = 0;
    uint32_t shift = 0;
    for (;;) {
        if (*pos >= len) return false;
        uint8_t byte = buf[(*pos)++];
        if (shift >= 28U && (byte & 0x7fU) > 0x0fU) return false;
        val |= ((uint32_t) (byte & 0x7fU)) << shift;
        if ((byte & 0x80U) == 0U) break;
        shift += 7U;
    }
    if (out != NULL) *out = val;
    return true;
}

static bool fuzz_ser_skip_bytes(const uint8_t *buf, size_t len, size_t *pos) {
    uint32_t n = 0;
    if (!fuzz_ser_read_varuint(buf, len, pos, &n)) return false;
    if ((size_t) n > len - *pos) return false;
    *pos += (size_t) n;
    return true;
}

static bool fuzz_ser_skip_loc(const uint8_t *buf, size_t len, size_t *pos) {
    return fuzz_ser_read_varuint(buf, len, pos, NULL) &&
           fuzz_ser_read_varuint(buf, len, pos, NULL);
}

static bool fuzz_ser_skip_diag_list(const uint8_t *buf, size_t len, size_t *pos) {
    uint32_t count = 0;
    if (!fuzz_ser_read_varuint(buf, len, pos, &count)) return false;
    for (uint32_t i = 0; i < count; i++) {
        if (!fuzz_ser_read_varuint(buf, len, pos, NULL) ||
            !fuzz_ser_skip_bytes(buf, len, pos) ||
            !fuzz_ser_skip_loc(buf, len, pos) ||
            *pos >= len) {
            return false;
        }
        (*pos)++;
    }
    return true;
}

typedef struct {
    size_t pre_checksum_end;
    size_t line_offsets_start;
    size_t comments_start;
    size_t data_loc_start;
    size_t diag_start;
    size_t continuable_pos;
    size_t ast_start;
    size_t cpool_offset;
    uint32_t cpool_size;
    uint8_t has_data_loc;
} fuzz_ser_spans_t;

static bool fuzz_ser_parse_spans(const uint8_t *buf, size_t len, fuzz_ser_spans_t *out) {
    if (buf == NULL || len < 10U || memcmp(buf, "PRISM", 5U) != 0) return false;
    uint8_t only_sem = buf[8];
    size_t pos = 9U;

    if (!fuzz_ser_skip_bytes(buf, len, &pos) || !fuzz_ser_read_varuint(buf, len, &pos, NULL)) return false;
    out->pre_checksum_end = pos;
    if (len - pos < 8U) return false;
    pos += 8U;
    out->line_offsets_start = pos;

    uint32_t line_cnt = 0;
    if (!fuzz_ser_read_varuint(buf, len, &pos, &line_cnt)) return false;
    for (uint32_t i = 0; i < line_cnt; i++) {
        if (!fuzz_ser_read_varuint(buf, len, &pos, NULL)) return false;
    }
    out->comments_start = pos;

    if (only_sem == 0U) {
        uint32_t com_cnt = 0;
        if (!fuzz_ser_read_varuint(buf, len, &pos, &com_cnt)) return false;
        for (uint32_t i = 0; i < com_cnt; i++) {
            if (pos >= len) return false;
            pos++;
            if (!fuzz_ser_skip_loc(buf, len, &pos)) return false;
        }
        uint32_t att_cnt = 0;
        if (!fuzz_ser_read_varuint(buf, len, &pos, &att_cnt)) return false;
        for (uint32_t i = 0; i < att_cnt; i++) {
            uint32_t idx_cnt = 0;
            if (!fuzz_ser_read_varuint(buf, len, &pos, NULL) ||
                !fuzz_ser_read_varuint(buf, len, &pos, &idx_cnt)) {
                return false;
            }
            for (uint32_t j = 0; j < idx_cnt; j++) {
                if (!fuzz_ser_read_varuint(buf, len, &pos, NULL)) return false;
            }
        }
    }

    uint32_t mc_cnt = 0;
    if (!fuzz_ser_read_varuint(buf, len, &pos, &mc_cnt)) return false;
    for (uint32_t i = 0; i < mc_cnt; i++) {
        if (!fuzz_ser_skip_loc(buf, len, &pos) || !fuzz_ser_skip_loc(buf, len, &pos)) return false;
    }

    out->data_loc_start = pos;
    if (pos >= len) return false;
    uint8_t has_data_loc = buf[pos++];
    if (has_data_loc != 0U && !fuzz_ser_skip_loc(buf, len, &pos)) return false;
    out->has_data_loc = has_data_loc;
    out->diag_start = pos;

    if (!fuzz_ser_skip_diag_list(buf, len, &pos) ||
        !fuzz_ser_skip_diag_list(buf, len, &pos) ||
        pos >= len) {
        return false;
    }
    out->continuable_pos = pos;
    pos++;

    if (len - pos < 4U) return false;
    uint32_t cpool_off = 0;
    memcpy(&cpool_off, buf + pos, sizeof(uint32_t));
    pos += 4U;

    uint32_t cpool_sz = 0;
    if (!fuzz_ser_read_varuint(buf, len, &pos, &cpool_sz)) return false;
    if ((size_t) cpool_off < pos || (size_t) cpool_off > len) return false;
    if ((size_t) cpool_sz > (len - (size_t) cpool_off) / 8U) return false;

    out->ast_start = pos;
    out->cpool_offset = (size_t) cpool_off;
    out->cpool_size = cpool_sz;
    return true;
}

static bool fuzz_ser_diag_list_equiv(
    const uint8_t *a, size_t len_a, size_t *pos_a,
    const uint8_t *b, size_t len_b, size_t *pos_b,
    bool ignore_loc
) {
    uint32_t cnt_a = 0, cnt_b = 0;
    if (!fuzz_ser_read_varuint(a, len_a, pos_a, &cnt_a) ||
        !fuzz_ser_read_varuint(b, len_b, pos_b, &cnt_b) ||
        cnt_a != cnt_b) {
        return false;
    }
    for (uint32_t i = 0; i < cnt_a; i++) {
        uint32_t type_a = 0, type_b = 0, mlen_a = 0, mlen_b = 0;
        if (!fuzz_ser_read_varuint(a, len_a, pos_a, &type_a) ||
            !fuzz_ser_read_varuint(b, len_b, pos_b, &type_b) ||
            type_a != type_b) {
            return false;
        }
        if (!fuzz_ser_read_varuint(a, len_a, pos_a, &mlen_a) ||
            !fuzz_ser_read_varuint(b, len_b, pos_b, &mlen_b) ||
            mlen_a != mlen_b ||
            (size_t) mlen_a > len_a - *pos_a ||
            (size_t) mlen_b > len_b - *pos_b ||
            (mlen_a > 0U && memcmp(a + *pos_a, b + *pos_b, (size_t) mlen_a) != 0)) {
            return false;
        }
        *pos_a += (size_t) mlen_a;
        *pos_b += (size_t) mlen_b;

        uint32_t sa = 0, la = 0, sb = 0, lb = 0;
        if (!fuzz_ser_read_varuint(a, len_a, pos_a, &sa) ||
            !fuzz_ser_read_varuint(a, len_a, pos_a, &la) ||
            !fuzz_ser_read_varuint(b, len_b, pos_b, &sb) ||
            !fuzz_ser_read_varuint(b, len_b, pos_b, &lb)) {
            return false;
        }
        if (!ignore_loc && (sa != sb || la != lb)) return false;
        if (*pos_a >= len_a || *pos_b >= len_b) return false;
        if (a[(*pos_a)++] != b[(*pos_b)++]) return false;
    }
    return true;
}

/* Compare stream vs full-buffer pm_serialize outputs when parsed_size != size
 * (early-EOF or __END__): checksum, data_loc.length, trailing __END__ line_offsets
 * (> parsed_size), and EOF diagnostic offsets legitimately reflect size vs parsed_size,
 * while AST, constant pool, comments, diagnostic types/messages, and continuable must match. */
static bool fuzz_serialized_equiv_ignoring_eof_len(
    const pm_buffer_t *a_buf,
    const pm_buffer_t *b_buf,
    size_t parsed_size
) {
    const uint8_t *a = (const uint8_t *) pm_buffer_value(a_buf);
    const uint8_t *b = (const uint8_t *) pm_buffer_value(b_buf);
    size_t len_a = pm_buffer_length(a_buf);
    size_t len_b = pm_buffer_length(b_buf);
    fuzz_ser_spans_t sa;
    fuzz_ser_spans_t sb;
    if (!fuzz_ser_parse_spans(a, len_a, &sa) || !fuzz_ser_parse_spans(b, len_b, &sb)) {
        return false;
    }
    if (sa.pre_checksum_end != sb.pre_checksum_end ||
        memcmp(a, b, sa.pre_checksum_end) != 0) {
        return false;
    }

    size_t lpos_a = sa.line_offsets_start;
    size_t lpos_b = sb.line_offsets_start;
    uint32_t lcnt_a = 0, lcnt_b = 0;
    if (!fuzz_ser_read_varuint(a, len_a, &lpos_a, &lcnt_a) ||
        !fuzz_ser_read_varuint(b, len_b, &lpos_b, &lcnt_b) ||
        lcnt_a > lcnt_b ||
        (lcnt_b > lcnt_a && sb.has_data_loc == 0U)) {
        return false;
    }
    for (uint32_t i = 0; i < lcnt_a; i++) {
        uint32_t oa = 0, ob = 0;
        if (!fuzz_ser_read_varuint(a, len_a, &lpos_a, &oa) ||
            !fuzz_ser_read_varuint(b, len_b, &lpos_b, &ob) ||
            oa != ob) {
            return false;
        }
    }
    for (uint32_t i = lcnt_a; i < lcnt_b; i++) {
        uint32_t ob = 0;
        if (!fuzz_ser_read_varuint(b, len_b, &lpos_b, &ob) || (size_t) ob <= parsed_size) {
            return false;
        }
    }

    size_t com_a = sa.data_loc_start - sa.comments_start;
    size_t com_b = sb.data_loc_start - sb.comments_start;
    if (com_a != com_b || memcmp(a + sa.comments_start, b + sb.comments_start, com_a) != 0) {
        return false;
    }

    size_t dpos_a = sa.diag_start;
    size_t dpos_b = sb.diag_start;
    bool ignore_diag_loc = sb.has_data_loc != 0U;
    if (!fuzz_ser_diag_list_equiv(a, len_a, &dpos_a, b, len_b, &dpos_b, ignore_diag_loc) ||
        !fuzz_ser_diag_list_equiv(a, len_a, &dpos_a, b, len_b, &dpos_b, ignore_diag_loc) ||
        a[sa.continuable_pos] != b[sb.continuable_pos]) {
        return false;
    }

    size_t ast_len_a = sa.cpool_offset - sa.ast_start;
    size_t ast_len_b = sb.cpool_offset - sb.ast_start;
    if (sa.cpool_size != sb.cpool_size || ast_len_a != ast_len_b ||
        memcmp(a + sa.ast_start, b + sb.ast_start, ast_len_a) != 0) {
        return false;
    }
    for (uint32_t i = 0; i < sa.cpool_size; i++) {
        uint32_t off_a = 0, clen_a = 0, off_b = 0, clen_b = 0;
        memcpy(&off_a, a + sa.cpool_offset + (size_t) i * 8U, 4U);
        memcpy(&clen_a, a + sa.cpool_offset + (size_t) i * 8U + 4U, 4U);
        memcpy(&off_b, b + sb.cpool_offset + (size_t) i * 8U, 4U);
        memcpy(&clen_b, b + sb.cpool_offset + (size_t) i * 8U + 4U, 4U);
        if (clen_a != clen_b) return false;
        if ((size_t) off_a > len_a || (size_t) clen_a > len_a - (size_t) off_a) return false;
        if ((size_t) off_b > len_b || (size_t) clen_b > len_b - (size_t) off_b) return false;
        if (clen_a > 0U && memcmp(a + off_a, b + off_b, (size_t) clen_a) != 0) return false;
    }
    return true;
}

static void fuzz_assert_serialized_equal(
    pm_parser_t *stream_parser,
    pm_node_t *stream_node,
    pm_parser_t *ref_parser,
    pm_node_t *ref_node,
    const pm_buffer_t *stream_buf,
    const pm_buffer_t *ref_buf,
    const char *kind,
    const char *ref_label,
    size_t parsed_size,
    size_t size
) {
    size_t stream_len = pm_buffer_length(stream_buf);
    size_t ref_len = pm_buffer_length(ref_buf);
    if (stream_len != ref_len || memcmp(pm_buffer_value(stream_buf), pm_buffer_value(ref_buf), stream_len) != 0) {
        fuzz_fail_classified_stream_diff(
            kind,
            stream_parser,
            stream_node,
            ref_parser,
            ref_node,
            parsed_size,
            size,
            "stream_len",
            stream_len,
            ref_label,
            ref_len
        );
    }
}

static void fuzz_check_stream_diff(
    pm_parser_t *parser,
    pm_node_t *node,
    const uint8_t *source_buf,
    size_t size,
    size_t parsed_size,
    const pm_options_t *options,
    pm_buffer_t *stream_buf
) {
    pm_arena_t *ref_arena = pm_arena_new();
    pm_parser_t *ref_parser = pm_parser_new(ref_arena, source_buf, size, options);
    pm_node_t *ref_node = pm_parse(ref_parser);
    pm_buffer_t *ref_buf = pm_buffer_new();

    if ((node == NULL) != (ref_node == NULL)) {
        fuzz_invariant_fail(
            "INVARIANT[stream_diff]: kind=null_node [detail: stream_null=%d full_null=%d parsed_size=%zu size=%zu]\n",
            node == NULL ? 1 : 0,
            ref_node == NULL ? 1 : 0,
            parsed_size,
            size
        );
    }

    if (parsed_size == size) {
        if (node != NULL) {
            pm_serialize(ref_parser, ref_node, ref_buf);
            fuzz_assert_serialized_equal(parser, node, ref_parser, ref_node, stream_buf, ref_buf, "serialize_mismatch", "ref_len", parsed_size, size);
        }
    } else {
        const pm_location_t *stream_data = pm_parser_data_loc(parser);
        const pm_location_t *full_data = pm_parser_data_loc(ref_parser);
        if (stream_data->length == 0) {
            // An early-EOF byte (\0, ^D, ^Z) stops lexing before pm_source_stream_read's __END__ marker, leaving data_loc empty on both parses.
            // pm_serialize checksums the full input buffer, so we check full_data, error/warning counts, serialized AST/cpool equivalence, and prefix serialization.
            uint64_t stream_end = fuzz_stream_node_end(node, parsed_size);
            uint64_t ref_end = fuzz_stream_node_end(ref_node, size);
            uint64_t ast_end = stream_end > ref_end ? stream_end : ref_end;
            if (full_data->length != 0 || parsed_size > size || !fuzz_has_eof_control_byte(source_buf, parsed_size, ast_end)) {
                fuzz_invariant_fail(
                    "INVARIANT[stream_diff]: kind=spurious_stop [detail: parsed_size=%zu size=%zu]\n",
                    parsed_size,
                    size
                );
            }
        } else if (full_data->length == 0 || stream_data->start != full_data->start) {
            fuzz_invariant_fail(
                "INVARIANT[stream_diff]: kind=data_loc_mismatch [detail: stream_start=%u stream_len=%u full_start=%u full_len=%u parsed_size=%zu size=%zu]\n",
                stream_data->start,
                stream_data->length,
                full_data->start,
                full_data->length,
                parsed_size,
                size
            );
        }
        size_t stream_errs = pm_parser_errors_size(parser);
        size_t full_errs = pm_parser_errors_size(ref_parser);
        if (stream_errs != full_errs) {
            fuzz_invariant_fail(
                "INVARIANT[stream_diff]: kind=error_count_mismatch [detail: stream=%zu full=%zu parsed_size=%zu size=%zu]\n",
                stream_errs,
                full_errs,
                parsed_size,
                size
            );
        }
        size_t stream_warns = pm_parser_warnings_size(parser);
        size_t full_warns = pm_parser_warnings_size(ref_parser);
        if (stream_warns != full_warns) {
            fuzz_invariant_fail(
                "INVARIANT[stream_diff]: kind=warning_count_mismatch [detail: stream=%zu full=%zu parsed_size=%zu size=%zu]\n",
                stream_warns,
                full_warns,
                parsed_size,
                size
            );
        }

        if (node != NULL) {
            pm_serialize(ref_parser, ref_node, ref_buf);
            if (!fuzz_serialized_equiv_ignoring_eof_len(stream_buf, ref_buf, parsed_size)) {
                fuzz_fail_classified_stream_diff(
                    "ast_mismatch",
                    parser,
                    node,
                    ref_parser,
                    ref_node,
                    parsed_size,
                    size,
                    "stream_len",
                    pm_buffer_length(stream_buf),
                    "full_len",
                    pm_buffer_length(ref_buf)
                );
            }

            pm_arena_t *prefix_arena = pm_arena_new();
            pm_parser_t *prefix_parser = pm_parser_new(prefix_arena, source_buf, parsed_size, options);
            pm_node_t *prefix_node = pm_parse(prefix_parser);
            pm_buffer_t *stream_ser = pm_buffer_new();
            pm_buffer_t *prefix_ser = pm_buffer_new();
            pm_serialize(parser, node, stream_ser);
            pm_serialize(prefix_parser, prefix_node, prefix_ser);
            fuzz_assert_serialized_equal(parser, node, prefix_parser, prefix_node, stream_ser, prefix_ser, "prefix_serialize_mismatch", "prefix_len", parsed_size, size);
            pm_buffer_free(prefix_ser);
            pm_buffer_free(stream_ser);
            pm_parser_free(prefix_parser);
            pm_arena_free(prefix_arena);
        }
    }

    pm_buffer_free(ref_buf);
    pm_parser_free(ref_parser);
    pm_arena_free(ref_arena);
}
#endif
#endif

__attribute__((noinline)) void harness_parse(const uint8_t *input, size_t size, const fuzz_options_t *opts) {
    uint8_t *source = malloc(size);
    if (size > 0) {
        assert(source != NULL);
        memcpy(source, input, size);
    }
    const uint8_t *source_buf = (size == 0 && source == NULL) ? (const uint8_t *) "" : source;

#ifdef PRISM_FUZZ_LEGACY_OPTIONS_STRUCT
    pm_options_t options_storage = { 0 };
    pm_options_t *options = &options_storage;
#else
    pm_options_t *options = pm_options_new();
#endif
    fuzz_options_populate(options, opts, source_buf, size, false);

#ifdef PRISM_FUZZ_LEGACY_ARENA_STRUCT
    pm_arena_t arena_storage = { 0 };
    pm_arena_t *arena = &arena_storage;
#elif !defined(PRISM_FUZZ_LEGACY_NO_ARENA)
    pm_arena_t *arena = pm_arena_new();
#endif
#if PRISM_FUZZ_STREAM_ENABLED
    pm_source_t *stream_src = NULL;
#endif
#ifdef PRISM_FUZZ_LEGACY_PARSER_INIT
    pm_parser_t parser_storage;
    pm_parser_t *parser = &parser_storage;
#else
    pm_parser_t *parser = NULL;
#endif
    pm_node_t *node = NULL;
    size_t parsed_size = size;

#if PRISM_FUZZ_STREAM_ENABLED
    if (opts->stream_mode) {
        fuzz_stream_t stream_state = {
            .data = source_buf,
            .size = size,
            .pos = 0,
            .eof = false,
        };
        stream_src = pm_source_stream_new(&stream_state, fuzz_stream_fgets, fuzz_stream_feof);
        node = pm_parse_stream(&parser, arena, stream_src, options);
        parsed_size = pm_source_length(stream_src);
        if (parsed_size > size) {
            fuzz_invariant_fail(
                "INVARIANT[stream]: kind=parsed_size_oob [detail: parsed_size=%zu size=%zu]\n",
                parsed_size,
                size
            );
        }
    } else
#endif
    {
#ifdef PRISM_FUZZ_LEGACY_PARSER_INIT
#ifdef PRISM_FUZZ_PARSER_INIT_ARENA
        pm_parser_init(arena, parser, source_buf, size, options);
#else
        pm_parser_init(parser, source_buf, size, options);
#endif
#else
        parser = pm_parser_new(arena, source_buf, size, options);
#endif
#ifdef PRISM_FUZZ_IJON
        fuzz_ijon_state_t ijon_state;
        fuzz_ijon_attach(parser, &ijon_state, 0U);
#endif
        node = pm_parse(parser);
    }

    // Line offsets must start at 0, be strictly monotonically increasing, and not exceed parsed_size.
#ifdef PRISM_FUZZ_PARSER_NEWLINE_LIST
    const pm_newline_list_t *line_offsets = &parser->newline_list;
#elif defined(PRISM_FUZZ_LEGACY_PARSER_LINE_OFFSETS)
    const pm_line_offset_list_t *line_offsets = &parser->line_offsets;
#else
    const pm_line_offset_list_t *line_offsets = pm_parser_line_offsets(parser);
#endif
    const size_t offset_count = line_offsets->size;
    const int stream_flag = opts->stream_mode ? 1 : 0;
#ifdef PRISM_FUZZ_NO_COMMAND_LINE
    const int cmd_x_flag = 0;
#else
    const int cmd_x_flag = ((opts->cmd_flags & PM_OPTIONS_COMMAND_LINE_X) != 0) ? 1 : 0;
#endif
    if (offset_count == 0) {
        fuzz_invariant_fail(
            "INVARIANT[line_offsets]: kind=empty ctx=default stream=%d cmd_x=%d [detail: parsed_size=%zu]\n",
            stream_flag,
            cmd_x_flag,
            parsed_size
        );
    }
    if (line_offsets->offsets[0] != 0) {
        fuzz_invariant_fail(
            "INVARIANT[line_offsets]: kind=nonzero_start ctx=default stream=%d cmd_x=%d [detail: first=%llu parsed_size=%zu]\n",
            stream_flag,
            cmd_x_flag,
            (unsigned long long) line_offsets->offsets[0],
            parsed_size
        );
    }
    for (size_t i = 1; i < offset_count; i++) {
        uint64_t prev = (uint64_t) line_offsets->offsets[i - 1];
        uint64_t curr = (uint64_t) line_offsets->offsets[i];
        const char *lo_kind = NULL;
        if ((uint64_t) parsed_size < 0x80000000ULL && curr >= 0x80000000ULL) {
            lo_kind = "underflow";
        } else if (curr == prev) {
            lo_kind = "duplicate";
        } else if (curr < prev) {
            lo_kind = "rewind";
        } else if (curr > (uint64_t) parsed_size) {
            lo_kind = "oob";
        }
        if (lo_kind != NULL) {
            const char *lo_ctx = fuzz_line_offset_context(parser, node, source_buf, parsed_size, (uint32_t) curr);
            fuzz_invariant_fail(
                "INVARIANT[line_offsets]: kind=%s ctx=%s stream=%d cmd_x=%d [detail: idx=%zu prev=%llu curr=%llu parsed_size=%zu]\n",
                lo_kind,
                lo_ctx,
                stream_flag,
                cmd_x_flag,
                i,
                (unsigned long long) prev,
                (unsigned long long) curr,
                parsed_size
            );
        }
    }

    fuzz_node_check_t node_check = {
        .source = source_buf,
        .parsed_size = parsed_size,
        .parent_type = 0,
        .parser = parser,
        .depth = 0,
    };
    if (node != NULL) {
#ifdef PRISM_FUZZ_NO_VISIT_NODE
        (void) check_node_location(node, &node_check);
#else
        pm_visit_node(node, check_node_location, &node_check);
#endif
    }

    fuzz_diag_check_ctx_t diag_ctx = {
        .source = source_buf,
        .parsed_size = parsed_size,
    };
    fuzz_for_each_error_diag(parser, fuzz_check_error_diag, &diag_ctx);
#ifdef PRISM_FUZZ_LIST_ITERATORS
    for (const pm_diagnostic_t *d = (const pm_diagnostic_t *) parser->warning_list.head; d != NULL; d = (const pm_diagnostic_t *) d->node.next) {
        fuzz_check_warning_diag(d, &diag_ctx);
    }
#elif defined(PRISM_FUZZ_ITER_OBJS)
    {
        pm_diagnostics_iter_t *warn_iter = pm_parser_warnings(parser);
        for (const pm_diagnostic_t *d = pm_diagnostics_iter_next(warn_iter); d != NULL; d = pm_diagnostics_iter_next(warn_iter)) {
            fuzz_check_warning_diag(d, &diag_ctx);
        }
        pm_diagnostics_iter_free(warn_iter);
    }
#elif defined(PRISM_FUZZ_EACH_ITERATORS)
    pm_parser_warnings_each(parser, fuzz_check_warning_diag, &diag_ctx);
#else
    for (const pm_diagnostic_t *d = pm_parser_warnings_first(parser); d != NULL; d = pm_diagnostic_next(d)) {
        fuzz_check_warning_diag(d, &diag_ctx);
    }
#endif

    fuzz_comment_check_state_t comment_state = {
        .source = source_buf,
        .parsed_size = parsed_size,
#ifdef PRISM_FUZZ_NO_ATTACH_COMMENTS
        .check_order = false,
#else
        .check_order = opts->attach_comments,
#endif
        .prev_start = 0,
        .prev_type = "none",
        .first = true,
    };
#ifdef PRISM_FUZZ_LIST_ITERATORS
    for (const pm_comment_t *c = (const pm_comment_t *) parser->comment_list.head; c != NULL; c = (const pm_comment_t *) c->node.next) {
        fuzz_check_comment(c, &comment_state);
    }
    for (const pm_magic_comment_t *mc = (const pm_magic_comment_t *) parser->magic_comment_list.head; mc != NULL; mc = (const pm_magic_comment_t *) mc->node.next) {
        fuzz_check_magic_comment(mc, &diag_ctx);
    }
#elif defined(PRISM_FUZZ_ITER_OBJS)
    {
        pm_comments_iter_t *c_iter = pm_parser_comments(parser);
        for (const pm_comment_t *c = pm_comments_iter_next(c_iter); c != NULL; c = pm_comments_iter_next(c_iter)) {
            fuzz_check_comment(c, &comment_state);
        }
        pm_comments_iter_free(c_iter);

        pm_magic_comments_iter_t *mc_iter = pm_parser_magic_comments(parser);
        for (const pm_magic_comment_t *mc = pm_magic_comments_iter_next(mc_iter); mc != NULL; mc = pm_magic_comments_iter_next(mc_iter)) {
            fuzz_check_magic_comment(mc, &diag_ctx);
        }
        pm_magic_comments_iter_free(mc_iter);
    }
#elif defined(PRISM_FUZZ_EACH_ITERATORS)
    pm_parser_comments_each(parser, fuzz_check_comment, &comment_state);
    pm_parser_magic_comments_each(parser, fuzz_check_magic_comment, &diag_ctx);
#else
    for (const pm_comment_t *c = pm_parser_comments_first(parser); c != NULL; c = pm_comment_next(c)) {
        fuzz_check_comment(c, &comment_state);
    }
    for (const pm_magic_comment_t *mc = pm_parser_magic_comments_first(parser); mc != NULL; mc = pm_magic_comment_next(mc)) {
        fuzz_check_magic_comment(mc, &diag_ctx);
    }
#endif

#ifdef SLOW
#ifdef PRISM_FUZZ_LEGACY_BUFFER_STRUCT
    pm_buffer_t buffer_storage = { 0 };
    pm_buffer_t *buffer = &buffer_storage;
    pm_buffer_init(buffer);
#else
    pm_buffer_t *buffer = pm_buffer_new();
#endif

    if (node != NULL) {
        pm_serialize(parser, node, buffer);
    }

#if PRISM_FUZZ_STREAM_ENABLED && !defined(PRISM_FUZZ_NO_STREAM_DIFF) && \
    !defined(PRISM_FUZZ_LEGACY_NO_ARENA) && !defined(PRISM_FUZZ_LEGACY_ARENA_STRUCT) && !defined(PRISM_FUZZ_LEGACY_PARSER_INIT) && \
    !defined(PRISM_FUZZ_LEGACY_PARSER_DATA_LOC) && !defined(PRISM_FUZZ_LEGACY_BUFFER_STRUCT) && !defined(PRISM_FUZZ_NO_PARSER_ERRORS_SIZE)
    if (opts->stream_mode) {
        fuzz_check_stream_diff(parser, node, source_buf, size, parsed_size, options, buffer);
    }
#endif
    fuzz_buffer_reset(buffer);

#ifndef PRISM_FUZZ_NO_STREAM
    if (opts->stream_mode) {
        fuzz_stream_t stream_state2 = {
            .data = source_buf,
            .size = size,
            .pos = 0,
            .eof = false,
        };
        pm_source_t *stream_src2 = pm_source_stream_new(&stream_state2, fuzz_stream_fgets, fuzz_stream_feof);
        pm_serialize_parse_stream(buffer, stream_src2, NULL);
        fuzz_buffer_reset(buffer);
        pm_source_free(stream_src2);
    }
#endif

#ifndef PRISM_FUZZ_NO_ERRORS_FORMAT
#ifdef PRISM_FUZZ_NO_PARSER_ERRORS_SIZE
    if (parser->error_list.size > 0) {
#else
    if (pm_parser_errors_size(parser) > 0) {
#endif
        (void) pm_errors_format(parser, buffer, PM_ERRORS_FORMAT_PLAIN);
        fuzz_buffer_reset(buffer);
        (void) pm_errors_format(parser, buffer, PM_ERRORS_FORMAT_COLOR);
        fuzz_buffer_reset(buffer);
    }
#endif

#if defined(PRISM_FUZZ_LEGACY_BUFFER_STRUCT) && defined(PRISM_FUZZ_BUFFER_CLEANUP)
    pm_buffer_cleanup(buffer);
#else
    pm_buffer_free(buffer);
#endif
#endif

#ifdef PRISM_FUZZ_LEGACY_NO_ARENA
    if (node != NULL) {
        pm_node_destroy(parser, node);
    }
#endif
#if defined(PRISM_FUZZ_LEGACY_PARSER_INIT) && defined(PRISM_FUZZ_PARSER_CLEANUP)
    pm_parser_cleanup(parser);
#else
    pm_parser_free(parser);
#endif
#if PRISM_FUZZ_STREAM_ENABLED
    if (stream_src != NULL) {
        pm_source_free(stream_src);
    }
#endif
#if defined(PRISM_FUZZ_LEGACY_ARENA_STRUCT)
#ifdef PRISM_FUZZ_ARENA_CLEANUP
    pm_arena_cleanup(arena);
#else
    pm_arena_free(arena);
#endif
#elif !defined(PRISM_FUZZ_LEGACY_NO_ARENA)
    pm_arena_free(arena);
#endif
    fuzz_options_dispose(options);
    free(source);
}

__attribute__((noinline)) void harness(const uint8_t *input, size_t size) {
    if (size < 4) return;

    fuzz_options_t opts;
    fuzz_options_decode(input, &opts);

    harness_parse(input + 4, size - 4, &opts);
}

