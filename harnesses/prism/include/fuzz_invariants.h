#ifndef PRISM_FUZZ_INVARIANTS_H
#define PRISM_FUZZ_INVARIANTS_H

/* Requires <prism.h> (and any PRISM_FUZZ_LEGACY_VISIT_BOOL shims) to be
 * included/defined by the enclosing translation unit first. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifndef PRISM_DEPTH_MAXIMUM
#define PRISM_DEPTH_MAXIMUM 10000
#endif
#define FUZZ_MAX_NON_ITER_DEPTH ((size_t) (PRISM_DEPTH_MAXIMUM) * 2u + 64u)

static inline bool fuzz_is_hex_digit_byte(uint8_t byte) {
    return (byte >= '0' && byte <= '9') ||
           (byte >= 'a' && byte <= 'f') ||
           (byte >= 'A' && byte <= 'F');
}

static inline bool fuzz_is_inline_whitespace_byte(uint8_t byte) {
    return byte == ' ' || byte == '\t' || byte == '\v' || byte == '\f' || byte == '\r';
}

/* escape_write_unicode attaches mixed_encoding to the inner hex digits of
 * \u{...} or the uXXXX body after '\\' in \uXXXX rather than including '\\'. */
static inline bool fuzz_is_unicode_escape_mixed_encoding_span(
    const uint8_t *source,
    uint32_t start,
    uint32_t length
) {
    if (length == 0) {
        return false;
    }

    if (length == 5 && start >= 1 && source[start - 1] == '\\' && source[start] == 'u') {
        for (uint32_t i = 1; i < 5; i++) {
            if (!fuzz_is_hex_digit_byte(source[start + i])) {
                return false;
            }
        }
        return true;
    }

    for (uint32_t i = 0; i < length; i++) {
        if (!fuzz_is_hex_digit_byte(source[start + i])) {
            return false;
        }
    }

    uint32_t pos = start;
    while (pos > 0) {
        uint8_t prev = source[pos - 1];
        if (fuzz_is_hex_digit_byte(prev) || fuzz_is_inline_whitespace_byte(prev)) {
            pos--;
        } else if (pos >= 2 && source[pos - 2] == '\\' && prev == 'n') {
            pos -= 2;
        } else {
            break;
        }
    }

    return pos >= 3 && source[pos - 3] == '\\' && source[pos - 2] == 'u' && source[pos - 1] == '{';
}

static inline bool fuzz_span_in_bounds(uint32_t start, uint32_t length, size_t parsed_size) {
    return (size_t) start <= parsed_size && (size_t) length <= parsed_size - (size_t) start;
}

/* Classify out-of-bounds/overflowed [start, start + length) spans.
 * When `distinguish_end_overflow` is false (parse.c), any 32-bit end wrap
 * reports "length_underflow" to preserve existing crash bucket signatures;
 * when true (explain.c), non-negative lengths whose sum wraps report "end_overflow". */
static inline const char *fuzz_span_violation_kind(
    uint32_t start,
    uint32_t length,
    size_t parsed_size,
    bool distinguish_end_overflow
) {
    if (fuzz_span_in_bounds(start, length, parsed_size)) {
        return NULL;
    }
    if ((uint64_t) parsed_size < 0x80000000ULL && start >= 0x80000000U) {
        return "start_underflow";
    }
    if ((uint64_t) parsed_size < 0x80000000ULL && length >= 0x80000000U) {
        return "length_underflow";
    }
    if ((uint64_t) start + (uint64_t) length >= 0x100000000ULL) {
        return distinguish_end_overflow ? "end_overflow" : "length_underflow";
    }
    if ((size_t) start > parsed_size) {
        return "start_oob";
    }
    return "end_oob";
}

static inline bool fuzz_is_heredoc_opening_span(
    uint32_t start,
    uint32_t length,
    const uint8_t *source,
    size_t parsed_size
) {
    return length >= 2 &&
        fuzz_span_in_bounds(start, length, parsed_size) &&
        memcmp(source + start, "<<", 2) == 0;
}

#ifndef PRISM_FUZZ_NO_VISIT_NODE
static inline bool fuzz_heredoc_node_type(pm_node_type_t type) {
    switch (type) {
        case PM_STRING_NODE:
        case PM_INTERPOLATED_STRING_NODE:
        case PM_X_STRING_NODE:
        case PM_INTERPOLATED_X_STRING_NODE:
            return true;
        default:
            return false;
    }
}

static inline bool fuzz_heredoc_node_locs(
    const pm_node_t *node,
    pm_location_t *opening_loc,
    pm_location_t *closing_loc
) {
    switch (PM_NODE_TYPE(node)) {
        case PM_STRING_NODE: {
            const pm_string_node_t *cast = (const pm_string_node_t *) node;
            *opening_loc = cast->opening_loc;
            if (closing_loc != NULL) *closing_loc = cast->closing_loc;
            return true;
        }
        case PM_INTERPOLATED_STRING_NODE: {
            const pm_interpolated_string_node_t *cast = (const pm_interpolated_string_node_t *) node;
            *opening_loc = cast->opening_loc;
            if (closing_loc != NULL) *closing_loc = cast->closing_loc;
            return true;
        }
        case PM_X_STRING_NODE: {
            const pm_x_string_node_t *cast = (const pm_x_string_node_t *) node;
            *opening_loc = cast->opening_loc;
            if (closing_loc != NULL) *closing_loc = cast->closing_loc;
            return true;
        }
        case PM_INTERPOLATED_X_STRING_NODE: {
            const pm_interpolated_x_string_node_t *cast = (const pm_interpolated_x_string_node_t *) node;
            *opening_loc = cast->opening_loc;
            if (closing_loc != NULL) *closing_loc = cast->closing_loc;
            return true;
        }
        default:
            return false;
    }
}
#endif

#if !defined(PRISM_FUZZ_NO_VISIT_NODE) && !defined(PRISM_FUZZ_POINTER_LOCATIONS) && !defined(PRISM_FUZZ_NO_NODE_RELATIONS)
static inline bool fuzz_is_iterative_chain_node(pm_node_type_t parent, pm_node_type_t child) {
    if (parent != child) return false;
    switch (child) {
        case PM_CALL_NODE:
        case PM_AND_NODE:
        case PM_OR_NODE:
        case PM_CONSTANT_PATH_NODE:
        case PM_IF_NODE:
        case PM_RESCUE_NODE:
        case PM_ALTERNATION_PATTERN_NODE:
        case PM_CAPTURE_PATTERN_NODE:
            return true;
        default:
            return false;
    }
}

typedef struct {
    uint64_t target;
    bool match_end;
    bool found;
    size_t budget;
    size_t depth;
} fuzz_er_edge_search_t;

static inline pm_visit_result_t fuzz_find_er_edge_cb(const pm_node_t *node, void *data) {
    fuzz_er_edge_search_t *s = (fuzz_er_edge_search_t *) data;
    if (s->found || s->budget == 0 || s->depth >= 256) {
        return PM_VISIT_STOP;
    }
    s->budget--;

    if (PM_NODE_TYPE_P(node, PM_ERROR_RECOVERY_NODE)) {
        uint64_t edge = s->match_end
            ? (uint64_t) node->location.start + (uint64_t) node->location.length
            : (uint64_t) node->location.start;
        if (edge == s->target) {
            s->found = true;
            return PM_VISIT_STOP;
        }
        return PM_VISIT_SKIP;
    }

    s->depth++;
    pm_visit_child_nodes(node, fuzz_find_er_edge_cb, s);
    s->depth--;
    return PM_VISIT_SKIP;
}

/* ErrorRecoveryNode borrows unconsumed lookahead token spans (which may match
 * a container's closing_loc or a subsequent sibling's start), so suppress
 * list-relation failures when the offending boundary belongs to recovery. */
static inline bool fuzz_node_edge_has_error_recovery(const pm_node_t *node, uint64_t target, bool match_end) {
    if (node == NULL) {
        return false;
    }
    if (PM_NODE_TYPE_P(node, PM_ERROR_RECOVERY_NODE)) {
        return true;
    }
    fuzz_er_edge_search_t s = {
        .target = target,
        .match_end = match_end,
        .found = false,
        .budget = 4096,
        .depth = 0,
    };
    pm_visit_child_nodes(node, fuzz_find_er_edge_cb, &s);
    return s.found;
}
#endif

#endif
