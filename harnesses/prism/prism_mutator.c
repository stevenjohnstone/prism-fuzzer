/*
 * Prism AST Source-Slice Custom Mutator for AFL++ (libprismmutator.so)
 *
 * Parses Ruby inputs with mainline Prism (pm_parse), collects AST node byte
 * spans and keyword/operator token spans, and mutates at the source-slice level
 * (subtree crossover from AFL++'s add_buf, internal copy/swap, compiler-torture
 * wrappers, surgical keyword/operator flips, and statement insertion/deletion).
 *
 * Environment variables:
 *   PRISM_MUTATOR_HEADER_BYTES  Number of leading non-Ruby header bytes to
 *                               preserve before parsing (default: 4, matching
 *                               the uniform 4-byte header used by prism_parse,
 *                               prism_diff_ruby, cruby_compile, and
 *                               cruby_pipeline_diff; set to 0 for raw Ruby).
 */

#include <prism.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PM_MUT_MAX_PARSE_LEN 16384u
#define PM_MUT_MAX_NODES     256u
#define PM_MUT_MAX_TOKENS    64u
#define PM_MUT_MAX_DEPTH     128u
#define PM_MUT_INIT_CAP      32768u

typedef struct {
    uint32_t start;
    uint32_t length;
    pm_node_type_t type;
} mut_span_t;

typedef enum {
    TOK_IF_UNLESS = 0,
    TOK_WHILE_UNTIL = 1,
    TOK_AND_OR = 2,
    TOK_DOT2_DOT3 = 3,
    TOK_CALL_OP = 4,
    TOK_HEREDOC_OPEN = 5,
    TOK_ASSIGN_OP = 6
} tok_kind_t;

typedef struct {
    uint32_t start;
    uint32_t length;
    tok_kind_t kind;
} mut_tok_t;

typedef struct {
    uint32_t open_start;
    uint32_t open_len;
    uint32_t close_start;
    uint32_t close_len;
    const char *open_repl;
    const char *close_repl;
} mut_delim_pair_t;

typedef struct {
    const uint8_t *src;
    size_t src_len;
    mut_span_t nodes[PM_MUT_MAX_NODES];
    size_t node_count;
    mut_tok_t tokens[PM_MUT_MAX_TOKENS];
    size_t token_count;
    mut_delim_pair_t delim_pairs[PM_MUT_MAX_TOKENS];
    size_t delim_pair_count;
    unsigned depth;
} ast_index_t;

typedef struct {
    uint64_t rng;
    size_t header_bytes;
    uint8_t *out_buf;
    size_t out_cap;
    uint8_t *cache_src;
    size_t cache_len;
    size_t cache_cap;
    uint64_t cache_hash;
    bool cache_valid;
    bool cache_has_nodes;
    ast_index_t cache_idx;
} prism_mutator_t;

static uint64_t fnv1a_64(const uint8_t *data, size_t len) {
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint64_t) data[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static inline uint64_t rng_next(prism_mutator_t *m) {
    uint64_t x = m->rng;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    m->rng = x;
    return x * 2685821657736338717ULL;
}

static inline size_t rng_below(prism_mutator_t *m, size_t n) {
    return n <= 1 ? 0 : (size_t) (rng_next(m) % n);
}

static bool ensure_out_cap(prism_mutator_t *m, size_t needed) {
    if (needed <= m->out_cap) {
        return true;
    }
    size_t next = m->out_cap ? m->out_cap : PM_MUT_INIT_CAP;
    while (next < needed) {
        if (next > SIZE_MAX / 2) {
            return false;
        }
        next *= 2;
    }
    uint8_t *p = (uint8_t *) realloc(m->out_buf, next);
    if (p == NULL) {
        return false;
    }
    m->out_buf = p;
    m->out_cap = next;
    return true;
}

static inline bool valid_loc(pm_location_t loc, size_t src_len) {
    return loc.length > 0 && loc.start <= src_len && loc.length <= src_len - loc.start;
}

static inline bool is_ident_message(const uint8_t *src, pm_location_t loc) {
    if (loc.length == 0) {
        return false;
    }
    uint8_t first = src[loc.start];
    uint8_t last = src[loc.start + loc.length - 1];
    bool start_ok = (first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || first == '_';
    return start_ok && last != '=';
}

static void record_delim_pair(
    ast_index_t *idx,
    uint32_t open_start,
    uint32_t open_len,
    uint32_t close_start,
    uint32_t close_len,
    const char *open_repl,
    const char *close_repl
) {
    if (idx->delim_pair_count >= PM_MUT_MAX_TOKENS) {
        return;
    }
    size_t open_end = (size_t) open_start + (size_t) open_len;
    size_t close_end = (size_t) close_start + (size_t) close_len;
    if (open_end > close_start || close_end > idx->src_len) {
        return;
    }
    idx->delim_pairs[idx->delim_pair_count++] = (mut_delim_pair_t) {
        .open_start = open_start,
        .open_len = open_len,
        .close_start = close_start,
        .close_len = close_len,
        .open_repl = open_repl,
        .close_repl = close_repl
    };
}

static void record_tok(ast_index_t *idx, pm_location_t loc, tok_kind_t kind) {
    if (idx->token_count < PM_MUT_MAX_TOKENS && valid_loc(loc, idx->src_len)) {
        idx->tokens[idx->token_count++] = (mut_tok_t) {
            .start = loc.start,
            .length = loc.length,
            .kind = kind
        };
    }
}

static void record_heredoc_open(ast_index_t *idx, pm_location_t loc) {
    if (valid_loc(loc, idx->src_len) && loc.length >= 3 &&
        idx->src[loc.start] == '<' && idx->src[loc.start + 1] == '<') {
        record_tok(idx, loc, TOK_HEREDOC_OPEN);
    }
}

static bool is_replaceable_node(pm_node_type_t type) {
    switch (type) {
        case PM_PROGRAM_NODE:
        case PM_PARAMETERS_NODE:
        case PM_BLOCK_PARAMETERS_NODE:
        case PM_REQUIRED_PARAMETER_NODE:
        case PM_OPTIONAL_PARAMETER_NODE:
        case PM_REST_PARAMETER_NODE:
        case PM_REQUIRED_KEYWORD_PARAMETER_NODE:
        case PM_OPTIONAL_KEYWORD_PARAMETER_NODE:
        case PM_KEYWORD_REST_PARAMETER_NODE:
        case PM_BLOCK_PARAMETER_NODE:
        case PM_NO_KEYWORDS_PARAMETER_NODE:
        case PM_FORWARDING_PARAMETER_NODE:
        case PM_ARGUMENTS_NODE:
        case PM_RESCUE_NODE:
        case PM_ENSURE_NODE:
        case PM_ELSE_NODE:
        case PM_WHEN_NODE:
        case PM_IN_NODE:
        case PM_ASSOC_NODE:
        case PM_ASSOC_SPLAT_NODE:
        case PM_KEYWORD_HASH_NODE:
            return false;
        default:
            return true;
    }
}

static pm_visit_result_t collect_ast_cb(const pm_node_t *node, void *data) {
    ast_index_t *idx = (ast_index_t *) data;
    if (idx->depth >= PM_MUT_MAX_DEPTH || idx->node_count >= PM_MUT_MAX_NODES) {
        return PM_VISIT_SKIP;
    }

    pm_node_type_t type = PM_NODE_TYPE(node);
    if (is_replaceable_node(type) && valid_loc(node->location, idx->src_len)) {
        idx->nodes[idx->node_count++] = (mut_span_t) {
            .start = node->location.start,
            .length = node->location.length,
            .type = type
        };
    }

    switch (type) {
        case PM_IF_NODE: {
            const pm_if_node_t *n = (const pm_if_node_t *) node;
            if (valid_loc(n->if_keyword_loc, idx->src_len) && n->if_keyword_loc.length == 2 &&
                memcmp(idx->src + n->if_keyword_loc.start, "if", 2) == 0) {
                record_tok(idx, n->if_keyword_loc, TOK_IF_UNLESS);
            }
            break;
        }
        case PM_UNLESS_NODE: {
            const pm_unless_node_t *n = (const pm_unless_node_t *) node;
            record_tok(idx, n->unless_keyword_loc, TOK_IF_UNLESS);
            break;
        }
        case PM_WHILE_NODE: {
            const pm_while_node_t *n = (const pm_while_node_t *) node;
            record_tok(idx, n->while_keyword_loc, TOK_WHILE_UNTIL);
            break;
        }
        case PM_UNTIL_NODE: {
            const pm_until_node_t *n = (const pm_until_node_t *) node;
            record_tok(idx, n->until_keyword_loc, TOK_WHILE_UNTIL);
            break;
        }
        case PM_AND_NODE: {
            const pm_and_node_t *n = (const pm_and_node_t *) node;
            record_tok(idx, n->operator_loc, TOK_AND_OR);
            break;
        }
        case PM_OR_NODE: {
            const pm_or_node_t *n = (const pm_or_node_t *) node;
            record_tok(idx, n->operator_loc, TOK_AND_OR);
            break;
        }
        case PM_RANGE_NODE: {
            const pm_range_node_t *n = (const pm_range_node_t *) node;
            record_tok(idx, n->operator_loc, TOK_DOT2_DOT3);
            break;
        }
        case PM_FLIP_FLOP_NODE: {
            const pm_flip_flop_node_t *n = (const pm_flip_flop_node_t *) node;
            record_tok(idx, n->operator_loc, TOK_DOT2_DOT3);
            break;
        }
        case PM_CALL_NODE: {
            const pm_call_node_t *n = (const pm_call_node_t *) node;
            if (valid_loc(n->call_operator_loc, idx->src_len) &&
                ((n->call_operator_loc.length == 1 && idx->src[n->call_operator_loc.start] == '.') ||
                 (n->call_operator_loc.length == 2 && memcmp(idx->src + n->call_operator_loc.start, "&.", 2) == 0))) {
                record_tok(idx, n->call_operator_loc, TOK_CALL_OP);
            }
            if (n->arguments != NULL &&
                valid_loc(n->message_loc, idx->src_len) && is_ident_message(idx->src, n->message_loc)) {
                if (valid_loc(n->opening_loc, idx->src_len) && valid_loc(n->closing_loc, idx->src_len) &&
                    n->opening_loc.length == 1 && idx->src[n->opening_loc.start] == '(' &&
                    n->closing_loc.length == 1 && idx->src[n->closing_loc.start] == ')') {
                    record_delim_pair(idx, n->opening_loc.start, 1, n->closing_loc.start, 1, " ", "");
                } else if (n->opening_loc.length == 0 && valid_loc(n->arguments->base.location, idx->src_len)) {
                    uint32_t msg_end = n->message_loc.start + n->message_loc.length;
                    uint32_t arg_start = n->arguments->base.location.start;
                    uint32_t arg_end = arg_start + n->arguments->base.location.length;
                    if (msg_end <= arg_start) {
                        record_delim_pair(idx, msg_end, arg_start - msg_end, arg_end, 0, "(", ")");
                    }
                }
            }
            break;
        }
        case PM_BLOCK_NODE: {
            const pm_block_node_t *n = (const pm_block_node_t *) node;
            if (valid_loc(n->opening_loc, idx->src_len) && valid_loc(n->closing_loc, idx->src_len)) {
                if (n->opening_loc.length == 1 && idx->src[n->opening_loc.start] == '{') {
                    record_delim_pair(idx, n->opening_loc.start, n->opening_loc.length,
                                      n->closing_loc.start, n->closing_loc.length, " do ", " end ");
                } else if (n->opening_loc.length == 2 && memcmp(idx->src + n->opening_loc.start, "do", 2) == 0) {
                    record_delim_pair(idx, n->opening_loc.start, n->opening_loc.length,
                                      n->closing_loc.start, n->closing_loc.length, " { ", " } ");
                }
            }
            break;
        }
        case PM_LAMBDA_NODE: {
            const pm_lambda_node_t *n = (const pm_lambda_node_t *) node;
            if (valid_loc(n->opening_loc, idx->src_len) && valid_loc(n->closing_loc, idx->src_len)) {
                if (n->opening_loc.length == 1 && idx->src[n->opening_loc.start] == '{') {
                    record_delim_pair(idx, n->opening_loc.start, n->opening_loc.length,
                                      n->closing_loc.start, n->closing_loc.length, " do ", " end ");
                } else if (n->opening_loc.length == 2 && memcmp(idx->src + n->opening_loc.start, "do", 2) == 0) {
                    record_delim_pair(idx, n->opening_loc.start, n->opening_loc.length,
                                      n->closing_loc.start, n->closing_loc.length, " { ", " } ");
                }
            }
            break;
        }
        case PM_PARENTHESES_NODE: {
            const pm_parentheses_node_t *n = (const pm_parentheses_node_t *) node;
            if (valid_loc(n->opening_loc, idx->src_len) && valid_loc(n->closing_loc, idx->src_len) &&
                n->opening_loc.length == 1 && idx->src[n->opening_loc.start] == '(' &&
                n->closing_loc.length == 1 && idx->src[n->closing_loc.start] == ')') {
                record_delim_pair(idx, n->opening_loc.start, 1, n->closing_loc.start, 1, " begin; ", "; end ");
            }
            break;
        }
        case PM_BEGIN_NODE: {
            const pm_begin_node_t *n = (const pm_begin_node_t *) node;
            if (n->rescue_clause == NULL && n->ensure_clause == NULL && n->else_clause == NULL &&
                valid_loc(n->begin_keyword_loc, idx->src_len) && valid_loc(n->end_keyword_loc, idx->src_len)) {
                record_delim_pair(idx, n->begin_keyword_loc.start, n->begin_keyword_loc.length,
                                  n->end_keyword_loc.start, n->end_keyword_loc.length, "(", ")");
            }
            break;
        }
        case PM_STRING_NODE:
            record_heredoc_open(idx, ((const pm_string_node_t *) node)->opening_loc);
            break;
        case PM_INTERPOLATED_STRING_NODE:
            record_heredoc_open(idx, ((const pm_interpolated_string_node_t *) node)->opening_loc);
            break;
        case PM_X_STRING_NODE:
            record_heredoc_open(idx, ((const pm_x_string_node_t *) node)->opening_loc);
            break;
        case PM_INTERPOLATED_X_STRING_NODE:
            record_heredoc_open(idx, ((const pm_interpolated_x_string_node_t *) node)->opening_loc);
            break;
        case PM_CALL_AND_WRITE_NODE: {
            const pm_call_and_write_node_t *n = (const pm_call_and_write_node_t *) node;
            if (valid_loc(n->call_operator_loc, idx->src_len) &&
                ((n->call_operator_loc.length == 1 && idx->src[n->call_operator_loc.start] == '.') ||
                 (n->call_operator_loc.length == 2 && memcmp(idx->src + n->call_operator_loc.start, "&.", 2) == 0))) {
                record_tok(idx, n->call_operator_loc, TOK_CALL_OP);
            }
            record_tok(idx, n->operator_loc, TOK_ASSIGN_OP);
            break;
        }
        case PM_CALL_OR_WRITE_NODE: {
            const pm_call_or_write_node_t *n = (const pm_call_or_write_node_t *) node;
            if (valid_loc(n->call_operator_loc, idx->src_len) &&
                ((n->call_operator_loc.length == 1 && idx->src[n->call_operator_loc.start] == '.') ||
                 (n->call_operator_loc.length == 2 && memcmp(idx->src + n->call_operator_loc.start, "&.", 2) == 0))) {
                record_tok(idx, n->call_operator_loc, TOK_CALL_OP);
            }
            record_tok(idx, n->operator_loc, TOK_ASSIGN_OP);
            break;
        }
        case PM_CALL_OPERATOR_WRITE_NODE: {
            const pm_call_operator_write_node_t *n = (const pm_call_operator_write_node_t *) node;
            if (valid_loc(n->call_operator_loc, idx->src_len) &&
                ((n->call_operator_loc.length == 1 && idx->src[n->call_operator_loc.start] == '.') ||
                 (n->call_operator_loc.length == 2 && memcmp(idx->src + n->call_operator_loc.start, "&.", 2) == 0))) {
                record_tok(idx, n->call_operator_loc, TOK_CALL_OP);
            }
            record_tok(idx, n->binary_operator_loc, TOK_ASSIGN_OP);
            break;
        }
        case PM_LOCAL_VARIABLE_AND_WRITE_NODE:
            record_tok(idx, ((const pm_local_variable_and_write_node_t *) node)->operator_loc, TOK_ASSIGN_OP);
            break;
        case PM_LOCAL_VARIABLE_OR_WRITE_NODE:
            record_tok(idx, ((const pm_local_variable_or_write_node_t *) node)->operator_loc, TOK_ASSIGN_OP);
            break;
        case PM_LOCAL_VARIABLE_OPERATOR_WRITE_NODE:
            record_tok(idx, ((const pm_local_variable_operator_write_node_t *) node)->binary_operator_loc, TOK_ASSIGN_OP);
            break;
        case PM_INDEX_AND_WRITE_NODE:
            record_tok(idx, ((const pm_index_and_write_node_t *) node)->operator_loc, TOK_ASSIGN_OP);
            break;
        case PM_INDEX_OR_WRITE_NODE:
            record_tok(idx, ((const pm_index_or_write_node_t *) node)->operator_loc, TOK_ASSIGN_OP);
            break;
        case PM_INDEX_OPERATOR_WRITE_NODE:
            record_tok(idx, ((const pm_index_operator_write_node_t *) node)->binary_operator_loc, TOK_ASSIGN_OP);
            break;
        default:
            break;
    }

    idx->depth++;
    pm_visit_child_nodes(node, collect_ast_cb, data);
    idx->depth--;
    return PM_VISIT_SKIP;
}

static bool index_ruby_source(const uint8_t *src, size_t src_len, ast_index_t *idx) {
    memset(idx, 0, sizeof(*idx));
    idx->src = src;
    idx->src_len = src_len;
    if (src == NULL || src_len == 0 || src_len > PM_MUT_MAX_PARSE_LEN) {
        return false;
    }

    pm_arena_t *arena = pm_arena_new();
    if (arena == NULL) {
        return false;
    }
    pm_parser_t *parser = pm_parser_new(arena, src, src_len, NULL);
    if (parser == NULL) {
        pm_arena_free(arena);
        return false;
    }

    pm_node_t *root = pm_parse(parser);
    if (root != NULL) {
        pm_visit_node(root, collect_ast_cb, idx);
    }

    pm_parser_free(parser);
    pm_arena_free(arena);
    return idx->node_count > 0;
}

typedef struct {
    uint8_t *buf;
    size_t len;
    size_t cap;
} out_writer_t;

static inline void ow_put(out_writer_t *w, const void *src, size_t n) {
    if (n == 0 || w->len >= w->cap) {
        return;
    }
    size_t avail = w->cap - w->len;
    if (n > avail) {
        n = avail;
    }
    memcpy(w->buf + w->len, src, n);
    w->len += n;
}

static inline void ow_puts(out_writer_t *w, const char *s) {
    ow_put(w, s, strlen(s));
}

static size_t emit_replace(
    out_writer_t *w,
    const uint8_t *src,
    size_t src_len,
    uint32_t rep_start,
    uint32_t rep_len,
    const uint8_t *repl,
    size_t repl_len,
    bool wrap_parens
) {
    ow_put(w, src, rep_start);
    if (wrap_parens) {
        ow_puts(w, "(");
    }
    ow_put(w, repl, repl_len);
    if (wrap_parens) {
        ow_puts(w, ")");
    }
    size_t tail = (size_t) rep_start + (size_t) rep_len;
    if (tail < src_len) {
        ow_put(w, src + tail, src_len - tail);
    }
    return w->len;
}

static size_t emit_swap(
    out_writer_t *w,
    const uint8_t *src,
    size_t src_len,
    mut_span_t a,
    mut_span_t b
) {
    if (a.start > b.start) {
        mut_span_t tmp = a;
        a = b;
        b = tmp;
    }
    size_t a_end = (size_t) a.start + (size_t) a.length;
    size_t b_end = (size_t) b.start + (size_t) b.length;
    if (a_end > b.start) {
        return 0;
    }
    ow_put(w, src, a.start);
    ow_put(w, src + b.start, b.length);
    ow_put(w, src + a_end, b.start - a_end);
    ow_put(w, src + a.start, a.length);
    if (b_end < src_len) {
        ow_put(w, src + b_end, src_len - b_end);
    }
    return w->len;
}

static size_t emit_heredoc_inject(
    prism_mutator_t *m,
    out_writer_t *w,
    const uint8_t *src,
    size_t src_len,
    mut_span_t x,
    const uint8_t *y_ptr,
    size_t y_len
) {
    static const struct {
        const char *open;
        const char *close;
        bool interp;
    } styles[] = {
        { "<<~_H",   "_H", true  },
        { "<<-_H",   "_H", true  },
        { "<<_H",    "_H", true  },
        { "<<'_H'",  "_H", false },
        { "<<\"_H\"", "_H", true },
        { "<<`_H`",  "_H", true  },
        { "<<~'_H'", "_H", false }
    };
    size_t style_idx = rng_below(m, sizeof(styles) / sizeof(styles[0]));
    const char *nl = (rng_below(m, 5) == 0) ? "\r\n" : "\n";
    size_t x_end = (size_t) x.start + (size_t) x.length;

    /* Find the end of the line containing X so the heredoc body starts on the next line. */
    size_t line_end = x_end;
    while (line_end < src_len && src[line_end] != '\n') {
        line_end++;
    }

    ow_put(w, src, x.start);
    ow_puts(w, styles[style_idx].open);
    if (line_end > x_end) {
        ow_put(w, src + x_end, line_end - x_end);
    }
    ow_puts(w, nl);
    if (styles[style_idx].interp) {
        ow_puts(w, "  #{");
        ow_put(w, y_ptr, y_len);
        ow_puts(w, "}");
    } else {
        ow_puts(w, "  ");
        ow_put(w, y_ptr, y_len);
    }
    ow_puts(w, nl);
    ow_puts(w, styles[style_idx].close);
    ow_puts(w, nl);

    if (line_end < src_len) {
        ow_put(w, src + line_end + 1, src_len - (line_end + 1));
    }
    return w->len;
}

static size_t emit_magic_or_end(
    prism_mutator_t *m,
    out_writer_t *w,
    const uint8_t *src,
    size_t src_len
) {
    static const char *const prefixes[] = {
        "# encoding: UTF-8\n",
        "# encoding: ASCII-8BIT\n",
        "# encoding: EUC-JP\n",
        "# encoding: Shift_JIS\n",
        "# encoding: Windows-31J\n",
        "# encoding: CESU-8\n",
        "# encoding: ISO-8859-1\n",
        "# frozen_string_literal: true\n",
        "# frozen_string_literal: false\n",
        "# shareable_constant_value: literal\n",
        "# shareable_constant_value: experimental_copy\n",
        "#!/usr/bin/ruby\n# encoding: UTF-8\n",
        "\xef\xbb\xbf"
    };
    if (rng_below(m, 6) == 0) {
        ow_put(w, src, src_len);
        ow_puts(w, "\n__END__\ndata\n");
        return w->len;
    }
    const char *pfx = prefixes[rng_below(m, sizeof(prefixes) / sizeof(prefixes[0]))];
    ow_puts(w, pfx);
    ow_put(w, src, src_len);
    return w->len;
}

static size_t emit_wrapper(
    prism_mutator_t *m,
    out_writer_t *w,
    const uint8_t *src,
    size_t src_len,
    mut_span_t x,
    const uint8_t *y_ptr,
    size_t y_len
) {
    const uint8_t *x_ptr = src + x.start;
    size_t x_len = x.length;
    size_t x_end = (size_t) x.start + (size_t) x.length;

    ow_put(w, src, x.start);

    switch (rng_below(m, 44)) {
        case 0:
            ow_puts(w, "defined?("); ow_put(w, x_ptr, x_len); ow_puts(w, ")");
            break;
        case 1:
            ow_puts(w, "begin; "); ow_put(w, x_ptr, x_len); ow_puts(w, "; ensure; "); ow_put(w, y_ptr, y_len); ow_puts(w, "; end");
            break;
        case 2:
            ow_puts(w, "begin; "); ow_put(w, x_ptr, x_len); ow_puts(w, "; rescue => _e; "); ow_put(w, y_ptr, y_len); ow_puts(w, "; else; "); ow_put(w, x_ptr, x_len); ow_puts(w, "; ensure; "); ow_put(w, y_ptr, y_len); ow_puts(w, "; end");
            break;
        case 3:
            ow_puts(w, "while "); ow_put(w, x_ptr, x_len); ow_puts(w, "; "); ow_put(w, y_ptr, y_len); ow_puts(w, "; end");
            break;
        case 4:
            ow_puts(w, "until "); ow_put(w, x_ptr, x_len); ow_puts(w, "; "); ow_put(w, y_ptr, y_len); ow_puts(w, "; end");
            break;
        case 5:
            ow_puts(w, "("); ow_put(w, x_ptr, x_len); ow_puts(w, ") while ("); ow_put(w, y_ptr, y_len); ow_puts(w, ")");
            break;
        case 6:
            ow_puts(w, "("); ow_put(w, x_ptr, x_len); ow_puts(w, ") until ("); ow_put(w, y_ptr, y_len); ow_puts(w, ")");
            break;
        case 7:
            ow_puts(w, "for _i in "); ow_put(w, x_ptr, x_len); ow_puts(w, "; "); ow_put(w, y_ptr, y_len); ow_puts(w, "; end");
            break;
        case 8:
            ow_puts(w, "return("); ow_put(w, x_ptr, x_len); ow_puts(w, ")");
            break;
        case 9:
            ow_puts(w, "break("); ow_put(w, x_ptr, x_len); ow_puts(w, ")");
            break;
        case 10:
            ow_puts(w, "next("); ow_put(w, x_ptr, x_len); ow_puts(w, ")");
            break;
        case 11:
            ow_puts(w, "yield("); ow_put(w, x_ptr, x_len); ow_puts(w, ")");
            break;
        case 12:
            ow_puts(w, "def _f(a, b = ("); ow_put(w, x_ptr, x_len); ow_puts(w, "), *c, d, k: ("); ow_put(w, y_ptr, y_len); ow_puts(w, "), **kw, &blk); "); ow_put(w, x_ptr, x_len); ow_puts(w, "; end");
            break;
        case 13:
            ow_puts(w, "->(a = ("); ow_put(w, x_ptr, x_len); ow_puts(w, "), *b, **c) { "); ow_put(w, y_ptr, y_len); ow_puts(w, " }");
            break;
        case 14:
            ow_puts(w, "case "); ow_put(w, x_ptr, x_len); ow_puts(w, "; in ^("); ow_put(w, y_ptr, y_len); ow_puts(w, "); "); ow_put(w, x_ptr, x_len); ow_puts(w, "; in [a, *b] if "); ow_put(w, y_ptr, y_len); ow_puts(w, "; a; else; "); ow_put(w, y_ptr, y_len); ow_puts(w, "; end");
            break;
        case 15:
            ow_puts(w, "if "); ow_put(w, x_ptr, x_len); ow_puts(w, "; "); ow_put(w, y_ptr, y_len); ow_puts(w, "; else; "); ow_put(w, x_ptr, x_len); ow_puts(w, "; end");
            break;
        case 16:
            ow_puts(w, "("); ow_put(w, x_ptr, x_len); ow_puts(w, ") ? ("); ow_put(w, y_ptr, y_len); ow_puts(w, ") : ("); ow_put(w, x_ptr, x_len); ow_puts(w, ")");
            break;
        case 17: {
            static const char *const ops[] = { " && ", " || ", " and ", " or " };
            ow_puts(w, "("); ow_put(w, x_ptr, x_len); ow_puts(w, ")");
            ow_puts(w, ops[rng_below(m, 4)]);
            ow_puts(w, "("); ow_put(w, y_ptr, y_len); ow_puts(w, ")");
            break;
        }
        case 18:
            ow_puts(w, "_a, (_b, *_c) = "); ow_put(w, x_ptr, x_len);
            break;
        case 19:
            ow_puts(w, "_x ||= ("); ow_put(w, x_ptr, x_len); ow_puts(w, "); _x &&= ("); ow_put(w, y_ptr, y_len); ow_puts(w, ")");
            break;
        case 20:
            ow_puts(w, "class _C; "); ow_put(w, x_ptr, x_len); ow_puts(w, "; end");
            break;
        case 21:
            ow_puts(w, "%I[#{"); ow_put(w, x_ptr, x_len); ow_puts(w, "} a]");
            break;
        case 22:
            ow_puts(w, "%w[a b]");
            break;
        case 23:
            ow_puts(w, "%r{(?<k>#{"); ow_put(w, x_ptr, x_len); ow_puts(w, "})}imx");
            break;
        case 24:
            ow_puts(w, "%x[#{"); ow_put(w, x_ptr, x_len); ow_puts(w, "}]");
            break;
        case 25:
            ow_puts(w, "/(?<k>#{"); ow_put(w, x_ptr, x_len); ow_puts(w, "})/ =~ ("); ow_put(w, y_ptr, y_len); ow_puts(w, ")");
            break;
        case 26: {
            const char *dots = (rng_below(m, 2) == 0) ? ".." : "...";
            ow_puts(w, "if ("); ow_put(w, x_ptr, x_len); ow_puts(w, ")"); ow_puts(w, dots); ow_puts(w, "("); ow_put(w, y_ptr, y_len); ow_puts(w, "); "); ow_put(w, x_ptr, x_len); ow_puts(w, "; end");
            break;
        }
        case 27: {
            const char *dots = (rng_below(m, 2) == 0) ? ".." : "...";
            ow_puts(w, "(("); ow_put(w, x_ptr, x_len); ow_puts(w, ")"); ow_puts(w, dots); ow_puts(w, "("); ow_put(w, y_ptr, y_len); ow_puts(w, ") ? ("); ow_put(w, x_ptr, x_len); ow_puts(w, ") : ("); ow_put(w, y_ptr, y_len); ow_puts(w, "))");
            break;
        }
        case 28: {
            const char *dots = (rng_below(m, 2) == 0) ? ".." : "...";
            ow_puts(w, "while !("); ow_put(w, x_ptr, x_len); ow_puts(w, ")"); ow_puts(w, dots); ow_puts(w, "("); ow_put(w, y_ptr, y_len); ow_puts(w, "); "); ow_put(w, x_ptr, x_len); ow_puts(w, "; end");
            break;
        }
        case 29: {
            const char *dots = (rng_below(m, 2) == 0) ? ".." : "...";
            ow_puts(w, "(("); ow_put(w, x_ptr, x_len); ow_puts(w, ")"); ow_puts(w, dots); ow_puts(w, "("); ow_put(w, y_ptr, y_len); ow_puts(w, "))");
            break;
        }
        case 30: {
            static const char *const forms[] = { "(..(", "(...(", "((", "((" };
            size_t fi = rng_below(m, 4);
            if (fi < 2) {
                ow_puts(w, forms[fi]); ow_put(w, x_ptr, x_len); ow_puts(w, "))");
            } else {
                ow_puts(w, forms[fi]); ow_put(w, x_ptr, x_len); ow_puts(w, fi == 2 ? ")..)" : ")...)");
            }
            break;
        }
        case 31:
            ow_puts(w, "module _M; K = ("); ow_put(w, x_ptr, x_len); ow_puts(w, "); "); ow_put(w, y_ptr, y_len); ow_puts(w, "; end");
            break;
        case 32:
            ow_puts(w, "module ("); ow_put(w, x_ptr, x_len); ow_puts(w, ")::_M; "); ow_put(w, y_ptr, y_len); ow_puts(w, "; end");
            break;
        case 33:
            ow_puts(w, "class << ("); ow_put(w, x_ptr, x_len); ow_puts(w, "); "); ow_put(w, y_ptr, y_len); ow_puts(w, "; end");
            break;
        case 34:
            ow_puts(w, "class _C < ("); ow_put(w, x_ptr, x_len); ow_puts(w, "); "); ow_put(w, y_ptr, y_len); ow_puts(w, "; end");
            break;
        case 35:
            ow_puts(w, "(("); ow_put(w, x_ptr, x_len); ow_puts(w, ") rescue ("); ow_put(w, y_ptr, y_len); ow_puts(w, "))");
            break;
        case 36:
            ow_puts(w, "begin; "); ow_put(w, x_ptr, x_len); ow_puts(w, "; rescue *("); ow_put(w, y_ptr, y_len); ow_puts(w, ") => _e; retry; rescue; "); ow_put(w, y_ptr, y_len); ow_puts(w, "; end");
            break;
        case 37:
            ow_puts(w, "def _f; "); ow_put(w, x_ptr, x_len); ow_puts(w, "; rescue => _e; "); ow_put(w, y_ptr, y_len); ow_puts(w, "; ensure; "); ow_put(w, x_ptr, x_len); ow_puts(w, "; end");
            break;
        case 38:
            ow_puts(w, "def _f(a = ("); ow_put(w, x_ptr, x_len); ow_puts(w, "), **k) = ("); ow_put(w, y_ptr, y_len); ow_puts(w, ")");
            break;
        case 39:
            ow_puts(w, "def _f(...); _g(...); "); ow_put(w, x_ptr, x_len); ow_puts(w, "; end");
            break;
        case 40:
            ow_puts(w, "def _f(*, **, &); _g(*, **, &); "); ow_put(w, x_ptr, x_len); ow_puts(w, "; end");
            break;
        case 41:
            ow_puts(w, "tap { _1 &&= ("); ow_put(w, x_ptr, x_len); ow_puts(w, "); _2 || ("); ow_put(w, y_ptr, y_len); ow_puts(w, ") }");
            break;
        case 42:
            ow_puts(w, "tap { it ||= ("); ow_put(w, x_ptr, x_len); ow_puts(w, "); ("); ow_put(w, y_ptr, y_len); ow_puts(w, ") }");
            break;
        default:
            ow_puts(w, "[*("); ow_put(w, x_ptr, x_len); ow_puts(w, "), "); ow_put(w, y_ptr, y_len); ow_puts(w, "]");
            break;
    }

    if (x_end < src_len) {
        ow_put(w, src + x_end, src_len - x_end);
    }
    return w->len;
}

static size_t emit_tok_flip(
    prism_mutator_t *m,
    out_writer_t *w,
    const uint8_t *src,
    size_t src_len,
    mut_tok_t tok
) {
    const char *repl = NULL;
    switch (tok.kind) {
        case TOK_IF_UNLESS:
            repl = (tok.length == 2) ? "unless" : "if";
            break;
        case TOK_WHILE_UNTIL:
            repl = (tok.length == 5 && memcmp(src + tok.start, "while", 5) == 0) ? "until" : "while";
            break;
        case TOK_AND_OR: {
            static const char *const ops[] = { "&&", "||", "and", "or" };
            repl = ops[rng_below(m, 4)];
            break;
        }
        case TOK_DOT2_DOT3:
            repl = (tok.length == 2) ? "..." : "..";
            break;
        case TOK_CALL_OP:
            repl = (tok.length == 1) ? "&." : ".";
            break;
        case TOK_HEREDOC_OPEN: {
            const uint8_t *p = src + tok.start + 2;
            const uint8_t *end = src + tok.start + tok.length;
            if (p < end && (*p == '-' || *p == '~')) {
                p++;
            }
            if (p < end && (*p == '\'' || *p == '"' || *p == '`')) {
                uint8_t q = *p++;
                if (end > p && end[-1] == q) {
                    end--;
                }
            }
            size_t id_len = (size_t) (end - p);
            static const char *const indents[] = { "", "-", "~" };
            static const char quotes[] = { '\0', '\'', '"', '`' };
            const char *ind = indents[rng_below(m, 3)];
            char q = (id_len == 0) ? quotes[1 + rng_below(m, 3)] : quotes[rng_below(m, 4)];
            size_t tail = (size_t) tok.start + (size_t) tok.length;

            ow_put(w, src, tok.start);
            ow_puts(w, "<<");
            ow_puts(w, ind);
            if (q != '\0') {
                ow_put(w, &q, 1);
            }
            ow_put(w, p, id_len);
            if (q != '\0') {
                ow_put(w, &q, 1);
            }
            if (tail < src_len) {
                ow_put(w, src + tail, src_len - tail);
            }
            return w->len;
        }
        case TOK_ASSIGN_OP: {
            static const char *const ops[] = { "=", "||=", "&&=", "+=", "-=", "*=" };
            repl = ops[rng_below(m, sizeof(ops) / sizeof(ops[0]))];
            break;
        }
    }
    if (repl == NULL) {
        return 0;
    }
    return emit_replace(w, src, src_len, tok.start, tok.length, (const uint8_t *) repl, strlen(repl), false);
}

static size_t emit_delim_pair_toggle(
    out_writer_t *w,
    const uint8_t *src,
    size_t src_len,
    mut_delim_pair_t dp
) {
    size_t open_end = (size_t) dp.open_start + (size_t) dp.open_len;
    size_t close_end = (size_t) dp.close_start + (size_t) dp.close_len;
    if (open_end > dp.close_start || close_end > src_len) {
        return 0;
    }
    ow_put(w, src, dp.open_start);
    ow_puts(w, dp.open_repl);
    ow_put(w, src + open_end, dp.close_start - open_end);
    ow_puts(w, dp.close_repl);
    if (close_end < src_len) {
        ow_put(w, src + close_end, src_len - close_end);
    }
    return w->len;
}

static void maybe_mutate_header(prism_mutator_t *m, uint8_t *hdr, size_t hdr_len) {
    if (hdr_len == 0) {
        return;
    }
    if (hdr_len == 1) {
        if (rng_below(m, 3) == 0) {
            uint8_t bit = (uint8_t) (1u << rng_below(m, 6));
            hdr[0] = (uint8_t) ((hdr[0] ^ bit) & 0x3fu);
        }
    } else {
        if (rng_below(m, 4) == 0) {
            size_t idx = rng_below(m, hdr_len);
            hdr[idx] ^= (uint8_t) (1u << rng_below(m, 8));
        }
    }
}

void *afl_custom_init(void *afl, unsigned int seed) {
    (void) afl;
    prism_mutator_t *m = (prism_mutator_t *) calloc(1, sizeof(*m));
    if (m == NULL) {
        return NULL;
    }
    m->rng = ((uint64_t) seed << 32) ^ 0x9e3779b97f4a7c15ULL;
    if (m->rng == 0) {
        m->rng = 0x2545f4914f6cdd1dULL;
    }
    m->header_bytes = 4;
    const char *hdr_env = getenv("PRISM_MUTATOR_HEADER_BYTES");
    if (hdr_env != NULL && hdr_env[0] != '\0') {
        long v = strtol(hdr_env, NULL, 10);
        if (v >= 0 && v <= 16) {
            m->header_bytes = (size_t) v;
        }
    }
    ensure_out_cap(m, PM_MUT_INIT_CAP);
    return m;
}

void afl_custom_deinit(void *data) {
    prism_mutator_t *m = (prism_mutator_t *) data;
    if (m == NULL) {
        return;
    }
    free(m->cache_src);
    free(m->out_buf);
    free(m);
}

static bool get_or_index_a(prism_mutator_t *m, const uint8_t *src, size_t src_len) {
    uint64_t h = fnv1a_64(src, src_len);
    if (m->cache_valid && m->cache_len == src_len && m->cache_hash == h &&
        (src_len == 0 || memcmp(m->cache_src, src, src_len) == 0)) {
        m->cache_idx.src = src;
        return m->cache_has_nodes;
    }

    m->cache_has_nodes = index_ruby_source(src, src_len, &m->cache_idx);
    m->cache_valid = false;
    if (src_len <= PM_MUT_MAX_PARSE_LEN) {
        if (src_len > m->cache_cap) {
            size_t next = src_len < 1024 ? 1024 : src_len;
            uint8_t *p = (uint8_t *) realloc(m->cache_src, next);
            if (p != NULL) {
                m->cache_src = p;
                m->cache_cap = next;
            }
        }
        if (src_len == 0 || (m->cache_src != NULL && src_len <= m->cache_cap)) {
            if (src_len > 0) {
                memcpy(m->cache_src, src, src_len);
            }
            m->cache_len = src_len;
            m->cache_hash = h;
            m->cache_valid = true;
        }
    }
    return m->cache_has_nodes;
}

size_t afl_custom_fuzz(
    void *data,
    uint8_t *buf,
    size_t buf_size,
    uint8_t **out_buf,
    uint8_t *add_buf,
    size_t add_buf_size,
    size_t max_size
) {
    prism_mutator_t *m = (prism_mutator_t *) data;
    if (m == NULL || buf == NULL || max_size == 0) {
        *out_buf = buf;
        return buf_size;
    }

    size_t cap = max_size;
    if (!ensure_out_cap(m, cap)) {
        *out_buf = buf;
        return buf_size;
    }

    size_t hdr_len = m->header_bytes;
    if (buf_size <= hdr_len || cap <= hdr_len) {
        size_t copy_len = buf_size < cap ? buf_size : cap;
        memcpy(m->out_buf, buf, copy_len);
        *out_buf = m->out_buf;
        return copy_len;
    }

    const uint8_t *src = buf + hdr_len;
    size_t src_len = buf_size - hdr_len;

    if (!get_or_index_a(m, src, src_len)) {
        size_t copy_len = buf_size < cap ? buf_size : cap;
        memcpy(m->out_buf, buf, copy_len);
        maybe_mutate_header(m, m->out_buf, copy_len < hdr_len ? copy_len : hdr_len);
        *out_buf = m->out_buf;
        return copy_len;
    }
    const ast_index_t *idx_a = &m->cache_idx;

    size_t op = rng_below(m, 100);
    ast_index_t idx_b;
    bool has_b = false;
    const uint8_t *src_b = NULL;
    if ((op < 66 || op >= 90) && add_buf != NULL && add_buf_size > hdr_len) {
        src_b = add_buf + hdr_len;
        has_b = index_ruby_source(src_b, add_buf_size - hdr_len, &idx_b);
    }

    memcpy(m->out_buf, buf, hdr_len);
    maybe_mutate_header(m, m->out_buf, hdr_len);

    out_writer_t w = {
        .buf = m->out_buf + hdr_len,
        .len = 0,
        .cap = cap - hdr_len
    };

    size_t written = 0;

    if (op < 26 && has_b) {
        /* Subtree crossover from donor input B */
        mut_span_t x = idx_a->nodes[rng_below(m, idx_a->node_count)];
        mut_span_t y = idx_b.nodes[rng_below(m, idx_b.node_count)];
        bool parens = rng_below(m, 5) < 2;
        written = emit_replace(&w, src, src_len, x.start, x.length, src_b + y.start, y.length, parens);
    } else if (op < 56) {
        /* Compiler-torture wrapper around node X (with Y from A or B) */
        mut_span_t x = idx_a->nodes[rng_below(m, idx_a->node_count)];
        const uint8_t *y_ptr;
        size_t y_len;
        if (has_b && rng_below(m, 2) == 0) {
            mut_span_t y = idx_b.nodes[rng_below(m, idx_b.node_count)];
            y_ptr = src_b + y.start;
            y_len = y.length;
        } else {
            mut_span_t y = idx_a->nodes[rng_below(m, idx_a->node_count)];
            y_ptr = src + y.start;
            y_len = y.length;
        }
        written = emit_wrapper(m, &w, src, src_len, x, y_ptr, y_len);
    } else if (op < 66) {
        /* Inline heredoc injection at expression X with body on next line */
        mut_span_t x = idx_a->nodes[rng_below(m, idx_a->node_count)];
        const uint8_t *y_ptr;
        size_t y_len;
        if (has_b && rng_below(m, 2) == 0) {
            mut_span_t y = idx_b.nodes[rng_below(m, idx_b.node_count)];
            y_ptr = src_b + y.start;
            y_len = y.length;
        } else {
            mut_span_t y = idx_a->nodes[rng_below(m, idx_a->node_count)];
            y_ptr = src + y.start;
            y_len = y.length;
        }
        written = emit_heredoc_inject(m, &w, src, src_len, x, y_ptr, y_len);
    } else if (op < 72) {
        /* Magic comment / encoding / shebang / BOM / __END__ injection */
        written = emit_magic_or_end(m, &w, src, src_len);
    } else if (op < 80 && idx_a->node_count >= 2) {
        /* Internal subtree copy or swap */
        mut_span_t a = idx_a->nodes[rng_below(m, idx_a->node_count)];
        mut_span_t b = idx_a->nodes[rng_below(m, idx_a->node_count)];
        if (rng_below(m, 2) == 0) {
            written = emit_swap(&w, src, src_len, a, b);
        }
        if (written == 0) {
            w.len = 0;
            bool parens = rng_below(m, 3) == 0;
            written = emit_replace(&w, src, src_len, a.start, a.length, src + b.start, b.length, parens);
        }
    } else if (op < 90 && (idx_a->token_count > 0 || idx_a->delim_pair_count > 0)) {
        /* Surgical keyword/operator flip or delimiter-pair toggle */
        if (idx_a->delim_pair_count > 0 && (idx_a->token_count == 0 || rng_below(m, 2) == 0)) {
            mut_delim_pair_t dp = idx_a->delim_pairs[rng_below(m, idx_a->delim_pair_count)];
            written = emit_delim_pair_toggle(&w, src, src_len, dp);
        } else {
            mut_tok_t tok = idx_a->tokens[rng_below(m, idx_a->token_count)];
            written = emit_tok_flip(m, &w, src, src_len, tok);
        }
    } else {
        /* Replace node with control-flow / literal atom, or insert statement */
        mut_span_t x = idx_a->nodes[rng_below(m, idx_a->node_count)];
        if (rng_below(m, 2) == 0) {
            static const char *const atoms[] = {
                "nil", "0", "true", "false", "yield", "super", "redo", "retry",
                "break", "next", "return", "self", "__FILE__", "()"
            };
            const char *atom = atoms[rng_below(m, sizeof(atoms) / sizeof(atoms[0]))];
            written = emit_replace(&w, src, src_len, x.start, x.length, (const uint8_t *) atom, strlen(atom), false);
        } else {
            const uint8_t *ins_ptr = src + x.start;
            size_t ins_len = x.length;
            if (has_b) {
                mut_span_t y = idx_b.nodes[rng_below(m, idx_b.node_count)];
                ins_ptr = src_b + y.start;
                ins_len = y.length;
            }
            ow_put(&w, src, x.start);
            ow_put(&w, ins_ptr, ins_len);
            ow_puts(&w, "\n");
            ow_put(&w, src + x.start, src_len - x.start);
            written = w.len;
        }
    }

    if (written == 0) {
        size_t copy_len = src_len < w.cap ? src_len : w.cap;
        memcpy(m->out_buf + hdr_len, src, copy_len);
        written = copy_len;
    }

    *out_buf = m->out_buf;
    return hdr_len + written;
}

#ifdef PRISM_MUTATOR_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) {
        return 0;
    }

    uint32_t seed = ((uint32_t) data[0]) | ((uint32_t) data[1] << 8);
    size_t hdr_bytes = data[2] % 5u; /* 0..4 */
    size_t max_size = (size_t) data[3] * 8u; /* 0..2040, exercises small/zero caps */
    const uint8_t *payload = data + 4;
    size_t payload_len = size - 4;

    /* Split payload into buf and add_buf */
    size_t split = payload_len > 0 ? ((size_t) data[0] % (payload_len + 1)) : 0;
    size_t buf_len = split;
    size_t add_len = payload_len - split;

    uint8_t *buf = buf_len > 0 ? (uint8_t *) malloc(buf_len) : NULL;
    uint8_t *add_buf = add_len > 0 ? (uint8_t *) malloc(add_len) : NULL;
    if ((buf_len > 0 && buf == NULL) || (add_len > 0 && add_buf == NULL)) {
        free(buf);
        free(add_buf);
        return 0;
    }
    if (buf_len > 0) memcpy(buf, payload, buf_len);
    if (add_len > 0) memcpy(add_buf, payload + split, add_len);

    char hdr_str[8];
    snprintf(hdr_str, sizeof(hdr_str), "%zu", hdr_bytes);
    setenv("PRISM_MUTATOR_HEADER_BYTES", hdr_str, 1);

    void *m = afl_custom_init(NULL, seed);
    if (m != NULL) {
        /* Run multiple rounds on the same buf to exercise both cache miss & cache hit,
         * with and without add_buf, and with both constrained and generous max_size. */
        size_t caps[3] = { max_size, buf_len + 256u, 16u };
        for (int i = 0; i < 6; i++) {
            uint8_t *out = NULL;
            uint8_t *donor = (i % 3 == 2) ? NULL : add_buf;
            size_t donor_len = (i % 3 == 2) ? 0 : add_len;
            size_t cap = caps[i % 3];
            size_t n = afl_custom_fuzz(m, buf, buf_len, &out, donor, donor_len, cap);
            if (cap > 0 && buf != NULL) {
                if (n > cap) {
                    abort();
                }
                volatile uint8_t sink = 0;
                for (size_t j = 0; j < n; j++) {
                    sink ^= out[j];
                }
                (void) sink;
            }
        }
        afl_custom_deinit(m);
    }

    free(buf);
    free(add_buf);
    return 0;
}
#endif

#ifdef PRISM_MUTATOR_STANDALONE_TEST
int main(void) {
    setenv("PRISM_MUTATOR_HEADER_BYTES", "1", 1);
    void *m = afl_custom_init(NULL, 42);
    uint8_t a[] = "\0" "def f(x); a = x + 1; if a; return a; end; end";
    uint8_t b[] = "\0" "while yield; begin; 1 && 2; ensure; next; end; end";
    for (int i = 0; i < 15; i++) {
        uint8_t *out = NULL;
        size_t n = afl_custom_fuzz(m, a, sizeof(a) - 1, &out, b, sizeof(b) - 1, 256);
        printf("[%02d] hdr=0x%02x len=%zu: %.*s\n", i, out[0], n - 1, (int) (n - 1), (const char *) (out + 1));
    }
    afl_custom_deinit(m);
    return 0;
}
#endif
