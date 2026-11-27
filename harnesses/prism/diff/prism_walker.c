#include "prism_walker.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const pm_parser_t *parser;
    diff_summary_t *out;
    size_t depth;
    uint32_t preexe_depth;
} diff_prism_ctx_t;

static void diff_prism_push_scope(
    const pm_parser_t *parser,
    diff_summary_t *out,
    diff_scope_kind_t kind,
    const pm_constant_id_list_t *list
) {
    if (out->locals.count > UINT32_MAX) {
        abort();
    }
    diff_scope_t sc;
    sc.kind = (uint8_t) kind;
    sc.local_start = (uint32_t) out->locals.count;
    uint32_t added = 0;
    for (size_t i = 0; i < list->size; i++) {
        const pm_constant_t *c = pm_parser_constant(parser, list->ids[i]);
        const char *ptr = (const char *) pm_constant_start(c);
        size_t len = pm_constant_length(c);
        if (diff_is_synthetic_local(ptr, len)) {
            continue;
        }
        diff_span_vec_push(&out->locals, diff_strbuf_add(&out->strbuf, ptr, len));
        added++;
    }
    sc.local_count = added;
    diff_scope_vec_push(&out->scopes, sc);
}

static void diff_prism_add_const(const pm_parser_t *parser, diff_summary_t *out, pm_constant_id_t id, diff_span_vec_t *vec) {
    const pm_constant_t *c = pm_parser_constant(parser, id);
    const char *ptr = (const char *) pm_constant_start(c);
    size_t len = pm_constant_length(c);
    diff_span_vec_push(vec, diff_strbuf_add(&out->strbuf, ptr, len));
}

static void diff_prism_const_buf(
    const pm_parser_t *parser,
    pm_constant_id_t id,
    const char **ptr_out,
    size_t *len_out
) {
    if (id == 0) {
        *ptr_out = NULL;
        *len_out = 0;
        return;
    }
    const pm_constant_t *c = pm_parser_constant(parser, id);
    *ptr_out = (const char *) pm_constant_start(c);
    *len_out = pm_constant_length(c);
}

static void diff_prism_tree_open_const(diff_prism_ctx_t *ctx, diff_tok_tag_t tag, pm_constant_id_t id) {
    const char *ptr = NULL;
    size_t len = 0;
    diff_prism_const_buf(ctx->parser, id, &ptr, &len);
    diff_tree_open(ctx->out, tag, ptr, len);
}

static void diff_prism_tree_leaf_const(diff_prism_ctx_t *ctx, diff_tok_tag_t tag, pm_constant_id_t id) {
    const char *ptr = NULL;
    size_t len = 0;
    diff_prism_const_buf(ctx->parser, id, &ptr, &len);
    diff_tree_leaf(ctx->out, tag, ptr, len);
}

static void diff_prism_emit_tagged_id(
    diff_prism_ctx_t *ctx,
    diff_tok_tag_t tag,
    char prefix,
    pm_constant_id_t id
) {
    const char *ptr = NULL;
    size_t len = 0;
    diff_prism_const_buf(ctx->parser, id, &ptr, &len);
    char stack_buf[128];
    if (len + 2 <= sizeof(stack_buf)) {
        stack_buf[0] = prefix;
        stack_buf[1] = ':';
        if (len > 0) {
            memcpy(stack_buf + 2, ptr, len);
        }
        diff_tree_open(ctx->out, tag, stack_buf, len + 2);
    } else {
        char *heap_buf = (char *) malloc(len + 2);
        if (heap_buf == NULL) {
            abort();
        }
        heap_buf[0] = prefix;
        heap_buf[1] = ':';
        memcpy(heap_buf + 2, ptr, len);
        diff_tree_open(ctx->out, tag, heap_buf, len + 2);
        free(heap_buf);
    }
}

static void diff_prism_visit_expr(const pm_node_t *node, diff_prism_ctx_t *ctx, bool in_args);

static pm_visit_result_t diff_prism_visit_cb(const pm_node_t *node, void *data) {
    diff_prism_visit_expr(node, (diff_prism_ctx_t *) data, false);
    return PM_VISIT_SKIP;
}

static void diff_prism_visit_child(const pm_node_t *child, diff_prism_ctx_t *ctx) {
    if (child != NULL && ctx->depth < DIFF_MAX_AST_DEPTH) {
        diff_prism_visit_expr(child, ctx, false);
    }
}

static void diff_prism_visit_slot(const char *slot, const pm_node_t *child, diff_prism_ctx_t *ctx) {
    diff_tree_open_slot(ctx->out, slot);
    if (child != NULL) {
        diff_prism_visit_child(child, ctx);
    }
    diff_tree_close(ctx->out);
}

static void diff_prism_visit_stmt_list(const pm_statements_node_t *stmts, diff_prism_ctx_t *ctx) {
    if (stmts == NULL) {
        return;
    }
    for (size_t i = 0; i < stmts->body.size; i++) {
        diff_prism_visit_child(stmts->body.nodes[i], ctx);
    }
}

static bool diff_is_embdoc_boundary(const uint8_t *buf, size_t stop, size_t pos, const char *kw, size_t kw_len) {
    if (pos == 0 || buf[pos - 1] != '\n' || pos + kw_len > stop) {
        return false;
    }
    if (memcmp(buf + pos, kw, kw_len) != 0) {
        return false;
    }
    if (pos + kw_len == stop) {
        return true;
    }
    uint8_t next = buf[pos + kw_len];
    return next == ' ' || next == '\t' || next == '\n' || next == '\r' || next == '\v' || next == '\f' || next == '\0';
}

static bool diff_prism_emb_has_leading_semicolon(const pm_parser_t *parser, const pm_embedded_statements_node_t *emb) {
    if (parser == NULL || emb == NULL || emb->statements == NULL || emb->statements->body.size == 0) {
        return false;
    }
    const pm_node_t *first = emb->statements->body.nodes[0];
    if (first == NULL || emb->opening_loc.start > first->location.start) {
        return false;
    }
    const uint8_t *start = pm_parser_start(parser);
    const uint8_t *end = pm_parser_end(parser);
    if (start == NULL || end == NULL || end < start) {
        return false;
    }
    size_t len = (size_t) (end - start);
    size_t pos = (size_t) emb->opening_loc.start + (size_t) emb->opening_loc.length;
    size_t stop = (size_t) first->location.start;
    if (pos >= stop || stop > len) {
        return false;
    }
    while (pos < stop) {
        uint8_t c = start[pos];
        if (c == ';') {
            return true;
        }
        if (c == '#') {
            while (pos < stop && start[pos] != '\n') {
                pos++;
            }
            continue;
        }
        if (diff_is_embdoc_boundary(start, stop, pos, "=begin", 6)) {
            pos += 6;
            while (pos < stop && !diff_is_embdoc_boundary(start, stop, pos, "=end", 4)) {
                pos++;
            }
            while (pos < stop && start[pos] != '\n') {
                pos++;
            }
            continue;
        }
        pos++;
    }
    return false;
}

/* Check whether a node contains only static string content within `embed_budget`
 * levels of `#{...}` interpolation (-1 = unlimited). Adjacent string concatenation
 * stays at the same level, matching CRuby parse.y folding 1-level `#{plain_str}`
 * into the parent DSTR/DSYM/DREGX while keeping deeper `EVSTR(DSTR ...)` explicit.
 * Unless `fold_leading_semi` is set (used only for DREGX where object identity diverges),
 * a leading `;` inside `#{;...}` is treated as unpacked `EVSTR(BLOCK(...))` to suppress
 * zero-runtime-difference mismatches on DSYM/DSTR/DXSTR. */
static bool diff_prism_node_is_static_str_depth(
    const pm_parser_t *parser,
    const pm_node_t *node,
    int embed_budget,
    bool fold_leading_semi
) {
    if (node == NULL) {
        return true;
    }
    switch (PM_NODE_TYPE(node)) {
        case PM_STRING_NODE:
            return true;
        case PM_EMBEDDED_STATEMENTS_NODE: {
            if (embed_budget == 0) {
                return false;
            }
            const pm_embedded_statements_node_t *emb = (const pm_embedded_statements_node_t *) node;
            if (emb->statements == NULL || emb->statements->body.size != 1) {
                return false;
            }
            if (!fold_leading_semi && diff_prism_emb_has_leading_semicolon(parser, emb)) {
                return false;
            }
            int next_budget = embed_budget > 0 ? embed_budget - 1 : -1;
            return diff_prism_node_is_static_str_depth(parser, emb->statements->body.nodes[0], next_budget, fold_leading_semi);
        }
        case PM_INTERPOLATED_STRING_NODE: {
            const pm_interpolated_string_node_t *istr = (const pm_interpolated_string_node_t *) node;
            for (size_t i = 0; i < istr->parts.size; i++) {
                if (!diff_prism_node_is_static_str_depth(parser, istr->parts.nodes[i], embed_budget, fold_leading_semi)) {
                    return false;
                }
            }
            return true;
        }
        case PM_BEGIN_NODE: {
            const pm_begin_node_t *bn = (const pm_begin_node_t *) node;
            if (bn->rescue_clause == NULL && bn->ensure_clause == NULL && bn->else_clause == NULL &&
                bn->statements != NULL && bn->statements->body.size == 1) {
                return diff_prism_node_is_static_str_depth(parser, bn->statements->body.nodes[0], embed_budget, fold_leading_semi);
            }
            return false;
        }
        default:
            return false;
    }
}

static void diff_prism_visit_interpolated_parts(const pm_node_list_t *parts, diff_prism_ctx_t *ctx) {
    for (size_t i = 0; i < parts->size; i++) {
        const pm_node_t *part = parts->nodes[i];
        if (part == NULL) {
            continue;
        }
        switch (PM_NODE_TYPE(part)) {
            case PM_STRING_NODE:
                break;
            case PM_INTERPOLATED_STRING_NODE: {
                const pm_interpolated_string_node_t *nested = (const pm_interpolated_string_node_t *) part;
                diff_prism_visit_interpolated_parts(&nested->parts, ctx);
                break;
            }
            case PM_EMBEDDED_STATEMENTS_NODE: {
                const pm_embedded_statements_node_t *emb = (const pm_embedded_statements_node_t *) part;
                if (diff_prism_node_is_static_str_depth(ctx->parser, part, -1, false)) {
                    break;
                }
                diff_prism_visit_stmt_list(emb->statements, ctx);
                break;
            }
            case PM_EMBEDDED_VARIABLE_NODE: {
                const pm_embedded_variable_node_t *embv = (const pm_embedded_variable_node_t *) part;
                diff_prism_visit_child(embv->variable, ctx);
                break;
            }
            default:
                diff_prism_visit_child(part, ctx);
                break;
        }
    }
}

static void diff_prism_hash_static_parts(
    const pm_node_list_t *parts,
    uint64_t *hash_io,
    size_t *len_io,
    size_t depth
) {
    if (parts == NULL || depth >= DIFF_MAX_AST_DEPTH) {
        return;
    }
    for (size_t i = 0; i < parts->size; i++) {
        const pm_node_t *part = parts->nodes[i];
        if (part == NULL) {
            continue;
        }
        switch (PM_NODE_TYPE(part)) {
            case PM_STRING_NODE: {
                const pm_string_node_t *sn = (const pm_string_node_t *) part;
                const uint8_t *src = pm_string_source(&sn->unescaped);
                size_t slen = pm_string_length(&sn->unescaped);
                if (src != NULL && slen > 0) {
                    *hash_io = diff_fnv64_update(*hash_io, src, slen);
                    *len_io += slen;
                }
                break;
            }
            case PM_INTERPOLATED_STRING_NODE: {
                const pm_interpolated_string_node_t *nested = (const pm_interpolated_string_node_t *) part;
                diff_prism_hash_static_parts(&nested->parts, hash_io, len_io, depth + 1);
                break;
            }
            case PM_EMBEDDED_STATEMENTS_NODE: {
                const pm_embedded_statements_node_t *emb = (const pm_embedded_statements_node_t *) part;
                if (emb->statements != NULL) {
                    diff_prism_hash_static_parts(&emb->statements->body, hash_io, len_io, depth + 1);
                }
                break;
            }
            case PM_BEGIN_NODE: {
                const pm_begin_node_t *bn = (const pm_begin_node_t *) part;
                if (bn->rescue_clause == NULL && bn->ensure_clause == NULL && bn->else_clause == NULL &&
                    bn->statements != NULL) {
                    diff_prism_hash_static_parts(&bn->statements->body, hash_io, len_io, depth + 1);
                }
                break;
            }
            default:
                break;
        }
    }
}

static unsigned int diff_prism_regexp_opts(pm_node_flags_t flags) {
    unsigned int opts = 0;
    if (flags & PM_REGULAR_EXPRESSION_FLAGS_IGNORE_CASE) opts |= 1u;
    if (flags & PM_REGULAR_EXPRESSION_FLAGS_EXTENDED)    opts |= 2u;
    if (flags & PM_REGULAR_EXPRESSION_FLAGS_MULTI_LINE)  opts |= 4u;
    return opts;
}

static void diff_prism_emit_bytes_leaf(
    diff_summary_t *out,
    diff_tok_tag_t tag,
    const uint8_t *data,
    size_t len
) {
    uint64_t h = DIFF_FNV64_OFFSET;
    if (data != NULL && len > 0) {
        h = diff_fnv64_update(h, data, len);
    }
    char buf[48];
    snprintf(buf, sizeof(buf), "%zu:%016llx", len, (unsigned long long) h);
    diff_tree_leaf_cstr(out, tag, buf);
}

static void diff_prism_emit_regexp_leaf(
    diff_summary_t *out,
    unsigned int opts,
    uint64_t h,
    size_t len
) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%u:%zu:%016llx", opts, len, (unsigned long long) h);
    diff_tree_leaf_cstr(out, DIFF_TOK_REGX, buf);
}

static void diff_prism_format_integer(const pm_integer_t *iv, char *buf, size_t cap) {
    uint32_t nwords = 0;
    const uint32_t *words = pm_integer_words(iv, &nwords);
    if (nwords == 0) {
        snprintf(buf, cap, "0");
    } else if (nwords <= 2) {
        uint64_t mag = (uint64_t) words[0];
        if (nwords == 2) {
            mag |= ((uint64_t) words[1]) << 32;
        }
        snprintf(buf, cap, "%s%llu", iv->negative ? "-" : "", (unsigned long long) mag);
    } else {
        uint64_t h = DIFF_FNV64_OFFSET;
        for (uint32_t i = 0; i < nwords; i++) {
            uint8_t le[4] = {
                (uint8_t) (words[i] & 0xffu),
                (uint8_t) ((words[i] >> 8) & 0xffu),
                (uint8_t) ((words[i] >> 16) & 0xffu),
                (uint8_t) ((words[i] >> 24) & 0xffu)
            };
            h = diff_fnv64_update(h, le, 4);
        }
        snprintf(buf, cap, "%sbig:%u:%016llx", iv->negative ? "-" : "", nwords, (unsigned long long) h);
    }
}

static void diff_prism_format_float(double val, char *buf, size_t cap) {
    uint64_t bits = 0;
    memcpy(&bits, &val, sizeof(bits));
    snprintf(buf, cap, "%016llx", (unsigned long long) bits);
}

static void diff_prism_visit_interpolated(
    const pm_node_t *node,
    const pm_node_list_t *parts,
    diff_tok_tag_t dyn_tag,
    diff_tok_tag_t leaf_tag,
    diff_prism_ctx_t *ctx
) {
    bool all_cruby_folded = true;
    bool all_deep_static = PM_NODE_FLAG_P(node, PM_NODE_FLAG_STATIC_LITERAL);
    bool fold_deep_semi = (dyn_tag == DIFF_TOK_DREGX);
    for (size_t i = 0; i < parts->size; i++) {
        if (!diff_prism_node_is_static_str_depth(ctx->parser, parts->nodes[i], -1, false)) {
            all_cruby_folded = false;
        }
        if (all_deep_static && !diff_prism_node_is_static_str_depth(ctx->parser, parts->nodes[i], -1, fold_deep_semi)) {
            all_deep_static = false;
        }
        if (!all_cruby_folded && !all_deep_static) {
            break;
        }
    }
    if (all_cruby_folded || all_deep_static) {
        uint64_t h = DIFF_FNV64_OFFSET;
        size_t total_len = 0;
        diff_prism_hash_static_parts(parts, &h, &total_len, ctx->depth);
        if (leaf_tag == DIFF_TOK_REGX) {
            /* If all parts are pure PM_STRING_NODEs (e.g. static %r{...} split across a
             * heredoc newline), parse.y emits static NODE_REGX with real option flags.
             * Otherwise parse.y emits NODE_DREGX whose RubyVM::AST hides option flags. */
            bool has_embed = false;
            for (size_t i = 0; i < parts->size; i++) {
                if (parts->nodes[i] != NULL && !PM_NODE_TYPE_P(parts->nodes[i], PM_STRING_NODE)) {
                    has_embed = true;
                    break;
                }
            }
            unsigned int regx_opts = has_embed ? 0u : diff_prism_regexp_opts(node->flags);
            diff_prism_emit_regexp_leaf(ctx->out, regx_opts, h, total_len);
        } else {
            char buf[48];
            snprintf(buf, sizeof(buf), "%zu:%016llx", total_len, (unsigned long long) h);
            diff_tree_leaf_cstr(ctx->out, leaf_tag, buf);
        }
        return;
    }
    diff_tree_open_cstr(ctx->out, dyn_tag, NULL);
    diff_prism_visit_interpolated_parts(parts, ctx);
    diff_tree_close(ctx->out);
}

static void diff_prism_emit_forwarding_args(diff_prism_ctx_t *ctx) {
    diff_tree_open_slot(ctx->out, "arg");
    diff_tree_open_cstr(ctx->out, DIFF_TOK_SPLAT, NULL);
    diff_tree_leaf_cstr(ctx->out, DIFF_TOK_LVAR, "*");
    diff_tree_close(ctx->out);
    diff_tree_close(ctx->out);

    diff_tree_open_slot(ctx->out, "arg");
    diff_tree_open_cstr(ctx->out, DIFF_TOK_HASH, NULL);
    diff_tree_open_cstr(ctx->out, DIFF_TOK_PAIR_SPLAT, NULL);
    diff_tree_leaf_cstr(ctx->out, DIFF_TOK_LVAR, "**");
    diff_tree_close(ctx->out);
    diff_tree_close(ctx->out);
    diff_tree_close(ctx->out);
}

static void diff_prism_emit_seq_elem_ex(
    const pm_node_t *elem,
    size_t idx,
    size_t total_len,
    const char *slot_name,
    diff_prism_ctx_t *ctx
) {
    if ((idx > 0 || total_len > 1) && elem != NULL && PM_NODE_TYPE_P(elem, PM_SPLAT_NODE)) {
        const pm_splat_node_t *sp = (const pm_splat_node_t *) elem;
        if (sp->expression != NULL && PM_NODE_TYPE_P(sp->expression, PM_ARRAY_NODE)) {
            const pm_array_node_t *inner = (const pm_array_node_t *) sp->expression;
            bool allow_flatten = false;
            if (idx > 0) {
                /* CRuby keeps non-initial `*[*expr]` as ARGSCAT(..., NODE_SPLAT) -> SPLAT(SPLAT). */
                allow_flatten = !(inner->elements.size == 1 && PM_NODE_TYPE_P(inner->elements.nodes[0], PM_SPLAT_NODE));
            } else if (inner->elements.size > 0) {
                /* CRuby flattens leading `*[...]` when followed by more elements and inner has no splat. */
                bool has_inner_splat = false;
                for (size_t j = 0; j < inner->elements.size; j++) {
                    if (inner->elements.nodes[j] != NULL && PM_NODE_TYPE_P(inner->elements.nodes[j], PM_SPLAT_NODE)) {
                        has_inner_splat = true;
                        break;
                    }
                }
                allow_flatten = !has_inner_splat;
            }
            if (allow_flatten) {
                for (size_t j = 0; j < inner->elements.size; j++) {
                    diff_prism_emit_seq_elem_ex(inner->elements.nodes[j], idx + j, total_len, slot_name, ctx);
                }
                return;
            }
        }
    }
    diff_tree_open_slot(ctx->out, slot_name);
    if (elem != NULL) {
        diff_prism_visit_expr(elem, ctx, true);
    }
    diff_tree_close(ctx->out);
}

static void diff_prism_emit_seq_elem(
    const pm_node_t *elem,
    size_t idx,
    const char *slot_name,
    diff_prism_ctx_t *ctx
) {
    diff_prism_emit_seq_elem_ex(elem, idx, 1, slot_name, ctx);
}

static bool diff_prism_is_nil_expr(const pm_node_t *node) {
    for (int unwrap = 0; unwrap < 8 && node != NULL; unwrap++) {
        if (PM_NODE_TYPE_P(node, PM_NIL_NODE)) {
            return true;
        }
        if (PM_NODE_TYPE_P(node, PM_PARENTHESES_NODE)) {
            node = ((const pm_parentheses_node_t *) node)->body;
        } else if (PM_NODE_TYPE_P(node, PM_STATEMENTS_NODE)) {
            const pm_statements_node_t *stmts = (const pm_statements_node_t *) node;
            if (stmts->body.size == 1) {
                node = stmts->body.nodes[0];
            } else {
                return false;
            }
        } else if (PM_NODE_TYPE_P(node, PM_BEGIN_NODE)) {
            const pm_begin_node_t *bn = (const pm_begin_node_t *) node;
            if (bn->rescue_clause == NULL && bn->ensure_clause == NULL && bn->else_clause == NULL) {
                node = bn->statements != NULL ? &bn->statements->base : NULL;
            } else {
                return false;
            }
        } else if (PM_NODE_TYPE_P(node, PM_ELSE_NODE)) {
            const pm_else_node_t *en = (const pm_else_node_t *) node;
            node = en->statements != NULL ? &en->statements->base : NULL;
        } else {
            return false;
        }
    }
    return false;
}

static void diff_prism_emit_arguments(
    const pm_arguments_node_t *args,
    const pm_node_t *block,
    diff_prism_ctx_t *ctx,
    bool emit_blk_slot
) {
    diff_tree_open_slot(ctx->out, "args");
    bool has_fwd = false;
    if (args != NULL) {
        size_t pos_count = 0;
        for (size_t i = 0; i < args->arguments.size; i++) {
            const pm_node_t *a = args->arguments.nodes[i];
            if (a != NULL && !PM_NODE_TYPE_P(a, PM_KEYWORD_HASH_NODE)) {
                pos_count++;
            }
        }
        for (size_t i = 0; i < args->arguments.size; i++) {
            const pm_node_t *arg = args->arguments.nodes[i];
            if (arg != NULL && PM_NODE_TYPE_P(arg, PM_FORWARDING_ARGUMENTS_NODE)) {
                has_fwd = true;
                diff_prism_emit_forwarding_args(ctx);
            } else {
                diff_prism_emit_seq_elem_ex(arg, i, pos_count, "arg", ctx);
            }
        }
    }
    diff_tree_close(ctx->out);

    if (emit_blk_slot) {
        diff_tree_open_slot(ctx->out, "blk");
        if (block != NULL) {
            diff_prism_visit_child(block, ctx);
        } else if (has_fwd) {
            diff_tree_open_cstr(ctx->out, DIFF_TOK_BLOCK_PASS, NULL);
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_LVAR, "&");
            diff_tree_close(ctx->out);
        }
        diff_tree_close(ctx->out);
    }
}

static void diff_prism_visit_begin_parts(
    const pm_statements_node_t *statements,
    const pm_rescue_node_t *rescue_clause,
    const pm_else_node_t *else_clause,
    const pm_ensure_node_t *ensure_clause,
    diff_prism_ctx_t *ctx
) {
    if (ensure_clause != NULL) {
        ctx->out->counts[DIFF_CNT_ENSURE]++;
        diff_tree_open_cstr(ctx->out, DIFF_TOK_ENSURE, NULL);
        diff_tree_open_slot(ctx->out, "body");
    }
    if (rescue_clause != NULL) {
        diff_tree_open_cstr(ctx->out, DIFF_TOK_RESCUE, NULL);
        diff_tree_open_slot(ctx->out, "body");
        if (!(statements != NULL && statements->body.size == 1 &&
              statements->body.nodes[0] != NULL && PM_NODE_TYPE_P(statements->body.nodes[0], PM_NIL_NODE))) {
            diff_prism_visit_stmt_list(statements, ctx);
        }
        diff_tree_close(ctx->out);

        diff_tree_open_slot(ctx->out, "resq");
        for (const pm_rescue_node_t *r = rescue_clause; r != NULL; r = r->subsequent) {
            ctx->out->counts[DIFF_CNT_RESCUE]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_RESBODY, NULL);
            diff_tree_open_slot(ctx->out, "exc");
            for (size_t i = 0; i < r->exceptions.size; i++) {
                const pm_node_t *ex = r->exceptions.nodes[i];
                if (i == 0 && ex != NULL && PM_NODE_TYPE_P(ex, PM_SPLAT_NODE)) {
                    const pm_splat_node_t *sp = (const pm_splat_node_t *) ex;
                    if (sp->expression != NULL && PM_NODE_TYPE_P(sp->expression, PM_ARRAY_NODE)) {
                        const pm_array_node_t *inner = (const pm_array_node_t *) sp->expression;
                        bool has_inner_splat = false;
                        for (size_t j = 0; j < inner->elements.size; j++) {
                            if (inner->elements.nodes[j] != NULL && PM_NODE_TYPE_P(inner->elements.nodes[j], PM_SPLAT_NODE)) {
                                has_inner_splat = true;
                                break;
                            }
                        }
                        if (inner->elements.size > 0 && !has_inner_splat) {
                            for (size_t j = 0; j < inner->elements.size; j++) {
                                diff_prism_emit_seq_elem(inner->elements.nodes[j], j, "elem", ctx);
                            }
                            continue;
                        }
                    }
                }
                diff_prism_emit_seq_elem(ex, i, "elem", ctx);
            }
            diff_tree_close(ctx->out);
            diff_prism_visit_slot("var", r->reference, ctx);
            diff_tree_open_slot(ctx->out, "body");
            diff_prism_visit_stmt_list(r->statements, ctx);
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
        }
        diff_tree_close(ctx->out);

        diff_tree_open_slot(ctx->out, "else");
        if (else_clause != NULL) {
            diff_prism_visit_stmt_list(else_clause->statements, ctx);
        }
        diff_tree_close(ctx->out);
        diff_tree_close(ctx->out);
    } else {
        diff_prism_visit_stmt_list(statements, ctx);
        if (else_clause != NULL) {
            diff_prism_visit_stmt_list(else_clause->statements, ctx);
        }
    }
    if (ensure_clause != NULL) {
        diff_tree_close(ctx->out);
        diff_tree_open_slot(ctx->out, "ens");
        diff_prism_visit_stmt_list(ensure_clause->statements, ctx);
        diff_tree_close(ctx->out);
        diff_tree_close(ctx->out);
    }
}

static bool diff_prism_params_all_empty(const pm_parameters_node_t *p) {
    return p == NULL || (
        p->requireds.size == 0 && p->optionals.size == 0 && p->rest == NULL &&
        p->posts.size == 0 && p->keywords.size == 0 && p->keyword_rest == NULL && p->block == NULL
    );
}

static void diff_prism_visit_params_node(const pm_node_t *pnode, diff_prism_ctx_t *ctx) {
    if (pnode == NULL) {
        return;
    }
    if (PM_NODE_TYPE_P(pnode, PM_BLOCK_PARAMETERS_NODE)) {
        const pm_block_parameters_node_t *bp = (const pm_block_parameters_node_t *) pnode;
        pnode = bp->parameters != NULL ? &bp->parameters->base : NULL;
        if (pnode == NULL) {
            return;
        }
    }
    if (PM_NODE_TYPE_P(pnode, PM_IT_PARAMETERS_NODE)) {
        diff_tree_open_cstr(ctx->out, DIFF_TOK_PARAMS, NULL);
        diff_tree_leaf_cstr(ctx->out, DIFF_TOK_PARAM, "pre=1");
        diff_tree_leaf_cstr(ctx->out, DIFF_TOK_PARAM, "post=0");
        diff_tree_close(ctx->out);
        return;
    }
    if (PM_NODE_TYPE_P(pnode, PM_NUMBERED_PARAMETERS_NODE)) {
        const pm_numbered_parameters_node_t *np = (const pm_numbered_parameters_node_t *) pnode;
        char buf[32];
        snprintf(buf, sizeof(buf), "pre=%u", (unsigned) np->maximum);
        diff_tree_open_cstr(ctx->out, DIFF_TOK_PARAMS, NULL);
        diff_tree_leaf_cstr(ctx->out, DIFF_TOK_PARAM, buf);
        diff_tree_leaf_cstr(ctx->out, DIFF_TOK_PARAM, "post=0");
        diff_tree_close(ctx->out);
        return;
    }
    if (!PM_NODE_TYPE_P(pnode, PM_PARAMETERS_NODE)) {
        diff_prism_visit_child(pnode, ctx);
        return;
    }
    const pm_parameters_node_t *p = (const pm_parameters_node_t *) pnode;
    if (diff_prism_params_all_empty(p)) {
        return;
    }

    char count_buf[32];
    diff_tree_open_cstr(ctx->out, DIFF_TOK_PARAMS, NULL);
    snprintf(count_buf, sizeof(count_buf), "pre=%lu", (unsigned long) p->requireds.size);
    diff_tree_leaf_cstr(ctx->out, DIFF_TOK_PARAM, count_buf);
    snprintf(count_buf, sizeof(count_buf), "post=%lu", (unsigned long) p->posts.size);
    diff_tree_leaf_cstr(ctx->out, DIFF_TOK_PARAM, count_buf);

    for (size_t i = 0; i < p->requireds.size; i++) {
        if (PM_NODE_TYPE_P(p->requireds.nodes[i], PM_MULTI_TARGET_NODE)) {
            diff_prism_visit_child(p->requireds.nodes[i], ctx);
        }
    }
    for (size_t i = 0; i < p->optionals.size; i++) {
        const pm_node_t *opt = p->optionals.nodes[i];
        if (opt != NULL && PM_NODE_TYPE_P(opt, PM_OPTIONAL_PARAMETER_NODE)) {
            const pm_optional_parameter_node_t *op = (const pm_optional_parameter_node_t *) opt;
            diff_prism_emit_tagged_id(ctx, DIFF_TOK_PARAM, 'o', op->name);
            diff_prism_visit_child(op->value, ctx);
            diff_tree_close(ctx->out);
        }
    }
    for (size_t i = 0; i < p->posts.size; i++) {
        if (PM_NODE_TYPE_P(p->posts.nodes[i], PM_MULTI_TARGET_NODE)) {
            diff_prism_visit_child(p->posts.nodes[i], ctx);
        }
    }

    bool has_fwd = p->keyword_rest != NULL && PM_NODE_TYPE_P(p->keyword_rest, PM_FORWARDING_PARAMETER_NODE);
    if (p->rest != NULL) {
        if (PM_NODE_TYPE_P(p->rest, PM_IMPLICIT_REST_NODE)) {
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_PARAM, "comma");
        } else if (PM_NODE_TYPE_P(p->rest, PM_REST_PARAMETER_NODE)) {
            const pm_rest_parameter_node_t *rp = (const pm_rest_parameter_node_t *) p->rest;
            if (rp->name != 0) {
                diff_prism_emit_tagged_id(ctx, DIFF_TOK_PARAM, 'r', rp->name);
                diff_tree_close(ctx->out);
            } else {
                diff_tree_leaf_cstr(ctx->out, DIFF_TOK_PARAM, "r:*");
            }
        }
    } else if (has_fwd) {
        diff_tree_leaf_cstr(ctx->out, DIFF_TOK_PARAM, "r:*");
    }

    for (size_t i = 0; i < p->keywords.size; i++) {
        const pm_node_t *kw = p->keywords.nodes[i];
        if (kw == NULL) {
            continue;
        }
        if (PM_NODE_TYPE_P(kw, PM_REQUIRED_KEYWORD_PARAMETER_NODE)) {
            const pm_required_keyword_parameter_node_t *rkw = (const pm_required_keyword_parameter_node_t *) kw;
            diff_prism_emit_tagged_id(ctx, DIFF_TOK_PARAM, 'k', rkw->name);
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_SLOT, "req");
            diff_tree_close(ctx->out);
        } else if (PM_NODE_TYPE_P(kw, PM_OPTIONAL_KEYWORD_PARAMETER_NODE)) {
            const pm_optional_keyword_parameter_node_t *okw = (const pm_optional_keyword_parameter_node_t *) kw;
            diff_prism_emit_tagged_id(ctx, DIFF_TOK_PARAM, 'k', okw->name);
            diff_prism_visit_child(okw->value, ctx);
            diff_tree_close(ctx->out);
        }
    }

    if (p->keyword_rest != NULL) {
        if (PM_NODE_TYPE_P(p->keyword_rest, PM_NO_KEYWORDS_PARAMETER_NODE)) {
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_PARAM, "nokw");
        } else if (PM_NODE_TYPE_P(p->keyword_rest, PM_FORWARDING_PARAMETER_NODE)) {
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_PARAM, "K:**");
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_PARAM, "b:&");
        } else if (PM_NODE_TYPE_P(p->keyword_rest, PM_KEYWORD_REST_PARAMETER_NODE)) {
            const pm_keyword_rest_parameter_node_t *krp = (const pm_keyword_rest_parameter_node_t *) p->keyword_rest;
            if (krp->name != 0) {
                diff_prism_emit_tagged_id(ctx, DIFF_TOK_PARAM, 'K', krp->name);
                diff_tree_close(ctx->out);
            } else {
                diff_tree_leaf_cstr(ctx->out, DIFF_TOK_PARAM, "K:**");
            }
        }
    }

    if (p->block != NULL && PM_NODE_TYPE_P(p->block, PM_BLOCK_PARAMETER_NODE)) {
        const pm_block_parameter_node_t *bp = (const pm_block_parameter_node_t *) p->block;
        if (bp->name != 0) {
            diff_prism_emit_tagged_id(ctx, DIFF_TOK_PARAM, 'b', bp->name);
            diff_tree_close(ctx->out);
        } else {
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_PARAM, "b:&");
        }
    }

    diff_tree_close(ctx->out);
}

static void diff_prism_visit_hash_elems(const pm_node_list_t *elements, diff_prism_ctx_t *ctx) {
    diff_tree_open_cstr(ctx->out, DIFF_TOK_HASH, NULL);
    for (size_t i = 0; i < elements->size; i++) {
        const pm_node_t *elem = elements->nodes[i];
        /* CRuby parse.y flattens non-initial `**{...}` literal hash splats inline. */
        if (i > 0 && elem != NULL && PM_NODE_TYPE_P(elem, PM_ASSOC_SPLAT_NODE)) {
            const pm_assoc_splat_node_t *as = (const pm_assoc_splat_node_t *) elem;
            if (as->value != NULL && PM_NODE_TYPE_P(as->value, PM_HASH_NODE)) {
                const pm_hash_node_t *inner = (const pm_hash_node_t *) as->value;
                for (size_t j = 0; j < inner->elements.size; j++) {
                    diff_prism_visit_child(inner->elements.nodes[j], ctx);
                }
                continue;
            }
        }
        diff_prism_visit_child(elem, ctx);
    }
    diff_tree_close(ctx->out);
}

static void diff_prism_visit_logical_leaf(const pm_node_t *node, pm_node_type_t ntype, diff_prism_ctx_t *ctx) {
    if (ntype == PM_ALTERNATION_PATTERN_NODE && node != NULL && ctx->depth < DIFF_MAX_AST_DEPTH) {
        while (node != NULL && PM_NODE_TYPE_P(node, PM_PARENTHESES_NODE)) {
            const pm_node_t *body = ((const pm_parentheses_node_t *) node)->body;
            if (body != NULL && PM_NODE_TYPE_P(body, PM_STATEMENTS_NODE)) {
                const pm_statements_node_t *stmts = (const pm_statements_node_t *) body;
                if (stmts->body.size == 1) {
                    node = stmts->body.nodes[0];
                    continue;
                }
                break;
            }
            node = body;
        }
    }
    if (node != NULL && PM_NODE_TYPE_P(node, ntype) && ctx->depth < DIFF_MAX_AST_DEPTH) {
        const pm_node_t *left = NULL;
        const pm_node_t *right = NULL;
        if (ntype == PM_AND_NODE) {
            left = ((const pm_and_node_t *) node)->left;
            right = ((const pm_and_node_t *) node)->right;
        } else if (ntype == PM_OR_NODE) {
            left = ((const pm_or_node_t *) node)->left;
            right = ((const pm_or_node_t *) node)->right;
        } else {
            left = ((const pm_alternation_pattern_node_t *) node)->left;
            right = ((const pm_alternation_pattern_node_t *) node)->right;
        }
        ctx->depth++;
        diff_prism_visit_logical_leaf(left, ntype, ctx);
        diff_prism_visit_logical_leaf(right, ntype, ctx);
        ctx->depth--;
        return;
    }
    diff_prism_visit_child(node, ctx);
}

static void diff_prism_visit_logical(const pm_node_t *node, diff_tok_tag_t tag, pm_node_type_t ntype, diff_prism_ctx_t *ctx) {
    /*
     * CRuby AST::Node#children flattens right-nested AND/OR chains (e.g. `2 or 3 || 3`
     * or `a && b && c`), while stopping at ParenthesesNode (`NODE_BLOCK`). Flatten both
     * unparenthesized child chains recursively in Prism so precedence grouping matches.
     */
    diff_tree_open_cstr(ctx->out, tag, NULL);
    diff_prism_visit_logical_leaf(node, ntype, ctx);
    diff_tree_close(ctx->out);
}

static void diff_prism_visit_ret_like(const pm_arguments_node_t *args, diff_tok_tag_t tag, diff_prism_ctx_t *ctx) {
    diff_tree_open_cstr(ctx->out, tag, NULL);
    if (args != NULL) {
        if (args->arguments.size == 1) {
            diff_prism_visit_child(args->arguments.nodes[0], ctx);
        } else if (args->arguments.size > 1) {
            diff_tree_open_cstr(ctx->out, DIFF_TOK_ARRAY, NULL);
            for (size_t i = 0; i < args->arguments.size; i++) {
                diff_prism_emit_seq_elem(args->arguments.nodes[i], i, "elem", ctx);
            }
            diff_tree_close(ctx->out);
        }
    }
    diff_tree_close(ctx->out);
}

static void diff_prism_visit_multi_targets(
    const pm_node_list_t *lefts,
    const pm_node_t *rest,
    const pm_node_list_t *rights,
    diff_prism_ctx_t *ctx
) {
    diff_tree_open_slot(ctx->out, "lhs");
    for (size_t i = 0; i < lefts->size; i++) {
        diff_prism_visit_child(lefts->nodes[i], ctx);
    }
    diff_tree_close(ctx->out);

    diff_tree_open_slot(ctx->out, "rest");
    if (rest != NULL && !PM_NODE_TYPE_P(rest, PM_IMPLICIT_REST_NODE)) {
        diff_tree_open_cstr(ctx->out, DIFF_TOK_TARGET_SPLAT, NULL);
        if (PM_NODE_TYPE_P(rest, PM_SPLAT_NODE)) {
            const pm_splat_node_t *sp = (const pm_splat_node_t *) rest;
            if (sp->expression == NULL) {
                diff_tree_leaf_cstr(ctx->out, DIFF_TOK_TARGET_NONE, NULL);
            } else {
                diff_prism_visit_child(sp->expression, ctx);
            }
        } else {
            diff_prism_visit_child(rest, ctx);
        }
        diff_tree_close(ctx->out);
    }
    for (size_t i = 0; i < rights->size; i++) {
        diff_prism_visit_child(rights->nodes[i], ctx);
    }
    diff_tree_close(ctx->out);
}

static void diff_prism_emit_desugared_op_write(
    diff_prism_ctx_t *ctx,
    char var_prefix,
    pm_constant_id_t name,
    pm_constant_id_t bin_op,
    const pm_node_t *value,
    diff_tok_tag_t read_tag,
    bool is_const
) {
    if (is_const) {
        diff_tree_open_cstr(ctx->out, DIFF_TOK_CDECL, NULL);
        diff_prism_tree_leaf_const(ctx, DIFF_TOK_CONST, name);
    } else {
        diff_prism_emit_tagged_id(ctx, DIFF_TOK_ASGN, var_prefix, name);
    }
    diff_prism_tree_open_const(ctx, DIFF_TOK_CALL, bin_op);
    diff_tree_open_slot(ctx->out, "recv");
    diff_prism_tree_leaf_const(ctx, read_tag, name);
    diff_tree_close(ctx->out);
    diff_tree_open_slot(ctx->out, "args");
    diff_tree_open_slot(ctx->out, "arg");
    diff_prism_visit_child(value, ctx);
    diff_tree_close(ctx->out);
    diff_tree_close(ctx->out);
    diff_tree_open_slot(ctx->out, "blk");
    diff_tree_close(ctx->out);
    diff_tree_close(ctx->out);
    diff_tree_close(ctx->out);
}

static void diff_prism_emit_short_circuit_write(
    diff_prism_ctx_t *ctx,
    diff_tok_tag_t outer_tag,
    char var_prefix,
    pm_constant_id_t name,
    const pm_node_t *value,
    diff_tok_tag_t read_tag,
    bool is_const
) {
    diff_tree_open_cstr(ctx->out, outer_tag, NULL);
    diff_prism_tree_leaf_const(ctx, read_tag, name);
    if (is_const) {
        diff_tree_open_cstr(ctx->out, DIFF_TOK_CDECL, NULL);
        diff_prism_tree_leaf_const(ctx, DIFF_TOK_CONST, name);
    } else {
        diff_prism_emit_tagged_id(ctx, DIFF_TOK_ASGN, var_prefix, name);
    }
    diff_prism_visit_child(value, ctx);
    diff_tree_close(ctx->out);
    diff_tree_close(ctx->out);
}

static void diff_prism_visit_expr(const pm_node_t *node, diff_prism_ctx_t *ctx, bool in_args) {
    if (node == NULL || ctx->depth >= DIFF_MAX_AST_DEPTH) {
        return;
    }
    ctx->depth++;

    switch (PM_NODE_TYPE(node)) {
        case PM_PROGRAM_NODE: {
            const pm_program_node_t *prog = (const pm_program_node_t *) node;
            diff_prism_push_scope(ctx->parser, ctx->out, DIFF_SCOPE_PROGRAM, &prog->locals);
            diff_tree_open_cstr(ctx->out, DIFF_TOK_SCOPE, "program");
            if (prog->statements != NULL) {
                const pm_node_list_t *stmts = &prog->statements->body;
                for (int pass = 0; pass < 2; pass++) {
                    bool want_pre = (pass == 0);
                    for (size_t i = 0; i < stmts->size; i++) {
                        const pm_node_t *stmt = stmts->nodes[i];
                        if (stmt != NULL && (PM_NODE_TYPE_P(stmt, PM_PRE_EXECUTION_NODE) != 0) == want_pre) {
                            diff_prism_visit_child(stmt, ctx);
                        }
                    }
                }
            }
            diff_tree_close(ctx->out);
            break;
        }
        case PM_STATEMENTS_NODE: {
            diff_prism_visit_stmt_list((const pm_statements_node_t *) node, ctx);
            break;
        }
        case PM_PARENTHESES_NODE: {
            const pm_parentheses_node_t *p = (const pm_parentheses_node_t *) node;
            if (in_args && p->body != NULL && PM_NODE_TYPE_P(p->body, PM_STATEMENTS_NODE)) {
                const pm_statements_node_t *stmts = (const pm_statements_node_t *) p->body;
                if (stmts->body.size == 1) {
                    diff_prism_visit_expr(stmts->body.nodes[0], ctx, true);
                    break;
                }
            }
            diff_prism_visit_child(p->body, ctx);
            break;
        }
        case PM_ELSE_NODE: {
            const pm_else_node_t *e = (const pm_else_node_t *) node;
            diff_prism_visit_stmt_list(e->statements, ctx);
            break;
        }
        case PM_BEGIN_NODE: {
            const pm_begin_node_t *b = (const pm_begin_node_t *) node;
            diff_prism_visit_begin_parts(b->statements, b->rescue_clause, b->else_clause, b->ensure_clause, ctx);
            break;
        }
        case PM_RESCUE_MODIFIER_NODE: {
            const pm_rescue_modifier_node_t *rm = (const pm_rescue_modifier_node_t *) node;
            ctx->out->counts[DIFF_CNT_RESCUE]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_RESCUE, NULL);
            const pm_node_t *rm_expr = diff_prism_is_nil_expr(rm->expression) ? NULL : rm->expression;
            diff_prism_visit_slot("body", rm_expr, ctx);
            diff_tree_open_slot(ctx->out, "resq");
            diff_tree_open_cstr(ctx->out, DIFF_TOK_RESBODY, NULL);
            diff_tree_open_slot(ctx->out, "exc");
            diff_tree_close(ctx->out);
            diff_tree_open_slot(ctx->out, "var");
            diff_tree_close(ctx->out);
            diff_prism_visit_slot("body", rm->rescue_expression, ctx);
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            diff_tree_open_slot(ctx->out, "else");
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_PRE_EXECUTION_NODE: {
            const pm_pre_execution_node_t *pre = (const pm_pre_execution_node_t *) node;
            if (ctx->preexe_depth > 0) {
                ctx->out->has_nested_preexe = true;
            }
            ctx->preexe_depth++;
            if (pre->statements != NULL) {
                const pm_node_list_t *stmts = &pre->statements->body;
                for (int pass = 0; pass < 2; pass++) {
                    bool want_pre = (pass == 0);
                    for (size_t i = 0; i < stmts->size; i++) {
                        const pm_node_t *stmt = stmts->nodes[i];
                        if (stmt != NULL && (PM_NODE_TYPE_P(stmt, PM_PRE_EXECUTION_NODE) != 0) == want_pre) {
                            diff_prism_visit_child(stmt, ctx);
                        }
                    }
                }
            }
            ctx->preexe_depth--;
            break;
        }
        case PM_POST_EXECUTION_NODE: {
            const pm_post_execution_node_t *post = (const pm_post_execution_node_t *) node;
            ctx->out->counts[DIFF_CNT_POSTEXE]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_POSTEXE, NULL);
            diff_prism_visit_stmt_list(post->statements, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_DEF_NODE: {
            const pm_def_node_t *def_n = (const pm_def_node_t *) node;
            if (def_n->receiver != NULL) {
                diff_prism_tree_open_const(ctx, DIFF_TOK_DEFS, def_n->name);
                diff_prism_visit_slot("recv", def_n->receiver, ctx);
            } else {
                diff_prism_tree_open_const(ctx, DIFF_TOK_DEF, def_n->name);
            }
            diff_prism_push_scope(ctx->parser, ctx->out, DIFF_SCOPE_DEF, &def_n->locals);
            diff_prism_add_const(ctx->parser, ctx->out, def_n->name, &ctx->out->defs);
            diff_tree_open_cstr(ctx->out, DIFF_TOK_SCOPE, "def");
            if (def_n->parameters != NULL) {
                diff_prism_visit_params_node(&def_n->parameters->base, ctx);
            }
            const pm_node_t *def_body = def_n->body;
            for (int unwrap = 0; unwrap < 8 && def_body != NULL; unwrap++) {
                if (PM_NODE_TYPE_P(def_body, PM_PARENTHESES_NODE)) {
                    def_body = ((const pm_parentheses_node_t *) def_body)->body;
                } else if (PM_NODE_TYPE_P(def_body, PM_STATEMENTS_NODE)) {
                    const pm_statements_node_t *stmts = (const pm_statements_node_t *) def_body;
                    if (stmts->body.size == 1) {
                        def_body = stmts->body.nodes[0];
                    } else {
                        break;
                    }
                } else if (PM_NODE_TYPE_P(def_body, PM_BEGIN_NODE)) {
                    const pm_begin_node_t *bn = (const pm_begin_node_t *) def_body;
                    if (bn->rescue_clause == NULL && bn->ensure_clause == NULL && bn->else_clause == NULL) {
                        def_body = bn->statements != NULL ? &bn->statements->base : NULL;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            if (def_body != NULL && PM_NODE_TYPE_P(def_body, PM_NIL_NODE)) {
                def_body = NULL;
            } else {
                def_body = def_n->body;
            }
            diff_prism_visit_slot("body", def_body, ctx);
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_CLASS_NODE: {
            const pm_class_node_t *cls = (const pm_class_node_t *) node;
            ctx->out->counts[DIFF_CNT_CLASS]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_CLASS, NULL);
            diff_prism_visit_slot("cpath", cls->constant_path, ctx);
            diff_prism_visit_slot("super", cls->superclass, ctx);
            diff_prism_push_scope(ctx->parser, ctx->out, DIFF_SCOPE_CLASS, &cls->locals);
            diff_tree_open_cstr(ctx->out, DIFF_TOK_SCOPE, "class");
            diff_prism_visit_slot("body", cls->body, ctx);
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_MODULE_NODE: {
            const pm_module_node_t *mod = (const pm_module_node_t *) node;
            ctx->out->counts[DIFF_CNT_MODULE]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_MODULE, NULL);
            diff_prism_visit_slot("cpath", mod->constant_path, ctx);
            diff_prism_push_scope(ctx->parser, ctx->out, DIFF_SCOPE_MODULE, &mod->locals);
            diff_tree_open_cstr(ctx->out, DIFF_TOK_SCOPE, "module");
            diff_prism_visit_slot("body", mod->body, ctx);
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_SINGLETON_CLASS_NODE: {
            const pm_singleton_class_node_t *scls = (const pm_singleton_class_node_t *) node;
            ctx->out->counts[DIFF_CNT_SCLASS]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_SCLASS, NULL);
            diff_prism_visit_slot("expr", scls->expression, ctx);
            diff_prism_push_scope(ctx->parser, ctx->out, DIFF_SCOPE_SCLASS, &scls->locals);
            diff_tree_open_cstr(ctx->out, DIFF_TOK_SCOPE, "sclass");
            diff_prism_visit_slot("body", scls->body, ctx);
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_FOR_NODE: {
            const pm_for_node_t *for_n = (const pm_for_node_t *) node;
            ctx->out->counts[DIFF_CNT_FOR]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_FOR, NULL);
            diff_prism_visit_slot("col", for_n->collection, ctx);
            diff_prism_visit_slot("idx", for_n->index, ctx);
            diff_prism_visit_slot("body", for_n->statements != NULL ? &for_n->statements->base : NULL, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_BLOCK_NODE: {
            const pm_block_node_t *blk = (const pm_block_node_t *) node;
            diff_prism_push_scope(ctx->parser, ctx->out, DIFF_SCOPE_BLOCK, &blk->locals);
            diff_tree_open_cstr(ctx->out, DIFF_TOK_SCOPE, "block");
            diff_prism_visit_params_node(blk->parameters, ctx);
            diff_prism_visit_slot("body", blk->body, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_LAMBDA_NODE: {
            const pm_lambda_node_t *lam = (const pm_lambda_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_LAMBDA, NULL);
            diff_prism_push_scope(ctx->parser, ctx->out, DIFF_SCOPE_LAMBDA, &lam->locals);
            diff_tree_open_cstr(ctx->out, DIFF_TOK_SCOPE, "lambda");
            diff_prism_visit_params_node(lam->parameters, ctx);
            diff_prism_visit_slot("body", lam->body, ctx);
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_CALL_NODE: {
            const pm_call_node_t *call = (const pm_call_node_t *) node;
            if (call->block != NULL && PM_NODE_TYPE_P(call->block, PM_BLOCK_NODE)) {
                diff_prism_add_const(ctx->parser, ctx->out, call->name, &ctx->out->block_owners);
            }
            if (PM_NODE_FLAG_P(call, PM_CALL_NODE_FLAGS_ATTRIBUTE_WRITE)) {
                const char *ptr = NULL;
                size_t len = 0;
                diff_prism_const_buf(ctx->parser, call->name, &ptr, &len);
                if (PM_NODE_FLAG_P(call, PM_CALL_NODE_FLAGS_SAFE_NAVIGATION)) {
                    diff_tree_open_attrasgn(ctx->out, ptr, len);
                } else {
                    diff_tree_open(ctx->out, DIFF_TOK_ATTRASGN, ptr, len);
                }
                diff_prism_visit_slot("recv", call->receiver, ctx);
                diff_prism_emit_arguments(call->arguments, call->block, ctx, false);
                diff_tree_close(ctx->out);
            } else {
                diff_tok_tag_t tag = PM_NODE_FLAG_P(call, PM_CALL_NODE_FLAGS_SAFE_NAVIGATION)
                    ? DIFF_TOK_QCALL
                    : DIFF_TOK_CALL;
                const char *cname = NULL;
                size_t clen = 0;
                diff_prism_const_buf(ctx->parser, call->name, &cname, &clen);
                diff_prism_tree_open_const(ctx, tag, call->name);
                /* CRuby parse.y lowers unspaced `not()` to `(OPCALL (NIL) :! nil)`,
                 * whereas `not ()` with whitespace becomes `(OPCALL (BEGIN nil) :! nil)`. */
                bool is_empty_not = clen == 1 && cname[0] == '!' &&
                    call->message_loc.length == 3 &&
                    call->receiver != NULL &&
                    PM_NODE_TYPE_P(call->receiver, PM_PARENTHESES_NODE) &&
                    ((const pm_parentheses_node_t *) call->receiver)->body == NULL &&
                    ((const pm_parentheses_node_t *) call->receiver)->opening_loc.start == call->message_loc.start + 3;
                if (is_empty_not) {
                    diff_tree_open_slot(ctx->out, "recv");
                    diff_tree_leaf_cstr(ctx->out, DIFF_TOK_NIL, NULL);
                    diff_tree_close(ctx->out);
                } else {
                    diff_prism_visit_slot("recv", call->receiver, ctx);
                }
                diff_prism_emit_arguments(call->arguments, call->block, ctx, true);
                diff_tree_close(ctx->out);
            }
            break;
        }
        case PM_BLOCK_ARGUMENT_NODE: {
            const pm_block_argument_node_t *ba = (const pm_block_argument_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_BLOCK_PASS, NULL);
            if (ba->expression != NULL) {
                diff_prism_visit_child(ba->expression, ctx);
            } else {
                diff_tree_leaf_cstr(ctx->out, DIFF_TOK_LVAR, "&");
            }
            diff_tree_close(ctx->out);
            break;
        }
        case PM_SUPER_NODE: {
            const pm_super_node_t *sup = (const pm_super_node_t *) node;
            ctx->out->counts[DIFF_CNT_SUPER]++;
            if (sup->block != NULL && PM_NODE_TYPE_P(sup->block, PM_BLOCK_NODE)) {
                diff_span_vec_push(&ctx->out->block_owners, diff_strbuf_add(&ctx->out->strbuf, "super", 5));
            }
            diff_tree_open_cstr(ctx->out, DIFF_TOK_SUPER, NULL);
            diff_prism_emit_arguments(sup->arguments, sup->block, ctx, true);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_FORWARDING_SUPER_NODE: {
            const pm_forwarding_super_node_t *fsup = (const pm_forwarding_super_node_t *) node;
            ctx->out->counts[DIFF_CNT_SUPER]++;
            if (fsup->block != NULL && PM_NODE_TYPE_P(&fsup->block->base, PM_BLOCK_NODE)) {
                diff_span_vec_push(&ctx->out->block_owners, diff_strbuf_add(&ctx->out->strbuf, "super", 5));
            }
            diff_tree_open_cstr(ctx->out, DIFF_TOK_ZSUPER, NULL);
            diff_prism_visit_slot("blk", fsup->block != NULL ? &fsup->block->base : NULL, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_YIELD_NODE: {
            const pm_yield_node_t *yn = (const pm_yield_node_t *) node;
            ctx->out->counts[DIFF_CNT_YIELD]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_YIELD, NULL);
            diff_prism_emit_arguments(yn->arguments, NULL, ctx, false);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_RETURN_NODE: {
            const pm_return_node_t *rn = (const pm_return_node_t *) node;
            ctx->out->counts[DIFF_CNT_RETURN]++;
            diff_prism_visit_ret_like(rn->arguments, DIFF_TOK_RETURN, ctx);
            break;
        }
        case PM_BREAK_NODE: {
            const pm_break_node_t *bn = (const pm_break_node_t *) node;
            ctx->out->counts[DIFF_CNT_BREAK]++;
            diff_prism_visit_ret_like(bn->arguments, DIFF_TOK_BREAK, ctx);
            break;
        }
        case PM_NEXT_NODE: {
            const pm_next_node_t *nn = (const pm_next_node_t *) node;
            ctx->out->counts[DIFF_CNT_NEXT]++;
            diff_prism_visit_ret_like(nn->arguments, DIFF_TOK_NEXT, ctx);
            break;
        }
        case PM_REDO_NODE:  ctx->out->counts[DIFF_CNT_REDO]++;  diff_tree_leaf_cstr(ctx->out, DIFF_TOK_REDO, NULL);  break;
        case PM_RETRY_NODE: ctx->out->counts[DIFF_CNT_RETRY]++; diff_tree_leaf_cstr(ctx->out, DIFF_TOK_RETRY, NULL); break;
        case PM_IF_NODE: {
            const pm_if_node_t *ifn = (const pm_if_node_t *) node;
            ctx->out->counts[DIFF_CNT_IF]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_IF, NULL);
            diff_prism_visit_slot("cond", ifn->predicate, ctx);
            diff_tree_open_slot(ctx->out, "then");
            if (!(ifn->statements != NULL && ifn->statements->body.size == 1 &&
                  ifn->statements->body.nodes[0] != NULL && PM_NODE_TYPE_P(ifn->statements->body.nodes[0], PM_NIL_NODE))) {
                diff_prism_visit_stmt_list(ifn->statements, ctx);
            }
            diff_tree_close(ctx->out);
            const pm_node_t *if_else = ifn->subsequent;
            if (if_else != NULL && PM_NODE_TYPE_P(if_else, PM_ELSE_NODE)) {
                const pm_else_node_t *en = (const pm_else_node_t *) if_else;
                if (en->statements != NULL && en->statements->body.size == 1 &&
                    en->statements->body.nodes[0] != NULL && PM_NODE_TYPE_P(en->statements->body.nodes[0], PM_NIL_NODE)) {
                    if_else = NULL;
                }
            }
            diff_prism_visit_slot("else", if_else, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_UNLESS_NODE: {
            const pm_unless_node_t *un = (const pm_unless_node_t *) node;
            ctx->out->counts[DIFF_CNT_UNLESS]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_UNLESS, NULL);
            diff_prism_visit_slot("cond", un->predicate, ctx);
            diff_tree_open_slot(ctx->out, "then");
            if (!(un->statements != NULL && un->statements->body.size == 1 &&
                  un->statements->body.nodes[0] != NULL && PM_NODE_TYPE_P(un->statements->body.nodes[0], PM_NIL_NODE))) {
                diff_prism_visit_stmt_list(un->statements, ctx);
            }
            diff_tree_close(ctx->out);
            const pm_node_t *un_else = un->else_clause != NULL ? &un->else_clause->base : NULL;
            if (un->else_clause != NULL && un->else_clause->statements != NULL &&
                un->else_clause->statements->body.size == 1 &&
                un->else_clause->statements->body.nodes[0] != NULL &&
                PM_NODE_TYPE_P(un->else_clause->statements->body.nodes[0], PM_NIL_NODE)) {
                un_else = NULL;
            }
            diff_prism_visit_slot("else", un_else, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_WHILE_NODE: {
            const pm_while_node_t *wn = (const pm_while_node_t *) node;
            ctx->out->counts[DIFF_CNT_WHILE]++;
            bool post = !PM_NODE_FLAG_P(wn, PM_LOOP_FLAGS_BEGIN_MODIFIER);
            diff_tree_open_cstr(ctx->out, DIFF_TOK_WHILE, post ? "post" : "pre");
            diff_prism_visit_slot("cond", wn->predicate, ctx);
            diff_tree_open_slot(ctx->out, "body");
            diff_prism_visit_stmt_list(wn->statements, ctx);
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_UNTIL_NODE: {
            const pm_until_node_t *un = (const pm_until_node_t *) node;
            ctx->out->counts[DIFF_CNT_UNTIL]++;
            bool post = !PM_NODE_FLAG_P(un, PM_LOOP_FLAGS_BEGIN_MODIFIER);
            diff_tree_open_cstr(ctx->out, DIFF_TOK_UNTIL, post ? "post" : "pre");
            diff_prism_visit_slot("cond", un->predicate, ctx);
            diff_tree_open_slot(ctx->out, "body");
            diff_prism_visit_stmt_list(un->statements, ctx);
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_CASE_NODE: {
            const pm_case_node_t *cn = (const pm_case_node_t *) node;
            ctx->out->counts[DIFF_CNT_CASE]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_CASE, NULL);
            diff_prism_visit_slot("head", cn->predicate, ctx);
            for (size_t i = 0; i < cn->conditions.size; i++) {
                diff_prism_visit_child(cn->conditions.nodes[i], ctx);
            }
            diff_prism_visit_slot("else", cn->else_clause != NULL ? &cn->else_clause->base : NULL, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_WHEN_NODE: {
            const pm_when_node_t *wn = (const pm_when_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_WHEN, NULL);
            diff_tree_open_slot(ctx->out, "conds");
            for (size_t i = 0; i < wn->conditions.size; i++) {
                diff_prism_emit_seq_elem(wn->conditions.nodes[i], i, "elem", ctx);
            }
            diff_tree_close(ctx->out);
            diff_tree_open_slot(ctx->out, "body");
            diff_prism_visit_stmt_list(wn->statements, ctx);
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_CASE_MATCH_NODE: {
            const pm_case_match_node_t *cm = (const pm_case_match_node_t *) node;
            ctx->out->counts[DIFF_CNT_CASE_MATCH]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_CASE_MATCH, NULL);
            diff_prism_visit_slot("head", cm->predicate, ctx);
            for (size_t i = 0; i < cm->conditions.size; i++) {
                diff_prism_visit_child(cm->conditions.nodes[i], ctx);
            }
            diff_prism_visit_slot("else", cm->else_clause != NULL ? &cm->else_clause->base : NULL, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_IN_NODE: {
            const pm_in_node_t *in_n = (const pm_in_node_t *) node;
            ctx->out->counts[DIFF_CNT_IN]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_IN, NULL);
            diff_prism_visit_slot("pat", in_n->pattern, ctx);
            diff_tree_open_slot(ctx->out, "body");
            diff_prism_visit_stmt_list(in_n->statements, ctx);
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_MATCH_PREDICATE_NODE: {
            const pm_match_predicate_node_t *mp = (const pm_match_predicate_node_t *) node;
            ctx->out->counts[DIFF_CNT_CASE_MATCH]++;
            ctx->out->counts[DIFF_CNT_IN]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_CASE_MATCH, NULL);
            diff_prism_visit_slot("head", mp->value, ctx);
            diff_tree_open_cstr(ctx->out, DIFF_TOK_IN, NULL);
            diff_prism_visit_slot("pat", mp->pattern, ctx);
            diff_tree_open_slot(ctx->out, "body");
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_TRUE, NULL);
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            diff_tree_open_slot(ctx->out, "else");
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_FALSE, NULL);
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_MATCH_REQUIRED_NODE: {
            const pm_match_required_node_t *mr = (const pm_match_required_node_t *) node;
            ctx->out->counts[DIFF_CNT_CASE_MATCH]++;
            ctx->out->counts[DIFF_CNT_IN]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_CASE_MATCH, NULL);
            diff_prism_visit_slot("head", mr->value, ctx);
            diff_tree_open_cstr(ctx->out, DIFF_TOK_IN, NULL);
            diff_prism_visit_slot("pat", mr->pattern, ctx);
            diff_tree_open_slot(ctx->out, "body");
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            diff_tree_open_slot(ctx->out, "else");
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_AND_NODE:
            diff_prism_visit_logical(node, DIFF_TOK_AND, PM_AND_NODE, ctx);
            break;
        case PM_OR_NODE:
            diff_prism_visit_logical(node, DIFF_TOK_OR, PM_OR_NODE, ctx);
            break;
        case PM_ALTERNATION_PATTERN_NODE:
            diff_prism_visit_logical(node, DIFF_TOK_OR, PM_ALTERNATION_PATTERN_NODE, ctx);
            break;
        case PM_DEFINED_NODE: {
            const pm_defined_node_t *dn = (const pm_defined_node_t *) node;
            ctx->out->counts[DIFF_CNT_DEFINED]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_DEFINED, NULL);
            diff_prism_visit_child(dn->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_ALIAS_METHOD_NODE: {
            const pm_alias_method_node_t *am = (const pm_alias_method_node_t *) node;
            ctx->out->counts[DIFF_CNT_ALIAS]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_ALIAS, NULL);
            diff_prism_visit_child(am->new_name, ctx);
            diff_prism_visit_child(am->old_name, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_ALIAS_GLOBAL_VARIABLE_NODE: {
            const pm_alias_global_variable_node_t *ag = (const pm_alias_global_variable_node_t *) node;
            ctx->out->counts[DIFF_CNT_ALIAS]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_VALIAS, NULL);
            const pm_node_t *sides[2] = { ag->new_name, ag->old_name };
            for (int si = 0; si < 2; si++) {
                const pm_node_t *sn = sides[si];
                if (sn != NULL && PM_NODE_TYPE_P(sn, PM_BACK_REFERENCE_READ_NODE)) {
                    diff_prism_tree_leaf_const(ctx, DIFF_TOK_GVAR, ((const pm_back_reference_read_node_t *) sn)->name);
                } else if (sn != NULL && PM_NODE_TYPE_P(sn, PM_NUMBERED_REFERENCE_READ_NODE)) {
                    char buf[32];
                    snprintf(buf, sizeof(buf), "$%u", ((const pm_numbered_reference_read_node_t *) sn)->number);
                    diff_tree_leaf_cstr(ctx->out, DIFF_TOK_GVAR, buf);
                } else {
                    diff_prism_visit_child(sn, ctx);
                }
            }
            diff_tree_close(ctx->out);
            break;
        }
        case PM_UNDEF_NODE: {
            const pm_undef_node_t *un = (const pm_undef_node_t *) node;
            ctx->out->counts[DIFF_CNT_UNDEF]++;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_UNDEF, NULL);
            for (size_t i = 0; i < un->names.size; i++) {
                diff_prism_visit_child(un->names.nodes[i], ctx);
            }
            diff_tree_close(ctx->out);
            break;
        }
        case PM_ARRAY_NODE: {
            const pm_array_node_t *an = (const pm_array_node_t *) node;
            if (!in_args && an->elements.size == 1 &&
                PM_NODE_TYPE_P(an->elements.nodes[0], PM_SPLAT_NODE)) {
                diff_prism_visit_child(an->elements.nodes[0], ctx);
                break;
            }
            diff_tree_open_cstr(ctx->out, DIFF_TOK_ARRAY, NULL);
            for (size_t i = 0; i < an->elements.size; i++) {
                diff_prism_emit_seq_elem_ex(an->elements.nodes[i], i, an->elements.size, "elem", ctx);
            }
            diff_tree_close(ctx->out);
            break;
        }
        case PM_SPLAT_NODE: {
            const pm_splat_node_t *sp = (const pm_splat_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_SPLAT, NULL);
            if (sp->expression != NULL) {
                diff_prism_visit_child(sp->expression, ctx);
            } else {
                diff_tree_leaf_cstr(ctx->out, DIFF_TOK_LVAR, "*");
            }
            diff_tree_close(ctx->out);
            break;
        }
        case PM_HASH_NODE:
            diff_prism_visit_hash_elems(&((const pm_hash_node_t *) node)->elements, ctx);
            break;
        case PM_KEYWORD_HASH_NODE:
            diff_prism_visit_hash_elems(&((const pm_keyword_hash_node_t *) node)->elements, ctx);
            break;
        case PM_ASSOC_NODE: {
            const pm_assoc_node_t *assoc = (const pm_assoc_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_PAIR, NULL);
            diff_prism_visit_child(assoc->key, ctx);
            diff_prism_visit_child(assoc->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_ASSOC_SPLAT_NODE: {
            const pm_assoc_splat_node_t *as = (const pm_assoc_splat_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_PAIR_SPLAT, NULL);
            if (as->value != NULL) {
                diff_prism_visit_child(as->value, ctx);
            } else {
                diff_tree_leaf_cstr(ctx->out, DIFF_TOK_LVAR, "**");
            }
            diff_tree_close(ctx->out);
            break;
        }
        case PM_IMPLICIT_NODE:
            diff_prism_visit_child(((const pm_implicit_node_t *) node)->value, ctx);
            break;
        case PM_SHAREABLE_CONSTANT_NODE:
            diff_prism_visit_child(((const pm_shareable_constant_node_t *) node)->write, ctx);
            break;
        case PM_PINNED_VARIABLE_NODE:
            diff_prism_visit_child(((const pm_pinned_variable_node_t *) node)->variable, ctx);
            break;
        case PM_PINNED_EXPRESSION_NODE:
            diff_prism_visit_child(((const pm_pinned_expression_node_t *) node)->expression, ctx);
            break;
        case PM_RANGE_NODE: {
            const pm_range_node_t *rn = (const pm_range_node_t *) node;
            bool excl = PM_NODE_FLAG_P(rn, PM_RANGE_FLAGS_EXCLUDE_END);
            diff_tree_open_cstr(ctx->out, DIFF_TOK_RANGE, excl ? "..." : "..");
            const pm_node_t *left = diff_prism_is_nil_expr(rn->left) ? NULL : rn->left;
            const pm_node_t *right = diff_prism_is_nil_expr(rn->right) ? NULL : rn->right;
            diff_prism_visit_slot("beg", left, ctx);
            diff_prism_visit_slot("end", right, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_FLIP_FLOP_NODE: {
            const pm_flip_flop_node_t *fn = (const pm_flip_flop_node_t *) node;
            bool excl = PM_NODE_FLAG_P(fn, PM_RANGE_FLAGS_EXCLUDE_END);
            diff_tree_open_cstr(ctx->out, DIFF_TOK_FLIP, excl ? "..." : "..");
            const pm_node_t *left = diff_prism_is_nil_expr(fn->left) ? NULL : fn->left;
            const pm_node_t *right = diff_prism_is_nil_expr(fn->right) ? NULL : fn->right;
            diff_prism_visit_slot("beg", left, ctx);
            diff_prism_visit_slot("end", right, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_REQUIRED_PARAMETER_NODE:
            diff_prism_emit_tagged_id(ctx, DIFF_TOK_TARGET, 'l', ((const pm_required_parameter_node_t *) node)->name);
            diff_tree_close(ctx->out);
            break;
        case PM_CONSTANT_READ_NODE:
            diff_prism_tree_leaf_const(ctx, DIFF_TOK_CONST, ((const pm_constant_read_node_t *) node)->name);
            break;
        case PM_CONSTANT_TARGET_NODE:
            diff_prism_emit_tagged_id(ctx, DIFF_TOK_TARGET, 'C', ((const pm_constant_target_node_t *) node)->name);
            diff_tree_close(ctx->out);
            break;
        case PM_CONSTANT_WRITE_NODE: {
            const pm_constant_write_node_t *cw = (const pm_constant_write_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_CDECL, NULL);
            diff_prism_tree_leaf_const(ctx, DIFF_TOK_CONST, cw->name);
            diff_prism_visit_child(cw->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_CONSTANT_PATH_NODE: {
            const pm_constant_path_node_t *cp = (const pm_constant_path_node_t *) node;
            if (cp->parent == NULL) {
                diff_prism_tree_leaf_const(ctx, DIFF_TOK_COLON3, cp->name);
            } else {
                diff_prism_tree_open_const(ctx, DIFF_TOK_COLON2, cp->name);
                diff_prism_visit_child(cp->parent, ctx);
                diff_tree_close(ctx->out);
            }
            break;
        }
        case PM_CONSTANT_PATH_TARGET_NODE: {
            const pm_constant_path_target_node_t *cpt = (const pm_constant_path_target_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_TARGET, "cp");
            if (cpt->parent == NULL) {
                diff_prism_tree_leaf_const(ctx, DIFF_TOK_COLON3, cpt->name);
            } else {
                diff_prism_tree_open_const(ctx, DIFF_TOK_COLON2, cpt->name);
                diff_prism_visit_child(cpt->parent, ctx);
                diff_tree_close(ctx->out);
            }
            diff_tree_close(ctx->out);
            break;
        }
        case PM_CONSTANT_PATH_WRITE_NODE: {
            const pm_constant_path_write_node_t *cpw = (const pm_constant_path_write_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_CDECL, NULL);
            diff_prism_visit_child(&cpw->target->base, ctx);
            diff_prism_visit_child(cpw->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_CONSTANT_AND_WRITE_NODE: {
            const pm_constant_and_write_node_t *n = (const pm_constant_and_write_node_t *) node;
            diff_prism_emit_short_circuit_write(ctx, DIFF_TOK_OP_ASGN_AND, 'C', n->name, n->value, DIFF_TOK_CONST, true);
            break;
        }
        case PM_CONSTANT_OR_WRITE_NODE: {
            const pm_constant_or_write_node_t *n = (const pm_constant_or_write_node_t *) node;
            diff_prism_emit_short_circuit_write(ctx, DIFF_TOK_OP_ASGN_OR, 'C', n->name, n->value, DIFF_TOK_CONST, true);
            break;
        }
        case PM_CONSTANT_OPERATOR_WRITE_NODE: {
            const pm_constant_operator_write_node_t *n = (const pm_constant_operator_write_node_t *) node;
            diff_prism_emit_desugared_op_write(ctx, 'C', n->name, n->binary_operator, n->value, DIFF_TOK_CONST, true);
            break;
        }
        case PM_CONSTANT_PATH_AND_WRITE_NODE: {
            const pm_constant_path_and_write_node_t *n = (const pm_constant_path_and_write_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_OP_CDECL, "&&");
            diff_prism_visit_slot("target", &n->target->base, ctx);
            diff_prism_visit_slot("val", n->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_CONSTANT_PATH_OR_WRITE_NODE: {
            const pm_constant_path_or_write_node_t *n = (const pm_constant_path_or_write_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_OP_CDECL, "||");
            diff_prism_visit_slot("target", &n->target->base, ctx);
            diff_prism_visit_slot("val", n->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_CONSTANT_PATH_OPERATOR_WRITE_NODE: {
            const pm_constant_path_operator_write_node_t *n = (const pm_constant_path_operator_write_node_t *) node;
            diff_prism_tree_open_const(ctx, DIFF_TOK_OP_CDECL, n->binary_operator);
            diff_prism_visit_slot("target", &n->target->base, ctx);
            diff_prism_visit_slot("val", n->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_LOCAL_VARIABLE_READ_NODE:
            diff_prism_tree_leaf_const(ctx, DIFF_TOK_LVAR, ((const pm_local_variable_read_node_t *) node)->name);
            break;
        case PM_IT_LOCAL_VARIABLE_READ_NODE:
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_LVAR, "<it>");
            break;
        case PM_LOCAL_VARIABLE_TARGET_NODE:
            diff_prism_emit_tagged_id(ctx, DIFF_TOK_TARGET, 'l', ((const pm_local_variable_target_node_t *) node)->name);
            diff_tree_close(ctx->out);
            break;
        case PM_LOCAL_VARIABLE_WRITE_NODE: {
            const pm_local_variable_write_node_t *lw = (const pm_local_variable_write_node_t *) node;
            diff_prism_emit_tagged_id(ctx, DIFF_TOK_ASGN, 'l', lw->name);
            diff_prism_visit_child(lw->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_LOCAL_VARIABLE_AND_WRITE_NODE: {
            const pm_local_variable_and_write_node_t *n = (const pm_local_variable_and_write_node_t *) node;
            diff_prism_emit_short_circuit_write(ctx, DIFF_TOK_OP_ASGN_AND, 'l', n->name, n->value, DIFF_TOK_LVAR, false);
            break;
        }
        case PM_LOCAL_VARIABLE_OR_WRITE_NODE: {
            const pm_local_variable_or_write_node_t *n = (const pm_local_variable_or_write_node_t *) node;
            diff_prism_emit_short_circuit_write(ctx, DIFF_TOK_OP_ASGN_OR, 'l', n->name, n->value, DIFF_TOK_LVAR, false);
            break;
        }
        case PM_LOCAL_VARIABLE_OPERATOR_WRITE_NODE: {
            const pm_local_variable_operator_write_node_t *n = (const pm_local_variable_operator_write_node_t *) node;
            diff_prism_emit_desugared_op_write(ctx, 'l', n->name, n->binary_operator, n->value, DIFF_TOK_LVAR, false);
            break;
        }
        case PM_INSTANCE_VARIABLE_READ_NODE:
            diff_prism_tree_leaf_const(ctx, DIFF_TOK_IVAR, ((const pm_instance_variable_read_node_t *) node)->name);
            break;
        case PM_INSTANCE_VARIABLE_TARGET_NODE:
            diff_prism_emit_tagged_id(ctx, DIFF_TOK_TARGET, 'i', ((const pm_instance_variable_target_node_t *) node)->name);
            diff_tree_close(ctx->out);
            break;
        case PM_INSTANCE_VARIABLE_WRITE_NODE: {
            const pm_instance_variable_write_node_t *n = (const pm_instance_variable_write_node_t *) node;
            diff_prism_emit_tagged_id(ctx, DIFF_TOK_ASGN, 'i', n->name);
            diff_prism_visit_child(n->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_INSTANCE_VARIABLE_AND_WRITE_NODE: {
            const pm_instance_variable_and_write_node_t *n = (const pm_instance_variable_and_write_node_t *) node;
            diff_prism_emit_short_circuit_write(ctx, DIFF_TOK_OP_ASGN_AND, 'i', n->name, n->value, DIFF_TOK_IVAR, false);
            break;
        }
        case PM_INSTANCE_VARIABLE_OR_WRITE_NODE: {
            const pm_instance_variable_or_write_node_t *n = (const pm_instance_variable_or_write_node_t *) node;
            diff_prism_emit_short_circuit_write(ctx, DIFF_TOK_OP_ASGN_OR, 'i', n->name, n->value, DIFF_TOK_IVAR, false);
            break;
        }
        case PM_INSTANCE_VARIABLE_OPERATOR_WRITE_NODE: {
            const pm_instance_variable_operator_write_node_t *n = (const pm_instance_variable_operator_write_node_t *) node;
            diff_prism_emit_desugared_op_write(ctx, 'i', n->name, n->binary_operator, n->value, DIFF_TOK_IVAR, false);
            break;
        }
        case PM_CLASS_VARIABLE_READ_NODE:
            diff_prism_tree_leaf_const(ctx, DIFF_TOK_CVAR, ((const pm_class_variable_read_node_t *) node)->name);
            break;
        case PM_CLASS_VARIABLE_TARGET_NODE:
            diff_prism_emit_tagged_id(ctx, DIFF_TOK_TARGET, 'c', ((const pm_class_variable_target_node_t *) node)->name);
            diff_tree_close(ctx->out);
            break;
        case PM_CLASS_VARIABLE_WRITE_NODE: {
            const pm_class_variable_write_node_t *n = (const pm_class_variable_write_node_t *) node;
            diff_prism_emit_tagged_id(ctx, DIFF_TOK_ASGN, 'c', n->name);
            diff_prism_visit_child(n->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_CLASS_VARIABLE_AND_WRITE_NODE: {
            const pm_class_variable_and_write_node_t *n = (const pm_class_variable_and_write_node_t *) node;
            diff_prism_emit_short_circuit_write(ctx, DIFF_TOK_OP_ASGN_AND, 'c', n->name, n->value, DIFF_TOK_CVAR, false);
            break;
        }
        case PM_CLASS_VARIABLE_OR_WRITE_NODE: {
            const pm_class_variable_or_write_node_t *n = (const pm_class_variable_or_write_node_t *) node;
            diff_prism_emit_short_circuit_write(ctx, DIFF_TOK_OP_ASGN_OR, 'c', n->name, n->value, DIFF_TOK_CVAR, false);
            break;
        }
        case PM_CLASS_VARIABLE_OPERATOR_WRITE_NODE: {
            const pm_class_variable_operator_write_node_t *n = (const pm_class_variable_operator_write_node_t *) node;
            diff_prism_emit_desugared_op_write(ctx, 'c', n->name, n->binary_operator, n->value, DIFF_TOK_CVAR, false);
            break;
        }
        case PM_GLOBAL_VARIABLE_READ_NODE:
            diff_prism_tree_leaf_const(ctx, DIFF_TOK_GVAR, ((const pm_global_variable_read_node_t *) node)->name);
            break;
        case PM_GLOBAL_VARIABLE_TARGET_NODE:
            diff_prism_emit_tagged_id(ctx, DIFF_TOK_TARGET, 'g', ((const pm_global_variable_target_node_t *) node)->name);
            diff_tree_close(ctx->out);
            break;
        case PM_GLOBAL_VARIABLE_WRITE_NODE: {
            const pm_global_variable_write_node_t *n = (const pm_global_variable_write_node_t *) node;
            diff_prism_emit_tagged_id(ctx, DIFF_TOK_ASGN, 'g', n->name);
            diff_prism_visit_child(n->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_GLOBAL_VARIABLE_AND_WRITE_NODE: {
            const pm_global_variable_and_write_node_t *n = (const pm_global_variable_and_write_node_t *) node;
            diff_prism_emit_short_circuit_write(ctx, DIFF_TOK_OP_ASGN_AND, 'g', n->name, n->value, DIFF_TOK_GVAR, false);
            break;
        }
        case PM_GLOBAL_VARIABLE_OR_WRITE_NODE: {
            const pm_global_variable_or_write_node_t *n = (const pm_global_variable_or_write_node_t *) node;
            diff_prism_emit_short_circuit_write(ctx, DIFF_TOK_OP_ASGN_OR, 'g', n->name, n->value, DIFF_TOK_GVAR, false);
            break;
        }
        case PM_GLOBAL_VARIABLE_OPERATOR_WRITE_NODE: {
            const pm_global_variable_operator_write_node_t *n = (const pm_global_variable_operator_write_node_t *) node;
            diff_prism_emit_desugared_op_write(ctx, 'g', n->name, n->binary_operator, n->value, DIFF_TOK_GVAR, false);
            break;
        }
        case PM_CALL_AND_WRITE_NODE: {
            const pm_call_and_write_node_t *n = (const pm_call_and_write_node_t *) node;
            bool q = PM_NODE_FLAG_P(n, PM_CALL_NODE_FLAGS_SAFE_NAVIGATION);
            const char *vid = NULL;
            size_t vlen = 0;
            diff_prism_const_buf(ctx->parser, n->read_name, &vid, &vlen);
            diff_tree_open(ctx->out, DIFF_TOK_OP_ASGN2, vid, vlen);
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_SLOT, q ? "1" : "0");
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_SLOT, "&&");
            diff_prism_visit_slot("recv", n->receiver, ctx);
            diff_prism_visit_slot("val", n->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_CALL_OR_WRITE_NODE: {
            const pm_call_or_write_node_t *n = (const pm_call_or_write_node_t *) node;
            bool q = PM_NODE_FLAG_P(n, PM_CALL_NODE_FLAGS_SAFE_NAVIGATION);
            const char *vid = NULL;
            size_t vlen = 0;
            diff_prism_const_buf(ctx->parser, n->read_name, &vid, &vlen);
            diff_tree_open(ctx->out, DIFF_TOK_OP_ASGN2, vid, vlen);
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_SLOT, q ? "1" : "0");
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_SLOT, "||");
            diff_prism_visit_slot("recv", n->receiver, ctx);
            diff_prism_visit_slot("val", n->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_CALL_OPERATOR_WRITE_NODE: {
            const pm_call_operator_write_node_t *n = (const pm_call_operator_write_node_t *) node;
            bool q = PM_NODE_FLAG_P(n, PM_CALL_NODE_FLAGS_SAFE_NAVIGATION);
            const char *vid = NULL, *op = NULL;
            size_t vlen = 0, olen = 0;
            diff_prism_const_buf(ctx->parser, n->read_name, &vid, &vlen);
            diff_prism_const_buf(ctx->parser, n->binary_operator, &op, &olen);
            diff_tree_open(ctx->out, DIFF_TOK_OP_ASGN2, vid, vlen);
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_SLOT, q ? "1" : "0");
            diff_tree_leaf(ctx->out, DIFF_TOK_SLOT, op, olen);
            diff_prism_visit_slot("recv", n->receiver, ctx);
            diff_prism_visit_slot("val", n->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_CALL_TARGET_NODE: {
            const pm_call_target_node_t *ct = (const pm_call_target_node_t *) node;
            const char *ptr = NULL;
            size_t len = 0;
            diff_prism_const_buf(ctx->parser, ct->name, &ptr, &len);
            diff_tree_open_cstr(ctx->out, DIFF_TOK_TARGET, "attr");
            if (PM_NODE_FLAG_P(ct, PM_CALL_NODE_FLAGS_SAFE_NAVIGATION)) {
                diff_prism_const_buf(ctx->parser, ct->name, &ptr, &len);
                diff_tree_open_attrasgn(ctx->out, ptr, len);
            } else {
                diff_tree_open(ctx->out, DIFF_TOK_ATTRASGN, ptr, len);
            }
            diff_prism_visit_slot("recv", ct->receiver, ctx);
            diff_tree_open_slot(ctx->out, "args");
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_INDEX_AND_WRITE_NODE: {
            const pm_index_and_write_node_t *n = (const pm_index_and_write_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_OP_ASGN1, "&&");
            diff_prism_visit_slot("recv", n->receiver, ctx);
            diff_prism_emit_arguments(n->arguments, n->block != NULL ? &n->block->base : NULL, ctx, false);
            diff_prism_visit_slot("val", n->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_INDEX_OR_WRITE_NODE: {
            const pm_index_or_write_node_t *n = (const pm_index_or_write_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_OP_ASGN1, "||");
            diff_prism_visit_slot("recv", n->receiver, ctx);
            diff_prism_emit_arguments(n->arguments, n->block != NULL ? &n->block->base : NULL, ctx, false);
            diff_prism_visit_slot("val", n->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_INDEX_OPERATOR_WRITE_NODE: {
            const pm_index_operator_write_node_t *n = (const pm_index_operator_write_node_t *) node;
            diff_prism_tree_open_const(ctx, DIFF_TOK_OP_ASGN1, n->binary_operator);
            diff_prism_visit_slot("recv", n->receiver, ctx);
            diff_prism_emit_arguments(n->arguments, n->block != NULL ? &n->block->base : NULL, ctx, false);
            diff_prism_visit_slot("val", n->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_INDEX_TARGET_NODE: {
            const pm_index_target_node_t *it = (const pm_index_target_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_TARGET, "attr");
            diff_tree_open_cstr(ctx->out, DIFF_TOK_ATTRASGN, "[]=");
            diff_prism_visit_slot("recv", it->receiver, ctx);
            diff_prism_emit_arguments(it->arguments, it->block != NULL ? &it->block->base : NULL, ctx, false);
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_MULTI_WRITE_NODE: {
            const pm_multi_write_node_t *mw = (const pm_multi_write_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_MASGN, NULL);
            diff_prism_visit_multi_targets(&mw->lefts, mw->rest, &mw->rights, ctx);
            diff_prism_visit_slot("rhs", mw->value, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_MULTI_TARGET_NODE: {
            const pm_multi_target_node_t *mt = (const pm_multi_target_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_MTARGET, NULL);
            diff_prism_visit_multi_targets(&mt->lefts, mt->rest, &mt->rights, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_MATCH_WRITE_NODE: {
            const pm_match_write_node_t *mw = (const pm_match_write_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_MATCH_WRITE, NULL);
            diff_prism_visit_child(&mw->call->base, ctx);
            for (size_t i = 0; i < mw->targets.size; i++) {
                diff_prism_visit_child(mw->targets.nodes[i], ctx);
            }
            diff_tree_close(ctx->out);
            break;
        }
        case PM_NUMBERED_REFERENCE_READ_NODE: {
            const pm_numbered_reference_read_node_t *nr = (const pm_numbered_reference_read_node_t *) node;
            char buf[32];
            snprintf(buf, sizeof(buf), "$%u", nr->number);
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_NTH_REF, buf);
            break;
        }
        case PM_BACK_REFERENCE_READ_NODE:
            diff_prism_tree_leaf_const(ctx, DIFF_TOK_BACK_REF, ((const pm_back_reference_read_node_t *) node)->name);
            break;
        case PM_SELF_NODE:            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_SELF, NULL);     break;
        case PM_NIL_NODE:             diff_tree_leaf_cstr(ctx->out, DIFF_TOK_NIL, NULL);      break;
        case PM_TRUE_NODE:            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_TRUE, NULL);     break;
        case PM_FALSE_NODE:           diff_tree_leaf_cstr(ctx->out, DIFF_TOK_FALSE, NULL);    break;
        case PM_SOURCE_FILE_NODE:     diff_tree_leaf_cstr(ctx->out, DIFF_TOK_FILE, NULL);     break;
        case PM_SOURCE_LINE_NODE:     diff_tree_leaf_cstr(ctx->out, DIFF_TOK_LINE, NULL);     break;
        case PM_SOURCE_ENCODING_NODE: diff_tree_leaf_cstr(ctx->out, DIFF_TOK_ENCODING, NULL); break;
        case PM_INTEGER_NODE: {
            const pm_integer_node_t *in = (const pm_integer_node_t *) node;
            char buf[64];
            diff_prism_format_integer(&in->value, buf, sizeof(buf));
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_INT, buf);
            break;
        }
        case PM_FLOAT_NODE: {
            const pm_float_node_t *fn = (const pm_float_node_t *) node;
            char buf[32];
            diff_prism_format_float(fn->value, buf, sizeof(buf));
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_FLOAT, buf);
            break;
        }
        case PM_RATIONAL_NODE: {
            const pm_rational_node_t *rn = (const pm_rational_node_t *) node;
            char nbuf[64], dbuf[64], buf[140];
            diff_prism_format_integer(&rn->numerator, nbuf, sizeof(nbuf));
            diff_prism_format_integer(&rn->denominator, dbuf, sizeof(dbuf));
            snprintf(buf, sizeof(buf), "%s/%s", nbuf, dbuf);
            diff_tree_leaf_cstr(ctx->out, DIFF_TOK_RATIONAL, buf);
            break;
        }
        case PM_IMAGINARY_NODE: {
            const pm_imaginary_node_t *im = (const pm_imaginary_node_t *) node;
            char buf[160];
            if (im->numeric != NULL && PM_NODE_TYPE_P(im->numeric, PM_INTEGER_NODE)) {
                char ibuf[64];
                diff_prism_format_integer(&((const pm_integer_node_t *) im->numeric)->value, ibuf, sizeof(ibuf));
                snprintf(buf, sizeof(buf), "i:%s", ibuf);
                diff_tree_leaf_cstr(ctx->out, DIFF_TOK_IMAGINARY, buf);
            } else if (im->numeric != NULL && PM_NODE_TYPE_P(im->numeric, PM_FLOAT_NODE)) {
                char fbuf[32];
                diff_prism_format_float(((const pm_float_node_t *) im->numeric)->value, fbuf, sizeof(fbuf));
                snprintf(buf, sizeof(buf), "f:%s", fbuf);
                diff_tree_leaf_cstr(ctx->out, DIFF_TOK_IMAGINARY, buf);
            } else if (im->numeric != NULL && PM_NODE_TYPE_P(im->numeric, PM_RATIONAL_NODE)) {
                const pm_rational_node_t *rn = (const pm_rational_node_t *) im->numeric;
                char nbuf[64], dbuf[64];
                diff_prism_format_integer(&rn->numerator, nbuf, sizeof(nbuf));
                diff_prism_format_integer(&rn->denominator, dbuf, sizeof(dbuf));
                snprintf(buf, sizeof(buf), "r:%s/%s", nbuf, dbuf);
                diff_tree_leaf_cstr(ctx->out, DIFF_TOK_IMAGINARY, buf);
            } else {
                diff_tree_leaf_cstr(ctx->out, DIFF_TOK_IMAGINARY, NULL);
            }
            break;
        }
        case PM_STRING_NODE: {
            const pm_string_node_t *sn = (const pm_string_node_t *) node;
            diff_prism_emit_bytes_leaf(ctx->out, DIFF_TOK_STR, pm_string_source(&sn->unescaped), pm_string_length(&sn->unescaped));
            break;
        }
        case PM_SYMBOL_NODE: {
            const pm_symbol_node_t *sn = (const pm_symbol_node_t *) node;
            diff_prism_emit_bytes_leaf(ctx->out, DIFF_TOK_SYM, pm_string_source(&sn->unescaped), pm_string_length(&sn->unescaped));
            break;
        }
        case PM_REGULAR_EXPRESSION_NODE: {
            const pm_regular_expression_node_t *re = (const pm_regular_expression_node_t *) node;
            const uint8_t *src = pm_string_source(&re->unescaped);
            size_t slen = pm_string_length(&re->unescaped);
            uint64_t h = (src != NULL && slen > 0) ? diff_fnv64_update(DIFF_FNV64_OFFSET, src, slen) : DIFF_FNV64_OFFSET;
            diff_prism_emit_regexp_leaf(ctx->out, diff_prism_regexp_opts(re->base.flags), h, slen);
            break;
        }
        case PM_X_STRING_NODE: {
            const pm_x_string_node_t *xs = (const pm_x_string_node_t *) node;
            diff_prism_emit_bytes_leaf(ctx->out, DIFF_TOK_XSTR, pm_string_source(&xs->unescaped), pm_string_length(&xs->unescaped));
            break;
        }
        case PM_MATCH_LAST_LINE_NODE: {
            const pm_match_last_line_node_t *ml = (const pm_match_last_line_node_t *) node;
            const uint8_t *src = pm_string_source(&ml->unescaped);
            size_t slen = pm_string_length(&ml->unescaped);
            uint64_t h = (src != NULL && slen > 0) ? diff_fnv64_update(DIFF_FNV64_OFFSET, src, slen) : DIFF_FNV64_OFFSET;
            diff_tree_open_match_last_line(ctx->out);
            diff_prism_emit_regexp_leaf(ctx->out, diff_prism_regexp_opts(ml->base.flags), h, slen);
            diff_tree_close_match_last_line(ctx->out);
            break;
        }
        case PM_INTERPOLATED_STRING_NODE:
            diff_prism_visit_interpolated(node, &((const pm_interpolated_string_node_t *) node)->parts, DIFF_TOK_DSTR, DIFF_TOK_STR, ctx);
            break;
        case PM_INTERPOLATED_SYMBOL_NODE:
            diff_prism_visit_interpolated(node, &((const pm_interpolated_symbol_node_t *) node)->parts, DIFF_TOK_DSYM, DIFF_TOK_SYM, ctx);
            break;
        case PM_INTERPOLATED_REGULAR_EXPRESSION_NODE:
            diff_prism_visit_interpolated(node, &((const pm_interpolated_regular_expression_node_t *) node)->parts, DIFF_TOK_DREGX, DIFF_TOK_REGX, ctx);
            break;
        case PM_INTERPOLATED_X_STRING_NODE:
            diff_prism_visit_interpolated(node, &((const pm_interpolated_x_string_node_t *) node)->parts, DIFF_TOK_DXSTR, DIFF_TOK_XSTR, ctx);
            break;
        case PM_INTERPOLATED_MATCH_LAST_LINE_NODE:
            diff_tree_open_match_last_line(ctx->out);
            diff_prism_visit_interpolated(node, &((const pm_interpolated_match_last_line_node_t *) node)->parts, DIFF_TOK_DREGX, DIFF_TOK_REGX, ctx);
            diff_tree_close_match_last_line(ctx->out);
            break;
        case PM_ARRAY_PATTERN_NODE: {
            const pm_array_pattern_node_t *ap = (const pm_array_pattern_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_ARYPTN, NULL);
            diff_prism_visit_slot("const", ap->constant, ctx);
            diff_tree_open_slot(ctx->out, "pre");
            for (size_t i = 0; i < ap->requireds.size; i++) {
                diff_tree_open_slot(ctx->out, "elem");
                diff_prism_visit_child(ap->requireds.nodes[i], ctx);
                diff_tree_close(ctx->out);
            }
            diff_tree_close(ctx->out);
            diff_tree_open_slot(ctx->out, "rest");
            if (ap->rest != NULL) {
                if (PM_NODE_TYPE_P(ap->rest, PM_IMPLICIT_REST_NODE)) {
                    diff_tree_leaf_cstr(ctx->out, DIFF_TOK_TARGET_NONE, NULL);
                } else if (PM_NODE_TYPE_P(ap->rest, PM_SPLAT_NODE)) {
                    const pm_splat_node_t *sp = (const pm_splat_node_t *) ap->rest;
                    if (sp->expression == NULL) {
                        diff_tree_leaf_cstr(ctx->out, DIFF_TOK_TARGET_NONE, NULL);
                    } else {
                        diff_prism_visit_child(sp->expression, ctx);
                    }
                } else {
                    diff_prism_visit_child(ap->rest, ctx);
                }
            }
            diff_tree_close(ctx->out);
            diff_tree_open_slot(ctx->out, "post");
            for (size_t i = 0; i < ap->posts.size; i++) {
                diff_tree_open_slot(ctx->out, "elem");
                diff_prism_visit_child(ap->posts.nodes[i], ctx);
                diff_tree_close(ctx->out);
            }
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_FIND_PATTERN_NODE: {
            const pm_find_pattern_node_t *fp = (const pm_find_pattern_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_FNDPTN, NULL);
            diff_prism_visit_slot("const", fp->constant, ctx);
            diff_tree_open_slot(ctx->out, "pre");
            if (fp->left != NULL) {
                if (fp->left->expression == NULL) {
                    diff_tree_leaf_cstr(ctx->out, DIFF_TOK_TARGET_NONE, NULL);
                } else {
                    diff_prism_visit_child(fp->left->expression, ctx);
                }
            }
            diff_tree_close(ctx->out);
            diff_tree_open_slot(ctx->out, "mid");
            for (size_t i = 0; i < fp->requireds.size; i++) {
                diff_tree_open_slot(ctx->out, "elem");
                diff_prism_visit_child(fp->requireds.nodes[i], ctx);
                diff_tree_close(ctx->out);
            }
            diff_tree_close(ctx->out);
            diff_tree_open_slot(ctx->out, "post");
            if (fp->right != NULL) {
                if (fp->right->expression == NULL) {
                    diff_tree_leaf_cstr(ctx->out, DIFF_TOK_TARGET_NONE, NULL);
                } else {
                    diff_prism_visit_child(fp->right->expression, ctx);
                }
            }
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_HASH_PATTERN_NODE: {
            const pm_hash_pattern_node_t *hp = (const pm_hash_pattern_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_HSHPTN, NULL);
            diff_prism_visit_slot("const", hp->constant, ctx);
            diff_tree_open_slot(ctx->out, "kw");
            diff_prism_visit_hash_elems(&hp->elements, ctx);
            diff_tree_close(ctx->out);
            diff_tree_open_slot(ctx->out, "kwrest");
            if (hp->rest != NULL) {
                if (PM_NODE_TYPE_P(hp->rest, PM_NO_KEYWORDS_PARAMETER_NODE)) {
                    diff_tree_leaf_cstr(ctx->out, DIFF_TOK_TARGET_NONE, "nokw");
                } else if (PM_NODE_TYPE_P(hp->rest, PM_ASSOC_SPLAT_NODE)) {
                    const pm_assoc_splat_node_t *as = (const pm_assoc_splat_node_t *) hp->rest;
                    if (as->value != NULL) {
                        diff_prism_visit_child(as->value, ctx);
                    }
                } else {
                    diff_prism_visit_child(hp->rest, ctx);
                }
            }
            diff_tree_close(ctx->out);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_CAPTURE_PATTERN_NODE: {
            const pm_capture_pattern_node_t *cp = (const pm_capture_pattern_node_t *) node;
            diff_tree_open_cstr(ctx->out, DIFF_TOK_CAPTURE, NULL);
            diff_prism_visit_child(cp->value, ctx);
            diff_prism_visit_child(&cp->target->base, ctx);
            diff_tree_close(ctx->out);
            break;
        }
        case PM_ERROR_RECOVERY_NODE: {
            uint32_t start = node->location.start;
            uint32_t length = node->location.length;
            diff_summary_free(ctx->out);
            diff_invariant_fail(
                "INVARIANT[diff_parse_y]: kind=ast_zero_error_recovery [detail: start=%u length=%u]\n",
                start,
                length
            );
        }
        default:
            pm_visit_child_nodes(node, diff_prism_visit_cb, ctx);
            break;
    }

    ctx->depth--;
}

void diff_collect_prism_summary(
    const pm_parser_t *parser,
    const pm_node_t *root,
    diff_summary_t *out
) {
    if (root == NULL) {
        return;
    }
    diff_prism_ctx_t ctx = { .parser = parser, .out = out, .depth = 0, .preexe_depth = 0 };
    diff_prism_visit_expr(root, &ctx, false);
    diff_finalize_summary(out);
}

typedef struct {
    uint32_t probe;
    bool has_probe;
    pm_node_type_t best_covering;
    uint32_t best_covering_len;
    pm_node_type_t nearest_before;
    uint32_t nearest_before_end;
    bool has_nearest_before;
    pm_node_type_t first_construct;
} diff_ast_ctx_search_t;

static bool diff_is_wrapper_node_type(pm_node_type_t type) {
    switch (type) {
        case PM_PROGRAM_NODE:
        case PM_STATEMENTS_NODE:
        case PM_ERROR_RECOVERY_NODE:
        case PM_PARENTHESES_NODE:
        case PM_SCOPE_NODE:
            return true;
        default:
            return false;
    }
}

static bool diff_is_structural_ctx_node(pm_node_type_t type) {
    switch (type) {
        case PM_INTEGER_NODE:
        case PM_FLOAT_NODE:
        case PM_RATIONAL_NODE:
        case PM_IMAGINARY_NODE:
        case PM_NIL_NODE:
        case PM_TRUE_NODE:
        case PM_FALSE_NODE:
        case PM_SELF_NODE:
        case PM_STRING_NODE:
        case PM_SYMBOL_NODE:
        case PM_LOCAL_VARIABLE_READ_NODE:
        case PM_INSTANCE_VARIABLE_READ_NODE:
        case PM_CLASS_VARIABLE_READ_NODE:
        case PM_GLOBAL_VARIABLE_READ_NODE:
        case PM_CONSTANT_READ_NODE:
        case PM_ARGUMENTS_NODE:
        case PM_PARAMETERS_NODE:
        case PM_REQUIRED_PARAMETER_NODE:
            return false;
        default:
            return !diff_is_wrapper_node_type(type);
    }
}

static pm_visit_result_t diff_ast_ctx_visit_cb(const pm_node_t *node, void *data) {
    diff_ast_ctx_search_t *s = (diff_ast_ctx_search_t *) data;
    pm_node_type_t type = node->type;
    if (diff_is_structural_ctx_node(type)) {
        if (s->first_construct == 0) {
            s->first_construct = type;
        }
        if (s->has_probe) {
            uint32_t start = node->location.start;
            uint32_t len = node->location.length;
            uint64_t end64 = (uint64_t) start + (uint64_t) len;
            uint32_t end = end64 > UINT32_MAX ? UINT32_MAX : (uint32_t) end64;
            if ((uint64_t) s->probe >= (uint64_t) start && (uint64_t) s->probe <= end64) {
                if (s->best_covering == 0 || len <= s->best_covering_len) {
                    s->best_covering = type;
                    s->best_covering_len = len;
                }
            } else if (end <= s->probe && (!s->has_nearest_before || end >= s->nearest_before_end)) {
                s->nearest_before = type;
                s->nearest_before_end = end;
                s->has_nearest_before = true;
            }
        }
    }
    return PM_VISIT_DESCEND;
}

static void diff_format_short_node_type(pm_node_type_t type, char *dst, size_t cap) {
    if (cap == 0) return;
    if (type == 0) {
        snprintf(dst, cap, "program");
        return;
    }
    const char *raw = pm_node_type(type);
    if (raw == NULL || raw[0] == '\0') {
        snprintf(dst, cap, "program");
        return;
    }
    if (strncmp(raw, "PM_", 3) == 0) {
        raw += 3;
    }
    size_t len = strlen(raw);
    if (len > 5 && strcmp(raw + len - 5, "_NODE") == 0) {
        len -= 5;
    }
    if (len >= cap) {
        len = cap - 1;
    }
    for (size_t i = 0; i < len; i++) {
        char c = raw[i];
        dst[i] = (c >= 'A' && c <= 'Z') ? (char) (c + ('a' - 'A')) : c;
    }
    dst[len] = '\0';
}

void diff_find_prism_ast_context(
    const pm_parser_t *parser,
    const pm_node_t *root,
    uint32_t probe_offset,
    bool has_probe,
    char *ctx_buf,
    size_t ctx_cap
) {
    (void) parser;
    if (ctx_cap == 0) return;
    if (root == NULL) {
        snprintf(ctx_buf, ctx_cap, "program");
        return;
    }
    diff_ast_ctx_search_t search = {
        .probe = probe_offset,
        .has_probe = has_probe,
        .best_covering = 0,
        .best_covering_len = UINT32_MAX,
        .nearest_before = 0,
        .nearest_before_end = 0,
        .has_nearest_before = false,
        .first_construct = 0,
    };
    pm_visit_node(root, diff_ast_ctx_visit_cb, &search);
    pm_node_type_t chosen = search.best_covering != 0
        ? search.best_covering
        : (search.nearest_before != 0 ? search.nearest_before : search.first_construct);
    diff_format_short_node_type(chosen, ctx_buf, ctx_cap);
}
