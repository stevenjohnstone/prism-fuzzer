#ifndef PRISM_FUZZ_IJON_H
#define PRISM_FUZZ_IJON_H

#ifdef PRISM_FUZZ_IJON
#if defined(__has_include)
#  if __has_include("prism_fuzz_compat.h")
#    include "prism_fuzz_compat.h"
#  endif
#endif
#include <stdint.h>
#include <string.h>
#include "prism/internal/parser.h"

#ifndef _USE_IJON
extern void ijon_set(uint32_t addr, uint32_t val);
extern void ijon_max(uint32_t addr, uint64_t val);
extern uint32_t ijon_hashstr(uint32_t old, const char *val);
#endif

static inline uint32_t fuzz_ijon_mix32(uint32_t h) {
    h ^= h >> 16;
    h *= 0x85ebca6bu;
    h ^= h >> 13;
    h *= 0xc2b2ae35u;
    h ^= h >> 16;
    return h;
}

#define FUZZ_IJON_SET(salt, x) \
    do { \
        static uint32_t loc_hash = 0; \
        if (loc_hash == 0) { \
            loc_hash = ijon_hashstr((uint32_t) __LINE__, (char *) (uintptr_t) __FILE__) ^ (uint32_t) (salt); \
            if (loc_hash == 0) loc_hash = 1u; \
        } \
        ijon_set(loc_hash, fuzz_ijon_mix32(loc_hash ^ (uint32_t) (x)) & 0xfffu); \
    } while (0)

#define FUZZ_IJON_MAX(salt, x) \
    do { \
        static uint32_t loc_hash = 0; \
        if (loc_hash == 0) { \
            loc_hash = ijon_hashstr((uint32_t) __LINE__, (char *) (uintptr_t) __FILE__) ^ (uint32_t) (salt); \
            if (loc_hash == 0) loc_hash = 1u; \
        } \
        ijon_max(loc_hash, (uint64_t) (x)); \
    } while (0)

typedef struct {
    uint32_t salt;
    uint32_t prev_lex_mode_sig;
    uint32_t prev_ctx_sig;
    uint32_t prev_state_flags;
    uint32_t prev_scope_sig;
    size_t prev_error_count;
    uint32_t max_lex_depth;
    uint32_t max_ctx_depth;
} fuzz_ijon_state_t;

#if !defined(PRISM_FUZZ_IJON_V2) || defined(PRISM_FUZZ_IJON_KEEP_V1)
static void fuzz_ijon_lex_callback(pm_parser_t *parser, pm_token_t *token, void *data) {
    (void) token;
    fuzz_ijon_state_t *state = (fuzz_ijon_state_t *) data;
    uint32_t salt = state->salt;

    // 1. Lexer mode stack signature (top 4 modes with delimiter-nesting / heredoc flags) + depth.
    uint32_t lex_mode_sig = 0;
    uint32_t top_lex_nibble = 0;
    uint32_t lex_depth = 0;
    for (const pm_lex_mode_t *m = parser->lex_modes.current; m != NULL && lex_depth < 128; m = m->prev, lex_depth++) {
        if (lex_depth < 4) {
            uint32_t sub = 0;
            switch (m->mode) {
                case PM_LEX_LIST:    sub = (m->as.list.nesting > 0) ? 1u : 0u; break;
                case PM_LEX_REGEXP:  sub = (m->as.regexp.nesting > 0) ? 1u : 0u; break;
                case PM_LEX_STRING:  sub = (m->as.string.nesting > 0) ? 1u : 0u; break;
                case PM_LEX_HEREDOC: sub = (m->as.heredoc.base.indent != PM_HEREDOC_INDENT_NONE) ? 1u : 0u; break;
                default: break;
            }
            uint32_t nibble = (((uint32_t) m->mode + 1u) & 0x07u) | (sub << 3);
            if (lex_depth == 0) top_lex_nibble = nibble;
            lex_mode_sig = (lex_mode_sig << 4) | nibble;
        }
    }
    if (lex_depth > 1 && lex_depth > state->max_lex_depth) {
        state->max_lex_depth = lex_depth;
        FUZZ_IJON_MAX(salt, lex_depth);
    }
    if (parser->lex_modes.current != NULL && parser->lex_modes.current->mode == PM_LEX_HEREDOC) {
        const pm_heredoc_lex_mode_t *hd = &parser->lex_modes.current->as.heredoc.base;
        uint32_t hd_bits = ((uint32_t) hd->indent & 0x3u) | (((uint32_t) hd->quote & 0x7u) << 2);
        lex_mode_sig |= (hd_bits << 16);
    }
    if (lex_mode_sig != state->prev_lex_mode_sig) {
        FUZZ_IJON_SET(salt, lex_mode_sig);
        state->prev_lex_mode_sig = lex_mode_sig;
    }

    // 2. Parser context stack signature (current and parent context) + nesting depth.
    uint32_t cur_ctx = parser->current_context != NULL ? (uint32_t) parser->current_context->context : 0u;
    uint32_t prev_ctx = (parser->current_context != NULL && parser->current_context->prev != NULL)
        ? (uint32_t) parser->current_context->prev->context
        : 0u;
    uint32_t ctx_sig = (cur_ctx << 6) | prev_ctx;
    if (ctx_sig != state->prev_ctx_sig) {
        FUZZ_IJON_SET(salt, ctx_sig);
        state->prev_ctx_sig = ctx_sig;
    }
    uint32_t ctx_depth = 0;
    for (const pm_context_node_t *c = parser->current_context; c != NULL && ctx_depth < 128; c = c->prev) {
        ctx_depth++;
    }
    if (ctx_depth > state->max_ctx_depth) {
        state->max_ctx_depth = ctx_depth;
        FUZZ_IJON_MAX(salt, ctx_depth);
    }

    // 3. Non-CFG parser mode flags and boolean stacks.
#ifdef PRISM_FUZZ_HAS_PATTERN_MATCHING_NEWLINES
#define FUZZ_IJON_PM_NEWLINES_BIT(parser_) ((uint32_t) (parser_)->pattern_matching_newlines << 8)
#else
#define FUZZ_IJON_PM_NEWLINES_BIT(parser_) 0u
#endif
    uint32_t mode_flags =
        (uint32_t) (parser->do_loop_stack.top & 0x7u) |
        ((uint32_t) (parser->accepts_block_stack.top & 0x7u) << 3) |
        ((uint32_t) parser->in_keyword_arg << 6) |
        ((uint32_t) parser->in_endless_def_body << 7) |
        FUZZ_IJON_PM_NEWLINES_BIT(parser) |
        ((uint32_t) (parser->lambda_enclosure_nesting >= 0) << 9);
    if (mode_flags != state->prev_state_flags) {
        FUZZ_IJON_SET(salt, mode_flags);
        state->prev_state_flags = mode_flags;
    }

    // 4. Scope parameter, closed, and shareable_constant flags across current and enclosing scope.
    if (parser->current_scope != NULL && (parser->current_scope->parameters != 0 || parser->current_scope->shareable_constant != 0)) {
        uint32_t cur_scope = ((uint32_t) parser->current_scope->parameters & 0x7fu) |
            ((uint32_t) parser->current_scope->closed << 7);
        uint32_t prev_scope = parser->current_scope->previous != NULL
            ? (((uint32_t) parser->current_scope->previous->parameters & 0x7fu) |
               ((uint32_t) parser->current_scope->previous->closed << 7))
            : 0u;
        uint32_t scope_sig = ((uint32_t) parser->current_scope->shareable_constant << 16) |
            (cur_scope << 8) | prev_scope;
        if (scope_sig != state->prev_scope_sig) {
            FUZZ_IJON_SET(salt, scope_sig);
            state->prev_scope_sig = scope_sig;
        }
    }

    // 5. Syntax error and recovery across active context and top lex mode.
    size_t error_count = parser->error_list.size;
    if (error_count != state->prev_error_count || parser->recovering) {
        state->prev_error_count = error_count;
        uint32_t rec_sig = ((uint32_t) parser->recovering << 10) | (cur_ctx << 4) | top_lex_nibble;
        FUZZ_IJON_SET(salt, rec_sig);
    }
}
#endif

static inline void fuzz_ijon_attach(pm_parser_t *parser, fuzz_ijon_state_t *state, uint32_t salt) {
    memset(state, 0, sizeof(*state));
    state->salt = salt;
#if !defined(PRISM_FUZZ_IJON_V2) || defined(PRISM_FUZZ_IJON_KEEP_V1)
    pm_parser_lex_callback_set(parser, fuzz_ijon_lex_callback, state);
#else
    (void) parser;
#endif
}

#ifdef PRISM_FUZZ_IJON_V2
#include "prism/internal/arena.h"
#include "prism/internal/comments.h"
#include "prism/internal/constant_pool.h"
#include "prism/internal/diagnostic.h"

#ifndef FUZZ_IJON_V2_MAX_DEPTH
#define FUZZ_IJON_V2_MAX_DEPTH 256u
#endif

typedef struct {
    uint32_t salt;
    uint32_t enc_tag;
    uint32_t has_errors;
    uint32_t parent_type;
    uint32_t depth;
    uint32_t max_depth;
    uint32_t max_local_depth;
    uint32_t max_bignum_limbs;
    uint32_t node_count;
} fuzz_ijon_v2_ctx_t;

static inline uint32_t fuzz_ijon_v2_hash_cstr(const char *s) {
    uint32_t h = 2166136261u;
    if (s == NULL) return 0u;
    for (const unsigned char *p = (const unsigned char *) s; *p != '\0'; p++) {
        h ^= (uint32_t) *p;
        h *= 16777619u;
    }
    return h;
}

static pm_visit_result_t fuzz_ijon_v2_visit(const pm_node_t *node, void *data) {
    fuzz_ijon_v2_ctx_t *ctx = (fuzz_ijon_v2_ctx_t *) data;
    uint32_t salt = ctx->salt;
    uint32_t ntype = (uint32_t) PM_NODE_TYPE(node);

    ctx->node_count++;
    if (ctx->depth > ctx->max_depth) {
        ctx->max_depth = ctx->depth;
    }

    /* 1. AST 2-path edge bigram (parent_type -> node_type) split by error state. */
    uint32_t edge_sig = (ctx->has_errors << 16) | ((ctx->parent_type & 0xffu) << 8) | (ntype & 0xffu);
    FUZZ_IJON_SET(salt ^ 0x101u, edge_sig);

    /* 2. Node flags diversity (safe navigation, regexp options, heredoc flags, etc.). */
    if (node->flags != 0) {
        uint32_t flag_sig = ((ntype & 0xffu) << 16) | (uint32_t) node->flags;
        FUZZ_IJON_SET(salt ^ 0x102u, flag_sig);
    }

    /* 3. Non-UTF-8 encoding x literal/regexp/symbol node types. */
    if (ctx->enc_tag != 0u) {
        switch (PM_NODE_TYPE(node)) {
            case PM_STRING_NODE:
            case PM_INTERPOLATED_STRING_NODE:
            case PM_SYMBOL_NODE:
            case PM_INTERPOLATED_SYMBOL_NODE:
            case PM_REGULAR_EXPRESSION_NODE:
            case PM_INTERPOLATED_REGULAR_EXPRESSION_NODE:
            case PM_X_STRING_NODE:
            case PM_INTERPOLATED_X_STRING_NODE:
                FUZZ_IJON_SET(salt ^ 0x103u, ((ctx->enc_tag & 0xffu) << 8) | (ntype & 0xffu));
                break;
            default:
                break;
        }
    }

    /* 4. Bignum limb count & local-variable scope depth hills. */
    switch (PM_NODE_TYPE(node)) {
        case PM_INTEGER_NODE: {
            const pm_integer_node_t *in = (const pm_integer_node_t *) node;
            if (in->value.length > ctx->max_bignum_limbs) {
                ctx->max_bignum_limbs = (uint32_t) in->value.length;
            }
            break;
        }
        case PM_LOCAL_VARIABLE_READ_NODE: {
            uint32_t d = ((const pm_local_variable_read_node_t *) node)->depth;
            if (d > ctx->max_local_depth) ctx->max_local_depth = d;
            break;
        }
        case PM_LOCAL_VARIABLE_WRITE_NODE: {
            uint32_t d = ((const pm_local_variable_write_node_t *) node)->depth;
            if (d > ctx->max_local_depth) ctx->max_local_depth = d;
            break;
        }
        default:
            break;
    }

    if (ctx->depth < FUZZ_IJON_V2_MAX_DEPTH && ctx->node_count < 4096u) {
        uint32_t saved_parent = ctx->parent_type;
        ctx->parent_type = ntype;
        ctx->depth++;
        pm_visit_child_nodes(node, fuzz_ijon_v2_visit, ctx);
        ctx->depth--;
        ctx->parent_type = saved_parent;
    }
    return PM_VISIT_SKIP;
}

static inline void fuzz_ijon_post_parse(
    const pm_arena_t *arena,
    const pm_parser_t *parser,
    const pm_node_t *root,
    uint32_t salt
) {
    if (parser == NULL) return;

    const char *enc_name = (parser->encoding != NULL && parser->encoding->name != NULL) ? parser->encoding->name : "UTF-8";
    uint32_t enc_tag = (strcmp(enc_name, "UTF-8") == 0) ? 0u : ((fuzz_ijon_v2_hash_cstr(enc_name) & 0xffu) | 1u);
    uint32_t has_errors = parser->error_list.size > 0 ? 1u : 0u;

    /* 1. Encoding, magic comments, comments, continuable/DATA state. */
    if (enc_tag != 0u) {
        FUZZ_IJON_SET(salt ^ 0x201u, enc_tag | ((parser->magic_comment_list.size > 0 ? 1u : 0u) << 8));
    }
    if (parser->magic_comment_list.size > 0) {
        uint32_t mc = parser->magic_comment_list.size > 8 ? 8u : (uint32_t) parser->magic_comment_list.size;
        FUZZ_IJON_MAX(salt ^ 0x202u, mc);
    }
    if (parser->comment_list.size > 0) {
        uint32_t cc = parser->comment_list.size > 16 ? 16u : (uint32_t) parser->comment_list.size;
        FUZZ_IJON_MAX(salt ^ 0x203u, cc);
        for (const pm_comment_t *c = (const pm_comment_t *) parser->comment_list.head; c != NULL; c = (const pm_comment_t *) c->node.next) {
            FUZZ_IJON_SET(salt ^ 0x204u, ((uint32_t) c->type << 8) | enc_tag);
        }
    }
    if (parser->data_loc.length > 0 || parser->continuable) {
        FUZZ_IJON_SET(salt ^ 0x205u, ((parser->data_loc.length > 0 ? 1u : 0u) << 1) | (parser->continuable ? 1u : 0u));
    }

    /* 2. Diagnostics (errors & warnings). */
    if (parser->error_list.size > 0) {
        uint32_t ec = parser->error_list.size > 32 ? 32u : (uint32_t) parser->error_list.size;
        FUZZ_IJON_MAX(salt ^ 0x210u, ec);
        uint32_t prev_id = 0u;
        uint32_t seen = 0u;
        for (const pm_diagnostic_t *d = (const pm_diagnostic_t *) parser->error_list.head; d != NULL && seen < 16u; d = (const pm_diagnostic_t *) d->node.next, seen++) {
            uint32_t did = (uint32_t) d->diag_id;
            FUZZ_IJON_SET(salt ^ 0x211u, ((enc_tag & 0x3fu) << 10) | (did & 0x3ffu));
            if (prev_id != 0u) {
                FUZZ_IJON_SET(salt ^ 0x212u, ((prev_id & 0x3ffu) << 10) | (did & 0x3ffu));
            }
            prev_id = did;
        }
    }
    if (parser->warning_list.size > 0) {
        uint32_t wc = parser->warning_list.size > 16 ? 16u : (uint32_t) parser->warning_list.size;
        FUZZ_IJON_MAX(salt ^ 0x213u, wc);
        uint32_t seen = 0u;
        for (const pm_diagnostic_t *d = (const pm_diagnostic_t *) parser->warning_list.head; d != NULL && seen < 16u; d = (const pm_diagnostic_t *) d->node.next, seen++) {
            FUZZ_IJON_SET(salt ^ 0x214u, (uint32_t) d->diag_id);
        }
    }

    /* 3. Arena block growth & large-allocation chain. */
    if (arena != NULL) {
        if (arena->block_count >= 2) {
            FUZZ_IJON_MAX(salt ^ 0x220u, (uint64_t) arena->block_count);
        }
        uint32_t large_count = 0u;
        for (const pm_arena_block_t *b = arena->large; b != NULL && large_count < 64u; b = b->prev) {
            large_count++;
        }
        if (large_count > 0u) {
            FUZZ_IJON_MAX(salt ^ 0x221u, large_count);
        }
    }

    /* 4. Constant pool size & max linear-probe collision distance. */
    const pm_constant_pool_t *pool = &parser->constant_pool;
    if (pool->size >= 16u) {
        FUZZ_IJON_MAX(salt ^ 0x230u, pool->size);
    }
    if (pool->buckets != NULL && pool->capacity > 0u && pool->capacity <= 4096u) {
        uint32_t mask = pool->capacity - 1u;
        uint32_t max_probe = 0u;
        for (uint32_t i = 0u; i < pool->capacity; i++) {
            if (pool->buckets[i].id != PM_CONSTANT_ID_UNSET) {
                uint32_t probe = (i - (pool->buckets[i].hash & mask)) & mask;
                if (probe > max_probe) max_probe = probe;
            }
        }
        if (max_probe > 0u) {
            FUZZ_IJON_MAX(salt ^ 0x231u, max_probe);
        }
    }

    /* 5. Post-parse AST walk (2-paths, flags, nesting depth, bignums, local depths). */
    if (root != NULL) {
        fuzz_ijon_v2_ctx_t ctx = {
            .salt = salt,
            .enc_tag = enc_tag,
            .has_errors = has_errors,
            .parent_type = 0u,
            .depth = 0u,
            .max_depth = 0u,
            .max_local_depth = 0u,
            .max_bignum_limbs = 0u,
            .node_count = 0u,
        };
        pm_visit_node(root, fuzz_ijon_v2_visit, &ctx);
        if (ctx.max_depth > 1u) {
            FUZZ_IJON_MAX(salt ^ 0x240u, ctx.max_depth);
        }
        if (ctx.max_local_depth > 0u) {
            FUZZ_IJON_MAX(salt ^ 0x241u, ctx.max_local_depth);
        }
        if (ctx.max_bignum_limbs > 0u) {
            FUZZ_IJON_MAX(salt ^ 0x242u, ctx.max_bignum_limbs);
        }
    }
}
#else
static inline void fuzz_ijon_post_parse(
    const pm_arena_t *arena,
    const pm_parser_t *parser,
    const pm_node_t *root,
    uint32_t salt
) {
    (void) arena;
    (void) parser;
    (void) root;
    (void) salt;
}
#endif
#endif

#endif
