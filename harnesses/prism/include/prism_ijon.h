#ifndef PRISM_FUZZ_IJON_H
#define PRISM_FUZZ_IJON_H

#ifdef PRISM_FUZZ_IJON
#include <stdint.h>
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
    uint32_t mode_flags =
        (uint32_t) (parser->do_loop_stack.top & 0x7u) |
        ((uint32_t) (parser->accepts_block_stack.top & 0x7u) << 3) |
        ((uint32_t) parser->in_keyword_arg << 6) |
        ((uint32_t) parser->in_endless_def_body << 7) |
        ((uint32_t) parser->pattern_matching_newlines << 8) |
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

static inline void fuzz_ijon_attach(pm_parser_t *parser, fuzz_ijon_state_t *state, uint32_t salt) {
    memset(state, 0, sizeof(*state));
    state->salt = salt;
    pm_parser_lex_callback_set(parser, fuzz_ijon_lex_callback, state);
}
#endif

#endif
