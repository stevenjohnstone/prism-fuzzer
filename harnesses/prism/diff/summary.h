#ifndef PRISM_DIFF_SUMMARY_H
#define PRISM_DIFF_SUMMARY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DIFF_STACK_STR_BYTES 1024
#define DIFF_STACK_SPANS     32
#define DIFF_STACK_SCOPES    16
#define DIFF_STACK_TREE_TOKS 128
#define DIFF_MAX_AST_DEPTH   4096

typedef enum {
    DIFF_SCOPE_PROGRAM = 0,
    DIFF_SCOPE_DEF,
    DIFF_SCOPE_CLASS,
    DIFF_SCOPE_MODULE,
    DIFF_SCOPE_SCLASS,
    DIFF_SCOPE_BLOCK,
    DIFF_SCOPE_LAMBDA
} diff_scope_kind_t;

typedef enum {
    DIFF_CNT_CLASS = 0,
    DIFF_CNT_MODULE,
    DIFF_CNT_SCLASS,
    DIFF_CNT_FOR,
    DIFF_CNT_IF,
    DIFF_CNT_UNLESS,
    DIFF_CNT_WHILE,
    DIFF_CNT_UNTIL,
    DIFF_CNT_YIELD,
    DIFF_CNT_RETURN,
    DIFF_CNT_SUPER,
    DIFF_CNT_DEFINED,
    DIFF_CNT_ALIAS,
    DIFF_CNT_UNDEF,
    DIFF_CNT_CASE,
    DIFF_CNT_BREAK,
    DIFF_CNT_NEXT,
    DIFF_CNT_REDO,
    DIFF_CNT_RETRY,
    DIFF_CNT_POSTEXE,
    DIFF_CNT_CASE_MATCH,
    DIFF_CNT_IN,
    DIFF_CNT_RESCUE,
    DIFF_CNT_ENSURE,
    DIFF_CNT_LEN
} diff_count_kind_t;

typedef enum {
    DIFF_TOK_CLOSE = 0,
    DIFF_TOK_SCOPE,
    DIFF_TOK_SLOT,
    DIFF_TOK_DEF,
    DIFF_TOK_DEFS,
    DIFF_TOK_CLASS,
    DIFF_TOK_MODULE,
    DIFF_TOK_SCLASS,
    DIFF_TOK_PARAMS,
    DIFF_TOK_PARAM,
    DIFF_TOK_IF,
    DIFF_TOK_UNLESS,
    DIFF_TOK_WHILE,
    DIFF_TOK_UNTIL,
    DIFF_TOK_CASE,
    DIFF_TOK_CASE_MATCH,
    DIFF_TOK_WHEN,
    DIFF_TOK_IN,
    DIFF_TOK_AND,
    DIFF_TOK_OR,
    DIFF_TOK_FOR,
    DIFF_TOK_RESCUE,
    DIFF_TOK_RESBODY,
    DIFF_TOK_ENSURE,
    DIFF_TOK_RETURN,
    DIFF_TOK_BREAK,
    DIFF_TOK_NEXT,
    DIFF_TOK_REDO,
    DIFF_TOK_RETRY,
    DIFF_TOK_YIELD,
    DIFF_TOK_SUPER,
    DIFF_TOK_ZSUPER,
    DIFF_TOK_DEFINED,
    DIFF_TOK_ALIAS,
    DIFF_TOK_VALIAS,
    DIFF_TOK_UNDEF,
    DIFF_TOK_POSTEXE,
    DIFF_TOK_ITER,
    DIFF_TOK_LAMBDA,
    DIFF_TOK_CALL,
    DIFF_TOK_QCALL,
    DIFF_TOK_ATTRASGN,
    DIFF_TOK_OP_ASGN_OR,
    DIFF_TOK_OP_ASGN_AND,
    DIFF_TOK_OP_ASGN1,
    DIFF_TOK_OP_ASGN2,
    DIFF_TOK_OP_CDECL,
    DIFF_TOK_ASGN,
    DIFF_TOK_CDECL,
    DIFF_TOK_MASGN,
    DIFF_TOK_MTARGET,
    DIFF_TOK_TARGET,
    DIFF_TOK_TARGET_SPLAT,
    DIFF_TOK_TARGET_NONE,
    DIFF_TOK_SPLAT,
    DIFF_TOK_BLOCK_PASS,
    DIFF_TOK_ARRAY,
    DIFF_TOK_HASH,
    DIFF_TOK_PAIR,
    DIFF_TOK_PAIR_SPLAT,
    DIFF_TOK_RANGE,
    DIFF_TOK_FLIP,
    DIFF_TOK_CONST,
    DIFF_TOK_COLON2,
    DIFF_TOK_COLON3,
    DIFF_TOK_LVAR,
    DIFF_TOK_IVAR,
    DIFF_TOK_CVAR,
    DIFF_TOK_GVAR,
    DIFF_TOK_NTH_REF,
    DIFF_TOK_BACK_REF,
    DIFF_TOK_SELF,
    DIFF_TOK_NIL,
    DIFF_TOK_TRUE,
    DIFF_TOK_FALSE,
    DIFF_TOK_FILE,
    DIFF_TOK_LINE,
    DIFF_TOK_ENCODING,
    DIFF_TOK_INT,
    DIFF_TOK_FLOAT,
    DIFF_TOK_RATIONAL,
    DIFF_TOK_IMAGINARY,
    DIFF_TOK_STR,
    DIFF_TOK_SYM,
    DIFF_TOK_REGX,
    DIFF_TOK_XSTR,
    DIFF_TOK_DSTR,
    DIFF_TOK_DREGX,
    DIFF_TOK_DXSTR,
    DIFF_TOK_DSYM,
    DIFF_TOK_MATCH_LAST_LINE,
    DIFF_TOK_MATCH_WRITE,
    DIFF_TOK_ARYPTN,
    DIFF_TOK_FNDPTN,
    DIFF_TOK_HSHPTN,
    DIFF_TOK_CAPTURE
} diff_tok_tag_t;

typedef struct {
    uint32_t offset;
    uint32_t length;
} diff_span_t;

typedef struct {
    uint16_t tag;
    diff_span_t label;
} diff_tree_tok_t;

typedef struct {
    diff_tree_tok_t *items;
    size_t count;
    size_t cap;
    bool on_heap;
    diff_tree_tok_t stack[DIFF_STACK_TREE_TOKS];
} diff_tree_tok_vec_t;

typedef struct {
    char *data;
    size_t used;
    size_t cap;
    bool on_heap;
    char stack[DIFF_STACK_STR_BYTES];
} diff_strbuf_t;

typedef struct {
    diff_span_t *items;
    size_t count;
    size_t cap;
    bool on_heap;
    diff_span_t stack[DIFF_STACK_SPANS];
} diff_span_vec_t;

typedef struct {
    uint8_t kind;
    uint32_t local_start;
    uint32_t local_count;
} diff_scope_t;

typedef struct {
    diff_scope_t *items;
    size_t count;
    size_t cap;
    bool on_heap;
    diff_scope_t stack[DIFF_STACK_SCOPES];
} diff_scope_vec_t;

typedef struct {
    diff_strbuf_t strbuf;
    diff_scope_vec_t scopes;
    diff_span_vec_t locals;
    diff_span_vec_t defs;
    diff_span_vec_t block_owners;
    diff_tree_tok_vec_t tree;
    size_t counts[DIFF_CNT_LEN];
} diff_summary_t;

void diff_invariant_fail(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));
bool diff_is_valid_utf8(const uint8_t *s, size_t len);
bool diff_has_nul(const uint8_t *s, size_t len);
bool diff_is_synthetic_local(const char *s, size_t len);

const char *diff_scope_kind_name(diff_scope_kind_t kind);

diff_span_t diff_strbuf_add(diff_strbuf_t *b, const char *ptr, size_t len);
void diff_span_vec_push(diff_span_vec_t *v, diff_span_t span);
void diff_scope_vec_push(diff_scope_vec_t *v, diff_scope_t scope);

void diff_tree_open(diff_summary_t *out, diff_tok_tag_t tag, const char *label, size_t len);
void diff_tree_open_cstr(diff_summary_t *out, diff_tok_tag_t tag, const char *cstr);
void diff_tree_close(diff_summary_t *out);
void diff_tree_leaf(diff_summary_t *out, diff_tok_tag_t tag, const char *label, size_t len);
void diff_tree_leaf_cstr(diff_summary_t *out, diff_tok_tag_t tag, const char *cstr);
void diff_tree_open_slot(diff_summary_t *out, const char *name);
void diff_tree_open_attrasgn(diff_summary_t *out, const char *name, size_t len);
void diff_tree_open_match_last_line(diff_summary_t *out);
void diff_tree_close_match_last_line(diff_summary_t *out);

void diff_summary_init(diff_summary_t *s);
void diff_summary_free(diff_summary_t *s);
void diff_finalize_summary(diff_summary_t *s);
void diff_compare_asts(diff_summary_t *prism, diff_summary_t *cruby);

#endif
