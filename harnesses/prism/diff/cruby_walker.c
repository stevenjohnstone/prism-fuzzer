#include "cruby_vm.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    ID scope, defn, defs, cls, mod, scls, iter, lambda, for_n, postexe;
    ID if_n, unless_n, while_n, until_n, yield_n, return_n, break_n, next_n, redo_n, retry_n;
    ID super_n, zsuper_n, defined_n, alias_n, valias_n, undef_n, case_n, case2_n;
    ID case3_n, in_n, resbody, ensure_n;
    ID masgn;
    ID fcall, vcall, call, qcall, opcall;
    ID and_n, or_n, argscat, argspush, args, opt_arg, kw_arg, postarg;
    ID aryptn, fndptn, hshptn, attrasgn, back_ref, begin_n, block_n, block_pass;
    ID colon2, colon3, const_n, cdecl, cvar, cvasgn, dasgn, dregx, dstr, dsym, dvar, dxstr;
    ID dot2, dot3, encoding_n, errinfo, evstr, false_n, file_n, flip2, flip3, float_n;
    ID for_masgn, gasgn, gvar, hash_n, iasgn, imaginary_n, integer_n, ivar, lasgn, line_n;
    ID list_n, lvar, match_n, match2, match3, nil_n, nth_ref, once_n;
    ID op_asgn1, op_asgn2, op_asgn_and, op_asgn_or, op_cdecl;
    ID rational_n, regx, rescue_n, self_n, splat, str_n, sym_n, true_n, when_n, xstr, zlist;
    ID no_name_rest, no_kw_rest, req_kw, excessive_comma;
} diff_cruby_ids_t;

static VALUE rb_cASTNode = Qnil;
static ID id_children = 0;
static ID id_type = 0;
static diff_cruby_ids_t diff_ids;

void diff_ast_ids_init(void) {
    static int initialized = 0;
    if (initialized) {
        return;
    }

    VALUE rb_cRubyVM = rb_const_get(rb_cObject, rb_intern("RubyVM"));
    VALUE rb_mAST = rb_const_get(rb_cRubyVM, rb_intern("AbstractSyntaxTree"));
    rb_cASTNode = rb_const_get(rb_mAST, rb_intern("Node"));
    rb_gc_register_mark_object(rb_cASTNode);

    id_children = rb_intern("children");
    id_type = rb_intern("type");

    static const struct {
        ID *slot;
        const char *name;
    } id_map[] = {
        { &diff_ids.scope,           "SCOPE" },
        { &diff_ids.defn,            "DEFN" },
        { &diff_ids.defs,            "DEFS" },
        { &diff_ids.cls,             "CLASS" },
        { &diff_ids.mod,             "MODULE" },
        { &diff_ids.scls,            "SCLASS" },
        { &diff_ids.iter,            "ITER" },
        { &diff_ids.lambda,          "LAMBDA" },
        { &diff_ids.for_n,           "FOR" },
        { &diff_ids.postexe,         "POSTEXE" },
        { &diff_ids.if_n,            "IF" },
        { &diff_ids.unless_n,        "UNLESS" },
        { &diff_ids.while_n,         "WHILE" },
        { &diff_ids.until_n,         "UNTIL" },
        { &diff_ids.yield_n,         "YIELD" },
        { &diff_ids.return_n,        "RETURN" },
        { &diff_ids.break_n,         "BREAK" },
        { &diff_ids.next_n,          "NEXT" },
        { &diff_ids.redo_n,          "REDO" },
        { &diff_ids.retry_n,         "RETRY" },
        { &diff_ids.super_n,         "SUPER" },
        { &diff_ids.zsuper_n,        "ZSUPER" },
        { &diff_ids.defined_n,       "DEFINED" },
        { &diff_ids.alias_n,         "ALIAS" },
        { &diff_ids.valias_n,        "VALIAS" },
        { &diff_ids.undef_n,         "UNDEF" },
        { &diff_ids.case_n,          "CASE" },
        { &diff_ids.case2_n,         "CASE2" },
        { &diff_ids.case3_n,         "CASE3" },
        { &diff_ids.in_n,            "IN" },
        { &diff_ids.resbody,         "RESBODY" },
        { &diff_ids.ensure_n,        "ENSURE" },
        { &diff_ids.masgn,           "MASGN" },
        { &diff_ids.fcall,           "FCALL" },
        { &diff_ids.vcall,           "VCALL" },
        { &diff_ids.call,            "CALL" },
        { &diff_ids.qcall,           "QCALL" },
        { &diff_ids.opcall,          "OPCALL" },
        { &diff_ids.and_n,           "AND" },
        { &diff_ids.or_n,            "OR" },
        { &diff_ids.argscat,         "ARGSCAT" },
        { &diff_ids.argspush,        "ARGSPUSH" },
        { &diff_ids.args,            "ARGS" },
        { &diff_ids.opt_arg,         "OPT_ARG" },
        { &diff_ids.kw_arg,          "KW_ARG" },
        { &diff_ids.postarg,         "POSTARG" },
        { &diff_ids.aryptn,          "ARYPTN" },
        { &diff_ids.fndptn,          "FNDPTN" },
        { &diff_ids.hshptn,          "HSHPTN" },
        { &diff_ids.attrasgn,        "ATTRASGN" },
        { &diff_ids.back_ref,        "BACK_REF" },
        { &diff_ids.begin_n,         "BEGIN" },
        { &diff_ids.block_n,         "BLOCK" },
        { &diff_ids.block_pass,      "BLOCK_PASS" },
        { &diff_ids.colon2,          "COLON2" },
        { &diff_ids.colon3,          "COLON3" },
        { &diff_ids.const_n,         "CONST" },
        { &diff_ids.cdecl,           "CDECL" },
        { &diff_ids.cvar,            "CVAR" },
        { &diff_ids.cvasgn,          "CVASGN" },
        { &diff_ids.dasgn,           "DASGN" },
        { &diff_ids.dregx,           "DREGX" },
        { &diff_ids.dstr,            "DSTR" },
        { &diff_ids.dsym,            "DSYM" },
        { &diff_ids.dvar,            "DVAR" },
        { &diff_ids.dxstr,           "DXSTR" },
        { &diff_ids.dot2,            "DOT2" },
        { &diff_ids.dot3,            "DOT3" },
        { &diff_ids.encoding_n,      "ENCODING" },
        { &diff_ids.errinfo,         "ERRINFO" },
        { &diff_ids.evstr,           "EVSTR" },
        { &diff_ids.false_n,         "FALSE" },
        { &diff_ids.file_n,          "FILE" },
        { &diff_ids.flip2,           "FLIP2" },
        { &diff_ids.flip3,           "FLIP3" },
        { &diff_ids.float_n,         "FLOAT" },
        { &diff_ids.for_masgn,       "FOR_MASGN" },
        { &diff_ids.gasgn,           "GASGN" },
        { &diff_ids.gvar,            "GVAR" },
        { &diff_ids.hash_n,          "HASH" },
        { &diff_ids.iasgn,           "IASGN" },
        { &diff_ids.imaginary_n,     "IMAGINARY" },
        { &diff_ids.integer_n,       "INTEGER" },
        { &diff_ids.ivar,            "IVAR" },
        { &diff_ids.lasgn,           "LASGN" },
        { &diff_ids.line_n,          "LINE" },
        { &diff_ids.list_n,          "LIST" },
        { &diff_ids.lvar,            "LVAR" },
        { &diff_ids.match_n,         "MATCH" },
        { &diff_ids.match2,          "MATCH2" },
        { &diff_ids.match3,          "MATCH3" },
        { &diff_ids.nil_n,           "NIL" },
        { &diff_ids.nth_ref,         "NTH_REF" },
        { &diff_ids.once_n,          "ONCE" },
        { &diff_ids.op_asgn1,        "OP_ASGN1" },
        { &diff_ids.op_asgn2,        "OP_ASGN2" },
        { &diff_ids.op_asgn_and,     "OP_ASGN_AND" },
        { &diff_ids.op_asgn_or,      "OP_ASGN_OR" },
        { &diff_ids.op_cdecl,        "OP_CDECL" },
        { &diff_ids.rational_n,      "RATIONAL" },
        { &diff_ids.regx,            "REGX" },
        { &diff_ids.rescue_n,        "RESCUE" },
        { &diff_ids.self_n,          "SELF" },
        { &diff_ids.splat,           "SPLAT" },
        { &diff_ids.str_n,           "STR" },
        { &diff_ids.sym_n,           "SYM" },
        { &diff_ids.true_n,          "TRUE" },
        { &diff_ids.when_n,          "WHEN" },
        { &diff_ids.xstr,            "XSTR" },
        { &diff_ids.zlist,           "ZLIST" },
        { &diff_ids.no_name_rest,    "NODE_SPECIAL_NO_NAME_REST" },
        { &diff_ids.no_kw_rest,      "NODE_SPECIAL_NO_REST_KEYWORD" },
        { &diff_ids.req_kw,          "NODE_SPECIAL_REQUIRED_KEYWORD" },
        { &diff_ids.excessive_comma, "NODE_SPECIAL_EXCESSIVE_COMMA" }
    };
    for (size_t i = 0; i < sizeof(id_map) / sizeof(id_map[0]); i++) {
        *id_map[i].slot = rb_intern(id_map[i].name);
    }

    initialized = 1;
}

static bool diff_cruby_is_ast_node(VALUE v) {
    return RB_TYPE_P(v, T_DATA) && rb_obj_is_kind_of(v, rb_cASTNode);
}

static ID diff_cruby_node_tid(VALUE node) {
    if (!diff_cruby_is_ast_node(node)) {
        return 0;
    }
    volatile VALUE type_sym = rb_funcall(node, id_type, 0);
    ID tid = SYMBOL_P(type_sym) ? SYM2ID(type_sym) : 0;
    RB_GC_GUARD(type_sym);
    return tid;
}

static bool diff_cruby_sym_bytes(VALUE sym, const char **ptr_out, size_t *len_out) {
    if (!SYMBOL_P(sym)) {
        return false;
    }
    volatile VALUE sym_str = rb_sym2str(sym);
    if (sym_str && RB_TYPE_P(sym_str, T_STRING)) {
        *ptr_out = RSTRING_PTR(sym_str);
        *len_out = (size_t) RSTRING_LEN(sym_str);
        RB_GC_GUARD(sym_str);
        return true;
    }
    RB_GC_GUARD(sym_str);
    return false;
}

static void diff_cruby_add_sym(VALUE sym, diff_summary_t *out, diff_span_vec_t *vec) {
    const char *ptr = NULL;
    size_t len = 0;
    if (!SYMBOL_P(sym)) {
        diff_span_vec_push(vec, diff_strbuf_add(&out->strbuf, "<nil>", 5));
        return;
    }
    if (diff_cruby_sym_bytes(sym, &ptr, &len)) {
        diff_span_vec_push(vec, diff_strbuf_add(&out->strbuf, ptr, len));
    } else {
        diff_span_vec_push(vec, diff_strbuf_add(&out->strbuf, "<sym>", 5));
    }
}

static void diff_cruby_tree_open_sym(VALUE sym, diff_tok_tag_t tag, diff_summary_t *out) {
    const char *ptr = NULL;
    size_t len = 0;
    if (diff_cruby_sym_bytes(sym, &ptr, &len)) {
        diff_tree_open(out, tag, ptr, len);
    } else {
        diff_tree_open_cstr(out, tag, "<sym>");
    }
}

static void diff_cruby_tree_leaf_sym(VALUE sym, diff_tok_tag_t tag, diff_summary_t *out) {
    diff_cruby_tree_open_sym(sym, tag, out);
    diff_tree_close(out);
}

static void diff_cruby_emit_tagged_sym(VALUE sym, diff_tok_tag_t tag, char prefix, diff_summary_t *out) {
    const char *ptr = NULL;
    size_t len = 0;
    if (!diff_cruby_sym_bytes(sym, &ptr, &len)) {
        ptr = "<sym>";
        len = 5;
    }
    char stack_buf[128];
    if (len + 2 <= sizeof(stack_buf)) {
        stack_buf[0] = prefix;
        stack_buf[1] = ':';
        if (len > 0) {
            memcpy(stack_buf + 2, ptr, len);
        }
        diff_tree_open(out, tag, stack_buf, len + 2);
    } else {
        char *heap_buf = (char *) malloc(len + 2);
        if (heap_buf == NULL) {
            abort();
        }
        heap_buf[0] = prefix;
        heap_buf[1] = ':';
        memcpy(heap_buf + 2, ptr, len);
        diff_tree_open(out, tag, heap_buf, len + 2);
        free(heap_buf);
    }
}

static void diff_cruby_record_block_owner(VALUE target, diff_summary_t *out) {
    volatile VALUE cur = target;
    for (int hop = 0; hop < 32 && diff_cruby_is_ast_node(cur); hop++) {
        volatile VALUE type_sym = rb_funcall(cur, id_type, 0);
        ID tid = SYMBOL_P(type_sym) ? SYM2ID(type_sym) : 0;
        volatile VALUE ch = rb_funcall(cur, id_children, 0);
        if (!RB_TYPE_P(ch, T_ARRAY)) {
            RB_GC_GUARD(ch);
            RB_GC_GUARD(type_sym);
            break;
        }
        long len = RARRAY_LEN(ch);
        if ((tid == diff_ids.return_n || tid == diff_ids.break_n || tid == diff_ids.next_n) && len >= 1) {
            cur = RARRAY_AREF(ch, 0);
            RB_GC_GUARD(ch);
            RB_GC_GUARD(type_sym);
            continue;
        }
        if ((tid == diff_ids.fcall || tid == diff_ids.vcall) && len >= 1) {
            diff_cruby_add_sym(RARRAY_AREF(ch, 0), out, &out->block_owners);
        } else if ((tid == diff_ids.call || tid == diff_ids.qcall || tid == diff_ids.opcall) && len >= 2) {
            diff_cruby_add_sym(RARRAY_AREF(ch, 1), out, &out->block_owners);
        } else if (tid == diff_ids.super_n || tid == diff_ids.zsuper_n) {
            diff_span_vec_push(&out->block_owners, diff_strbuf_add(&out->strbuf, "super", 5));
        } else {
            const char *tname = SYMBOL_P(type_sym) ? rb_id2name(tid) : "unknown";
            diff_span_vec_push(&out->block_owners, diff_strbuf_add(&out->strbuf, tname ? tname : "unknown", tname ? strlen(tname) : 7));
        }
        RB_GC_GUARD(ch);
        RB_GC_GUARD(type_sym);
        RB_GC_GUARD(cur);
        return;
    }
    diff_span_vec_push(&out->block_owners, diff_strbuf_add(&out->strbuf, "<unknown>", 9));
    RB_GC_GUARD(cur);
}

static void diff_cruby_extract_scope_locals(VALUE tbl, diff_scope_kind_t kind, diff_summary_t *out) {
    if (!RB_TYPE_P(tbl, T_ARRAY)) {
        int t = (int) TYPE(tbl);
        diff_summary_free(out);
        diff_invariant_fail("INVARIANT[diff_parse_y]: kind=ast_tbl_type [detail: type=%d]\n", t);
    }
    if (out->locals.count > UINT32_MAX) {
        abort();
    }
    diff_scope_t sc;
    sc.kind = (uint8_t) kind;
    sc.local_start = (uint32_t) out->locals.count;
    uint32_t added = 0;

    long tbl_len = RARRAY_LEN(tbl);
    for (long i = 0; i < tbl_len; i++) {
        VALUE sym = RARRAY_AREF(tbl, i);
        const char *ptr = NULL;
        size_t len = 0;
        if (!diff_cruby_sym_bytes(sym, &ptr, &len)) {
            continue;
        }
        if (!diff_is_synthetic_local(ptr, len)) {
            diff_span_vec_push(&out->locals, diff_strbuf_add(&out->strbuf, ptr, len));
            added++;
        }
    }
    sc.local_count = added;
    diff_scope_vec_push(&out->scopes, sc);
}

typedef struct {
    diff_summary_t *out;
    int depth;
    bool in_target;
    bool in_pattern;
    bool in_container;
} diff_cruby_ctx_t;

static void diff_cruby_visit_val_ctx(VALUE val, diff_cruby_ctx_t ctx);

static void diff_cruby_visit_slot(const char *slot, VALUE val, diff_cruby_ctx_t ctx) {
    diff_tree_open_slot(ctx.out, slot);
    if (!NIL_P(val)) {
        diff_cruby_visit_val_ctx(val, ctx);
    }
    diff_tree_close(ctx.out);
}

static bool diff_cruby_sym_is(VALUE v, ID expected) {
    return SYMBOL_P(v) && SYM2ID(v) == expected;
}

static VALUE diff_cruby_get_children(VALUE node, diff_summary_t *out, ID *tid_out) {
    volatile VALUE type_sym = rb_funcall(node, id_type, 0);
    ID tid = SYMBOL_P(type_sym) ? SYM2ID(type_sym) : 0;
    volatile VALUE ch = rb_funcall(node, id_children, 0);
    if (!RB_TYPE_P(ch, T_ARRAY)) {
        const char *tname = SYMBOL_P(type_sym) ? rb_id2name(tid) : "unknown";
        RB_GC_GUARD(ch);
        RB_GC_GUARD(type_sym);
        diff_summary_free(out);
        diff_invariant_fail("INVARIANT[diff_parse_y]: kind=ast_shape [detail: node=%s children_len=-1]\n", tname ? tname : "unknown");
    }
    *tid_out = tid;
    RB_GC_GUARD(type_sym);
    return ch;
}

static void diff_cruby_emit_seq_elems(VALUE val, const char *slot_name, diff_cruby_ctx_t ctx, bool skip_errinfo) {
    if (ctx.depth >= DIFF_MAX_AST_DEPTH || NIL_P(val) || !diff_cruby_is_ast_node(val)) {
        return;
    }
    ID tid = 0;
    volatile VALUE ch = diff_cruby_get_children(val, ctx.out, &tid);
    long len = RARRAY_LEN(ch);

    if (tid == diff_ids.zlist) {
        /* empty */
    } else if (tid == diff_ids.list_n) {
        diff_cruby_ctx_t elem_ctx = ctx;
        elem_ctx.depth = ctx.depth + 1;
        elem_ctx.in_container = true;
        for (long i = 0; i < len; i++) {
            VALUE item = RARRAY_AREF(ch, i);
            if (NIL_P(item)) {
                continue;
            }
            if (skip_errinfo && diff_cruby_node_tid(item) == diff_ids.errinfo) {
                continue;
            }
            diff_tree_open_slot(ctx.out, slot_name);
            diff_cruby_visit_val_ctx(item, elem_ctx);
            diff_tree_close(ctx.out);
        }
    } else if (tid == diff_ids.argscat && len >= 2) {
        diff_cruby_ctx_t sub = ctx;
        sub.depth = ctx.depth + 1;
        sub.in_container = false;
        VALUE head = RARRAY_AREF(ch, 0);
        VALUE body = RARRAY_AREF(ch, 1);
        ID htid = diff_cruby_node_tid(head);
        ID btid = diff_cruby_node_tid(body);
        if (htid == diff_ids.splat) {
            diff_tree_open_slot(ctx.out, slot_name);
            diff_cruby_visit_val_ctx(head, sub);
            diff_tree_close(ctx.out);
        } else {
            diff_cruby_emit_seq_elems(head, slot_name, sub, skip_errinfo);
        }
        if (btid == diff_ids.zlist || btid == diff_ids.list_n ||
            btid == diff_ids.argscat || btid == diff_ids.argspush) {
            diff_cruby_emit_seq_elems(body, slot_name, sub, skip_errinfo);
        } else {
            diff_tree_open_slot(ctx.out, slot_name);
            diff_tree_open_cstr(ctx.out, DIFF_TOK_SPLAT, NULL);
            diff_cruby_visit_val_ctx(body, sub);
            diff_tree_close(ctx.out);
            diff_tree_close(ctx.out);
        }
    } else if (tid == diff_ids.argspush && len >= 2) {
        diff_cruby_ctx_t sub = ctx;
        sub.depth = ctx.depth + 1;
        sub.in_container = false;
        VALUE head = RARRAY_AREF(ch, 0);
        VALUE tail_item = RARRAY_AREF(ch, 1);
        ID htid = diff_cruby_node_tid(head);
        if (htid == diff_ids.splat) {
            diff_tree_open_slot(ctx.out, slot_name);
            diff_cruby_visit_val_ctx(head, sub);
            diff_tree_close(ctx.out);
        } else {
            diff_cruby_emit_seq_elems(head, slot_name, sub, skip_errinfo);
        }
        if (!(skip_errinfo && diff_cruby_node_tid(tail_item) == diff_ids.errinfo)) {
            diff_tree_open_slot(ctx.out, slot_name);
            sub.in_container = true;
            diff_cruby_visit_val_ctx(tail_item, sub);
            diff_tree_close(ctx.out);
        }
    } else {
        diff_cruby_ctx_t sub = ctx;
        sub.depth = ctx.depth + 1;
        sub.in_container = false;
        diff_tree_open_slot(ctx.out, slot_name);
        diff_cruby_visit_val_ctx(val, sub);
        diff_tree_close(ctx.out);
    }
    RB_GC_GUARD(ch);
}

static void diff_cruby_emit_call_args_and_blk(VALUE args_node, VALUE iter_block, diff_cruby_ctx_t ctx, bool emit_blk_slot) {
    VALUE blk_pass_body = Qnil;
    VALUE real_args = args_node;
    if (diff_cruby_is_ast_node(args_node) && diff_cruby_node_tid(args_node) == diff_ids.block_pass) {
        ID bt = 0;
        volatile VALUE bch = diff_cruby_get_children(args_node, ctx.out, &bt);
        if (RARRAY_LEN(bch) >= 2) {
            real_args = RARRAY_AREF(bch, 0);
            blk_pass_body = RARRAY_AREF(bch, 1);
        }
        RB_GC_GUARD(bch);
    }

    diff_tree_open_slot(ctx.out, "args");
    diff_cruby_emit_seq_elems(real_args, "arg", ctx, false);
    diff_tree_close(ctx.out);

    if (emit_blk_slot) {
        diff_tree_open_slot(ctx.out, "blk");
        if (!NIL_P(iter_block)) {
            diff_cruby_ctx_t bctx = ctx;
            bctx.depth = ctx.depth + 1;
            bctx.in_target = false;
            bctx.in_pattern = false;
            bctx.in_container = false;
            if (diff_cruby_node_tid(iter_block) == diff_ids.scope) {
                /* handled cleanly via scope child */
                ID st = 0;
                volatile VALUE sch = diff_cruby_get_children(iter_block, ctx.out, &st);
                if (RARRAY_LEN(sch) >= 3) {
                    diff_cruby_extract_scope_locals(RARRAY_AREF(sch, 0), DIFF_SCOPE_BLOCK, ctx.out);
                    diff_tree_open_cstr(ctx.out, DIFF_TOK_SCOPE, "block");
                    if (!NIL_P(RARRAY_AREF(sch, 1))) {
                        diff_cruby_visit_val_ctx(RARRAY_AREF(sch, 1), bctx);
                    }
                    diff_cruby_visit_slot("body", RARRAY_AREF(sch, 2), bctx);
                    diff_tree_close(ctx.out);
                }
                RB_GC_GUARD(sch);
            } else {
                diff_cruby_visit_val_ctx(iter_block, bctx);
            }
        } else if (!NIL_P(blk_pass_body)) {
            diff_tree_open_cstr(ctx.out, DIFF_TOK_BLOCK_PASS, NULL);
            diff_cruby_ctx_t bpctx = ctx;
            bpctx.depth = ctx.depth + 1;
            bpctx.in_container = false;
            diff_cruby_visit_val_ctx(blk_pass_body, bpctx);
            diff_tree_close(ctx.out);
        }
        diff_tree_close(ctx.out);
    }
    RB_GC_GUARD(real_args);
    RB_GC_GUARD(blk_pass_body);
}

static bool diff_cruby_args_is_empty(VALUE ch) {
    if (!RB_TYPE_P(ch, T_ARRAY) || RARRAY_LEN(ch) < 10) {
        return true;
    }
    long pre_num = FIXNUM_P(RARRAY_AREF(ch, 0)) ? FIX2LONG(RARRAY_AREF(ch, 0)) : 0;
    long post_num = FIXNUM_P(RARRAY_AREF(ch, 4)) ? FIX2LONG(RARRAY_AREF(ch, 4)) : 0;
    return pre_num == 0 && post_num == 0 &&
        NIL_P(RARRAY_AREF(ch, 1)) &&
        NIL_P(RARRAY_AREF(ch, 2)) &&
        NIL_P(RARRAY_AREF(ch, 5)) &&
        NIL_P(RARRAY_AREF(ch, 6)) &&
        RARRAY_AREF(ch, 7) == Qnil &&
        RARRAY_AREF(ch, 8) == Qnil &&
        NIL_P(RARRAY_AREF(ch, 9));
}

static void diff_cruby_emit_args_chain(VALUE node, ID wrapper_id, char tag_prefix, diff_cruby_ctx_t ctx) {
    volatile VALUE cur = node;
    while (diff_cruby_is_ast_node(cur)) {
        ID tid = 0;
        volatile VALUE ch = diff_cruby_get_children(cur, ctx.out, &tid);
        long len = RARRAY_LEN(ch);
        if (tid != wrapper_id || len < 2) {
            RB_GC_GUARD(ch);
            break;
        }
        VALUE assign = RARRAY_AREF(ch, 0);
        if (diff_cruby_is_ast_node(assign)) {
            ID atid = 0;
            volatile VALUE ach = diff_cruby_get_children(assign, ctx.out, &atid);
            if (RARRAY_LEN(ach) >= 2) {
                diff_cruby_emit_tagged_sym(RARRAY_AREF(ach, 0), DIFF_TOK_PARAM, tag_prefix, ctx.out);
                VALUE rhs = RARRAY_AREF(ach, 1);
                if (diff_cruby_sym_is(rhs, diff_ids.req_kw)) {
                    diff_tree_leaf_cstr(ctx.out, DIFF_TOK_SLOT, "req");
                } else {
                    diff_cruby_ctx_t sub = ctx;
                    sub.depth = ctx.depth + 1;
                    sub.in_target = false;
                    sub.in_pattern = false;
                    diff_cruby_visit_val_ctx(rhs, sub);
                }
                diff_tree_close(ctx.out);
            }
            RB_GC_GUARD(ach);
        }
        cur = RARRAY_AREF(ch, 1);
        RB_GC_GUARD(ch);
    }
    RB_GC_GUARD(cur);
}

static void diff_cruby_emit_args_node(VALUE args_node, diff_cruby_ctx_t ctx) {
    ID tid = 0;
    volatile VALUE ch = diff_cruby_get_children(args_node, ctx.out, &tid);
    if (diff_cruby_args_is_empty(ch)) {
        RB_GC_GUARD(ch);
        return;
    }

    long pre_num = FIXNUM_P(RARRAY_AREF(ch, 0)) ? FIX2LONG(RARRAY_AREF(ch, 0)) : 0;
    long post_num = FIXNUM_P(RARRAY_AREF(ch, 4)) ? FIX2LONG(RARRAY_AREF(ch, 4)) : 0;
    char buf[32];

    diff_tree_open_cstr(ctx.out, DIFF_TOK_PARAMS, NULL);
    snprintf(buf, sizeof(buf), "pre=%ld", pre_num);
    diff_tree_leaf_cstr(ctx.out, DIFF_TOK_PARAM, buf);
    snprintf(buf, sizeof(buf), "post=%ld", post_num);
    diff_tree_leaf_cstr(ctx.out, DIFF_TOK_PARAM, buf);

    diff_cruby_ctx_t sub = ctx;
    sub.depth = ctx.depth + 1;
    sub.in_target = true;
    sub.in_pattern = false;

    if (!NIL_P(RARRAY_AREF(ch, 1))) {
        diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 1), sub);
    }
    if (!NIL_P(RARRAY_AREF(ch, 2))) {
        diff_cruby_emit_args_chain(RARRAY_AREF(ch, 2), diff_ids.opt_arg, 'o', ctx);
    }
    if (!NIL_P(RARRAY_AREF(ch, 5))) {
        diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 5), sub);
    }

    VALUE rest = RARRAY_AREF(ch, 6);
    if (!NIL_P(rest)) {
        if (diff_cruby_sym_is(rest, diff_ids.excessive_comma)) {
            diff_tree_leaf_cstr(ctx.out, DIFF_TOK_PARAM, "comma");
        } else if (SYMBOL_P(rest)) {
            diff_cruby_emit_tagged_sym(rest, DIFF_TOK_PARAM, 'r', ctx.out);
            diff_tree_close(ctx.out);
        }
    }

    VALUE kw = RARRAY_AREF(ch, 7);
    VALUE kw_rest = RARRAY_AREF(ch, 8);
    if (kw == Qfalse) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_PARAM, "nokw");
    } else {
        if (!NIL_P(kw)) {
            diff_cruby_emit_args_chain(kw, diff_ids.kw_arg, 'k', ctx);
        }
        if (diff_cruby_is_ast_node(kw_rest)) {
            ID kt = 0;
            volatile VALUE kch = diff_cruby_get_children(kw_rest, ctx.out, &kt);
            if (RARRAY_LEN(kch) >= 1 && SYMBOL_P(RARRAY_AREF(kch, 0))) {
                diff_cruby_emit_tagged_sym(RARRAY_AREF(kch, 0), DIFF_TOK_PARAM, 'K', ctx.out);
                diff_tree_close(ctx.out);
            }
            RB_GC_GUARD(kch);
        } else if (diff_cruby_sym_is(kw_rest, diff_ids.no_kw_rest)) {
            diff_tree_leaf_cstr(ctx.out, DIFF_TOK_PARAM, "nokw");
        }
    }

    VALUE blk = RARRAY_AREF(ch, 9);
    if (SYMBOL_P(blk)) {
        diff_cruby_emit_tagged_sym(blk, DIFF_TOK_PARAM, 'b', ctx.out);
        diff_tree_close(ctx.out);
    }

    diff_tree_close(ctx.out);
    RB_GC_GUARD(ch);
}

static void diff_cruby_visit_scope_child_ctx(VALUE sc, int scope_kind, diff_cruby_ctx_t ctx) {
    if (ctx.depth >= DIFF_MAX_AST_DEPTH) {
        return;
    }
    if (!diff_cruby_is_ast_node(sc)) {
        diff_cruby_visit_val_ctx(sc, ctx);
        return;
    }
    ID tid = diff_cruby_node_tid(sc);
    if (tid != diff_ids.scope) {
        diff_cruby_visit_val_ctx(sc, ctx);
        return;
    }
    volatile VALUE ch = rb_funcall(sc, id_children, 0);
    if (!RB_TYPE_P(ch, T_ARRAY) || RARRAY_LEN(ch) < 3) {
        long clen = RB_TYPE_P(ch, T_ARRAY) ? RARRAY_LEN(ch) : -1L;
        RB_GC_GUARD(ch);
        diff_summary_free(ctx.out);
        diff_invariant_fail("INVARIANT[diff_parse_y]: kind=ast_shape [detail: node=SCOPE children_len=%ld]\n", clen);
    }
    diff_cruby_ctx_t sub = ctx;
    sub.depth = ctx.depth + 1;
    sub.in_target = false;
    sub.in_pattern = false;
    sub.in_container = false;

    if (scope_kind >= 0) {
        diff_cruby_extract_scope_locals(RARRAY_AREF(ch, 0), (diff_scope_kind_t) scope_kind, ctx.out);
        diff_tree_open_cstr(ctx.out, DIFF_TOK_SCOPE, diff_scope_kind_name((diff_scope_kind_t) scope_kind));
        if (!NIL_P(RARRAY_AREF(ch, 1))) {
            diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 1), sub);
        }
        if ((diff_scope_kind_t) scope_kind == DIFF_SCOPE_PROGRAM) {
            if (!NIL_P(RARRAY_AREF(ch, 2))) {
                diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 2), sub);
            }
        } else {
            diff_cruby_visit_slot("body", RARRAY_AREF(ch, 2), sub);
        }
        diff_tree_close(ctx.out);
    } else {
        for (long i = 1; i < RARRAY_LEN(ch); i++) {
            diff_cruby_visit_val_ctx(RARRAY_AREF(ch, i), sub);
        }
    }
    RB_GC_GUARD(ch);
}

static bool diff_cruby_hash_is_pattern_capture(VALUE list_val, diff_summary_t *out) {
    if (!diff_cruby_is_ast_node(list_val)) {
        return false;
    }
    ID lt = 0;
    volatile VALUE lch = diff_cruby_get_children(list_val, out, &lt);
    bool is_cap = false;
    if (lt == diff_ids.list_n && RARRAY_LEN(lch) >= 2) {
        VALUE target = RARRAY_AREF(lch, 1);
        ID tt = diff_cruby_node_tid(target);
        if (tt == diff_ids.lasgn || tt == diff_ids.dasgn) {
            ID at = 0;
            volatile VALUE ach = diff_cruby_get_children(target, out, &at);
            if (RARRAY_LEN(ach) >= 2 && NIL_P(RARRAY_AREF(ach, 1))) {
                is_cap = true;
            }
            RB_GC_GUARD(ach);
        }
    }
    RB_GC_GUARD(lch);
    return is_cap;
}

static void diff_cruby_visit_hash_node(VALUE hash_node, bool maybe_pattern_capture, diff_cruby_ctx_t ctx) {
    ID tid = 0;
    volatile VALUE ch = diff_cruby_get_children(hash_node, ctx.out, &tid);
    VALUE list_val = RARRAY_LEN(ch) >= 1 ? RARRAY_AREF(ch, 0) : Qnil;
    RB_GC_GUARD(ch);

    if (maybe_pattern_capture && diff_cruby_hash_is_pattern_capture(list_val, ctx.out)) {
        /* Inside pattern matching (outside HSHPTN kwargs), NODE_HASH encodes CapturePattern (val => var) */
        if (diff_cruby_is_ast_node(list_val)) {
            ID lt = 0;
            volatile VALUE lch = diff_cruby_get_children(list_val, ctx.out, &lt);
            long lcount = RARRAY_LEN(lch);
            if (lcount >= 2) {
                diff_tree_open_cstr(ctx.out, DIFF_TOK_CAPTURE, NULL);
                diff_cruby_ctx_t pctx = ctx;
                pctx.depth = ctx.depth + 1;
                pctx.in_target = false;
                diff_cruby_visit_val_ctx(RARRAY_AREF(lch, 0), pctx);
                diff_cruby_ctx_t tctx = ctx;
                tctx.depth = ctx.depth + 1;
                tctx.in_target = true;
                diff_cruby_visit_val_ctx(RARRAY_AREF(lch, 1), tctx);
                diff_tree_close(ctx.out);
                RB_GC_GUARD(lch);
                return;
            }
            RB_GC_GUARD(lch);
        }
        diff_tree_open_cstr(ctx.out, DIFF_TOK_CAPTURE, NULL);
        diff_tree_close(ctx.out);
        return;
    }

    diff_tree_open_cstr(ctx.out, DIFF_TOK_HASH, NULL);
    if (diff_cruby_is_ast_node(list_val)) {
        ID lt = 0;
        volatile VALUE lch = diff_cruby_get_children(list_val, ctx.out, &lt);
        if (lt == diff_ids.list_n) {
            long lcount = RARRAY_LEN(lch);
            /* Last element of dump_array LIST is trailing nd_next (usually Qnil) */
            long usable = (lcount > 0 && NIL_P(RARRAY_AREF(lch, lcount - 1))) ? lcount - 1 : lcount;
            diff_cruby_ctx_t sub = ctx;
            sub.depth = ctx.depth + 1;
            sub.in_container = false;
            for (long i = 0; i + 1 < usable; i += 2) {
                VALUE k = RARRAY_AREF(lch, i);
                VALUE v = RARRAY_AREF(lch, i + 1);
                if (NIL_P(k)) {
                    diff_tree_open_cstr(ctx.out, DIFF_TOK_PAIR_SPLAT, NULL);
                    diff_cruby_ctx_t vctx = sub;
                    vctx.in_target = false;
                    diff_cruby_visit_val_ctx(v, vctx);
                    diff_tree_close(ctx.out);
                } else {
                    diff_tree_open_cstr(ctx.out, DIFF_TOK_PAIR, NULL);
                    diff_cruby_ctx_t kctx = sub;
                    kctx.in_target = false;
                    diff_cruby_visit_val_ctx(k, kctx);
                    diff_cruby_visit_val_ctx(v, sub);
                    diff_tree_close(ctx.out);
                }
            }
        }
        RB_GC_GUARD(lch);
    }
    diff_tree_close(ctx.out);
}

static bool diff_cruby_dstr_val_has_dynamic(VALUE val, int depth) {
    if (depth >= DIFF_MAX_AST_DEPTH || NIL_P(val)) {
        return false;
    }
    if (RB_TYPE_P(val, T_ARRAY)) {
        for (long i = 0; i < RARRAY_LEN(val); i++) {
            if (diff_cruby_dstr_val_has_dynamic(RARRAY_AREF(val, i), depth + 1)) {
                return true;
            }
        }
        return false;
    }
    if (!diff_cruby_is_ast_node(val)) {
        return false;
    }
    ID tid = diff_cruby_node_tid(val);
    if (tid == diff_ids.str_n) {
        return false;
    }
    if (tid == diff_ids.list_n) {
        volatile VALUE ch = rb_funcall(val, id_children, 0);
        bool dyn = RB_TYPE_P(ch, T_ARRAY) && diff_cruby_dstr_val_has_dynamic(ch, depth + 1);
        RB_GC_GUARD(ch);
        return dyn;
    }
    if (tid == diff_ids.dstr || tid == diff_ids.dregx || tid == diff_ids.dsym || tid == diff_ids.dxstr) {
        volatile VALUE ch = rb_funcall(val, id_children, 0);
        bool dyn = false;
        if (RB_TYPE_P(ch, T_ARRAY)) {
            if (RARRAY_LEN(ch) >= 2 && diff_cruby_dstr_val_has_dynamic(RARRAY_AREF(ch, 1), depth + 1)) {
                dyn = true;
            } else if (RARRAY_LEN(ch) >= 3 && diff_cruby_dstr_val_has_dynamic(RARRAY_AREF(ch, 2), depth + 1)) {
                dyn = true;
            }
        }
        RB_GC_GUARD(ch);
        return dyn;
    }
    return true;
}

static void diff_cruby_emit_dstr_dyn_parts(VALUE val, diff_cruby_ctx_t ctx) {
    if (ctx.depth >= DIFF_MAX_AST_DEPTH || NIL_P(val)) {
        return;
    }
    if (RB_TYPE_P(val, T_ARRAY)) {
        for (long i = 0; i < RARRAY_LEN(val); i++) {
            diff_cruby_emit_dstr_dyn_parts(RARRAY_AREF(val, i), ctx);
        }
        return;
    }
    if (!diff_cruby_is_ast_node(val)) {
        return;
    }
    ID tid = diff_cruby_node_tid(val);
    if (tid == diff_ids.str_n) {
        return;
    }
    if (tid == diff_ids.list_n) {
        volatile VALUE ch = rb_funcall(val, id_children, 0);
        if (RB_TYPE_P(ch, T_ARRAY)) {
            diff_cruby_ctx_t sub = ctx;
            sub.depth = ctx.depth + 1;
            for (long i = 0; i < RARRAY_LEN(ch); i++) {
                diff_cruby_emit_dstr_dyn_parts(RARRAY_AREF(ch, i), sub);
            }
        }
        RB_GC_GUARD(ch);
        return;
    }
    if (tid == diff_ids.dstr || tid == diff_ids.dregx || tid == diff_ids.dsym || tid == diff_ids.dxstr) {
        volatile VALUE ch = rb_funcall(val, id_children, 0);
        if (RB_TYPE_P(ch, T_ARRAY)) {
            diff_cruby_ctx_t sub = ctx;
            sub.depth = ctx.depth + 1;
            if (RARRAY_LEN(ch) >= 2) {
                diff_cruby_emit_dstr_dyn_parts(RARRAY_AREF(ch, 1), sub);
            }
            if (RARRAY_LEN(ch) >= 3) {
                diff_cruby_emit_dstr_dyn_parts(RARRAY_AREF(ch, 2), sub);
            }
        }
        RB_GC_GUARD(ch);
        return;
    }
    diff_cruby_visit_val_ctx(val, ctx);
}

static void diff_cruby_visit_dstr_like(
    VALUE ch,
    diff_tok_tag_t dyn_tag,
    diff_tok_tag_t leaf_tag,
    diff_cruby_ctx_t ctx
) {
    VALUE head = RARRAY_LEN(ch) >= 2 ? RARRAY_AREF(ch, 1) : Qnil;
    VALUE tail = RARRAY_LEN(ch) >= 3 ? RARRAY_AREF(ch, 2) : Qnil;
    bool has_dyn = diff_cruby_dstr_val_has_dynamic(head, ctx.depth + 1) ||
                   diff_cruby_dstr_val_has_dynamic(tail, ctx.depth + 1);
    if (!has_dyn) {
        diff_tree_leaf_cstr(ctx.out, leaf_tag, NULL);
        return;
    }
    diff_tree_open_cstr(ctx.out, dyn_tag, NULL);
    diff_cruby_ctx_t sub = ctx;
    sub.depth = ctx.depth + 1;
    sub.in_target = false;
    sub.in_pattern = false;
    sub.in_container = false;
    diff_cruby_emit_dstr_dyn_parts(head, sub);
    diff_cruby_emit_dstr_dyn_parts(tail, sub);
    diff_tree_close(ctx.out);
}

static void diff_cruby_count_if_matched(ID tid, diff_summary_t *out) {
    if      (tid == diff_ids.if_n)      out->counts[DIFF_CNT_IF]++;
    else if (tid == diff_ids.unless_n)  out->counts[DIFF_CNT_UNLESS]++;
    else if (tid == diff_ids.while_n)   out->counts[DIFF_CNT_WHILE]++;
    else if (tid == diff_ids.until_n)   out->counts[DIFF_CNT_UNTIL]++;
    else if (tid == diff_ids.yield_n)   out->counts[DIFF_CNT_YIELD]++;
    else if (tid == diff_ids.return_n)  out->counts[DIFF_CNT_RETURN]++;
    else if (tid == diff_ids.super_n || tid == diff_ids.zsuper_n) out->counts[DIFF_CNT_SUPER]++;
    else if (tid == diff_ids.defined_n) out->counts[DIFF_CNT_DEFINED]++;
    else if (tid == diff_ids.alias_n || tid == diff_ids.valias_n) out->counts[DIFF_CNT_ALIAS]++;
    else if (tid == diff_ids.undef_n)   out->counts[DIFF_CNT_UNDEF]++;
    else if (tid == diff_ids.case_n || tid == diff_ids.case2_n)   out->counts[DIFF_CNT_CASE]++;
    else if (tid == diff_ids.break_n)                              out->counts[DIFF_CNT_BREAK]++;
    else if (tid == diff_ids.next_n)                               out->counts[DIFF_CNT_NEXT]++;
    else if (tid == diff_ids.redo_n)                               out->counts[DIFF_CNT_REDO]++;
    else if (tid == diff_ids.retry_n)                              out->counts[DIFF_CNT_RETRY]++;
    else if (tid == diff_ids.postexe)                              out->counts[DIFF_CNT_POSTEXE]++;
    else if (tid == diff_ids.case3_n)                              out->counts[DIFF_CNT_CASE_MATCH]++;
    else if (tid == diff_ids.in_n)                                 out->counts[DIFF_CNT_IN]++;
    else if (tid == diff_ids.resbody)                              out->counts[DIFF_CNT_RESCUE]++;
    else if (tid == diff_ids.ensure_n)                             out->counts[DIFF_CNT_ENSURE]++;
}

static void diff_cruby_visit_var_assign(VALUE ch, char prefix, diff_cruby_ctx_t ctx) {
    if (RARRAY_LEN(ch) < 2) {
        return;
    }
    VALUE name_sym = RARRAY_AREF(ch, 0);
    VALUE val = RARRAY_AREF(ch, 1);
    if (ctx.in_target || (NIL_P(val) && !ctx.in_target) || diff_cruby_node_tid(val) == diff_ids.errinfo) {
        if (NIL_P(name_sym)) {
            diff_tree_leaf_cstr(ctx.out, DIFF_TOK_TARGET_NONE, NULL);
        } else {
            diff_cruby_emit_tagged_sym(name_sym, DIFF_TOK_TARGET, prefix, ctx.out);
            diff_tree_close(ctx.out);
        }
        return;
    }
    diff_cruby_emit_tagged_sym(name_sym, DIFF_TOK_ASGN, prefix, ctx.out);
    diff_cruby_ctx_t sub = ctx;
    sub.depth = ctx.depth + 1;
    sub.in_container = false;
    diff_cruby_visit_val_ctx(val, sub);
    diff_tree_close(ctx.out);
}

static void diff_cruby_visit_masgn_targets(VALUE head, VALUE args, diff_cruby_ctx_t ctx) {
    diff_cruby_ctx_t tctx = ctx;
    tctx.depth = ctx.depth + 1;
    tctx.in_target = true;
    tctx.in_container = false;

    diff_tree_open_slot(ctx.out, "lhs");
    if (diff_cruby_is_ast_node(head)) {
        ID ht = 0;
        volatile VALUE hch = diff_cruby_get_children(head, ctx.out, &ht);
        if (ht == diff_ids.list_n) {
            for (long i = 0; i < RARRAY_LEN(hch); i++) {
                VALUE item = RARRAY_AREF(hch, i);
                if (!NIL_P(item)) {
                    diff_cruby_visit_val_ctx(item, tctx);
                }
            }
        } else {
            diff_cruby_visit_val_ctx(head, tctx);
        }
        RB_GC_GUARD(hch);
    }
    diff_tree_close(ctx.out);

    diff_tree_open_slot(ctx.out, "rest");
    if (!NIL_P(args)) {
        if (diff_cruby_sym_is(args, diff_ids.no_name_rest)) {
            diff_tree_open_cstr(ctx.out, DIFF_TOK_TARGET_SPLAT, NULL);
            diff_tree_leaf_cstr(ctx.out, DIFF_TOK_TARGET_NONE, NULL);
            diff_tree_close(ctx.out);
        } else if (diff_cruby_is_ast_node(args) && diff_cruby_node_tid(args) == diff_ids.postarg) {
            ID pt = 0;
            volatile VALUE pch = diff_cruby_get_children(args, ctx.out, &pt);
            if (RARRAY_LEN(pch) >= 2) {
                VALUE rpart = RARRAY_AREF(pch, 0);
                diff_tree_open_cstr(ctx.out, DIFF_TOK_TARGET_SPLAT, NULL);
                if (diff_cruby_sym_is(rpart, diff_ids.no_name_rest)) {
                    diff_tree_leaf_cstr(ctx.out, DIFF_TOK_TARGET_NONE, NULL);
                } else {
                    diff_cruby_visit_val_ctx(rpart, tctx);
                }
                diff_tree_close(ctx.out);

                VALUE post_list = RARRAY_AREF(pch, 1);
                if (diff_cruby_is_ast_node(post_list)) {
                    ID plt = 0;
                    volatile VALUE plch = diff_cruby_get_children(post_list, ctx.out, &plt);
                    if (plt == diff_ids.list_n) {
                        for (long i = 0; i < RARRAY_LEN(plch); i++) {
                            VALUE item = RARRAY_AREF(plch, i);
                            if (!NIL_P(item)) {
                                diff_cruby_visit_val_ctx(item, tctx);
                            }
                        }
                    } else {
                        diff_cruby_visit_val_ctx(post_list, tctx);
                    }
                    RB_GC_GUARD(plch);
                }
            }
            RB_GC_GUARD(pch);
        } else {
            diff_tree_open_cstr(ctx.out, DIFF_TOK_TARGET_SPLAT, NULL);
            diff_cruby_visit_val_ctx(args, tctx);
            diff_tree_close(ctx.out);
        }
    }
    diff_tree_close(ctx.out);
}

static bool diff_cruby_emit_call_like(VALUE target, VALUE iter_block, diff_cruby_ctx_t ctx) {
    if (!diff_cruby_is_ast_node(target)) {
        return false;
    }
    ID tid = 0;
    volatile VALUE ch = diff_cruby_get_children(target, ctx.out, &tid);
    long len = RARRAY_LEN(ch);
    diff_cruby_ctx_t sub = ctx;
    sub.depth = ctx.depth + 1;
    sub.in_container = false;

    if ((tid == diff_ids.call || tid == diff_ids.opcall || tid == diff_ids.qcall) && len >= 3) {
        diff_tok_tag_t tag = (tid == diff_ids.qcall) ? DIFF_TOK_QCALL : DIFF_TOK_CALL;
        diff_cruby_tree_open_sym(RARRAY_AREF(ch, 1), tag, ctx.out);
        diff_cruby_visit_slot("recv", RARRAY_AREF(ch, 0), sub);
        diff_cruby_emit_call_args_and_blk(RARRAY_AREF(ch, 2), iter_block, sub, true);
        diff_tree_close(ctx.out);
        RB_GC_GUARD(ch);
        return true;
    }
    if (tid == diff_ids.fcall && len >= 2) {
        diff_cruby_tree_open_sym(RARRAY_AREF(ch, 0), DIFF_TOK_CALL, ctx.out);
        diff_cruby_visit_slot("recv", Qnil, sub);
        diff_cruby_emit_call_args_and_blk(RARRAY_AREF(ch, 1), iter_block, sub, true);
        diff_tree_close(ctx.out);
        RB_GC_GUARD(ch);
        return true;
    }
    if (tid == diff_ids.vcall && len >= 1) {
        diff_cruby_tree_open_sym(RARRAY_AREF(ch, 0), DIFF_TOK_CALL, ctx.out);
        diff_cruby_visit_slot("recv", Qnil, sub);
        diff_cruby_emit_call_args_and_blk(Qnil, iter_block, sub, true);
        diff_tree_close(ctx.out);
        RB_GC_GUARD(ch);
        return true;
    }
    if (tid == diff_ids.super_n && len >= 1) {
        ctx.out->counts[DIFF_CNT_SUPER]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_SUPER, NULL);
        diff_cruby_emit_call_args_and_blk(RARRAY_AREF(ch, 0), iter_block, sub, true);
        diff_tree_close(ctx.out);
        RB_GC_GUARD(ch);
        return true;
    }
    if (tid == diff_ids.zsuper_n) {
        ctx.out->counts[DIFF_CNT_SUPER]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_ZSUPER, NULL);
        diff_tree_open_slot(ctx.out, "blk");
        if (!NIL_P(iter_block)) {
            diff_cruby_visit_scope_child_ctx(iter_block, DIFF_SCOPE_BLOCK, sub);
        }
        diff_tree_close(ctx.out);
        diff_tree_close(ctx.out);
        RB_GC_GUARD(ch);
        return true;
    }
    RB_GC_GUARD(ch);
    return false;
}

static void diff_cruby_visit_node_ctx(VALUE node, diff_cruby_ctx_t ctx) {
    if (ctx.depth >= DIFF_MAX_AST_DEPTH) {
        return;
    }
    ID tid = 0;
    volatile VALUE ch = diff_cruby_get_children(node, ctx.out, &tid);
    long len = RARRAY_LEN(ch);
    diff_cruby_ctx_t sub = ctx;
    sub.depth = ctx.depth + 1;
    sub.in_container = false;

    if (tid == diff_ids.scope) {
        diff_cruby_visit_scope_child_ctx(node, ctx.depth == 0 ? (int) DIFF_SCOPE_PROGRAM : -1, ctx);
    } else if (tid == diff_ids.defn && len >= 2) {
        diff_cruby_add_sym(RARRAY_AREF(ch, 0), ctx.out, &ctx.out->defs);
        diff_cruby_tree_open_sym(RARRAY_AREF(ch, 0), DIFF_TOK_DEF, ctx.out);
        diff_cruby_visit_scope_child_ctx(RARRAY_AREF(ch, 1), DIFF_SCOPE_DEF, sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.defs && len >= 3) {
        diff_cruby_tree_open_sym(RARRAY_AREF(ch, 1), DIFF_TOK_DEFS, ctx.out);
        diff_cruby_visit_slot("recv", RARRAY_AREF(ch, 0), sub);
        diff_cruby_add_sym(RARRAY_AREF(ch, 1), ctx.out, &ctx.out->defs);
        diff_cruby_visit_scope_child_ctx(RARRAY_AREF(ch, 2), DIFF_SCOPE_DEF, sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.cls && len >= 3) {
        ctx.out->counts[DIFF_CNT_CLASS]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_CLASS, NULL);
        diff_cruby_visit_slot("cpath", RARRAY_AREF(ch, 0), sub);
        diff_cruby_visit_slot("super", RARRAY_AREF(ch, 1), sub);
        diff_cruby_visit_scope_child_ctx(RARRAY_AREF(ch, 2), DIFF_SCOPE_CLASS, sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.mod && len >= 2) {
        ctx.out->counts[DIFF_CNT_MODULE]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_MODULE, NULL);
        diff_cruby_visit_slot("cpath", RARRAY_AREF(ch, 0), sub);
        diff_cruby_visit_scope_child_ctx(RARRAY_AREF(ch, 1), DIFF_SCOPE_MODULE, sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.scls && len >= 2) {
        ctx.out->counts[DIFF_CNT_SCLASS]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_SCLASS, NULL);
        diff_cruby_visit_slot("expr", RARRAY_AREF(ch, 0), sub);
        diff_cruby_visit_scope_child_ctx(RARRAY_AREF(ch, 1), DIFF_SCOPE_SCLASS, sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.iter && len >= 2) {
        diff_cruby_record_block_owner(RARRAY_AREF(ch, 0), ctx.out);
        if (!diff_cruby_emit_call_like(RARRAY_AREF(ch, 0), RARRAY_AREF(ch, 1), ctx)) {
            diff_tree_open_cstr(ctx.out, DIFF_TOK_ITER, NULL);
            diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 0), sub);
            diff_tree_open_slot(ctx.out, "blk");
            diff_cruby_visit_scope_child_ctx(RARRAY_AREF(ch, 1), DIFF_SCOPE_BLOCK, sub);
            diff_tree_close(ctx.out);
            diff_tree_close(ctx.out);
        }
    } else if (tid == diff_ids.lambda && len >= 1) {
        diff_tree_open_cstr(ctx.out, DIFF_TOK_LAMBDA, NULL);
        diff_cruby_visit_scope_child_ctx(RARRAY_AREF(ch, 0), DIFF_SCOPE_LAMBDA, sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.for_n && len >= 2) {
        ctx.out->counts[DIFF_CNT_FOR]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_FOR, NULL);
        diff_cruby_visit_slot("col", RARRAY_AREF(ch, 0), sub);
        VALUE sc = RARRAY_AREF(ch, 1);
        VALUE idx_node = Qnil;
        VALUE body_node = Qnil;
        if (diff_cruby_is_ast_node(sc) && diff_cruby_node_tid(sc) == diff_ids.scope) {
            ID st = 0;
            volatile VALUE sch = diff_cruby_get_children(sc, ctx.out, &st);
            if (RARRAY_LEN(sch) >= 3) {
                VALUE fargs = RARRAY_AREF(sch, 1);
                body_node = RARRAY_AREF(sch, 2);
                if (diff_cruby_is_ast_node(fargs) && diff_cruby_node_tid(fargs) == diff_ids.args) {
                    ID at = 0;
                    volatile VALUE ach = diff_cruby_get_children(fargs, ctx.out, &at);
                    if (RARRAY_LEN(ach) >= 2) {
                        idx_node = RARRAY_AREF(ach, 1);
                    }
                    RB_GC_GUARD(ach);
                }
            }
            RB_GC_GUARD(sch);
        }
        diff_cruby_ctx_t idx_ctx = sub;
        idx_ctx.in_target = true;
        diff_cruby_visit_slot("idx", idx_node, idx_ctx);
        diff_cruby_visit_slot("body", body_node, sub);
        diff_tree_close(ctx.out);
        RB_GC_GUARD(idx_node);
        RB_GC_GUARD(body_node);
    } else if (tid == diff_ids.for_masgn && len >= 1) {
        diff_cruby_ctx_t tctx = sub;
        tctx.in_target = true;
        diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 0), tctx);
    } else if (tid == diff_ids.postexe && len >= 1) {
        ctx.out->counts[DIFF_CNT_POSTEXE]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_POSTEXE, NULL);
        diff_cruby_visit_scope_child_ctx(RARRAY_AREF(ch, 0), -1, sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.masgn && len >= 3) {
        VALUE rhs = RARRAY_AREF(ch, 0);
        VALUE head = RARRAY_AREF(ch, 1);
        VALUE args = RARRAY_AREF(ch, 2);
        bool is_target_only = ctx.in_target || NIL_P(rhs) || diff_cruby_node_tid(rhs) == diff_ids.for_masgn;
        diff_tree_open_cstr(ctx.out, is_target_only ? DIFF_TOK_MTARGET : DIFF_TOK_MASGN, NULL);
        diff_cruby_visit_masgn_targets(head, args, ctx);
        if (!is_target_only) {
            diff_cruby_visit_slot("rhs", rhs, sub);
        }
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.args) {
        diff_cruby_emit_args_node(node, ctx);
    } else if (tid == diff_ids.block_n || tid == diff_ids.begin_n || tid == diff_ids.once_n) {
        for (long i = 0; i < len; i++) {
            diff_cruby_visit_val_ctx(RARRAY_AREF(ch, i), sub);
        }
    } else if (tid == diff_ids.errinfo) {
        /* stripped synthetic $! reference */
    } else if (tid == diff_ids.if_n && len >= 3) {
        ctx.out->counts[DIFF_CNT_IF]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_IF, NULL);
        diff_cruby_visit_slot("cond", RARRAY_AREF(ch, 0), sub);
        diff_cruby_visit_slot("then", RARRAY_AREF(ch, 1), ctx);
        diff_cruby_visit_slot("else", RARRAY_AREF(ch, 2), ctx);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.unless_n && len >= 3) {
        ctx.out->counts[DIFF_CNT_UNLESS]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_UNLESS, NULL);
        diff_cruby_visit_slot("cond", RARRAY_AREF(ch, 0), sub);
        diff_cruby_visit_slot("then", RARRAY_AREF(ch, 1), ctx);
        diff_cruby_visit_slot("else", RARRAY_AREF(ch, 2), ctx);
        diff_tree_close(ctx.out);
    } else if ((tid == diff_ids.while_n || tid == diff_ids.until_n) && len >= 3) {
        ctx.out->counts[tid == diff_ids.while_n ? DIFF_CNT_WHILE : DIFF_CNT_UNTIL]++;
        bool post = RTEST(RARRAY_AREF(ch, 2));
        diff_tree_open_cstr(ctx.out, tid == diff_ids.while_n ? DIFF_TOK_WHILE : DIFF_TOK_UNTIL, post ? "post" : "pre");
        diff_cruby_visit_slot("cond", RARRAY_AREF(ch, 0), sub);
        diff_cruby_visit_slot("body", RARRAY_AREF(ch, 1), sub);
        diff_tree_close(ctx.out);
    } else if ((tid == diff_ids.case_n || tid == diff_ids.case2_n) && len >= 2) {
        ctx.out->counts[DIFF_CNT_CASE]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_CASE, NULL);
        diff_cruby_visit_slot("head", RARRAY_AREF(ch, 0), sub);
        volatile VALUE cur = RARRAY_AREF(ch, 1);
        while (diff_cruby_is_ast_node(cur) && diff_cruby_node_tid(cur) == diff_ids.when_n) {
            ID wt = 0;
            volatile VALUE wch = diff_cruby_get_children(cur, ctx.out, &wt);
            if (RARRAY_LEN(wch) < 3) {
                RB_GC_GUARD(wch);
                break;
            }
            diff_tree_open_cstr(ctx.out, DIFF_TOK_WHEN, NULL);
            diff_tree_open_slot(ctx.out, "conds");
            diff_cruby_emit_seq_elems(RARRAY_AREF(wch, 0), "elem", sub, false);
            diff_tree_close(ctx.out);
            diff_cruby_visit_slot("body", RARRAY_AREF(wch, 1), sub);
            diff_tree_close(ctx.out);
            cur = RARRAY_AREF(wch, 2);
            RB_GC_GUARD(wch);
        }
        diff_cruby_visit_slot("else", cur, sub);
        diff_tree_close(ctx.out);
        RB_GC_GUARD(cur);
    } else if (tid == diff_ids.case3_n && len >= 2) {
        ctx.out->counts[DIFF_CNT_CASE_MATCH]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_CASE_MATCH, NULL);
        diff_cruby_visit_slot("head", RARRAY_AREF(ch, 0), sub);
        volatile VALUE cur = RARRAY_AREF(ch, 1);
        while (diff_cruby_is_ast_node(cur) && diff_cruby_node_tid(cur) == diff_ids.in_n) {
            ctx.out->counts[DIFF_CNT_IN]++;
            ID it = 0;
            volatile VALUE ich = diff_cruby_get_children(cur, ctx.out, &it);
            if (RARRAY_LEN(ich) < 3) {
                RB_GC_GUARD(ich);
                break;
            }
            diff_cruby_ctx_t pat_ctx = sub;
            pat_ctx.in_pattern = true;
            pat_ctx.in_target = false;
            diff_tree_open_cstr(ctx.out, DIFF_TOK_IN, NULL);
            diff_cruby_visit_slot("pat", RARRAY_AREF(ich, 0), pat_ctx);
            diff_cruby_visit_slot("body", RARRAY_AREF(ich, 1), sub);
            diff_tree_close(ctx.out);
            cur = RARRAY_AREF(ich, 2);
            RB_GC_GUARD(ich);
        }
        diff_cruby_visit_slot("else", cur, sub);
        diff_tree_close(ctx.out);
        RB_GC_GUARD(cur);
    } else if ((tid == diff_ids.and_n || tid == diff_ids.or_n)) {
        diff_tree_open_cstr(ctx.out, tid == diff_ids.and_n ? DIFF_TOK_AND : DIFF_TOK_OR, NULL);
        for (long i = 0; i < len; i++) {
            diff_cruby_visit_val_ctx(RARRAY_AREF(ch, i), sub);
        }
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.rescue_n && len >= 3) {
        diff_tree_open_cstr(ctx.out, DIFF_TOK_RESCUE, NULL);
        diff_cruby_visit_slot("body", RARRAY_AREF(ch, 0), sub);
        diff_tree_open_slot(ctx.out, "resq");
        volatile VALUE cur = RARRAY_AREF(ch, 1);
        while (diff_cruby_is_ast_node(cur) && diff_cruby_node_tid(cur) == diff_ids.resbody) {
            ctx.out->counts[DIFF_CNT_RESCUE]++;
            ID rt = 0;
            volatile VALUE rch = diff_cruby_get_children(cur, ctx.out, &rt);
            if (RARRAY_LEN(rch) < 4) {
                RB_GC_GUARD(rch);
                break;
            }
            diff_tree_open_cstr(ctx.out, DIFF_TOK_RESBODY, NULL);
            diff_tree_open_slot(ctx.out, "exc");
            diff_cruby_emit_seq_elems(RARRAY_AREF(rch, 0), "elem", sub, false);
            diff_tree_close(ctx.out);
            diff_cruby_ctx_t var_ctx = sub;
            var_ctx.in_target = true;
            diff_cruby_visit_slot("var", RARRAY_AREF(rch, 1), var_ctx);
            diff_cruby_visit_slot("body", RARRAY_AREF(rch, 2), sub);
            diff_tree_close(ctx.out);
            cur = RARRAY_AREF(rch, 3);
            RB_GC_GUARD(rch);
        }
        diff_tree_close(ctx.out);
        diff_cruby_visit_slot("else", RARRAY_AREF(ch, 2), sub);
        diff_tree_close(ctx.out);
        RB_GC_GUARD(cur);
    } else if (tid == diff_ids.ensure_n && len >= 2) {
        ctx.out->counts[DIFF_CNT_ENSURE]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_ENSURE, NULL);
        diff_cruby_visit_slot("body", RARRAY_AREF(ch, 0), sub);
        diff_cruby_visit_slot("ens", RARRAY_AREF(ch, 1), sub);
        diff_tree_close(ctx.out);
    } else if ((tid == diff_ids.return_n || tid == diff_ids.break_n || tid == diff_ids.next_n) && len >= 1) {
        diff_tok_tag_t tag = tid == diff_ids.return_n ? DIFF_TOK_RETURN
            : (tid == diff_ids.break_n ? DIFF_TOK_BREAK : DIFF_TOK_NEXT);
        ctx.out->counts[tid == diff_ids.return_n ? DIFF_CNT_RETURN
            : (tid == diff_ids.break_n ? DIFF_CNT_BREAK : DIFF_CNT_NEXT)]++;
        diff_tree_open_cstr(ctx.out, tag, NULL);
        diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 0), sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.redo_n) {
        ctx.out->counts[DIFF_CNT_REDO]++;
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_REDO, NULL);
    } else if (tid == diff_ids.retry_n) {
        ctx.out->counts[DIFF_CNT_RETRY]++;
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_RETRY, NULL);
    } else if (tid == diff_ids.yield_n && len >= 1) {
        ctx.out->counts[DIFF_CNT_YIELD]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_YIELD, NULL);
        diff_cruby_emit_call_args_and_blk(RARRAY_AREF(ch, 0), Qnil, sub, false);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.defined_n && len >= 1) {
        ctx.out->counts[DIFF_CNT_DEFINED]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_DEFINED, NULL);
        diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 0), sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.alias_n && len >= 2) {
        ctx.out->counts[DIFF_CNT_ALIAS]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_ALIAS, NULL);
        diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 0), sub);
        diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 1), sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.valias_n && len >= 2) {
        ctx.out->counts[DIFF_CNT_ALIAS]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_VALIAS, NULL);
        diff_cruby_tree_leaf_sym(RARRAY_AREF(ch, 0), DIFF_TOK_GVAR, ctx.out);
        diff_cruby_tree_leaf_sym(RARRAY_AREF(ch, 1), DIFF_TOK_GVAR, ctx.out);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.undef_n && len >= 1) {
        ctx.out->counts[DIFF_CNT_UNDEF]++;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_UNDEF, NULL);
        diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 0), sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.call || tid == diff_ids.opcall || tid == diff_ids.qcall ||
               tid == diff_ids.fcall || tid == diff_ids.vcall ||
               tid == diff_ids.super_n || tid == diff_ids.zsuper_n) {
        diff_cruby_emit_call_like(node, Qnil, ctx);
    } else if (tid == diff_ids.attrasgn && len >= 3) {
        if (ctx.in_target) {
            diff_tree_open_cstr(ctx.out, DIFF_TOK_TARGET, "attr");
        }
        diff_cruby_tree_open_sym(RARRAY_AREF(ch, 1), DIFF_TOK_ATTRASGN, ctx.out);
        diff_cruby_visit_slot("recv", RARRAY_AREF(ch, 0), sub);
        diff_tree_open_slot(ctx.out, "args");
        diff_cruby_emit_seq_elems(RARRAY_AREF(ch, 2), "arg", sub, ctx.in_target);
        diff_tree_close(ctx.out);
        diff_tree_close(ctx.out);
        if (ctx.in_target) {
            diff_tree_close(ctx.out);
        }
    } else if (tid == diff_ids.lasgn || tid == diff_ids.dasgn) {
        diff_cruby_visit_var_assign(ch, 'l', ctx);
    } else if (tid == diff_ids.iasgn) {
        diff_cruby_visit_var_assign(ch, 'i', ctx);
    } else if (tid == diff_ids.cvasgn) {
        diff_cruby_visit_var_assign(ch, 'c', ctx);
    } else if (tid == diff_ids.gasgn) {
        diff_cruby_visit_var_assign(ch, 'g', ctx);
    } else if (tid == diff_ids.cdecl && len >= 2) {
        if (len == 2) {
            if (ctx.in_target) {
                diff_cruby_emit_tagged_sym(RARRAY_AREF(ch, 0), DIFF_TOK_TARGET, 'C', ctx.out);
                diff_tree_close(ctx.out);
            } else {
                diff_tree_open_cstr(ctx.out, DIFF_TOK_CDECL, NULL);
                diff_cruby_tree_leaf_sym(RARRAY_AREF(ch, 0), DIFF_TOK_CONST, ctx.out);
                diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 1), sub);
                diff_tree_close(ctx.out);
            }
        } else {
            /*
             * IMPORTANT: Never inspect RARRAY_AREF(ch, 1) on 3-element NODE_CDECL;
             * CRuby ast.c reads RNODE_COLON2(nd_else)->nd_mid even on NODE_COLON3 (::C = 1),
             * producing a bogus Symbol whose rb_sym2str crashes CRuby. ch[0] already has COLON2/COLON3.
             */
            if (ctx.in_target) {
                diff_tree_open_cstr(ctx.out, DIFF_TOK_TARGET, "cp");
                diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 0), sub);
                diff_tree_close(ctx.out);
            } else {
                diff_tree_open_cstr(ctx.out, DIFF_TOK_CDECL, NULL);
                diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 0), sub);
                diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 2), sub);
                diff_tree_close(ctx.out);
            }
        }
    } else if (tid == diff_ids.op_asgn_and && len >= 3) {
        diff_tree_open_cstr(ctx.out, DIFF_TOK_OP_ASGN_AND, NULL);
        diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 0), sub);
        diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 2), sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.op_asgn_or && len >= 3) {
        diff_tree_open_cstr(ctx.out, DIFF_TOK_OP_ASGN_OR, NULL);
        diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 0), sub);
        diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 2), sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.op_cdecl && len >= 3) {
        diff_cruby_tree_open_sym(RARRAY_AREF(ch, 1), DIFF_TOK_OP_CDECL, ctx.out);
        diff_cruby_visit_slot("target", RARRAY_AREF(ch, 0), sub);
        diff_cruby_visit_slot("val", RARRAY_AREF(ch, 2), sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.op_asgn1 && len >= 4) {
        diff_cruby_tree_open_sym(RARRAY_AREF(ch, 1), DIFF_TOK_OP_ASGN1, ctx.out);
        diff_cruby_visit_slot("recv", RARRAY_AREF(ch, 0), sub);
        diff_tree_open_slot(ctx.out, "args");
        diff_cruby_emit_seq_elems(RARRAY_AREF(ch, 2), "arg", sub, false);
        diff_tree_close(ctx.out);
        diff_cruby_visit_slot("val", RARRAY_AREF(ch, 3), sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.op_asgn2 && len >= 5) {
        diff_cruby_tree_open_sym(RARRAY_AREF(ch, 2), DIFF_TOK_OP_ASGN2, ctx.out);
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_SLOT, RTEST(RARRAY_AREF(ch, 1)) ? "1" : "0");
        diff_cruby_tree_leaf_sym(RARRAY_AREF(ch, 3), DIFF_TOK_SLOT, ctx.out);
        diff_cruby_visit_slot("recv", RARRAY_AREF(ch, 0), sub);
        diff_cruby_visit_slot("val", RARRAY_AREF(ch, 4), sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.zlist || tid == diff_ids.list_n || tid == diff_ids.argscat || tid == diff_ids.argspush) {
        diff_tree_open_cstr(ctx.out, DIFF_TOK_ARRAY, NULL);
        diff_cruby_emit_seq_elems(node, "elem", ctx, false);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.splat && len >= 1) {
        if (ctx.in_container) {
            diff_tree_open_cstr(ctx.out, DIFF_TOK_ARRAY, NULL);
            diff_tree_open_slot(ctx.out, "elem");
        }
        diff_tree_open_cstr(ctx.out, DIFF_TOK_SPLAT, NULL);
        diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 0), sub);
        diff_tree_close(ctx.out);
        if (ctx.in_container) {
            diff_tree_close(ctx.out);
            diff_tree_close(ctx.out);
        }
    } else if (tid == diff_ids.hash_n) {
        diff_cruby_visit_hash_node(node, ctx.in_pattern, ctx);
    } else if (tid == diff_ids.dot2 || tid == diff_ids.dot3) {
        diff_tree_open_cstr(ctx.out, DIFF_TOK_RANGE, tid == diff_ids.dot3 ? "..." : "..");
        VALUE beg = len >= 1 ? RARRAY_AREF(ch, 0) : Qnil;
        VALUE end = len >= 2 ? RARRAY_AREF(ch, 1) : Qnil;
        if (diff_cruby_node_tid(beg) == diff_ids.nil_n) beg = Qnil;
        if (diff_cruby_node_tid(end) == diff_ids.nil_n) end = Qnil;
        diff_cruby_visit_slot("beg", beg, sub);
        diff_cruby_visit_slot("end", end, sub);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.flip2 || tid == diff_ids.flip3) {
        diff_tree_open_cstr(ctx.out, DIFF_TOK_FLIP, tid == diff_ids.flip3 ? "..." : "..");
        VALUE eps[2] = { len >= 1 ? RARRAY_AREF(ch, 0) : Qnil, len >= 2 ? RARRAY_AREF(ch, 1) : Qnil };
        const char *slots[2] = { "beg", "end" };
        for (int ei = 0; ei < 2; ei++) {
            VALUE ep = eps[ei];
            if (diff_cruby_node_tid(ep) == diff_ids.nil_n) {
                ep = Qnil;
            } else if (diff_cruby_node_tid(ep) == diff_ids.call) {
                /* CRuby parse.y lowers integer flip-flop endpoints `n` to `n == $.` */
                ID ct = 0;
                volatile VALUE cch = diff_cruby_get_children(ep, ctx.out, &ct);
                if (RARRAY_LEN(cch) >= 3 &&
                    diff_cruby_node_tid(RARRAY_AREF(cch, 0)) == diff_ids.integer_n) {
                    const char *mptr = NULL;
                    size_t mlen = 0;
                    if (diff_cruby_sym_bytes(RARRAY_AREF(cch, 1), &mptr, &mlen) &&
                        mlen == 2 && memcmp(mptr, "==", 2) == 0 &&
                        diff_cruby_node_tid(RARRAY_AREF(cch, 2)) == diff_ids.list_n) {
                        ID at = 0;
                        volatile VALUE ach = diff_cruby_get_children(RARRAY_AREF(cch, 2), ctx.out, &at);
                        if (RARRAY_LEN(ach) >= 1 && diff_cruby_node_tid(RARRAY_AREF(ach, 0)) == diff_ids.gvar) {
                            ep = RARRAY_AREF(cch, 0);
                        }
                        RB_GC_GUARD(ach);
                    }
                }
                RB_GC_GUARD(cch);
            }
            diff_cruby_visit_slot(slots[ei], ep, sub);
        }
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.colon2 && len >= 2) {
        if (NIL_P(RARRAY_AREF(ch, 0))) {
            diff_cruby_tree_leaf_sym(RARRAY_AREF(ch, 1), DIFF_TOK_CONST, ctx.out);
        } else {
            diff_cruby_tree_open_sym(RARRAY_AREF(ch, 1), DIFF_TOK_COLON2, ctx.out);
            diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 0), sub);
            diff_tree_close(ctx.out);
        }
    } else if (tid == diff_ids.colon3 && len >= 1) {
        diff_cruby_tree_leaf_sym(RARRAY_AREF(ch, 0), DIFF_TOK_COLON3, ctx.out);
    } else if (tid == diff_ids.const_n && len >= 1) {
        diff_cruby_tree_leaf_sym(RARRAY_AREF(ch, 0), DIFF_TOK_CONST, ctx.out);
    } else if ((tid == diff_ids.lvar || tid == diff_ids.dvar) && len >= 1) {
        diff_cruby_tree_leaf_sym(RARRAY_AREF(ch, 0), DIFF_TOK_LVAR, ctx.out);
    } else if (tid == diff_ids.ivar && len >= 1) {
        diff_cruby_tree_leaf_sym(RARRAY_AREF(ch, 0), DIFF_TOK_IVAR, ctx.out);
    } else if (tid == diff_ids.cvar && len >= 1) {
        diff_cruby_tree_leaf_sym(RARRAY_AREF(ch, 0), DIFF_TOK_CVAR, ctx.out);
    } else if (tid == diff_ids.gvar && len >= 1) {
        diff_cruby_tree_leaf_sym(RARRAY_AREF(ch, 0), DIFF_TOK_GVAR, ctx.out);
    } else if (tid == diff_ids.nth_ref && len >= 1) {
        diff_cruby_tree_leaf_sym(RARRAY_AREF(ch, 0), DIFF_TOK_NTH_REF, ctx.out);
    } else if (tid == diff_ids.back_ref && len >= 1) {
        diff_cruby_tree_leaf_sym(RARRAY_AREF(ch, 0), DIFF_TOK_BACK_REF, ctx.out);
    } else if (tid == diff_ids.self_n) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_SELF, NULL);
    } else if (tid == diff_ids.nil_n) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_NIL, NULL);
    } else if (tid == diff_ids.true_n) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_TRUE, NULL);
    } else if (tid == diff_ids.false_n) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_FALSE, NULL);
    } else if (tid == diff_ids.file_n) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_FILE, NULL);
    } else if (tid == diff_ids.line_n) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_LINE, NULL);
    } else if (tid == diff_ids.encoding_n) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_ENCODING, NULL);
    } else if (tid == diff_ids.integer_n) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_INT, NULL);
    } else if (tid == diff_ids.float_n) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_FLOAT, NULL);
    } else if (tid == diff_ids.rational_n) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_RATIONAL, NULL);
    } else if (tid == diff_ids.imaginary_n) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_IMAGINARY, NULL);
    } else if (tid == diff_ids.str_n) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_STR, NULL);
    } else if (tid == diff_ids.sym_n) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_SYM, NULL);
    } else if (tid == diff_ids.regx) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_REGX, NULL);
    } else if (tid == diff_ids.xstr) {
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_XSTR, NULL);
    } else if (tid == diff_ids.match_n) {
        diff_tree_open_match_last_line(ctx.out);
        diff_tree_leaf_cstr(ctx.out, DIFF_TOK_REGX, NULL);
        diff_tree_close_match_last_line(ctx.out);
    } else if (tid == diff_ids.dstr) {
        diff_cruby_visit_dstr_like(ch, DIFF_TOK_DSTR, DIFF_TOK_STR, ctx);
    } else if (tid == diff_ids.dsym) {
        diff_cruby_visit_dstr_like(ch, DIFF_TOK_DSYM, DIFF_TOK_SYM, ctx);
    } else if (tid == diff_ids.dregx) {
        diff_cruby_visit_dstr_like(ch, DIFF_TOK_DREGX, DIFF_TOK_REGX, ctx);
    } else if (tid == diff_ids.dxstr) {
        diff_cruby_visit_dstr_like(ch, DIFF_TOK_DXSTR, DIFF_TOK_XSTR, ctx);
    } else if (tid == diff_ids.match2 && len >= 2) {
        bool has_targets = len >= 3 && !NIL_P(RARRAY_AREF(ch, 2));
        if (has_targets) {
            diff_tree_open_cstr(ctx.out, DIFF_TOK_MATCH_WRITE, NULL);
        }
        diff_tree_open_cstr(ctx.out, DIFF_TOK_CALL, "=~");
        diff_cruby_visit_slot("recv", RARRAY_AREF(ch, 0), sub);
        diff_tree_open_slot(ctx.out, "args");
        diff_cruby_visit_slot("arg", RARRAY_AREF(ch, 1), sub);
        diff_tree_close(ctx.out);
        diff_tree_open_slot(ctx.out, "blk");
        diff_tree_close(ctx.out);
        diff_tree_close(ctx.out);
        if (has_targets) {
            diff_cruby_ctx_t tctx = sub;
            tctx.in_target = true;
            diff_cruby_visit_val_ctx(RARRAY_AREF(ch, 2), tctx);
            diff_tree_close(ctx.out);
        }
    } else if (tid == diff_ids.match3 && len >= 2) {
        diff_tree_open_cstr(ctx.out, DIFF_TOK_CALL, "=~");
        diff_cruby_visit_slot("recv", RARRAY_AREF(ch, 1), sub);
        diff_tree_open_slot(ctx.out, "args");
        diff_cruby_visit_slot("arg", RARRAY_AREF(ch, 0), sub);
        diff_tree_close(ctx.out);
        diff_tree_open_slot(ctx.out, "blk");
        diff_tree_close(ctx.out);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.aryptn && len >= 4) {
        diff_cruby_ctx_t pctx = sub;
        pctx.in_pattern = true;
        pctx.in_target = true;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_ARYPTN, NULL);
        diff_cruby_ctx_t cctx = sub;
        cctx.in_pattern = false;
        cctx.in_target = false;
        diff_cruby_visit_slot("const", RARRAY_AREF(ch, 0), cctx);
        diff_tree_open_slot(ctx.out, "pre");
        diff_cruby_emit_seq_elems(RARRAY_AREF(ch, 1), "elem", pctx, false);
        diff_tree_close(ctx.out);
        diff_tree_open_slot(ctx.out, "rest");
        VALUE rval = RARRAY_AREF(ch, 2);
        if (diff_cruby_sym_is(rval, diff_ids.no_name_rest)) {
            diff_tree_leaf_cstr(ctx.out, DIFF_TOK_TARGET_NONE, NULL);
        } else if (!NIL_P(rval)) {
            diff_cruby_visit_val_ctx(rval, pctx);
        }
        diff_tree_close(ctx.out);
        diff_tree_open_slot(ctx.out, "post");
        diff_cruby_emit_seq_elems(RARRAY_AREF(ch, 3), "elem", pctx, false);
        diff_tree_close(ctx.out);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.fndptn && len >= 4) {
        diff_cruby_ctx_t pctx = sub;
        pctx.in_pattern = true;
        pctx.in_target = true;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_FNDPTN, NULL);
        diff_cruby_ctx_t cctx = sub;
        cctx.in_pattern = false;
        cctx.in_target = false;
        diff_cruby_visit_slot("const", RARRAY_AREF(ch, 0), cctx);
        diff_tree_open_slot(ctx.out, "pre");
        VALUE r1 = RARRAY_AREF(ch, 1);
        if (diff_cruby_sym_is(r1, diff_ids.no_name_rest)) {
            diff_tree_leaf_cstr(ctx.out, DIFF_TOK_TARGET_NONE, NULL);
        } else if (!NIL_P(r1)) {
            diff_cruby_visit_val_ctx(r1, pctx);
        }
        diff_tree_close(ctx.out);
        diff_tree_open_slot(ctx.out, "mid");
        diff_cruby_emit_seq_elems(RARRAY_AREF(ch, 2), "elem", pctx, false);
        diff_tree_close(ctx.out);
        diff_tree_open_slot(ctx.out, "post");
        VALUE r2 = RARRAY_AREF(ch, 3);
        if (diff_cruby_sym_is(r2, diff_ids.no_name_rest)) {
            diff_tree_leaf_cstr(ctx.out, DIFF_TOK_TARGET_NONE, NULL);
        } else if (!NIL_P(r2)) {
            diff_cruby_visit_val_ctx(r2, pctx);
        }
        diff_tree_close(ctx.out);
        diff_tree_close(ctx.out);
    } else if (tid == diff_ids.hshptn && len >= 3) {
        diff_cruby_ctx_t pctx = sub;
        pctx.in_pattern = true;
        pctx.in_target = true;
        diff_tree_open_cstr(ctx.out, DIFF_TOK_HSHPTN, NULL);
        diff_cruby_ctx_t cctx = sub;
        cctx.in_pattern = false;
        cctx.in_target = false;
        diff_cruby_visit_slot("const", RARRAY_AREF(ch, 0), cctx);
        diff_tree_open_slot(ctx.out, "kw");
        if (diff_cruby_is_ast_node(RARRAY_AREF(ch, 1))) {
            diff_cruby_visit_hash_node(RARRAY_AREF(ch, 1), false, pctx);
        } else {
            diff_tree_open_cstr(ctx.out, DIFF_TOK_HASH, NULL);
            diff_tree_close(ctx.out);
        }
        diff_tree_close(ctx.out);
        diff_tree_open_slot(ctx.out, "kwrest");
        VALUE kwrest = RARRAY_AREF(ch, 2);
        if (diff_cruby_sym_is(kwrest, diff_ids.no_kw_rest)) {
            diff_tree_leaf_cstr(ctx.out, DIFF_TOK_TARGET_NONE, "nokw");
        } else if (!NIL_P(kwrest)) {
            diff_cruby_visit_val_ctx(kwrest, pctx);
        }
        diff_tree_close(ctx.out);
        diff_tree_close(ctx.out);
    } else {
        diff_cruby_count_if_matched(tid, ctx.out);
        for (long i = 0; i < len; i++) {
            diff_cruby_visit_val_ctx(RARRAY_AREF(ch, i), sub);
        }
    }

    RB_GC_GUARD(ch);
}

static void diff_cruby_visit_val_ctx(VALUE val, diff_cruby_ctx_t ctx) {
    if (ctx.depth >= DIFF_MAX_AST_DEPTH) {
        return;
    }
    if (diff_cruby_is_ast_node(val)) {
        diff_cruby_visit_node_ctx(val, ctx);
    } else if (RB_TYPE_P(val, T_ARRAY)) {
        long len = RARRAY_LEN(val);
        diff_cruby_ctx_t sub = ctx;
        sub.depth = ctx.depth + 1;
        for (long i = 0; i < len; i++) {
            diff_cruby_visit_val_ctx(RARRAY_AREF(val, i), sub);
        }
    }
}

void diff_collect_cruby_summary(VALUE ast_node, diff_summary_t *out) {
    if (NIL_P(ast_node)) {
        return;
    }
    diff_ast_ids_init();
    diff_cruby_ctx_t ctx = {
        .out = out,
        .depth = 0,
        .in_target = false,
        .in_pattern = false,
        .in_container = false
    };
    diff_cruby_visit_val_ctx(ast_node, ctx);
    diff_finalize_summary(out);
}
