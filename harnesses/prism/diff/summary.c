#include "summary.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void diff_invariant_fail(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fflush(stderr);
    abort();
}

bool diff_is_valid_utf8(const uint8_t *s, size_t len) {
    size_t i = 0;
    while (i < len) {
        uint8_t b0 = s[i];
        if (b0 <= 0x7F) {
            i += 1;
        } else if (b0 >= 0xC2 && b0 <= 0xDF) {
            if (i + 2 > len || (s[i + 1] & 0xC0) != 0x80) return false;
            i += 2;
        } else if (b0 == 0xE0) {
            if (i + 3 > len || s[i + 1] < 0xA0 || s[i + 1] > 0xBF || (s[i + 2] & 0xC0) != 0x80) return false;
            i += 3;
        } else if ((b0 >= 0xE1 && b0 <= 0xEC) || (b0 >= 0xEE && b0 <= 0xEF)) {
            if (i + 3 > len || (s[i + 1] & 0xC0) != 0x80 || (s[i + 2] & 0xC0) != 0x80) return false;
            i += 3;
        } else if (b0 == 0xED) {
            if (i + 3 > len || s[i + 1] < 0x80 || s[i + 1] > 0x9F || (s[i + 2] & 0xC0) != 0x80) return false;
            i += 3;
        } else if (b0 == 0xF0) {
            if (i + 4 > len || s[i + 1] < 0x90 || s[i + 1] > 0xBF || (s[i + 2] & 0xC0) != 0x80 || (s[i + 3] & 0xC0) != 0x80) return false;
            i += 4;
        } else if (b0 >= 0xF1 && b0 <= 0xF3) {
            if (i + 4 > len || (s[i + 1] & 0xC0) != 0x80 || (s[i + 2] & 0xC0) != 0x80 || (s[i + 3] & 0xC0) != 0x80) return false;
            i += 4;
        } else if (b0 == 0xF4) {
            if (i + 4 > len || s[i + 1] < 0x80 || s[i + 1] > 0x8F || (s[i + 2] & 0xC0) != 0x80 || (s[i + 3] & 0xC0) != 0x80) return false;
            i += 4;
        } else {
            return false;
        }
    }
    return true;
}

bool diff_has_nul(const uint8_t *s, size_t len) {
    return len > 0 && memchr(s, '\0', len) != NULL;
}

const char *diff_scope_kind_name(diff_scope_kind_t kind) {
    static const char *const names[] = {
        "program", "def", "class", "module", "sclass", "block", "lambda"
    };
    size_t idx = (size_t) kind;
    return idx < (sizeof(names) / sizeof(names[0])) ? names[idx] : "unknown";
}

static const char *diff_count_kind_name(diff_count_kind_t kind) {
    static const char *const names[] = {
        "class", "module", "sclass", "for", "if", "unless", "while", "until",
        "yield", "return", "super", "defined", "alias", "undef", "case",
        "break", "next", "redo", "retry", "postexe", "case_match", "in", "rescue", "ensure"
    };
    size_t idx = (size_t) kind;
    return idx < (sizeof(names) / sizeof(names[0])) ? names[idx] : "unknown";
}

static const char *diff_tok_tag_name(diff_tok_tag_t tag) {
    static const char *const names[] = {
        "CLOSE", "SCOPE", "SLOT", "DEF", "DEFS", "CLASS", "MODULE", "SCLASS",
        "PARAMS", "PARAM", "IF", "UNLESS", "WHILE", "UNTIL", "CASE", "CASE_MATCH",
        "WHEN", "IN", "AND", "OR", "FOR", "RESCUE", "RESBODY", "ENSURE",
        "RETURN", "BREAK", "NEXT", "REDO", "RETRY", "YIELD", "SUPER", "ZSUPER",
        "DEFINED", "ALIAS", "VALIAS", "UNDEF", "POSTEXE", "ITER", "LAMBDA",
        "CALL", "QCALL", "ATTRASGN", "OP_ASGN_OR", "OP_ASGN_AND",
        "OP_ASGN1", "OP_ASGN2", "OP_CDECL", "ASGN", "CDECL", "MASGN", "MTARGET",
        "TARGET", "TARGET_SPLAT", "TARGET_NONE", "SPLAT", "BLOCK_PASS",
        "ARRAY", "HASH", "PAIR", "PAIR_SPLAT", "RANGE", "FLIP",
        "CONST", "COLON2", "COLON3", "LVAR", "IVAR", "CVAR", "GVAR",
        "NTH_REF", "BACK_REF", "SELF", "NIL", "TRUE", "FALSE", "FILE", "LINE",
        "ENCODING", "INT", "FLOAT", "RATIONAL", "IMAGINARY",
        "STR", "SYM", "REGX", "XSTR", "DSTR", "DREGX", "DXSTR", "DSYM",
        "MATCH_LAST_LINE", "MATCH_WRITE", "ARYPTN", "FNDPTN", "HSHPTN", "CAPTURE"
    };
    size_t idx = (size_t) tag;
    return idx < (sizeof(names) / sizeof(names[0])) ? names[idx] : "UNKNOWN";
}

static void diff_strbuf_init(diff_strbuf_t *b) {
    b->data = b->stack;
    b->used = 0;
    b->cap = sizeof(b->stack);
    b->on_heap = false;
}

static void diff_ensure_cap(
    void **buf,
    size_t *cap,
    bool *on_heap,
    const void *stack_buf,
    size_t used_count,
    size_t elem_size,
    size_t needed
) {
    if (needed <= *cap) {
        return;
    }
    size_t new_cap = *cap;
    while (new_cap < needed) {
        if (new_cap > SIZE_MAX / 2) {
            abort();
        }
        new_cap *= 2;
    }
    if (new_cap > SIZE_MAX / elem_size) {
        abort();
    }
    void *next = NULL;
    if (*on_heap) {
        next = realloc(*buf, new_cap * elem_size);
    } else {
        next = malloc(new_cap * elem_size);
        if (next != NULL && used_count > 0) {
            memcpy(next, stack_buf, used_count * elem_size);
        }
    }
    if (next == NULL) {
        abort();
    }
    *buf = next;
    *cap = new_cap;
    *on_heap = true;
}

static void diff_strbuf_free(diff_strbuf_t *b) {
    if (b->on_heap) {
        free(b->data);
    }
    diff_strbuf_init(b);
}

diff_span_t diff_strbuf_add(diff_strbuf_t *b, const char *ptr, size_t len) {
    if (len > UINT32_MAX || b->used > (size_t) UINT32_MAX - len) {
        abort();
    }
    void *data_ptr = b->data;
    diff_ensure_cap(&data_ptr, &b->cap, &b->on_heap, b->stack, b->used, 1, b->used + len);
    b->data = (char *) data_ptr;

    diff_span_t span;
    span.offset = (uint32_t) b->used;
    span.length = (uint32_t) len;
    if (len > 0) {
        memcpy(b->data + b->used, ptr, len);
        b->used += len;
    }
    return span;
}

static void diff_span_vec_init(diff_span_vec_t *v) {
    v->items = v->stack;
    v->count = 0;
    v->cap = DIFF_STACK_SPANS;
    v->on_heap = false;
}

static void diff_span_vec_free(diff_span_vec_t *v) {
    if (v->on_heap) {
        free(v->items);
    }
    diff_span_vec_init(v);
}

void diff_span_vec_push(diff_span_vec_t *v, diff_span_t span) {
    void *items_ptr = v->items;
    diff_ensure_cap(&items_ptr, &v->cap, &v->on_heap, v->stack, v->count, sizeof(diff_span_t), v->count + 1);
    v->items = (diff_span_t *) items_ptr;
    v->items[v->count++] = span;
}

static void diff_scope_vec_init(diff_scope_vec_t *v) {
    v->items = v->stack;
    v->count = 0;
    v->cap = DIFF_STACK_SCOPES;
    v->on_heap = false;
}

static void diff_scope_vec_free(diff_scope_vec_t *v) {
    if (v->on_heap) {
        free(v->items);
    }
    diff_scope_vec_init(v);
}

void diff_scope_vec_push(diff_scope_vec_t *v, diff_scope_t scope) {
    void *items_ptr = v->items;
    diff_ensure_cap(&items_ptr, &v->cap, &v->on_heap, v->stack, v->count, sizeof(diff_scope_t), v->count + 1);
    v->items = (diff_scope_t *) items_ptr;
    v->items[v->count++] = scope;
}

static void diff_tree_tok_vec_init(diff_tree_tok_vec_t *v) {
    v->items = v->stack;
    v->count = 0;
    v->cap = DIFF_STACK_TREE_TOKS;
    v->on_heap = false;
}

static void diff_tree_tok_vec_free(diff_tree_tok_vec_t *v) {
    if (v->on_heap) {
        free(v->items);
    }
    diff_tree_tok_vec_init(v);
}

static void diff_tree_tok_vec_push(diff_tree_tok_vec_t *v, diff_tree_tok_t tok) {
    void *items_ptr = v->items;
    diff_ensure_cap(&items_ptr, &v->cap, &v->on_heap, v->stack, v->count, sizeof(diff_tree_tok_t), v->count + 1);
    v->items = (diff_tree_tok_t *) items_ptr;
    v->items[v->count++] = tok;
}

void diff_tree_open(diff_summary_t *out, diff_tok_tag_t tag, const char *label, size_t len) {
    diff_tree_tok_t tok;
    tok.tag = (uint16_t) tag;
    tok.label = (label != NULL && len > 0) ? diff_strbuf_add(&out->strbuf, label, len) : (diff_span_t) { 0, 0 };
    diff_tree_tok_vec_push(&out->tree, tok);
}

void diff_tree_open_cstr(diff_summary_t *out, diff_tok_tag_t tag, const char *cstr) {
    diff_tree_open(out, tag, cstr, cstr != NULL ? strlen(cstr) : 0);
}

void diff_tree_close(diff_summary_t *out) {
    diff_tree_tok_t tok = { (uint16_t) DIFF_TOK_CLOSE, { 0, 0 } };
    diff_tree_tok_vec_push(&out->tree, tok);
}

void diff_tree_leaf(diff_summary_t *out, diff_tok_tag_t tag, const char *label, size_t len) {
    diff_tree_open(out, tag, label, len);
    diff_tree_close(out);
}

void diff_tree_leaf_cstr(diff_summary_t *out, diff_tok_tag_t tag, const char *cstr) {
    diff_tree_leaf(out, tag, cstr, cstr != NULL ? strlen(cstr) : 0);
}

void diff_tree_open_slot(diff_summary_t *out, const char *name) {
    diff_tree_open_cstr(out, DIFF_TOK_SLOT, name);
}

void diff_tree_open_attrasgn(diff_summary_t *out, const char *name, size_t len) {
    if (len > 1 && name[len - 1] == '=' && !(len == 3 && memcmp(name, "[]=", 3) == 0)) {
        len--;
    }
    diff_tree_open(out, DIFF_TOK_ATTRASGN, name, len);
}

/* CRuby parse.y lowers conditional `/#{...}/` (and regexes like `/ #$ /`) to
 * `(MATCH2 <REGX|DREGX> (GVAR :$_))`; lower both static and interpolated forms symmetrically. */
void diff_tree_open_match_last_line(diff_summary_t *out) {
    diff_tree_open_cstr(out, DIFF_TOK_CALL, "=~");
    diff_tree_open_slot(out, "recv");
}

void diff_tree_close_match_last_line(diff_summary_t *out) {
    diff_tree_close(out);
    diff_tree_open_slot(out, "args");
    diff_tree_open_slot(out, "arg");
    diff_tree_leaf_cstr(out, DIFF_TOK_GVAR, "$_");
    diff_tree_close(out);
    diff_tree_close(out);
    diff_tree_open_slot(out, "blk");
    diff_tree_close(out);
    diff_tree_close(out);
}

void diff_summary_init(diff_summary_t *s) {
    diff_strbuf_init(&s->strbuf);
    diff_scope_vec_init(&s->scopes);
    diff_span_vec_init(&s->locals);
    diff_span_vec_init(&s->defs);
    diff_span_vec_init(&s->block_owners);
    diff_tree_tok_vec_init(&s->tree);
    memset(s->counts, 0, sizeof(s->counts));
    s->has_nested_preexe = false;
}

void diff_summary_free(diff_summary_t *s) {
    diff_strbuf_free(&s->strbuf);
    diff_scope_vec_free(&s->scopes);
    diff_span_vec_free(&s->locals);
    diff_span_vec_free(&s->defs);
    diff_span_vec_free(&s->block_owners);
    diff_tree_tok_vec_free(&s->tree);
    memset(s->counts, 0, sizeof(s->counts));
    s->has_nested_preexe = false;
}

static int diff_span_cmp(diff_span_t a, diff_span_t b, const char *buf) {
    size_t min_len = a.length < b.length ? a.length : b.length;
    int cmp = min_len > 0 ? memcmp(buf + a.offset, buf + b.offset, min_len) : 0;
    if (cmp != 0) {
        return cmp;
    }
    return (a.length > b.length) - (a.length < b.length);
}

static void diff_sift_down(diff_span_t *arr, size_t start, size_t end, const char *buf) {
    size_t root = start;
    while (root * 2 + 1 <= end) {
        size_t child = root * 2 + 1;
        size_t swap_idx = root;
        if (diff_span_cmp(arr[swap_idx], arr[child], buf) < 0) {
            swap_idx = child;
        }
        if (child + 1 <= end && diff_span_cmp(arr[swap_idx], arr[child + 1], buf) < 0) {
            swap_idx = child + 1;
        }
        if (swap_idx == root) {
            return;
        }
        diff_span_t tmp = arr[root];
        arr[root] = arr[swap_idx];
        arr[swap_idx] = tmp;
        root = swap_idx;
    }
}

/* Portable in-place O(N log N) sort over spans indexed into a string buffer. */
static void diff_sort_spans(diff_span_t *arr, size_t n, const char *buf) {
    if (n < 2) {
        return;
    }
    for (size_t start = n / 2; start > 0; start--) {
        diff_sift_down(arr, start - 1, n - 1, buf);
    }
    for (size_t end = n - 1; end > 0; end--) {
        diff_span_t tmp = arr[0];
        arr[0] = arr[end];
        arr[end] = tmp;
        diff_sift_down(arr, 0, end - 1, buf);
    }
}

/* Sort and deduplicate locals per scope and sort block owners for traversal invariance. */
void diff_finalize_summary(diff_summary_t *s) {
    for (size_t i = 0; i < s->scopes.count; i++) {
        diff_scope_t *sc = &s->scopes.items[i];
        size_t n = sc->local_count;
        if (n < 2) {
            continue;
        }
        diff_span_t *slice = &s->locals.items[sc->local_start];
        diff_sort_spans(slice, n, s->strbuf.data);
        size_t unique = 1;
        for (size_t j = 1; j < n; j++) {
            if (diff_span_cmp(slice[j], slice[unique - 1], s->strbuf.data) != 0) {
                slice[unique++] = slice[j];
            }
        }
        sc->local_count = (uint32_t) unique;
    }
    /* Keep block_owners in AST traversal order rather than sorting them. */
}

/* Ignore CRuby synthetic parameter table entries (*, **, &, ..., <it>) so scope locals align. */
bool diff_is_synthetic_local(const char *s, size_t len) {
    switch (len) {
        case 1: return s[0] == '*' || s[0] == '&';
        case 2: return memcmp(s, "**", 2) == 0;
        case 3: return memcmp(s, "...", 3) == 0;
        case 4: return memcmp(s, "<it>", 4) == 0;
        default: return false;
    }
}

static const char *diff_block_mismatch_sub(
    const char *p_ptr,
    size_t p_len,
    const char *c_ptr,
    size_t c_len
) {
    if ((p_len == 5 && memcmp(p_ptr, "super", 5) == 0) ||
        (c_len == 5 && memcmp(c_ptr, "super", 5) == 0)) {
        return "super";
    }
    if (p_len > 0) {
        char p0 = p_ptr[0];
        if (!((p0 >= 'a' && p0 <= 'z') || (p0 >= 'A' && p0 <= 'Z') || p0 == '_')) {
            return "operator";
        }
    }
    if (c_len > 0) {
        char c0 = c_ptr[0];
        if (!((c0 >= 'a' && c0 <= 'z') || (c0 >= 'A' && c0 <= 'Z') || c0 == '_')) {
            return "operator";
        }
    }
    return "method";
}

static bool diff_span_equal(const char *pbuf, diff_span_t pspan, const char *cbuf, diff_span_t cspan) {
    return pspan.length == cspan.length &&
           (pspan.length == 0 || memcmp(pbuf + pspan.offset, cbuf + cspan.offset, pspan.length) == 0);
}

static size_t diff_copy_span(const char *buf, diff_span_t span, char dst[97]) {
    size_t len = span.length > 96 ? 96 : (size_t) span.length;
    if (len > 0) {
        memcpy(dst, buf + span.offset, len);
    }
    dst[len] = '\0';
    return len;
}

static void diff_compare_locals(diff_summary_t *prism, diff_summary_t *cruby) {
    for (size_t s = 0; s < prism->scopes.count; s++) {
        const diff_scope_t *ps = &prism->scopes.items[s];
        const diff_scope_t *cs = &cruby->scopes.items[s];
        const char *sname = diff_scope_kind_name((diff_scope_kind_t) ps->kind);
        if (ps->local_count != cs->local_count) {
            size_t pc = ps->local_count;
            size_t cc = cs->local_count;
            diff_summary_free(prism);
            diff_summary_free(cruby);
            diff_invariant_fail(
                "INVARIANT[diff_parse_y]: kind=locals_count_mismatch scope=%s [detail: scope_idx=%zu prism=%zu cruby=%zu]\n",
                sname,
                s,
                pc,
                cc
            );
        }
        for (uint32_t j = 0; j < ps->local_count; j++) {
            diff_span_t pspan = prism->locals.items[ps->local_start + j];
            diff_span_t cspan = cruby->locals.items[cs->local_start + j];
            if (!diff_span_equal(prism->strbuf.data, pspan, cruby->strbuf.data, cspan)) {
                char pcopy[97];
                char ccopy[97];
                diff_copy_span(prism->strbuf.data, pspan, pcopy);
                diff_copy_span(cruby->strbuf.data, cspan, ccopy);
                diff_summary_free(prism);
                diff_summary_free(cruby);
                diff_invariant_fail(
                    "INVARIANT[diff_parse_y]: kind=locals_name_mismatch scope=%s [detail: scope_idx=%zu idx=%zu prism=%s cruby=%s]\n",
                    sname,
                    s,
                    (size_t) j,
                    pcopy,
                    ccopy
                );
            }
        }
    }
}

static void diff_format_tok_full(const diff_summary_t *s, diff_tree_tok_t tok, char dst[97]) {
    const char *tname = diff_tok_tag_name((diff_tok_tag_t) tok.tag);
    size_t tlen = strlen(tname);
    if (tlen > 40) {
        tlen = 40;
    }
    memcpy(dst, tname, tlen);
    size_t pos = tlen;
    if (tok.label.length > 0 && pos + 2 < 96) {
        dst[pos++] = ':';
        const char *lptr = s->strbuf.data + tok.label.offset;
        size_t lmax = 96 - pos;
        size_t llen = tok.label.length < lmax ? (size_t) tok.label.length : lmax;
        for (size_t i = 0; i < llen; i++) {
            unsigned char ch = (unsigned char) lptr[i];
            dst[pos++] = (ch >= 0x21 && ch <= 0x7e && ch != '[' && ch != ']') ? (char) ch : '_';
        }
    }
    dst[pos] = '\0';
}

static bool diff_is_ident_starter(unsigned char ch) {
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_' || ch >= 0x80;
}

/* Format a structural signature token for `sub=label` headlines: preserve
 * operators, slot/scope names, and variable target prefixes (`l:`, `i:`, `$!`)
 * while normalizing fuzzed user identifier/literal spellings to `<id>`. */
static void diff_format_tok_sig(const diff_summary_t *s, diff_tree_tok_t tok, char dst[97]) {
    const char *tname = diff_tok_tag_name((diff_tok_tag_t) tok.tag);
    if (tok.label.length == 0) {
        snprintf(dst, 97, "%s", tname);
        return;
    }

    const char *lptr = s->strbuf.data + tok.label.offset;
    size_t llen = tok.label.length;

    switch ((diff_tok_tag_t) tok.tag) {
        case DIFF_TOK_SCOPE:
        case DIFF_TOK_SLOT:
        case DIFF_TOK_RANGE:
        case DIFF_TOK_FLIP:
        case DIFF_TOK_TARGET_NONE:
            diff_format_tok_full(s, tok, dst);
            return;
        case DIFF_TOK_CALL:
        case DIFF_TOK_QCALL:
        case DIFF_TOK_ATTRASGN:
        case DIFF_TOK_OP_ASGN1:
        case DIFF_TOK_OP_ASGN2: {
            if (diff_is_ident_starter((unsigned char) lptr[0])) {
                char suffix = (llen > 1 && (lptr[llen - 1] == '?' || lptr[llen - 1] == '!' || lptr[llen - 1] == '='))
                    ? lptr[llen - 1]
                    : '\0';
                if (suffix != '\0') {
                    snprintf(dst, 97, "%s:<id>%c", tname, suffix);
                } else {
                    snprintf(dst, 97, "%s:<id>", tname);
                }
            } else {
                diff_format_tok_full(s, tok, dst);
            }
            return;
        }
        case DIFF_TOK_GVAR: {
            if (llen >= 2 && lptr[0] == '$') {
                unsigned char c1 = (unsigned char) lptr[1];
                if (diff_is_ident_starter(c1)) {
                    snprintf(dst, 97, "GVAR:$<id>");
                } else if (c1 >= '0' && c1 <= '9') {
                    snprintf(dst, 97, "GVAR:$<nth>");
                } else {
                    diff_format_tok_full(s, tok, dst);
                }
            } else {
                snprintf(dst, 97, "GVAR:<id>");
            }
            return;
        }
        case DIFF_TOK_ASGN:
        case DIFF_TOK_TARGET: {
            if (llen >= 2 && lptr[1] == ':') {
                snprintf(dst, 97, "%s:%c:<id>", tname, lptr[0]);
            } else {
                diff_format_tok_full(s, tok, dst);
            }
            return;
        }
        default:
            snprintf(dst, 97, "%s:<id>", tname);
            return;
    }
}

static void diff_format_tree_ctx(
    const diff_summary_t *s,
    const size_t *open_stack,
    size_t open_depth,
    char dst[64]
) {
    if (open_depth == 0) {
        snprintf(dst, 64, "ROOT");
        return;
    }

    diff_tree_tok_t top = s->tree.items[open_stack[open_depth - 1]];
    if ((diff_tok_tag_t) top.tag == DIFF_TOK_SLOT && open_depth >= 2) {
        size_t pidx = open_depth - 2;
        while (pidx > 0 && (diff_tok_tag_t) s->tree.items[open_stack[pidx]].tag == DIFF_TOK_SLOT) {
            pidx--;
        }
        diff_tree_tok_t parent = s->tree.items[open_stack[pidx]];
        const char *ptag = diff_tok_tag_name((diff_tok_tag_t) parent.tag);
        char slot_name[24];
        size_t slen = top.label.length < sizeof(slot_name) - 1 ? (size_t) top.label.length : sizeof(slot_name) - 1;
        for (size_t k = 0; k < slen; k++) {
            unsigned char ch = (unsigned char) s->strbuf.data[top.label.offset + k];
            slot_name[k] = ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_') ? (char) ch : '_';
        }
        slot_name[slen] = '\0';
        snprintf(dst, 64, "%s.%s", ptag, slot_name);
        return;
    }

    if ((diff_tok_tag_t) top.tag == DIFF_TOK_SCOPE && top.label.length > 0) {
        char sc_name[24];
        size_t slen = top.label.length < sizeof(sc_name) - 1 ? (size_t) top.label.length : sizeof(sc_name) - 1;
        memcpy(sc_name, s->strbuf.data + top.label.offset, slen);
        sc_name[slen] = '\0';
        snprintf(dst, 64, "SCOPE.%s", sc_name);
        return;
    }

    snprintf(dst, 64, "%s", diff_tok_tag_name((diff_tok_tag_t) top.tag));
}

static void diff_compare_tree(diff_summary_t *prism, diff_summary_t *cruby) {
    size_t plen = prism->tree.count;
    size_t clen = cruby->tree.count;
    size_t common = plen < clen ? plen : clen;
    size_t open_stack[256];
    size_t open_depth = 0;

    for (size_t i = 0; i < common; i++) {
        diff_tree_tok_t pt = prism->tree.items[i];
        diff_tree_tok_t ct = cruby->tree.items[i];
        if (pt.tag == ct.tag && diff_span_equal(prism->strbuf.data, pt.label, cruby->strbuf.data, ct.label)) {
            if ((diff_tok_tag_t) pt.tag == DIFF_TOK_CLOSE) {
                if (open_depth > 0) {
                    open_depth--;
                }
            } else if (open_depth < sizeof(open_stack) / sizeof(open_stack[0])) {
                open_stack[open_depth++] = i;
            }
            continue;
        }
        const char *sub = (pt.tag != ct.tag) ? "tag" : "label";
        const char *ptag = diff_tok_tag_name((diff_tok_tag_t) pt.tag);
        const char *ctag = diff_tok_tag_name((diff_tok_tag_t) ct.tag);
        char pfull[97];
        char cfull[97];
        char prev_tok[97];
        char ctx_buf[64];
        diff_format_tok_full(prism, pt, pfull);
        diff_format_tok_full(cruby, ct, cfull);
        diff_format_tree_ctx(prism, open_stack, open_depth, ctx_buf);
        if (i > 0) {
            diff_format_tok_full(prism, prism->tree.items[i - 1], prev_tok);
        } else {
            snprintf(prev_tok, sizeof(prev_tok), "START");
        }
        char phead_buf[97];
        char chead_buf[97];
        if (pt.tag != ct.tag) {
            snprintf(phead_buf, sizeof(phead_buf), "%s", ptag);
            snprintf(chead_buf, sizeof(chead_buf), "%s", ctag);
        } else {
            diff_format_tok_sig(prism, pt, phead_buf);
            diff_format_tok_sig(cruby, ct, chead_buf);
        }
        bool nested_preexe = prism->has_nested_preexe;
        diff_summary_free(prism);
        diff_summary_free(cruby);
        if (nested_preexe) {
            diff_invariant_fail(
                "INVARIANT[diff_parse_y]: kind=ast_preexe_order_mismatch sub=tree [detail: idx=%zu ctx=%s prev=%s prism_len=%zu cruby_len=%zu prism_tok=%s cruby_tok=%s]\n",
                i,
                ctx_buf,
                prev_tok,
                plen,
                clen,
                pfull,
                cfull
            );
        }
        diff_invariant_fail(
            "INVARIANT[diff_parse_y]: kind=ast_tree_mismatch sub=%s ctx=%s prism=%s cruby=%s [detail: idx=%zu prev=%s prism_len=%zu cruby_len=%zu prism_tok=%s cruby_tok=%s]\n",
            sub,
            ctx_buf,
            phead_buf,
            chead_buf,
            i,
            prev_tok,
            plen,
            clen,
            pfull,
            cfull
        );
    }

    if (plen != clen) {
        const char *phead = plen > clen ? diff_tok_tag_name((diff_tok_tag_t) prism->tree.items[common].tag) : "EOF";
        const char *chead = clen > plen ? diff_tok_tag_name((diff_tok_tag_t) cruby->tree.items[common].tag) : "EOF";
        char pfull[97];
        char cfull[97];
        char ctx_buf[64];
        diff_format_tree_ctx(prism, open_stack, open_depth, ctx_buf);
        if (plen > clen) {
            diff_format_tok_full(prism, prism->tree.items[common], pfull);
        } else {
            snprintf(pfull, sizeof(pfull), "EOF");
        }
        if (clen > plen) {
            diff_format_tok_full(cruby, cruby->tree.items[common], cfull);
        } else {
            snprintf(cfull, sizeof(cfull), "EOF");
        }
        bool nested_preexe = prism->has_nested_preexe;
        diff_summary_free(prism);
        diff_summary_free(cruby);
        if (nested_preexe) {
            diff_invariant_fail(
                "INVARIANT[diff_parse_y]: kind=ast_preexe_order_mismatch sub=tree_len [detail: idx=%zu ctx=%s prism_len=%zu cruby_len=%zu prism_tok=%s cruby_tok=%s]\n",
                common,
                ctx_buf,
                plen,
                clen,
                pfull,
                cfull
            );
        }
        diff_invariant_fail(
            "INVARIANT[diff_parse_y]: kind=ast_tree_mismatch sub=len ctx=%s prism=%s cruby=%s [detail: idx=%zu prism_len=%zu cruby_len=%zu prism_tok=%s cruby_tok=%s]\n",
            ctx_buf,
            phead,
            chead,
            common,
            plen,
            clen,
            pfull,
            cfull
        );
    }
}

void diff_compare_asts(diff_summary_t *prism, diff_summary_t *cruby) {
    size_t common_scopes = prism->scopes.count < cruby->scopes.count ? prism->scopes.count : cruby->scopes.count;
    for (size_t i = 0; i < common_scopes; i++) {
        if (prism->scopes.items[i].kind != cruby->scopes.items[i].kind) {
            const char *pk = diff_scope_kind_name((diff_scope_kind_t) prism->scopes.items[i].kind);
            const char *ck = diff_scope_kind_name((diff_scope_kind_t) cruby->scopes.items[i].kind);
            size_t pc = prism->scopes.count;
            size_t cc = cruby->scopes.count;
            diff_summary_free(prism);
            diff_summary_free(cruby);
            diff_invariant_fail(
                "INVARIANT[diff_parse_y]: kind=ast_scope_kind_mismatch prism=%s cruby=%s [detail: scope_idx=%zu prism_scopes=%zu cruby_scopes=%zu]\n",
                pk,
                ck,
                i,
                pc,
                cc
            );
        }
    }

    if (prism->scopes.count != cruby->scopes.count) {
        size_t pc = prism->scopes.count;
        size_t cc = cruby->scopes.count;
        diff_summary_free(prism);
        diff_summary_free(cruby);
        diff_invariant_fail(
            "INVARIANT[diff_parse_y]: kind=ast_scope_count_mismatch [detail: prism=%zu cruby=%zu]\n",
            pc,
            cc
        );
    }

    diff_compare_locals(prism, cruby);

    for (size_t k = 0; k < DIFF_CNT_LEN; k++) {
        if (prism->counts[k] != cruby->counts[k]) {
            size_t pc = prism->counts[k];
            size_t cc = cruby->counts[k];
            diff_summary_free(prism);
            diff_summary_free(cruby);
            diff_invariant_fail(
                "INVARIANT[diff_parse_y]: kind=ast_node_count_mismatch node=%s [detail: prism=%zu cruby=%zu]\n",
                diff_count_kind_name((diff_count_kind_t) k),
                pc,
                cc
            );
        }
    }

    size_t common_defs = prism->defs.count < cruby->defs.count ? prism->defs.count : cruby->defs.count;
    for (size_t i = 0; i < common_defs; i++) {
        diff_span_t ps = prism->defs.items[i];
        diff_span_t cs = cruby->defs.items[i];
        if (!diff_span_equal(prism->strbuf.data, ps, cruby->strbuf.data, cs)) {
            char pcopy[97];
            char ccopy[97];
            diff_copy_span(prism->strbuf.data, ps, pcopy);
            diff_copy_span(cruby->strbuf.data, cs, ccopy);
            diff_summary_free(prism);
            diff_summary_free(cruby);
            diff_invariant_fail(
                "INVARIANT[diff_parse_y]: kind=ast_def_name_mismatch [detail: idx=%zu prism=%s cruby=%s]\n",
                i,
                pcopy,
                ccopy
            );
        }
    }
    if (prism->defs.count != cruby->defs.count) {
        size_t pc = prism->defs.count;
        size_t cc = cruby->defs.count;
        diff_summary_free(prism);
        diff_summary_free(cruby);
        diff_invariant_fail(
            "INVARIANT[diff_parse_y]: kind=ast_node_count_mismatch node=def [detail: prism=%zu cruby=%zu]\n",
            pc,
            cc
        );
    }

    if (prism->block_owners.count != cruby->block_owners.count) {
        size_t pc = prism->block_owners.count;
        size_t cc = cruby->block_owners.count;
        diff_summary_free(prism);
        diff_summary_free(cruby);
        diff_invariant_fail(
            "INVARIANT[diff_parse_y]: kind=ast_block_owner_mismatch sub=count [detail: prism=%zu cruby=%zu]\n",
            pc,
            cc
        );
    }
    for (size_t i = 0; i < prism->block_owners.count; i++) {
        diff_span_t ps = prism->block_owners.items[i];
        diff_span_t cs = cruby->block_owners.items[i];
        if (!diff_span_equal(prism->strbuf.data, ps, cruby->strbuf.data, cs)) {
            char pcopy[97];
            char ccopy[97];
            size_t plen = diff_copy_span(prism->strbuf.data, ps, pcopy);
            size_t clen = diff_copy_span(cruby->strbuf.data, cs, ccopy);
            const char *sub = diff_block_mismatch_sub(pcopy, plen, ccopy, clen);
            bool nested_preexe = prism->has_nested_preexe;
            diff_summary_free(prism);
            diff_summary_free(cruby);
            if (nested_preexe) {
                diff_invariant_fail(
                    "INVARIANT[diff_parse_y]: kind=ast_preexe_order_mismatch sub=block_owner [detail: idx=%zu prism=%s cruby=%s]\n",
                    i,
                    pcopy,
                    ccopy
                );
            }
            diff_invariant_fail(
                "INVARIANT[diff_parse_y]: kind=ast_block_owner_mismatch sub=%s [detail: idx=%zu prism=%s cruby=%s]\n",
                sub,
                i,
                pcopy,
                ccopy
            );
        }
    }

    diff_compare_tree(prism, cruby);
}
