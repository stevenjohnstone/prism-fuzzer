#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE 1
#endif

#include <errno.h>
#if defined(__linux__) || defined(__APPLE__)
#include <execinfo.h>
#endif
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cruby_vm.h"

/* CRuby internal helpers in thread.c (not exposed in public ruby.h). */
extern void rb_thread_stop_timer_thread(void);

static VALUE diff_warning_warn(int argc, VALUE *argv, VALUE self) {
    (void) argc;
    (void) argv;
    (void) self;
    return Qnil;
}

static bool diff_starts_with(const char *s, const char *prefix) {
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

static void diff_sanitize_ident(const char *src, char *dst, size_t cap, const char *fallback) {
    if (cap == 0) return;
    size_t out = 0;
    if (src != NULL) {
        for (size_t i = 0; src[i] != '\0' && out + 1 < cap; i++) {
            char c = src[i];
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
                dst[out++] = c;
            }
        }
    }
    if (out == 0) {
        snprintf(dst, cap, "%s", fallback);
    } else {
        dst[out] = '\0';
    }
}

void diff_classify_cruby_msg(const char *cls, const char *line, char *tag_buf, size_t tag_cap) {
    /* RubyVM::InstructionSequence.compile prefixes diagnostics with "<compiled>:<line>: ". */
    if (diff_starts_with(line, "<compiled>:")) {
        const char *p = line + 11;
        if (*p >= '0' && *p <= '9') {
            while (*p >= '0' && *p <= '9') {
                p++;
            }
            if (p[0] == ':' && p[1] == ' ') {
                line = p + 2;
            }
        }
    }

    static const struct {
        const char *prefix;
        const char *tag;
    } prefix_tags[] = {
        { "unknown encoding name:",                        "unknown_encoding" },
        { "invalid multibyte char (UTF-8)",                "invalid_multibyte_utf8" },
        { "invalid multibyte char (US-ASCII)",             "invalid_multibyte_us_ascii" },
        { "invalid multibyte char",                        "invalid_multibyte" },
        { "string literal encodings differ",               "string_encodings_differ" },
        { "invalid symbol",                                "invalid_symbol" },
        { "premature end of char-class",                   "regexp_char_class" },
        { "invalid character property name",               "regexp_property" },
        { "invalid POSIX bracket type",                    "regexp_char_class" },
        { "char-class value at ",                          "regexp_char_class" },
        { "unmatched range specifier in char-class",       "regexp_char_class" },
        { "empty range in char class",                     "regexp_char_class" },
        { "mismatch multibyte code length in char-class range", "regexp_char_class" },
        { "too many multibyte code ranges",                "regexp_char_class" },
        { "empty char-class",                              "regexp_char_class" },
        { "invalid backref number",                        "regexp_backref" },
        { "too big backref number",                        "regexp_backref" },
        { "numbered backref/call is not allowed",          "regexp_backref" },
        { "too short escape sequence:",                    "regexp_escape" },
        { "invalid escape:",                               "regexp_escape" },
        { "invalid meta-code syntax",                      "regexp_escape" },
        { "invalid control-code syntax",                   "regexp_escape" },
        { "invalid code point value",                      "regexp_escape" },
        { "too long wide-char value",                      "regexp_escape" },
        { "too big wide-char value",                       "regexp_escape" },
        { "too short digits",                              "regexp_escape" },
        { "too short multibyte code string",               "regexp_escape" },
        { "end pattern",                                   "regexp_pattern" },
        { "unmatched close parenthesis",                   "regexp_pattern" },
        { "invalid conditional pattern",                   "regexp_pattern" },
        { "never ending recursion",                        "regexp_pattern" },
        { "parse depth limit over",                        "regexp_pattern" },
        { "too big compiled program",                      "regexp_pattern" },
        { "too many null check",                           "regexp_pattern" },
        { "target of repeat-operator",                     "regexp_repeat" },
        { "target of repeat operator",                     "regexp_repeat" },
        { "nested repeat operator",                        "regexp_repeat" },
        { "invalid repeat range",                          "regexp_repeat" },
        { "too big number",                                "regexp_repeat" },
        { "upper is smaller than lower in repeat range",   "regexp_repeat" },
        { "too many range repeat",                         "regexp_repeat" },
        { "invalid pattern in look-behind",                "regexp_lookbehind" },
        { "invalid group name",                            "regexp_group" },
        { "invalid char in group ",                        "regexp_group" },
        { "undefined name <",                              "regexp_group" },
        { "undefined group <",                             "regexp_group" },
        { "multiplex defined name <",                      "regexp_group" },
        { "multiplex definition name <",                   "regexp_group" },
        { "group name is empty",                           "regexp_group" },
        { "group number is too big",                       "regexp_group" },
        { "too many capture groups",                       "regexp_group" },
        { "undefined group option",                        "regexp_options" },
        { "invalid combination of options",                "regexp_options" },
        { "not supported encoding combination",            "regexp_options" },
        { "unterminated string meets end of file",         "unterminated_string" },
        { "unterminated regexp meets end of file",         "unterminated_regexp" },
        { "can't find string \"",                          "unterminated_heredoc" },
        { "embedded document meets end of file",           "unterminated_embdoc" },
        { "dynamic constant assignment",                   "dynamic_constant_assign" },
        { "formal argument cannot be",                     "invalid_formal_arg" },
        { "duplicated argument name",                      "duplicate_arg_name" },
        { "circular argument reference",                   "circular_arg_ref" },
        { "Invalid break",                                 "invalid_break" },
        { "Invalid next",                                  "invalid_next" },
        { "Invalid redo",                                  "invalid_redo" },
        { "Invalid retry",                                 "invalid_retry" },
        { "Invalid yield",                                 "invalid_yield" },
        { "numbered parameter",                            "numbered_param" },
        { "ordinary parameter is defined",                 "ordinary_param_conflict" },
        { "no .<digit> floating literal anymore",          "float_literal_method" },
        { "syntax error, unexpected 'do' for block",       "unexpected_do_block" },
        { "syntax error, unexpected '\\n'",                "unexpected_newline" }
    };

    for (size_t i = 0; i < sizeof(prefix_tags) / sizeof(prefix_tags[0]); i++) {
        if (diff_starts_with(line, prefix_tags[i].prefix)) {
            snprintf(tag_buf, tag_cap, "%s:%s", cls, prefix_tags[i].tag);
            return;
        }
    }

    if (diff_starts_with(line, "identifier ")) {
        if (strstr(line, " is not valid to get") != NULL) {
            snprintf(tag_buf, tag_cap, "%s:invalid_identifier_get", cls);
            return;
        }
        if (strstr(line, " is not valid to set") != NULL) {
            snprintf(tag_buf, tag_cap, "%s:invalid_identifier_set", cls);
            return;
        }
    }

    static const char unexpected_pfx[] = "syntax error, unexpected ";
    if (diff_starts_with(line, unexpected_pfx)) {
        const char *p = line + sizeof(unexpected_pfx) - 1;
        char tok[48];
        size_t len = 0;
        bool has_alnum = false;
        while (*p != '\0' && *p != ',' && len + 1 < sizeof(tok)) {
            unsigned char ch = (unsigned char) *p++;
            if (ch >= 'A' && ch <= 'Z') {
                tok[len++] = (char) (ch + ('a' - 'A'));
                has_alnum = true;
            } else if ((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')) {
                tok[len++] = (char) ch;
                has_alnum = true;
            } else if ((ch == ' ' || ch == '-' || ch == '_') && len > 0 && tok[len - 1] != '_') {
                tok[len++] = '_';
            }
        }
        while (len > 0 && tok[len - 1] == '_') {
            len--;
        }
        tok[len] = '\0';
        snprintf(tag_buf, tag_cap, "%s:unexpected_%s", cls, has_alnum ? tok : "punct");
        return;
    }

    if (strcmp(cls, "RegexpError") == 0 || strstr(line, ": /") != NULL) {
        snprintf(tag_buf, tag_cap, "%s:regexp_other", cls);
        return;
    }

    snprintf(tag_buf, tag_cap, "%s:other", cls);
}

static VALUE diff_rb_mAST = Qnil;
static ID diff_id_parse = 0;
static VALUE diff_rb_cISeq = Qnil;
static ID diff_id_compile = 0;
static ID diff_id_message = 0;

/* Pre-resolve RubyVM constants and IDs so persistent worker forks avoid lazy writes. */
static void diff_core_ids_init(void) {
    if (!NIL_P(diff_rb_mAST)) {
        return;
    }

    VALUE rb_cRubyVM = rb_const_get(rb_cObject, rb_intern("RubyVM"));
    diff_rb_mAST = rb_const_get(rb_cRubyVM, rb_intern("AbstractSyntaxTree"));
    rb_gc_register_mark_object(diff_rb_mAST);
    diff_id_parse = rb_intern("parse");

    diff_rb_cISeq = rb_const_get(rb_cRubyVM, rb_intern("InstructionSequence"));
    rb_gc_register_mark_object(diff_rb_cISeq);
    diff_id_compile = rb_intern("compile");

    diff_id_message = rb_intern("message");
}

static VALUE diff_ast_parse_cb(VALUE src_str) {
    diff_core_ids_init();
    return rb_funcall(diff_rb_mAST, diff_id_parse, 1, src_str);
}

static VALUE diff_iseq_compile_cb(VALUE src_str) {
    diff_core_ids_init();
    return rb_funcall(diff_rb_cISeq, diff_id_compile, 1, src_str);
}

static uint32_t diff_extract_compiled_line(const char *line) {
    if (!diff_starts_with(line, "<compiled>:")) {
        return 0;
    }
    const char *p = line + 11;
    if (*p < '0' || *p > '9') {
        return 0;
    }
    uint64_t val = 0;
    while (*p >= '0' && *p <= '9') {
        val = val * 10 + (uint64_t) (*p - '0');
        if (val > UINT32_MAX) {
            return UINT32_MAX;
        }
        p++;
    }
    return (p[0] == ':' && p[1] == ' ') ? (uint32_t) val : 0;
}

static void diff_format_exception(
    VALUE err,
    char *exc_buf,
    size_t exc_cap,
    char *tag_buf,
    size_t tag_cap,
    uint32_t *out_err_line
) {
    if (out_err_line != NULL) {
        *out_err_line = 0;
    }
    if (NIL_P(err)) {
        if (exc_cap > 0) snprintf(exc_buf, exc_cap, "nil");
        if (tag_cap > 0) snprintf(tag_buf, tag_cap, "nil");
        return;
    }

    char cls_buf[48];
    diff_sanitize_ident(rb_obj_classname(err), cls_buf, sizeof(cls_buf), "Exception");

    diff_core_ids_init();
    volatile VALUE msg = rb_funcall(err, diff_id_message, 0);
    const char *mptr = (RB_TYPE_P(msg, T_STRING) && RSTRING_LEN(msg) > 0) ? RSTRING_PTR(msg) : "";
    long mlen = RB_TYPE_P(msg, T_STRING) ? RSTRING_LEN(msg) : 0;

    char line[128];
    long line_len = 0;
    while (line_len < mlen && line_len < (long) (sizeof(line) - 1) &&
           mptr[line_len] != '\n' && mptr[line_len] != '\r') {
        line[line_len] = (mptr[line_len] != '\0') ? mptr[line_len] : ' ';
        line_len++;
    }
    line[line_len] = '\0';

    if (out_err_line != NULL) {
        *out_err_line = diff_extract_compiled_line(line);
    }
    if (exc_cap > 0) {
        int detail_len = (int) (line_len > 96 ? 96 : line_len);
        snprintf(exc_buf, exc_cap, "%s: %.*s", cls_buf, detail_len, line);
    }
    if (tag_cap > 0) {
        diff_classify_cruby_msg(cls_buf, line, tag_buf, tag_cap);
    }
    RB_GC_GUARD(msg);
}

static VALUE diff_run_cruby_callback(
    VALUE (*cb)(VALUE),
    const char *source,
    size_t size,
    bool *out_ok,
    char *exc_buf,
    size_t exc_cap,
    char *tag_buf,
    size_t tag_cap,
    uint32_t *out_err_line
) {
    if (out_err_line != NULL) {
        *out_err_line = 0;
    }
    if (size > (size_t) LONG_MAX) {
        abort();
    }
    volatile VALUE src_str = rb_utf8_str_new(source != NULL ? source : "", (long) size);
    int state = 0;
    volatile VALUE res = rb_protect(cb, src_str, &state);
    if (state != 0) {
        VALUE err = rb_errinfo();
        rb_set_errinfo(Qnil);
        *out_ok = false;
        diff_format_exception(err, exc_buf, exc_cap, tag_buf, tag_cap, out_err_line);
        RB_GC_GUARD(src_str);
        return Qnil;
    }

    *out_ok = true;
    if (exc_cap > 0) exc_buf[0] = '\0';
    if (tag_cap > 0) snprintf(tag_buf, tag_cap, "ok");
    RB_GC_GUARD(src_str);
    return res;
}

VALUE diff_run_cruby(
    const char *source,
    size_t size,
    bool *out_ok,
    char *exc_buf,
    size_t exc_cap,
    char *tag_buf,
    size_t tag_cap,
    uint32_t *out_err_line
) {
    return diff_run_cruby_callback(diff_ast_parse_cb, source, size, out_ok, exc_buf, exc_cap, tag_buf, tag_cap, out_err_line);
}

void diff_run_cruby_compile(
    const char *source,
    size_t size,
    bool *out_ok,
    char *exc_buf,
    size_t exc_cap,
    char *tag_buf,
    size_t tag_cap,
    uint32_t *out_err_line
) {
    volatile VALUE iseq = diff_run_cruby_callback(diff_iseq_compile_cb, source, size, out_ok, exc_buf, exc_cap, tag_buf, tag_cap, out_err_line);
    RB_GC_GUARD(iseq);
}

static bool diff_is_encoding_related_mismatch(
    const char *prism_enc,
    const char *prism_diag,
    const char *cruby_tag
) {
    if (prism_enc != NULL && prism_enc[0] != '\0' && strcmp(prism_enc, "UTF-8") != 0 && strcmp(prism_enc, "UTF_8") != 0) {
        return true;
    }
    if (prism_diag != NULL && (
        strstr(prism_diag, "encoding") != NULL ||
        strstr(prism_diag, "multibyte") != NULL ||
        strstr(prism_diag, "invalid_symbol") != NULL ||
        strstr(prism_diag, "unicode") != NULL)) {
        return true;
    }
    if (cruby_tag != NULL && (
        strstr(cruby_tag, "encoding") != NULL ||
        strstr(cruby_tag, "multibyte") != NULL ||
        strstr(cruby_tag, "invalid_symbol") != NULL)) {
        return true;
    }
    return false;
}

void diff_fail_syntax_mismatch(
    const uint8_t *source,
    size_t source_size,
    bool prism_ok,
    size_t prism_errs,
    const char *prism_diag,
    const char *prism_enc,
    const char *ast_ctx,
    bool cruby_ok,
    const char *cruby_tag,
    const char *exc_buf
) {
    const char *sub = prism_ok ? "prism_ok_cruby_err" : "prism_err_cruby_ok";
    int has_nul = diff_has_nul(source, source_size) ? 1 : 0;
    int valid_utf8 = diff_is_valid_utf8(source, source_size) ? 1 : 0;
    const char *enc = (prism_enc != NULL && prism_enc[0] != '\0') ? prism_enc : "UTF-8";
    const char *ctx = (ast_ctx != NULL && ast_ctx[0] != '\0') ? ast_ctx : "program";

    if (diff_is_encoding_related_mismatch(enc, prism_diag, cruby_tag)) {
        diff_invariant_fail(
            "INVARIANT[diff_parse_y]: kind=syntax_mismatch sub=%s enc=%s ctx=%s prism=%s cruby=%s [detail: nul=%d utf8=%d prism_errs=%zu cruby=%s]\n",
            sub,
            enc,
            ctx,
            prism_diag,
            cruby_ok ? "ok" : cruby_tag,
            has_nul,
            valid_utf8,
            prism_errs,
            cruby_ok ? "ok" : exc_buf
        );
    }

    diff_invariant_fail(
        "INVARIANT[diff_parse_y]: kind=syntax_mismatch sub=%s ctx=%s prism=%s cruby=%s [detail: enc=%s nul=%d utf8=%d prism_errs=%zu cruby=%s]\n",
        sub,
        ctx,
        prism_diag,
        cruby_ok ? "ok" : cruby_tag,
        enc,
        has_nul,
        valid_utf8,
        prism_errs,
        cruby_ok ? "ok" : exc_buf
    );
}

int diff_oracle_initialized = 0;
static volatile sig_atomic_t diff_print_backtrace_enabled = 1;

#if defined(__SANITIZE_ADDRESS__) || (defined(__has_feature) && __has_feature(address_sanitizer))
#define DIFF_ASAN_ACTIVE 1
#else
#define DIFF_ASAN_ACTIVE 0
#endif

static const int diff_crash_signals[] = { SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGTRAP, SIGPIPE };
#if DIFF_ASAN_ACTIVE
/* Keep ASan's SA_ONSTACK deadly-signal handler on SIGSEGV/SIGBUS/SIGFPE so stack
 * overflows emit AddressSanitizer diagnostics instead of double-faulting. */
static const int diff_fatal_signals[] = { SIGILL, SIGTRAP };
#else
static const int diff_fatal_signals[] = { SIGSEGV, SIGBUS, SIGILL, SIGTRAP, SIGFPE };
static uint8_t diff_signal_altstack[65536];
#endif
#define DIFF_CRASH_SIGNAL_COUNT (sizeof(diff_crash_signals) / sizeof(diff_crash_signals[0]))

static void diff_write_stderr_str(const char *s, size_t len) {
    while (len > 0) {
        ssize_t written = write(STDERR_FILENO, s, len);
        if (written <= 0) {
            if (written < 0 && errno == EINTR) {
                continue;
            }
            break;
        }
        s += written;
        len -= (size_t) written;
    }
}

static void diff_fatal_signal_handler(int sig) {
    const char *msg = "CRASH[diff_parse_y]: signal=SIGNAL\n";
    switch (sig) {
        case SIGSEGV: msg = "CRASH[diff_parse_y]: signal=SIGSEGV (11)\n"; break;
        case SIGBUS:  msg = "CRASH[diff_parse_y]: signal=SIGBUS (7)\n"; break;
        case SIGILL:  msg = "CRASH[diff_parse_y]: signal=SIGILL (4)\n"; break;
        case SIGTRAP: msg = "CRASH[diff_parse_y]: signal=SIGTRAP (5)\n"; break;
        case SIGFPE:  msg = "CRASH[diff_parse_y]: signal=SIGFPE (8)\n"; break;
        default:      break;
    }
    size_t msg_len = 0;
    while (msg[msg_len] != '\0') {
        msg_len++;
    }
    diff_write_stderr_str(msg, msg_len);
    if (diff_print_backtrace_enabled) {
#if defined(__linux__) || defined(__APPLE__)
        void *frames[64];
        int nframes = backtrace(frames, (int) (sizeof(frames) / sizeof(frames[0])));
        if (nframes > 0) {
            backtrace_symbols_fd(frames, nframes, STDERR_FILENO);
        }
#endif
    }
    sigset_t unblock;
    sigemptyset(&unblock);
    sigaddset(&unblock, sig);
    sigprocmask(SIG_UNBLOCK, &unblock, NULL);
    raise(sig);
    _exit(128 + sig);
}

static void diff_snapshot_signals(struct sigaction saved[DIFF_CRASH_SIGNAL_COUNT]) {
    for (size_t i = 0; i < DIFF_CRASH_SIGNAL_COUNT; i++) {
        sigaction(diff_crash_signals[i], NULL, &saved[i]);
    }
}

static void diff_restore_signals(const struct sigaction saved[DIFF_CRASH_SIGNAL_COUNT]) {
    for (size_t i = 0; i < DIFF_CRASH_SIGNAL_COUNT; i++) {
        sigaction(diff_crash_signals[i], &saved[i], NULL);
    }
}

static void diff_install_fatal_signal_handlers(void) {
#if !DIFF_ASAN_ACTIVE
    stack_t cur_ss;
    memset(&cur_ss, 0, sizeof(cur_ss));
    if (sigaltstack(NULL, &cur_ss) == 0 && (cur_ss.ss_flags & SS_DISABLE) != 0) {
        stack_t ss;
        memset(&ss, 0, sizeof(ss));
        ss.ss_sp = diff_signal_altstack;
        ss.ss_size = sizeof(diff_signal_altstack);
        ss.ss_flags = 0;
        (void) sigaltstack(&ss, NULL);
    }
#endif
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = diff_fatal_signal_handler;
    sigemptyset(&sa.sa_mask);
    /* Reset to SIG_DFL and unmask on delivery so raise(sig) kills with WTERMSIG == sig. */
    sa.sa_flags = SA_RESETHAND | SA_NODEFER | SA_ONSTACK;
    for (size_t i = 0; i < sizeof(diff_fatal_signals) / sizeof(diff_fatal_signals[0]); i++) {
        sigaction(diff_fatal_signals[i], &sa, NULL);
    }
}

void diff_oracle_init_with_stack(void *stack_top) {
    if (diff_oracle_initialized) {
        return;
    }

    const char *bt_env = getenv("FUZZ_DIFF_BACKTRACE");
    diff_print_backtrace_enabled = (bt_env != NULL && strcmp(bt_env, "0") == 0) ? 0 : 1;

    struct sigaction saved[DIFF_CRASH_SIGNAL_COUNT];
    diff_snapshot_signals(saved);

    if (stack_top != NULL) {
        ruby_init_stack(stack_top);
    } else {
        RUBY_INIT_STACK;
    }
    if (ruby_setup() != 0) {
        fprintf(stderr, "fuzz.diff: ruby_setup() failed\n");
        abort();
    }

    // Boot Ruby prelude once (without running user code) so RubyVM::AbstractSyntaxTree.parse is loaded.
    char *opts[] = {
        (char *) "ruby",
        (char *) "--disable=gems",
        (char *) "--parser=parse.y",
        (char *) "-e",
        (char *) ""
    };
    (void) ruby_options(5, opts);

    diff_restore_signals(saved);
    diff_install_fatal_signal_handlers();
#if defined(__linux__) || defined(__APPLE__)
    if (diff_print_backtrace_enabled) {
        void *warmup_frames[2];
        (void) backtrace(warmup_frames, 2);
    }
#endif

    VALUE warning_mod = rb_const_get(rb_cObject, rb_intern("Warning"));
    rb_define_singleton_method(warning_mod, "warn", diff_warning_warn, -1);

    diff_core_ids_init();
    diff_ast_ids_init();

    rb_thread_stop_timer_thread();
    diff_oracle_initialized = 1;
}

void diff_oracle_init(void) {
    volatile VALUE stack_top = Qnil;
    diff_oracle_init_with_stack((void *) &stack_top);
}
