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
#include <sys/stat.h>
#include <unistd.h>

#include <ruby.h>
#include <ruby/version.h>

#ifndef FUZZ_MAX_INPUT_SIZE
#define FUZZ_MAX_INPUT_SIZE 1024
#endif

#ifndef FUZZ_COMPILE_PERSISTENT_ITERS
#define FUZZ_COMPILE_PERSISTENT_ITERS 1000
#endif

#ifdef FUZZ_CRUBY_PIPELINE_DIFF
#define FUZZ_COMPILE_NAMESPACE "cruby_pipeline"
#define FUZZ_COMPILE_BIN_LABEL "fuzz.pipeline"
#else
#define FUZZ_COMPILE_NAMESPACE "cruby_compile"
#define FUZZ_COMPILE_BIN_LABEL "fuzz.compile"
#endif

#define FUZZ_STR_HELPER(x) #x
#define FUZZ_STR(x) FUZZ_STR_HELPER(x)

#ifndef FUZZ_GIT_COMMIT
#define FUZZ_GIT_COMMIT unknown
#endif

#ifndef FUZZ_GIT_DIRTY
#define FUZZ_GIT_DIRTY unknown
#endif

#ifndef FUZZ_RUBY_VERSION
#define FUZZ_RUBY_VERSION "unknown"
#endif

#ifndef FUZZ_RUBY_REVISION
#define FUZZ_RUBY_REVISION "unknown"
#endif

#ifndef FUZZ_RUBY_RELEASE_DATE
#define FUZZ_RUBY_RELEASE_DATE "unknown"
#endif

#if defined(__has_attribute)
#  if __has_attribute(retain)
#    define FUZZ_PROVENANCE_ATTR __attribute__((used, retain))
#  else
#    define FUZZ_PROVENANCE_ATTR __attribute__((used))
#  endif
#else
#  define FUZZ_PROVENANCE_ATTR __attribute__((used))
#endif

static const char compile_fuzz_provenance[] FUZZ_PROVENANCE_ATTR =
    "@(#)PRISM_FUZZ_PROVENANCE\tgit_commit=" FUZZ_STR(FUZZ_GIT_COMMIT)
    "\tgit_dirty=" FUZZ_STR(FUZZ_GIT_DIRTY)
    "\truby_version=" FUZZ_RUBY_VERSION
    "\truby_revision=" FUZZ_RUBY_REVISION
    "\truby_release_date=" FUZZ_RUBY_RELEASE_DATE
    "\n";

/* CRuby internal helpers in thread.c and bundled Prism serialize.c. */
extern void rb_thread_stop_timer_thread(void);
extern bool pm_serialize_parse_success_p(const uint8_t *source, size_t size, const char *data);

#ifdef PRISM_FUZZ_IJON
#ifndef _USE_IJON
extern void ijon_set(uint32_t addr, uint32_t val);
extern uint32_t ijon_hashstr(uint32_t old, const char *val);
#endif

static inline uint32_t compile_ijon_mix32(uint32_t h) {
    h ^= h >> 16;
    h *= 0x85ebca6bu;
    h ^= h >> 13;
    h *= 0xc2b2ae35u;
    h ^= h >> 16;
    return h;
}

static inline void compile_ijon_record(uint32_t salt, uint32_t val) {
    static uint32_t base_hash = 0;
    if (base_hash == 0) {
        base_hash = ijon_hashstr(101u, (char *) "cruby_compile.c");
        if (base_hash == 0) base_hash = 1u;
    }
    uint32_t h = base_hash ^ salt;
    if (h == 0) h = 1u;
    ijon_set(h, compile_ijon_mix32(h ^ val) & 0xfffu);
}
#endif

#define COMPILE_OPT_COMBOS 64

static int g_compile_initialized = 0;
static volatile sig_atomic_t g_print_backtrace_enabled = 1;

#ifdef FUZZ_WRAP_RB_VM_BUGREPORT
extern bool __real_rb_vm_bugreport(const void *ctx, FILE *errout);

/* Skip CRuby's ~400ms DWARF addr2line walk inside rb_vm_bugreport when running
 * under afl-fuzz (FUZZ_DIFF_BACKTRACE=0) so rb_bug / RUBY_ASSERT aborts in <1ms
 * instead of tripping AFL++'s hang timeout; triage/CLI runs keep full traces. */
__attribute__((visibility("default")))
bool __wrap_rb_vm_bugreport(const void *ctx, FILE *errout) {
    if (!g_print_backtrace_enabled) {
        return true;
    }
    return __real_rb_vm_bugreport(ctx, errout);
}
#endif

static VALUE g_rb_mAST = Qnil;
static VALUE g_rb_cISeq = Qnil;
#ifdef FUZZ_CRUBY_PIPELINE_DIFF
static VALUE g_rb_mPrism = Qnil;
static ID g_id_parse_success_p = 0;
#endif
static VALUE g_compiled_label = Qnil;
static ID g_id_parse = 0;
static ID g_id_compile_prism = 0;
static ID g_id_compile_parsey = 0;
static ID g_id_message = 0;
static VALUE g_compile_opts[COMPILE_OPT_COMBOS];

static VALUE compile_warning_warn(int argc, VALUE *argv, VALUE self) {
    (void) argc;
    (void) argv;
    (void) self;
    return Qnil;
}

static VALUE compile_build_opt_hash(unsigned int mask) {
    VALUE h = rb_hash_new();
    rb_hash_aset(h, ID2SYM(rb_intern("peephole_optimization")), (mask & 0x01u) ? Qfalse : Qtrue);
    rb_hash_aset(h, ID2SYM(rb_intern("tailcall_optimization")), (mask & 0x02u) ? Qtrue : Qfalse);
    rb_hash_aset(h, ID2SYM(rb_intern("specialized_instruction")), (mask & 0x04u) ? Qfalse : Qtrue);
    rb_hash_aset(h, ID2SYM(rb_intern("operands_unification")), (mask & 0x08u) ? Qfalse : Qtrue);
    rb_hash_aset(h, ID2SYM(rb_intern("frozen_string_literal")), (mask & 0x10u) ? Qtrue : Qfalse);
    rb_hash_aset(h, ID2SYM(rb_intern("debug_frozen_string_literal")), (mask & 0x20u) ? Qtrue : Qfalse);
    RB_OBJ_FREEZE(h);
    rb_gc_register_mark_object(h);
    return h;
}

static void compile_core_ids_init(void) {
    if (!NIL_P(g_rb_cISeq)) {
        return;
    }

    VALUE rb_cRubyVM = rb_const_get(rb_cObject, rb_intern("RubyVM"));
    g_rb_mAST = rb_const_get(rb_cRubyVM, rb_intern("AbstractSyntaxTree"));
    rb_gc_register_mark_object(g_rb_mAST);
    g_id_parse = rb_intern("parse");

    g_rb_cISeq = rb_const_get(rb_cRubyVM, rb_intern("InstructionSequence"));
    rb_gc_register_mark_object(g_rb_cISeq);
    g_id_compile_prism = rb_intern("compile_prism");
    g_id_compile_parsey = rb_intern("compile_parsey");
    g_id_message = rb_intern("message");

#ifdef FUZZ_CRUBY_PIPELINE_DIFF
    /* Load CRuby's statically registered built-in Prism extension in-memory
     * (registered by Init_Prism() during ruby_setup) without needing ruby/prism.rb. */
    VALUE rb_mRuby = rb_define_module("Ruby");
    g_rb_mPrism = rb_define_module_under(rb_mRuby, "Prism");
    rb_define_class_under(g_rb_mPrism, "CurrentVersionError", rb_eArgError);
    rb_require("ruby/prism/prism.so");
    rb_gc_register_mark_object(g_rb_mPrism);
    g_id_parse_success_p = rb_intern("parse_success?");
#endif

    g_compiled_label = rb_utf8_str_new_lit("<compiled>");
    RB_OBJ_FREEZE(g_compiled_label);
    rb_gc_register_mark_object(g_compiled_label);

    for (unsigned int mask = 0; mask < COMPILE_OPT_COMBOS; mask++) {
        g_compile_opts[mask] = compile_build_opt_hash(mask);
    }
}

#if defined(__SANITIZE_ADDRESS__) || (defined(__has_feature) && __has_feature(address_sanitizer))
#define COMPILE_ASAN_ACTIVE 1
/* libruby-static.a's gc.c is built without ASan, so Ruby GC object slots are
 * never poisoned by GC. Provide weak no-op shims for ASan-instrumented iseq.c
 * calls to rb_asan_*_object; if libruby-static.a is ever built with ASan, its
 * strong definitions in gc.c take precedence. */
__attribute__((weak)) void rb_asan_poison_object(VALUE obj) {
    (void) obj;
}
__attribute__((weak)) void *rb_asan_poisoned_object_p(VALUE obj) {
    (void) obj;
    return NULL;
}
__attribute__((weak)) void rb_asan_unpoison_object(VALUE obj, bool newobj_p) {
    (void) obj;
    (void) newobj_p;
}
#else
#define COMPILE_ASAN_ACTIVE 0
#endif

static const int compile_crash_signals[] = { SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGTRAP, SIGPIPE };
#if COMPILE_ASAN_ACTIVE
static const int compile_fatal_signals[] = { SIGILL, SIGTRAP };
#else
static const int compile_fatal_signals[] = { SIGSEGV, SIGBUS, SIGILL, SIGTRAP, SIGFPE };
static uint8_t compile_signal_altstack[65536];
#endif
#define COMPILE_CRASH_SIGNAL_COUNT (sizeof(compile_crash_signals) / sizeof(compile_crash_signals[0]))

static void compile_write_stderr_str(const char *s, size_t len) {
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

static void compile_fatal_signal_handler(int sig) {
    const char *msg = "CRASH[" FUZZ_COMPILE_NAMESPACE "]: signal=SIGNAL\n";
    switch (sig) {
        case SIGSEGV: msg = "CRASH[" FUZZ_COMPILE_NAMESPACE "]: signal=SIGSEGV (11)\n"; break;
        case SIGBUS:  msg = "CRASH[" FUZZ_COMPILE_NAMESPACE "]: signal=SIGBUS (7)\n"; break;
        case SIGILL:  msg = "CRASH[" FUZZ_COMPILE_NAMESPACE "]: signal=SIGILL (4)\n"; break;
        case SIGTRAP: msg = "CRASH[" FUZZ_COMPILE_NAMESPACE "]: signal=SIGTRAP (5)\n"; break;
        case SIGFPE:  msg = "CRASH[" FUZZ_COMPILE_NAMESPACE "]: signal=SIGFPE (8)\n"; break;
        default:      break;
    }
    size_t msg_len = 0;
    while (msg[msg_len] != '\0') {
        msg_len++;
    }
    compile_write_stderr_str(msg, msg_len);
    if (g_print_backtrace_enabled) {
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

static void compile_snapshot_signals(struct sigaction saved[COMPILE_CRASH_SIGNAL_COUNT]) {
    for (size_t i = 0; i < COMPILE_CRASH_SIGNAL_COUNT; i++) {
        sigaction(compile_crash_signals[i], NULL, &saved[i]);
    }
}

static void compile_restore_signals(const struct sigaction saved[COMPILE_CRASH_SIGNAL_COUNT]) {
    for (size_t i = 0; i < COMPILE_CRASH_SIGNAL_COUNT; i++) {
        sigaction(compile_crash_signals[i], &saved[i], NULL);
    }
}

static void compile_install_fatal_signal_handlers(void) {
#if !COMPILE_ASAN_ACTIVE
    stack_t cur_ss;
    memset(&cur_ss, 0, sizeof(cur_ss));
    if (sigaltstack(NULL, &cur_ss) == 0 && (cur_ss.ss_flags & SS_DISABLE) != 0) {
        stack_t ss;
        memset(&ss, 0, sizeof(ss));
        ss.ss_sp = compile_signal_altstack;
        ss.ss_size = sizeof(compile_signal_altstack);
        ss.ss_flags = 0;
        (void) sigaltstack(&ss, NULL);
    }
#endif
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = compile_fatal_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESETHAND | SA_NODEFER | SA_ONSTACK;
    for (size_t i = 0; i < sizeof(compile_fatal_signals) / sizeof(compile_fatal_signals[0]); i++) {
        sigaction(compile_fatal_signals[i], &sa, NULL);
    }
}

static void compile_oracle_init_with_stack(void *stack_top) {
    if (g_compile_initialized) {
        return;
    }

    const char *bt_env = getenv("FUZZ_DIFF_BACKTRACE");
    g_print_backtrace_enabled = (bt_env != NULL && strcmp(bt_env, "0") == 0) ? 0 : 1;

    struct sigaction saved[COMPILE_CRASH_SIGNAL_COUNT];
    compile_snapshot_signals(saved);

    if (stack_top != NULL) {
        ruby_init_stack(stack_top);
    } else {
        RUBY_INIT_STACK;
    }
    if (ruby_setup() != 0) {
        fprintf(stderr, FUZZ_COMPILE_BIN_LABEL ": ruby_setup() failed\n");
        abort();
    }

    char *opts[] = {
        (char *) "ruby",
        (char *) "--disable=gems",
        (char *) "--parser=parse.y",
        (char *) "-e",
        (char *) ""
    };
    (void) ruby_options(5, opts);

    compile_restore_signals(saved);
    compile_install_fatal_signal_handlers();
#if defined(__linux__) || defined(__APPLE__)
    if (g_print_backtrace_enabled) {
        void *warmup_frames[2];
        (void) backtrace(warmup_frames, 2);
    }
#endif

    VALUE warning_mod = rb_const_get(rb_cObject, rb_intern("Warning"));
    rb_define_singleton_method(warning_mod, "warn", compile_warning_warn, -1);

    compile_core_ids_init();
    rb_thread_stop_timer_thread();
    const char *disable_gc = getenv("FUZZ_DISABLE_GC");
    if (disable_gc != NULL && disable_gc[0] != '\0' && strcmp(disable_gc, "0") != 0) {
        (void) rb_gc_disable();
    }
    g_compile_initialized = 1;
}

typedef struct {
    ID method_id;
    VALUE src_str;
    VALUE opt_hash;
} compile_call_arg_t;

static VALUE compile_ast_parse_cb(VALUE src_str) {
    return rb_funcall(g_rb_mAST, g_id_parse, 1, src_str);
}

#ifdef FUZZ_CRUBY_PIPELINE_DIFF
static VALUE compile_prism_parse_cb(VALUE src_str) {
    return rb_funcall(g_rb_mPrism, g_id_parse_success_p, 1, src_str);
}

static bool compile_prism_accepts(VALUE src_str) {
    int state = 0;
    volatile VALUE res = rb_protect(compile_prism_parse_cb, src_str, &state);
    if (state != 0) {
        rb_set_errinfo(Qnil);
        return false;
    }
    return RTEST(res);
}
#endif

static VALUE compile_iseq_cb(VALUE raw_arg) {
    const compile_call_arg_t *arg = (const compile_call_arg_t *) raw_arg;
    VALUE argv[5] = {
        arg->src_str,
        g_compiled_label,
        g_compiled_label,
        INT2FIX(1),
        arg->opt_hash
    };
    return rb_funcallv(g_rb_cISeq, arg->method_id, 5, argv);
}

/* Detects internal CRuby compiler / bytecode verifier COMPILE_ERRORs in
 * fix_sp_depth / iseq_set_sequence / compile.c / prism_compile.c that CRuby
 * surfaces as SyntaxError exceptions instead of rb_bug(). */
static const char *compile_detect_internal_verifier_bug(const char *msg) {
    if (msg == NULL || msg[0] == '\0') {
        return NULL;
    }
    static const struct {
        const char *needle;
        const char *tag;
    } checks[] = {
        { "argument stack underflow (",                   "stack_underflow" },
        { "operand size miss! (",                         "operand_size_miss" },
        { "unknown label: ",                              "unknown_label" },
        { "iseq_set_sequence: adjust bug",                "adjust_bug" },
        { "unknown list type: ",                          "unknown_list_type" },
        { "iseq_set_sequence: ic_index overflow:",        "ic_index_overflow" },
        { ": unknown node (",                             "unexpected_node" },
        { "unexpected node",                              "unexpected_node" },
        { "NODE_DASGN: unknown id",                       "unexpected_node" },
        { "unknown scope: ",                              "unreachable_scope" },
        { "should not be reached",                        "unreachable_scope" },
        { "local_self! called but 'self' not found",      "missing_local_self" },
        { "can't find builtin function:",                 "builtin_mismatch" },
        { "argc is not match for builtin function:",      "builtin_mismatch" }
    };
    for (size_t i = 0; i < sizeof(checks) / sizeof(checks[0]); i++) {
        if (strstr(msg, checks[i].needle) != NULL) {
            return checks[i].tag;
        }
    }
    return NULL;
}

static void compile_classify_exc_tag(const char *cls, const char *msg, char *tag_buf, size_t tag_cap) {
    if (tag_cap == 0) return;
    static const struct {
        const char *needle;
        const char *tag;
    } tags[] = {
        { "Invalid break",                                "invalid_break" },
        { "Can't escape from eval with break",            "invalid_break" },
        { "Invalid next",                                 "invalid_next" },
        { "Can't escape from eval with next",             "invalid_next" },
        { "Invalid redo",                                 "invalid_redo" },
        { "Can't escape from eval with redo",             "invalid_redo" },
        { "Invalid retry",                                "invalid_retry" },
        { "Invalid yield",                                "invalid_yield" },
        { "can not yield from isolated Proc",             "isolated_proc_yield" },
        { "can not access variable",                      "isolated_proc_var" },
        { "too many keyword parameters",                  "too_many_kw_params" },
        { "too many keyword arguments",                   "too_many_kw_args" },
        { "illegal variable in alternative pattern",      "alt_pattern_var" },
        { "dynamic constant assignment",                  "dynamic_constant_assign" },
        { "duplicated argument name",                     "duplicate_arg_name" },
        { "circular argument reference",                  "circular_arg_ref" },
        { "numbered parameter",                           "numbered_param" },
        { "ordinary parameter is defined",                "ordinary_param_conflict" },
        { "invalid multibyte char",                       "invalid_multibyte" },
        { "unknown encoding name",                        "unknown_encoding" },
        { "string literal encodings differ",              "string_encodings_differ" }
    };
    for (size_t i = 0; i < sizeof(tags) / sizeof(tags[0]); i++) {
        if (strstr(msg, tags[i].needle) != NULL) {
            snprintf(tag_buf, tag_cap, "%s", tags[i].tag);
            return;
        }
    }
    const char *unexp = strstr(msg, "syntax error, unexpected ");
    if (unexp != NULL) {
        const char *p = unexp + sizeof("syntax error, unexpected ") - 1;
        char tok[32];
        size_t len = 0;
        bool has_alnum = false;
        while (*p != '\0' && *p != ',' && *p != ';' && *p != '\n' && len + 1 < sizeof(tok)) {
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
        snprintf(tag_buf, tag_cap, "unexpected_%s", has_alnum ? tok : "punct");
        return;
    }
    snprintf(tag_buf, tag_cap, "%s_other", (cls && cls[0] != '\0') ? cls : "Exception");
}

/* Extracts up to 220 sanitized bytes of exception text (handling multi-line
 * Prism and CRuby diagnostics where the specific message follows `> 1 | ...`)
 * and returns any internal bytecode-verifier bug tag. */
static const char *compile_extract_exception(
    VALUE err,
    char *tag_buf,
    size_t tag_cap,
    char *msg_buf,
    size_t msg_cap
) {
    if (NIL_P(err)) {
        if (tag_cap > 0) snprintf(tag_buf, tag_cap, "nil");
        if (msg_cap > 0) snprintf(msg_buf, msg_cap, "nil");
        return NULL;
    }
    const char *cls = rb_obj_classname(err);
    volatile VALUE msg = rb_funcall(err, g_id_message, 0);
    const char *mptr = (RB_TYPE_P(msg, T_STRING) && RSTRING_LEN(msg) > 0) ? RSTRING_PTR(msg) : "";
    long mlen = RB_TYPE_P(msg, T_STRING) ? RSTRING_LEN(msg) : 0;

    char flat[256];
    size_t n = 0;
    for (long i = 0; i < mlen && n + 1 < sizeof(flat); i++) {
        char c = mptr[i];
        if (c == '\n' || c == '\r' || c == '\t') {
            if (n > 0 && flat[n - 1] != ' ') flat[n++] = ' ';
        } else if (c != '\0' && c != ']') {
            flat[n++] = c;
        }
    }
    flat[n] = '\0';
    RB_GC_GUARD(msg);

    const char *bug_tag = compile_detect_internal_verifier_bug(flat);
    if (tag_cap > 0) {
        compile_classify_exc_tag(cls, flat, tag_buf, tag_cap);
    }
    if (msg_cap > 0) {
        size_t clip = n > 110 ? 110 : n;
        snprintf(msg_buf, msg_cap, "%s:%.*s", cls ? cls : "Exception", (int) clip, flat);
    }
    return bug_tag;
}

static bool compile_parse_y_accepts(
    VALUE src_str,
    char *tag_buf,
    size_t tag_cap,
    char *msg_buf,
    size_t msg_cap
) {
    int state = 0;
    volatile VALUE ast = rb_protect(compile_ast_parse_cb, src_str, &state);
    if (state != 0) {
        VALUE err = rb_errinfo();
        rb_set_errinfo(Qnil);
        /* RubyVM::AbstractSyntaxTree.parse (ast.c) raises RuntimeError on valid
         * parse.y NODE_ITER(NODE_DASGN) after parse.y already succeeded. */
        if (!NIL_P(err) && !RTEST(rb_obj_is_kind_of(err, rb_eSyntaxError))) {
            if (tag_cap > 0) snprintf(tag_buf, tag_cap, "ok");
            if (msg_cap > 0) snprintf(msg_buf, msg_cap, "ok");
            return true;
        }
        (void) compile_extract_exception(err, tag_buf, tag_cap, msg_buf, msg_cap);
        return false;
    }
    if (tag_cap > 0) snprintf(tag_buf, tag_cap, "ok");
    if (msg_cap > 0) snprintf(msg_buf, msg_cap, "ok");
    RB_GC_GUARD(ast);
    return true;
}

static bool compile_run_iseq(
    const char *compiler_name,
    ID method_id,
    unsigned int opt_mask,
    VALUE src_str,
    VALUE opt_hash,
    char *tag_buf,
    size_t tag_cap,
    char *msg_buf,
    size_t msg_cap
) {
    compile_call_arg_t arg = {
        .method_id = method_id,
        .src_str = src_str,
        .opt_hash = opt_hash
    };
    int state = 0;
    volatile VALUE iseq = rb_protect(compile_iseq_cb, (VALUE) &arg, &state);
    if (state != 0) {
        VALUE err = rb_errinfo();
        rb_set_errinfo(Qnil);
        char local_msg[160];
        char *eff_msg = (msg_buf != NULL && msg_cap > 0) ? msg_buf : local_msg;
        size_t eff_cap = (msg_buf != NULL && msg_cap > 0) ? msg_cap : sizeof(local_msg);
        const char *bug_tag = compile_extract_exception(err, tag_buf, tag_cap, eff_msg, eff_cap);
        if (bug_tag != NULL) {
            fprintf(
                stderr,
                "INVARIANT[" FUZZ_COMPILE_NAMESPACE "]: kind=internal_compile_error compiler=%s bug=%s [detail: opt=0x%02x err=%s]\n",
                compiler_name,
                bug_tag,
                opt_mask,
                eff_msg
            );
            fflush(stderr);
            abort();
        }
        return false;
    }
    if (tag_cap > 0) snprintf(tag_buf, tag_cap, "ok");
    if (msg_cap > 0) snprintf(msg_buf, msg_cap, "ok");
    RB_GC_GUARD(iseq);
    return true;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!g_compile_initialized) {
        volatile VALUE ruby_stack_top = Qnil;
        compile_oracle_init_with_stack((void *) &ruby_stack_top);
    }

    if (size < 4 || (size - 4) > (size_t) FUZZ_MAX_INPUT_SIZE) {
        return 0;
    }

    const uint8_t *source = data + 4;
    size_t source_size = size - 4;
    if (source_size > (size_t) LONG_MAX) {
        return 0;
    }

    /* NUL bytes truncate C strings inside parse.y helpers, making inputs non-comparable. */
    if (source_size > 0 && memchr(source, '\0', source_size) != NULL) {
        return 0;
    }

    unsigned int opt_mask = (unsigned int) (data[0] & 0x3fu);

#ifdef FUZZ_CRUBY_PIPELINE_DIFF
    volatile VALUE src_str = rb_utf8_str_new((const char *) source, (long) source_size);
    char prism_tag[64] = "parse_err";
    char prism_msg[160] = "SyntaxError:prism_parse";
    char parse_y_tag[64] = "parse_err";
    char parse_y_msg[160] = "SyntaxError:parse_y_parse";

    bool prism_parsed = compile_prism_accepts(src_str);
    bool prism_compiled = false;
    if (prism_parsed) {
        prism_compiled = compile_run_iseq(
            "prism", g_id_compile_prism, opt_mask, src_str, g_compile_opts[opt_mask],
            prism_tag, sizeof(prism_tag), prism_msg, sizeof(prism_msg)
        );
    }

    bool parse_y_parsed = compile_parse_y_accepts(
        src_str, parse_y_tag, sizeof(parse_y_tag), parse_y_msg, sizeof(parse_y_msg)
    );
    bool parse_y_compiled = false;
    if (parse_y_parsed) {
        parse_y_compiled = compile_run_iseq(
            "parse_y", g_id_compile_parsey, opt_mask, src_str, g_compile_opts[opt_mask],
            parse_y_tag, sizeof(parse_y_tag), parse_y_msg, sizeof(parse_y_msg)
        );
    }

#ifdef PRISM_FUZZ_IJON
    uint32_t state_bits = (opt_mask << 4u) |
                          ((prism_parsed ? 1u : 0u) << 3u) |
                          ((prism_compiled ? 1u : 0u) << 2u) |
                          ((parse_y_parsed ? 1u : 0u) << 1u) |
                          (parse_y_compiled ? 1u : 0u);
    compile_ijon_record(2u, state_bits);
#endif

    if (prism_compiled != parse_y_compiled) {
        if (prism_parsed && parse_y_parsed) {
            const char *sub = prism_compiled ? "prism_ok_parse_y_err" : "prism_err_parse_y_ok";
            const char *err_tag = prism_compiled ? parse_y_tag : prism_tag;
            fprintf(
                stderr,
                "INVARIANT[cruby_pipeline]: kind=compile_mismatch sub=%s tag=%s [detail: opt=0x%02x prism=%s parse_y=%s]\n",
                sub,
                err_tag,
                opt_mask,
                prism_msg,
                parse_y_msg
            );
            fflush(stderr);
            abort();
        } else {
            const char *sub = prism_compiled ? "prism_ok_parse_y_err" : "prism_err_parse_y_ok";
            const char *err_tag = prism_compiled ? parse_y_tag : prism_tag;
            fprintf(
                stderr,
                "INVARIANT[cruby_pipeline]: kind=syntax_mismatch sub=%s tag=%s [detail: opt=0x%02x prism=%s parse_y=%s]\n",
                sub,
                err_tag,
                opt_mask,
                prism_msg,
                parse_y_msg
            );
            fflush(stderr);
            abort();
        }
    }

    RB_GC_GUARD(src_str);
    return 0;
#else
    /* Fast C-level Prism syntax gate: skip invalid Ruby before allocating VM objects. */
    if (!pm_serialize_parse_success_p(source, source_size, NULL)) {
        return 0;
    }

    volatile VALUE src_str = rb_utf8_str_new((const char *) source, (long) source_size);
    if (!compile_parse_y_accepts(src_str, NULL, 0, NULL, 0)) {
        RB_GC_GUARD(src_str);
        return 0;
    }

    /* Both Prism and parse.y accepted the input as valid syntax; compile with both. */
    char prism_msg[160];
    char parse_y_msg[160];
    bool prism_ok = compile_run_iseq("prism", g_id_compile_prism, opt_mask, src_str, g_compile_opts[opt_mask], NULL, 0, prism_msg, sizeof(prism_msg));
    bool parse_y_ok = compile_run_iseq("parse_y", g_id_compile_parsey, opt_mask, src_str, g_compile_opts[opt_mask], NULL, 0, parse_y_msg, sizeof(parse_y_msg));

#ifdef PRISM_FUZZ_IJON
    compile_ijon_record(1u, (opt_mask << 2u) | ((prism_ok ? 1u : 0u) << 1u) | (parse_y_ok ? 1u : 0u));
#endif

#ifdef FUZZ_COMPILE_CHECK_PARITY
    if (prism_ok != parse_y_ok) {
        const char *sub = prism_ok ? "prism_ok_parse_y_err" : "prism_err_parse_y_ok";
        fprintf(
            stderr,
            "INVARIANT[cruby_compile]: kind=compile_status_mismatch sub=%s [detail: opt=0x%02x prism=%s parse_y=%s]\n",
            sub,
            opt_mask,
            prism_msg,
            parse_y_msg
        );
        fflush(stderr);
        abort();
    }
#else
    (void) prism_ok;
    (void) parse_y_ok;
#endif

    RB_GC_GUARD(src_str);
    return 0;
#endif
}

#ifndef PRISM_DIFF_NO_MAIN
#ifdef __AFL_FUZZ_INIT
__AFL_FUZZ_INIT();
#endif

static int compile_run_file(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        fprintf(stderr, FUZZ_COMPILE_BIN_LABEL ": failed to open '%s': %s\n", path, strerror(errno));
        return 1;
    }

    struct stat st;
    if (fstat(fileno(fp), &st) != 0 || st.st_size < 0) {
        fclose(fp);
        return 1;
    }

    size_t size = (size_t) st.st_size;
    uint8_t *buf = (uint8_t *) malloc(size > 0 ? size : 1);
    if (buf == NULL) {
        fclose(fp);
        return 1;
    }

    size_t read_bytes = size > 0 ? fread(buf, 1, size, fp) : 0;
    int had_error = ferror(fp);
    fclose(fp);

    if (!had_error) {
        LLVMFuzzerTestOneInput(buf, read_bytes);
    }

    free(buf);
    return had_error ? 1 : 0;
}

static int compile_run_stdin(void) {
    size_t cap = 4096;
    size_t len = 0;
    uint8_t *buf = (uint8_t *) malloc(cap);
    if (buf == NULL) {
        return EXIT_FAILURE;
    }

    size_t n;
    while ((n = fread(buf + len, 1, cap - len, stdin)) > 0) {
        len += n;
        if (len == cap) {
            if (cap > SIZE_MAX / 2) {
                free(buf);
                return EXIT_FAILURE;
            }
            cap *= 2;
            uint8_t *next = (uint8_t *) realloc(buf, cap);
            if (next == NULL) {
                free(buf);
                return EXIT_FAILURE;
            }
            buf = next;
        }
    }

    if (ferror(stdin)) {
        free(buf);
        return EXIT_FAILURE;
    }

    LLVMFuzzerTestOneInput(buf, len);
    free(buf);
    return EXIT_SUCCESS;
}

#ifndef PRISM_OSS_FUZZ
__attribute__((visibility("default"))) extern const char *__asan_default_options(void);
__attribute__((visibility("default"))) extern const char *__ubsan_default_options(void);

const char *__asan_default_options(void) {
    return "detect_leaks=0:detect_stack_use_after_return=0:abort_on_error=1:handle_abort=1:handle_segv=2:use_sigaltstack=1";
}

const char *__ubsan_default_options(void) {
    return "abort_on_error=1:print_stacktrace=1";
}
#endif

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf(
            "git_commit=%s\ngit_dirty=%s\nruby_version=%s\nruby_release_date=%s\nruby_description=%s\n",
            FUZZ_STR(FUZZ_GIT_COMMIT),
            FUZZ_STR(FUZZ_GIT_DIRTY),
            ruby_version,
            ruby_release_date,
            ruby_description
        );
        return 0;
    }

    volatile VALUE ruby_stack_top = Qnil;
    compile_oracle_init_with_stack((void *) &ruby_stack_top);

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

#ifdef __AFL_FUZZ_TESTCASE_BUF
    if (__afl_fuzz_ptr != NULL) {
#ifdef __AFL_LOOP
        while (__AFL_LOOP(FUZZ_COMPILE_PERSISTENT_ITERS))
#endif
        {
            const uint8_t *buf = __AFL_FUZZ_TESTCASE_BUF;
            size_t len = (size_t) __AFL_FUZZ_TESTCASE_LEN;
            LLVMFuzzerTestOneInput(buf, len);
        }
        return 0;
    }
#endif

    if (argc >= 2) {
        int rc = 0;
        for (int i = 1; i < argc; i++) {
            if (compile_run_file(argv[i]) != 0) {
                rc = 1;
            }
        }
        return rc;
    }

    return compile_run_stdin();
}
#endif
