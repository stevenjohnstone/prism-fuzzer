#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <prism.h>
#ifdef PRISM_FUZZ_IJON
#include "prism_ijon.h"
#endif

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "diff/summary.h"
#include "diff/prism_walker.h"
#include "diff/cruby_vm.h"

#ifndef FUZZ_MAX_INPUT_SIZE
#define FUZZ_MAX_INPUT_SIZE 1024
#endif

#ifndef FUZZ_DIFF_PERSISTENT_ITERS
#define FUZZ_DIFF_PERSISTENT_ITERS 1000
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

static const char diff_fuzz_provenance[] FUZZ_PROVENANCE_ATTR =
    "@(#)PRISM_FUZZ_PROVENANCE\tprism=" PRISM_VERSION
    "\tgit_commit=" FUZZ_STR(FUZZ_GIT_COMMIT)
    "\tgit_dirty=" FUZZ_STR(FUZZ_GIT_DIRTY)
    "\truby_version=" FUZZ_RUBY_VERSION
    "\truby_revision=" FUZZ_RUBY_REVISION
    "\truby_release_date=" FUZZ_RUBY_RELEASE_DATE
    "\n";

static void diff_copy_enc_token(const char *raw, char *dst, size_t cap) {
    if (cap == 0) return;
    if (raw == NULL || raw[0] == '\0') {
        snprintf(dst, cap, "UTF-8");
        return;
    }
    size_t out = 0;
    for (size_t i = 0; raw[i] != '\0' && out + 1 < cap; i++) {
        char c = raw[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
            dst[out++] = c;
        }
    }
    if (out == 0) {
        snprintf(dst, cap, "UTF-8");
    } else {
        dst[out] = '\0';
    }
}

/* Cold-path helper invoked only when syntax_mismatch fires: re-parses `source`
 * with Prism to locate the deepest structural AST node near the diagnostic or
 * CRuby `<compiled>:<line>:` error line, adding zero overhead to passing runs. */
static void diff_resolve_mismatch_prism_context(
    const uint8_t *source,
    size_t size,
    bool prism_ok,
    uint32_t cruby_err_line,
    char *out_ctx,
    size_t ctx_cap
) {
    snprintf(out_ctx, ctx_cap, "program");
    uint8_t *copy = size > 0 ? (uint8_t *) malloc(size) : NULL;
    if (size > 0 && copy == NULL) return;
    if (size > 0) memcpy(copy, source, size);
    const uint8_t *source_buf = (size == 0) ? (const uint8_t *) "" : copy;

    pm_options_t *options = pm_options_new();
    if (options != NULL && pm_options_version_set(options, "4.1", 3)) {
        pm_arena_t *arena = pm_arena_new();
        pm_parser_t *parser = pm_parser_new(arena, source_buf, size, options);
        pm_node_t *root = pm_parse(parser);
        uint32_t probe = 0;
        bool has_probe = false;
        if (!prism_ok) {
            const pm_diagnostic_t *first = pm_parser_errors_first(parser);
            if (first != NULL) {
                probe = pm_diagnostic_location(first).start;
                has_probe = true;
            }
        } else if (cruby_err_line >= 1) {
            const pm_line_offset_list_t *lo = pm_parser_line_offsets(parser);
            if (lo != NULL && lo->size > 0) {
                size_t idx = (size_t) (cruby_err_line - 1);
                if (idx >= lo->size) idx = lo->size - 1;
                probe = lo->offsets[idx];
                has_probe = true;
            }
        }
        diff_find_prism_ast_context(parser, root, probe, has_probe, out_ctx, ctx_cap);
        pm_parser_free(parser);
        pm_arena_free(arena);
    }
    if (options != NULL) pm_options_free(options);
    free(copy);
}

static bool diff_enc_equal(const char *a, const char *b) {
    if (a == NULL || b == NULL) return false;
    while (*a != '\0' && *b != '\0') {
        char ca = (*a >= 'A' && *a <= 'Z') ? (char) (*a + ('a' - 'A')) : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? (char) (*b + ('a' - 'A')) : *b;
        if (ca == '_') ca = '-';
        if (cb == '_') cb = '-';
        if (ca != cb) return false;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

static void diff_run_prism(
    const uint8_t *source,
    size_t size,
    bool *out_ok,
    size_t *out_err_count,
    const char **out_first_diag,
    char *out_enc,
    size_t out_enc_cap,
    bool *out_has_data_loc,
    uint32_t *out_data_start,
    uint32_t *out_data_len,
    diff_summary_t *out_summary
) {
    *out_ok = false;
    *out_err_count = 0;
    *out_first_diag = "ok";
    *out_has_data_loc = false;
    *out_data_start = 0;
    *out_data_len = 0;
    if (out_enc_cap > 0) {
        snprintf(out_enc, out_enc_cap, "UTF-8");
    }

    uint8_t *copy = size > 0 ? (uint8_t *) malloc(size) : NULL;
    if (size > 0 && copy == NULL) {
        abort();
    }
    if (size > 0) {
        memcpy(copy, source, size);
    }
    const uint8_t *source_buf = (size == 0) ? (const uint8_t *) "" : copy;

    pm_options_t *options = pm_options_new();
    if (!pm_options_version_set(options, "4.1", 3)) {
        abort();
    }

    pm_arena_t *arena = pm_arena_new();
    pm_parser_t *parser = pm_parser_new(arena, source_buf, size, options);
    pm_node_t *root = pm_parse(parser);
#ifdef PRISM_FUZZ_IJON
    fuzz_ijon_post_parse(arena, parser, root, 0U);
#endif
    diff_copy_enc_token(pm_parser_encoding_name(parser), out_enc, out_enc_cap);
    const pm_location_t *dloc = pm_parser_data_loc(parser);
    if (dloc != NULL && dloc->length > 0) {
        *out_has_data_loc = true;
        *out_data_start = dloc->start;
        *out_data_len = dloc->length;
    }

    size_t err_count = pm_parser_errors_size(parser);
    *out_err_count = err_count;
    *out_ok = (err_count == 0);

    if (*out_ok) {
        if (root != NULL && PM_NODE_TYPE_P(root, PM_PROGRAM_NODE)) {
            diff_collect_prism_summary(parser, root, out_summary);
        }
    } else {
        const pm_diagnostic_t *first = pm_parser_errors_first(parser);
        *out_first_diag = (first != NULL) ? pm_diagnostic_type(first) : "error";
    }

    pm_parser_free(parser);
    pm_arena_free(arena);
    pm_options_free(options);
    free(copy);
}

static bool
diff_ignore_syntax_mismatch(bool prism_ok, bool cruby_ok, const char *cruby_tag, const char *exc_buf) {
    if (!(prism_ok && !cruby_ok)) {
        return false;
    }

    // Prism intentionally defers full Onigmo regexp compilation errors and
    // tolerates raw invalid UTF-8 bytes in string/regexp literals.
    if (strcmp(cruby_tag, "SyntaxError:invalid_multibyte_utf8") == 0) {
        return true;
    }
    if (strncmp(cruby_tag, "SyntaxError:regexp_", 19) == 0) {
        return true;
    }

    // Documented Prism vs CRuby parse.y divergence (test/prism/fixtures_test.rb):
    // 3.4/command_call_do_block_in_arguments.txt (Ruby #21168).
    if (strcmp(cruby_tag, "SyntaxError:unexpected_do_block") == 0) {
        return true;
    }

    // RubyVM::AbstractSyntaxTree.parse (ast.c) fails converting valid parse.y
    // NODE_ITER(NODE_DASGN) even when `ruby --parser=parse.y` accepts the code.
    if (strstr(exc_buf, "get_nd_args: unexpected node:") != NULL) {
        return true;
    }

    return false;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!diff_oracle_initialized) {
        volatile VALUE ruby_stack_top = Qnil;
        diff_oracle_init_with_stack((void *) &ruby_stack_top);
    }

    // FUZZ_MAX_INPUT_SIZE bounds the Ruby source payload after the 4-byte option header.
    if (size < 4 || (size - 4) > (size_t) FUZZ_MAX_INPUT_SIZE) {
        return 0;
    }

    const uint8_t *source = data + 4;
    size_t source_size = size - 4;

    // CRuby parse.y treats NUL bytes as EOF in lexing and truncates C strings in
    // magic-comment/error helpers, making NUL-containing inputs non-comparable.
    if (diff_has_nul(source, source_size)) {
        return 0;
    }

    bool prism_ok = false;
    size_t prism_errs = 0;
    const char *prism_diag = "ok";
    char prism_enc[48];
    bool prism_has_data = false;
    uint32_t prism_data_start = 0;
    uint32_t prism_data_len = 0;
    diff_summary_t prism_ast;
    diff_summary_init(&prism_ast);

    diff_run_prism(
        source,
        source_size,
        &prism_ok,
        &prism_errs,
        &prism_diag,
        prism_enc,
        sizeof(prism_enc),
        &prism_has_data,
        &prism_data_start,
        &prism_data_len,
        &prism_ast
    );

    bool cruby_ok = false;
    char exc_buf[160];
    char cruby_tag[128];
    uint32_t cruby_err_line = 0;
    volatile VALUE ast_node = diff_run_cruby(
        (const char *) source,
        source_size,
        &cruby_ok,
        exc_buf,
        sizeof(exc_buf),
        cruby_tag,
        sizeof(cruby_tag),
        &cruby_err_line
    );

    if (!prism_ok && cruby_ok) {
        diff_run_cruby_compile(
            (const char *) source,
            source_size,
            &cruby_ok,
            exc_buf,
            sizeof(exc_buf),
            cruby_tag,
            sizeof(cruby_tag),
            &cruby_err_line
        );
    }

    if (prism_ok != cruby_ok) {
        diff_summary_free(&prism_ast);
        if (diff_ignore_syntax_mismatch(prism_ok, cruby_ok, cruby_tag, exc_buf)) {
            return 0;
        }
        char ast_ctx[64];
        diff_resolve_mismatch_prism_context(source, source_size, prism_ok, cruby_err_line, ast_ctx, sizeof(ast_ctx));
        diff_fail_syntax_mismatch(
            source,
            source_size,
            prism_ok,
            prism_errs,
            prism_diag,
            prism_enc,
            ast_ctx,
            cruby_ok,
            cruby_tag,
            exc_buf
        );
    }

    if (prism_ok && cruby_ok) {
        char cruby_enc_raw[48];
        char cruby_enc[48];
        bool cruby_has_lines = false;
        size_t cruby_total_bytes = 0;
        size_t cruby_last_line_bytes = 0;
        bool cruby_last_line_is_end = false;
        diff_cruby_extract_script_meta(
            ast_node,
            cruby_enc_raw,
            sizeof(cruby_enc_raw),
            &cruby_has_lines,
            &cruby_total_bytes,
            &cruby_last_line_bytes,
            &cruby_last_line_is_end
        );
        diff_copy_enc_token(cruby_enc_raw, cruby_enc, sizeof(cruby_enc));

        if (cruby_has_lines && !diff_enc_equal(prism_enc, cruby_enc)) {
            diff_summary_free(&prism_ast);
            diff_invariant_fail(
                "INVARIANT[diff_parse_y]: kind=encoding_mismatch prism=%s cruby=%s\n",
                prism_enc,
                cruby_enc
            );
        }

        bool has_bom = (source_size >= 3 && source[0] == 0xEF && source[1] == 0xBB && source[2] == 0xBF);
        if (cruby_has_lines && !has_bom) {
            bool cruby_has_data = (cruby_total_bytes < source_size && cruby_last_line_is_end);
            size_t end_marker_len = 8;
            if (prism_has_data && (size_t) prism_data_start + 9 <= source_size &&
                source[prism_data_start + 7] == '\r' && source[prism_data_start + 8] == '\n') {
                end_marker_len = 9;
            }
            bool prism_has_trailing_data = (prism_has_data && (size_t) prism_data_start + end_marker_len < source_size);
            if (cruby_has_data != prism_has_trailing_data) {
                if (cruby_has_data || prism_has_trailing_data) {
                    size_t cruby_start = cruby_has_data ? (cruby_total_bytes - cruby_last_line_bytes) : 0;
                    diff_summary_free(&prism_ast);
                    diff_invariant_fail(
                        "INVARIANT[diff_parse_y]: kind=data_loc_mismatch [detail: prism_has=%d prism_start=%u prism_len=%u cruby_has=%d cruby_start=%zu cruby_bytes=%zu size=%zu]\n",
                        prism_has_data ? 1 : 0,
                        prism_data_start,
                        prism_data_len,
                        cruby_has_data ? 1 : 0,
                        cruby_start,
                        cruby_total_bytes,
                        source_size
                    );
                }
            } else if (cruby_has_data) {
                size_t cruby_start = cruby_total_bytes - cruby_last_line_bytes;
                if (cruby_start != (size_t) prism_data_start) {
                    diff_summary_free(&prism_ast);
                    diff_invariant_fail(
                        "INVARIANT[diff_parse_y]: kind=data_loc_mismatch [detail: prism_has=1 prism_start=%u prism_len=%u cruby_has=1 cruby_start=%zu cruby_bytes=%zu size=%zu]\n",
                        prism_data_start,
                        prism_data_len,
                        cruby_start,
                        cruby_total_bytes,
                        source_size
                    );
                }
            }
        }

        diff_summary_t cruby_ast;
        diff_summary_init(&cruby_ast);
        diff_collect_cruby_summary(ast_node, &cruby_ast);
        diff_compare_asts(&prism_ast, &cruby_ast);
        diff_summary_free(&cruby_ast);
    }

    RB_GC_GUARD(ast_node);
    diff_summary_free(&prism_ast);
    return 0;
}

#ifndef PRISM_DIFF_NO_MAIN
#ifdef __AFL_FUZZ_INIT
__AFL_FUZZ_INIT();
#endif

static int diff_run_file(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "fuzz.diff: failed to open '%s': %s\n", path, strerror(errno));
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

static int diff_run_stdin(void) {
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
/* Embedded CRuby retains VM/AST allocations through process exit (so disable LSan)
   and scans the native OS stack conservatively (so disable ASan UAR FakeStack). */
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
            "prism=%s\ngit_commit=%s\ngit_dirty=%s\nruby_version=%s\nruby_release_date=%s\nruby_description=%s\n",
            pm_version(),
            FUZZ_STR(FUZZ_GIT_COMMIT),
            FUZZ_STR(FUZZ_GIT_DIRTY),
            ruby_version,
            ruby_release_date,
            ruby_description
        );
        return 0;
    }

    volatile VALUE ruby_stack_top = Qnil;
    diff_oracle_init_with_stack((void *) &ruby_stack_top);

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

#ifdef __AFL_FUZZ_TESTCASE_BUF
    if (__afl_fuzz_ptr != NULL) {
#ifdef __AFL_LOOP
        while (__AFL_LOOP(FUZZ_DIFF_PERSISTENT_ITERS))
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
            if (diff_run_file(argv[i]) != 0) {
                rc = 1;
            }
        }
        return rc;
    }

    return diff_run_stdin();
}
#endif
