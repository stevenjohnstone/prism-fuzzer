#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "prism_diff_side.h"

#ifndef FUZZ_PRISM_DIFF_PERSISTENT_ITERS
#define FUZZ_PRISM_DIFF_PERSISTENT_ITERS 5000
#endif

__attribute__((noreturn, noinline, format(printf, 3, 4)))
static void prism_diff_fail(fuzz_prism_side_result_t *a, fuzz_prism_side_result_t *b, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputc('\n', stderr);
    fflush(stderr);
    fuzz_prism_side_a_free(a);
    fuzz_prism_side_b_free(b);
    abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *input, size_t size) {
    if (input == NULL || size < 4) return 0;

    fuzz_prism_side_result_t a;
    fuzz_prism_side_result_t b;
    fuzz_prism_side_a_run(input, size, &a);
    fuzz_prism_side_b_run(input, size, &b);

    if (a.parsed_size != b.parsed_size) {
        prism_diff_fail(&a, &b,
            "INVARIANT[diff_prism]: kind=parsed_size_mismatch a=%u b=%u",
            a.parsed_size, b.parsed_size);
    }

    if (a.continuable != b.continuable) {
        prism_diff_fail(&a, &b,
            "INVARIANT[diff_prism]: kind=continuable_mismatch a=%d b=%d",
            a.continuable ? 1 : 0, b.continuable ? 1 : 0);
    }

    if (a.has_data_loc != b.has_data_loc ||
        (a.has_data_loc && (a.data_loc_start != b.data_loc_start || a.data_loc_length != b.data_loc_length))) {
        prism_diff_fail(&a, &b,
            "INVARIANT[diff_prism]: kind=data_loc_mismatch a=(%u,%u,%d) b=(%u,%u,%d)",
            a.data_loc_start, a.data_loc_length, a.has_data_loc ? 1 : 0,
            b.data_loc_start, b.data_loc_length, b.has_data_loc ? 1 : 0);
    }

    if (a.error_count != b.error_count) {
        prism_diff_fail(&a, &b,
            "INVARIANT[diff_prism]: kind=error_mismatch sub=count a=%u b=%u a_err=%s b_err=%s",
            a.error_count, b.error_count,
            a.first_error_type[0] ? a.first_error_type : "none",
            b.first_error_type[0] ? b.first_error_type : "none");
    }

    if (a.error_count > 0) {
        if (strcmp(a.first_error_type, b.first_error_type) != 0) {
            prism_diff_fail(&a, &b,
                "INVARIANT[diff_prism]: kind=error_mismatch sub=first_type a=%s b=%s",
                a.first_error_type, b.first_error_type);
        }
        if (a.first_error_start != b.first_error_start || a.first_error_length != b.first_error_length) {
            prism_diff_fail(&a, &b,
                "INVARIANT[diff_prism]: kind=error_mismatch sub=first_loc err=%s a=(%u,%u) b=(%u,%u)",
                a.first_error_type,
                a.first_error_start, a.first_error_length,
                b.first_error_start, b.first_error_length);
        }
    }

    if (a.warning_count != b.warning_count) {
        prism_diff_fail(&a, &b,
            "INVARIANT[diff_prism]: kind=warning_count_mismatch a=%u b=%u",
            a.warning_count, b.warning_count);
    }

    if (a.comment_count != b.comment_count) {
        prism_diff_fail(&a, &b,
            "INVARIANT[diff_prism]: kind=comment_count_mismatch a=%u b=%u",
            a.comment_count, b.comment_count);
    }

    if (a.magic_comment_count != b.magic_comment_count) {
        prism_diff_fail(&a, &b,
            "INVARIANT[diff_prism]: kind=magic_comment_count_mismatch a=%u b=%u",
            a.magic_comment_count, b.magic_comment_count);
    }

    if (a.serialized_len != b.serialized_len) {
        size_t min_len = a.serialized_len < b.serialized_len ? a.serialized_len : b.serialized_len;
        size_t first_diff = min_len;
        for (size_t i = 0; i < min_len; i++) {
            if (a.serialized[i] != b.serialized[i]) {
                first_diff = i;
                break;
            }
        }
        uint8_t ba = first_diff < a.serialized_len ? a.serialized[first_diff] : 0;
        uint8_t bb = first_diff < b.serialized_len ? b.serialized[first_diff] : 0;
        prism_diff_fail(&a, &b,
            "INVARIANT[diff_prism]: kind=serialize_mismatch sub=len a_len=%zu b_len=%zu first_diff=%zu byte_a=0x%02x byte_b=0x%02x",
            a.serialized_len, b.serialized_len, first_diff, ba, bb);
    }

    if (a.serialized_len > 0 && memcmp(a.serialized, b.serialized, a.serialized_len) != 0) {
        size_t first_diff = 0;
        for (size_t i = 0; i < a.serialized_len; i++) {
            if (a.serialized[i] != b.serialized[i]) {
                first_diff = i;
                break;
            }
        }
        prism_diff_fail(&a, &b,
            "INVARIANT[diff_prism]: kind=serialize_mismatch sub=bytes a_len=%zu b_len=%zu first_diff=%zu byte_a=0x%02x byte_b=0x%02x",
            a.serialized_len, b.serialized_len, first_diff, a.serialized[first_diff], b.serialized[first_diff]);
    }

    if (a.prettyprint_len != b.prettyprint_len ||
        (a.prettyprint_len > 0 && memcmp(a.prettyprint, b.prettyprint, a.prettyprint_len) != 0)) {
        prism_diff_fail(&a, &b,
            "INVARIANT[diff_prism]: kind=prettyprint_mismatch a_len=%zu b_len=%zu",
            a.prettyprint_len, b.prettyprint_len);
    }

    fuzz_prism_side_a_free(&a);
    fuzz_prism_side_b_free(&b);
    return 0;
}

#ifndef PRISM_PRISM_DIFF_NO_MAIN
#ifdef __AFL_FUZZ_INIT
__AFL_FUZZ_INIT();
#endif

static int run_file(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "fuzz.prism_diff: failed to open '%s': %s\n", path, strerror(errno));
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

    size_t n = size > 0 ? fread(buf, 1, size, fp) : 0;
    int err = ferror(fp);
    fclose(fp);

    if (!err) LLVMFuzzerTestOneInput(buf, n);
    free(buf);
    return err ? 1 : 0;
}

static int run_stdin(void) {
    size_t cap = 4096;
    size_t len = 0;
    uint8_t *buf = (uint8_t *) malloc(cap);
    if (buf == NULL) return 1;

    size_t n;
    while ((n = fread(buf + len, 1, cap - len, stdin)) > 0) {
        len += n;
        if (len == cap) {
            cap *= 2;
            uint8_t *next = (uint8_t *) realloc(buf, cap);
            if (next == NULL) {
                free(buf);
                return 1;
            }
            buf = next;
        }
    }

    if (!ferror(stdin)) LLVMFuzzerTestOneInput(buf, len);
    free(buf);
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        fuzz_prism_side_info_t ia = fuzz_prism_side_a_info();
        fuzz_prism_side_info_t ib = fuzz_prism_side_b_info();
        printf(
            "prism_a=%s\nprism_a_git_commit=%s\nprism_a_git_dirty=%s\nprism_b=%s\nprism_b_git_commit=%s\nprism_b_git_dirty=%s\n",
            ia.version, ia.git_commit, ia.git_dirty,
            ib.version, ib.git_commit, ib.git_dirty
        );
        return 0;
    }

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

#ifdef __AFL_FUZZ_TESTCASE_BUF
    if (__afl_fuzz_ptr != NULL) {
#ifdef __AFL_LOOP
        while (__AFL_LOOP(FUZZ_PRISM_DIFF_PERSISTENT_ITERS))
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
            if (run_file(argv[i]) != 0) rc = 1;
        }
        return rc;
    }

    return run_stdin();
}
#endif
