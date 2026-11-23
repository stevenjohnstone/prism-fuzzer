#ifndef PRISM_DIFF_CRUBY_VM_H
#define PRISM_DIFF_CRUBY_VM_H

#include "summary.h"

#include <ruby.h>
#include <ruby/version.h>

extern int diff_oracle_initialized;

void diff_oracle_init(void);
void diff_oracle_init_with_stack(void *stack_top);
void diff_classify_cruby_msg(const char *cls, const char *line, char *tag_buf, size_t tag_cap);
VALUE diff_run_cruby(
    const char *source,
    size_t size,
    bool *out_ok,
    char *exc_buf,
    size_t exc_cap,
    char *tag_buf,
    size_t tag_cap,
    uint32_t *out_err_line
);
void diff_run_cruby_compile(
    const char *source,
    size_t size,
    bool *out_ok,
    char *exc_buf,
    size_t exc_cap,
    char *tag_buf,
    size_t tag_cap,
    uint32_t *out_err_line
);
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
) __attribute__((noreturn));

/* cruby_walker.c */
void diff_ast_ids_init(void);
void diff_collect_cruby_summary(VALUE ast_node, diff_summary_t *out);

#endif
