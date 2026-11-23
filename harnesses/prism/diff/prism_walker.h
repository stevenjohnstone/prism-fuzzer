#ifndef PRISM_DIFF_PRISM_WALKER_H
#define PRISM_DIFF_PRISM_WALKER_H

#include "summary.h"

#include <prism.h>

void diff_collect_prism_summary(
    const pm_parser_t *parser,
    const pm_node_t *root,
    diff_summary_t *out
);

void diff_find_prism_ast_context(
    const pm_parser_t *parser,
    const pm_node_t *root,
    uint32_t probe_offset,
    bool has_probe,
    char *ctx_buf,
    size_t ctx_cap
);

#endif
