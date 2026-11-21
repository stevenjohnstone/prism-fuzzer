#ifndef PRISM_DIFF_PRISM_WALKER_H
#define PRISM_DIFF_PRISM_WALKER_H

#include "summary.h"

#include <prism.h>

void diff_collect_prism_summary(
    const pm_parser_t *parser,
    const pm_node_t *root,
    diff_summary_t *out
);

#endif
