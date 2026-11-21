#include "explain.h"
#include "../include/fuzz_invariants.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

void explain_print_escaped_slice(FILE *out, const uint8_t *buf, size_t len, size_t max_chars) {
    size_t emitted = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = buf[i];
        char tmp[8];
        size_t tok_len;
        if (c == '\0') {
            memcpy(tmp, "\\0", 3);
            tok_len = 2;
        } else if (c == '\n') {
            memcpy(tmp, "\\n", 3);
            tok_len = 2;
        } else if (c == '\r') {
            memcpy(tmp, "\\r", 3);
            tok_len = 2;
        } else if (c == '\t') {
            memcpy(tmp, "\\t", 3);
            tok_len = 2;
        } else if (c == '\\') {
            memcpy(tmp, "\\\\", 3);
            tok_len = 2;
        } else if (c >= 0x20 && c <= 0x7e) {
            tmp[0] = (char) c;
            tmp[1] = '\0';
            tok_len = 1;
        } else {
            snprintf(tmp, sizeof(tmp), "\\x%02x", (unsigned) c);
            tok_len = 4;
        }

        if (max_chars > 0 && emitted + tok_len > max_chars) {
            fputs("...", out);
            return;
        }
        fputs(tmp, out);
        emitted += tok_len;
    }
}

static const char *error_level_name(pm_error_level_t level) {
    switch (level) {
        case PM_ERROR_LEVEL_SYNTAX: return "syntax";
        case PM_ERROR_LEVEL_ARGUMENT: return "argument";
        case PM_ERROR_LEVEL_LOAD: return "load";
        case PM_ERROR_LEVEL_STACK: return "stack";
        case PM_ERROR_LEVEL_ENCODING_COMPATIBILITY: return "encoding_compatibility";
        default: return "unknown";
    }
}

static const char *warning_level_name(pm_warning_level_t level) {
    switch (level) {
        case PM_WARNING_LEVEL_DEFAULT: return "default";
        case PM_WARNING_LEVEL_VERBOSE: return "verbose";
        default: return "unknown";
    }
}

void explain_print_decoded_options(const uint8_t hdr[4], const fuzz_options_t *opts, size_t src_len) {
    printf("header:      %02x%02x%02x%02x (bytes: 0x%02x 0x%02x 0x%02x 0x%02x)\n",
        hdr[0], hdr[1], hdr[2], hdr[3], hdr[0], hdr[1], hdr[2], hdr[3]);

    int32_t line_val = fuzz_option_effective_start_line(opts);
    printf("options:     version=%s stream_mode=%s start_line=%d",
        opts->version, opts->stream_mode ? "true" : "false", (int) line_val);

    if (opts->has_limit_opts) {
        printf(" stack_budget=%s", fuzz_option_stack_budget_name(opts->aux_byte));
    }

    if (opts->has_encoding_opts) {
        printf(" encoding=%s filepath=fuzz.rb", fuzz_option_encoding_name(opts->aux_byte));
        if ((opts->aux_byte & 0x08) != 0) printf(" shebang_cb=true");
    }

    if (opts->cmd_flags != 0) {
        printf(" cmd=-");
        if ((opts->cmd_flags & PM_OPTIONS_COMMAND_LINE_A) != 0) putchar('a');
        if ((opts->cmd_flags & PM_OPTIONS_COMMAND_LINE_E) != 0) putchar('e');
        if ((opts->cmd_flags & PM_OPTIONS_COMMAND_LINE_L) != 0) putchar('l');
        if ((opts->cmd_flags & PM_OPTIONS_COMMAND_LINE_N) != 0) putchar('n');
        if ((opts->cmd_flags & PM_OPTIONS_COMMAND_LINE_P) != 0) putchar('p');
        if ((opts->cmd_flags & PM_OPTIONS_COMMAND_LINE_X) != 0) putchar('x');
    }

    if (opts->main_script) printf(" main_script=true");
    if (opts->partial_script) printf(" partial_script=true");
    if (opts->freeze) printf(" freeze=true");
    if (opts->attach_comments) printf(" attach_comments=true");
    if (opts->encoding_locked) printf(" encoding_locked=true");
    if (opts->has_frozen_string_literal) {
        printf(" frozen_string_literal=%s", opts->frozen_string_literal ? "true" : "false");
    }

    if (opts->scopes_count > 0) {
        size_t fwd_scope = fuzz_option_forwarding_scope(opts);
        printf(" scopes=%u(fwd_scope=%zu,fwd=0x%x,src_len=%zu)",
            (unsigned) opts->scopes_count, fwd_scope, (unsigned) opts->forwarding, src_len);
    }
    putchar('\n');
}

static void print_inline_node_tags(const parse_analysis_t *a, anomaly_scope_t scope, size_t node_idx, const char *field_name) {
    bool any = false;
    for (size_t i = 0; i < a->count; i++) {
        const anomaly_t *entry = &a->items[i];
        if (entry->scope != scope || entry->node_idx != node_idx) continue;
        if (scope == ANOMALY_SCOPE_SUB_LOC) {
            if (field_name == NULL || entry->field_name == NULL || strcmp(entry->field_name, field_name) != 0) continue;
        }
        if (!any) {
            fputs("  <-- [! ", stdout);
            any = true;
        } else {
            fputs("; ", stdout);
        }
        printf("%s: %s", entry->kind, entry->detail);
    }
    if (any) {
        putchar(']');
    }
}

typedef struct {
    size_t col;
    size_t node_idx;
} pp_stack_frame_t;

static bool match_node_header_line(const char *line, size_t len, const char *expected_camel, size_t *out_col) {
    size_t i = 0;
    while (i < len && (line[i] == ' ' || line[i] == '|' || line[i] == '+' || line[i] == '-')) {
        i++;
    }
    if (i + 2 >= len || line[i] != '@' || line[i + 1] != ' ') return false;
    size_t name_len = strlen(expected_camel);
    if (i + 2 + name_len + 12 > len) return false;
    if (memcmp(line + i + 2, expected_camel, name_len) != 0) return false;
    if (memcmp(line + i + 2 + name_len, " (location: ", 12) != 0) return false;
    *out_col = i;
    return true;
}

static bool match_subloc_field_line(const char *line, size_t len, size_t *out_col, char *field_buf, size_t field_cap) {
    size_t i = 0;
    while (i < len && (line[i] == ' ' || line[i] == '|')) {
        i++;
    }
    if (i + 4 >= len || memcmp(line + i, "+-- ", 4) != 0) return false;
    size_t fstart = i + 4;
    size_t j = fstart;
    while (j < len && (isalnum((unsigned char) line[j]) || line[j] == '_')) {
        j++;
    }
    if (j == fstart || j >= len || line[j] != ':') return false;
    size_t flen = j - fstart;
    if (flen >= field_cap) return false;
    memcpy(field_buf, line + fstart, flen);
    field_buf[flen] = '\0';
    *out_col = i;
    return true;
}

static void print_annotated_prettyprint(const pm_buffer_t *pretty_buf, const parse_analysis_t *a, const char *indent_prefix) {
    const char *buf = pm_buffer_value(pretty_buf);
    size_t total = pm_buffer_length(pretty_buf);
    if (a == NULL || a->count == 0) {
        size_t pos = 0;
        while (pos < total) {
            const char *nl = memchr(buf + pos, '\n', total - pos);
            size_t llen = nl != NULL ? (size_t) (nl - (buf + pos)) : (total - pos);
            if (indent_prefix != NULL) fputs(indent_prefix, stdout);
            fwrite(buf + pos, 1, llen, stdout);
            putchar('\n');
            pos += llen + (nl != NULL ? 1u : 0u);
        }
        return;
    }

    size_t stack_cap = 64;
    pp_stack_frame_t *stack = malloc(stack_cap * sizeof(pp_stack_frame_t));
    size_t sp = 0;
    size_t next_node_idx = 0;
    size_t pos = 0;

    while (pos < total) {
        const char *line = buf + pos;
        const char *nl = memchr(line, '\n', total - pos);
        size_t llen = nl != NULL ? (size_t) (nl - line) : (total - pos);

        if (indent_prefix != NULL) fputs(indent_prefix, stdout);
        fwrite(line, 1, llen, stdout);

        size_t col = 0;
        if (stack != NULL && next_node_idx < a->node_count &&
            match_node_header_line(line, llen, a->nodes[next_node_idx].camel_name, &col)) {
            size_t my_idx = next_node_idx++;
            while (sp > 0 && stack[sp - 1].col >= col) {
                sp--;
            }
            if (sp == stack_cap) {
                size_t new_cap = stack_cap * 2;
                pp_stack_frame_t *grown = realloc(stack, new_cap * sizeof(pp_stack_frame_t));
                if (grown != NULL) {
                    stack = grown;
                    stack_cap = new_cap;
                }
            }
            if (sp < stack_cap) {
                stack[sp++] = (pp_stack_frame_t) { .col = col, .node_idx = my_idx };
            }
            print_inline_node_tags(a, ANOMALY_SCOPE_NODE, my_idx, NULL);
        } else if (stack != NULL && sp > 0) {
            char field_buf[96];
            if (match_subloc_field_line(line, llen, &col, field_buf, sizeof(field_buf))) {
                while (sp > 0 && stack[sp - 1].col > col) {
                    sp--;
                }
                if (sp > 0 && stack[sp - 1].col == col) {
                    print_inline_node_tags(a, ANOMALY_SCOPE_SUB_LOC, stack[sp - 1].node_idx, field_buf);
                }
            }
        }

        putchar('\n');
        pos += llen + (nl != NULL ? 1u : 0u);
    }

    free(stack);
}

typedef struct {
    const parse_analysis_t *analysis;
    size_t next_idx;
} safe_ast_print_ctx_t;

static void print_indent(FILE *out, size_t depth, const char *prefix) {
    if (prefix != NULL) fputs(prefix, out);
    for (size_t i = 0; i < depth; i++) {
        fputs("  ", out);
    }
}

static void print_safe_ast_node(safe_ast_print_ctx_t *pctx, const pm_node_t *node, size_t depth, const char *prefix) {
    if (node == NULL || PM_NODE_TYPE_P(node, PM_SCOPE_NODE)) return;

    size_t my_idx = SIZE_MAX;
    if (pctx->next_idx < pctx->analysis->node_count && pctx->analysis->nodes[pctx->next_idx].node == node) {
        my_idx = pctx->next_idx++;
    }

    char camel[64];
    explain_node_camel_name(node->type, camel, sizeof(camel));
    uint64_t end = (uint64_t) node->location.start + (uint64_t) node->location.length;

    print_indent(stdout, depth, prefix);
    printf("@ %s [start=%u len=%u end=%llu]", camel,
        (unsigned) node->location.start, (unsigned) node->location.length, (unsigned long long) end);
    if (my_idx != SIZE_MAX) {
        print_inline_node_tags(pctx->analysis, ANOMALY_SCOPE_NODE, my_idx, NULL);
    }
    putchar('\n');

    if (my_idx != SIZE_MAX) {
        for (size_t i = 0; i < pctx->analysis->count; i++) {
            const anomaly_t *entry = &pctx->analysis->items[i];
            if (entry->scope == ANOMALY_SCOPE_SUB_LOC && entry->node_idx == my_idx) {
                print_indent(stdout, depth + 1, prefix);
                printf("+-- %s  <-- [! %s: %s]\n",
                    entry->field_name ? entry->field_name : "?", entry->kind, entry->detail);
            }
        }
    }

    if (depth >= EXPLAIN_MAX_VISIT_DEPTH) return;
    node_ptr_vec_t direct = { 0 };
    pm_visit_child_nodes(node, explain_collect_direct_child_cb, &direct);
    for (size_t i = 0; i < direct.count; i++) {
        print_safe_ast_node(pctx, direct.items[i], depth + 1, prefix);
    }
    free((void *) direct.items);
}

static void print_anomalies_section(const parse_analysis_t *a, const pm_parser_t *parser) {
    if (!a->analyzed || a->count == 0) return;

    const pm_line_offset_list_t *lo = pm_parser_line_offsets(parser);
    int32_t start_line = pm_parser_start_line(parser);

    printf("anomalies:   %zu issue(s)%s\n", a->count, a->oom ? " (truncated: OOM)" : "");
    for (size_t i = 0; i < a->count; i++) {
        const anomaly_t *entry = &a->items[i];
        printf("  [%zu] %s: kind=%s %s", i, entry->category, entry->kind, entry->detail);
        if (entry->scope != ANOMALY_SCOPE_GENERAL && entry->node_idx < a->node_count) {
            const pm_node_t *n = a->nodes[entry->node_idx].node;
            pm_line_column_t lc_s;
            pm_line_column_t lc_e;
            uint32_t wrapped_end = (uint32_t) (((uint64_t) n->location.start + (uint64_t) n->location.length) & 0xffffffffULL);
            if (explain_safe_line_column(lo, start_line, a->line_offsets_can_query, n->location.start, &lc_s) &&
                explain_safe_line_column(lo, start_line, a->line_offsets_can_query, wrapped_end, &lc_e)) {
                printf(" lc=(%d,%u)-(%d,%u)", (int) lc_s.line, (unsigned) lc_s.column, (int) lc_e.line, (unsigned) lc_e.column);
            }
        }
        putchar('\n');
    }
}

void explain_print_single_parse_details(
    const parsed_run_t *run,
    const uint8_t *src_buf,
    bool stream_mode,
    const explain_cfg_t *cfg
) {
    const pm_parser_t *parser = run->parser;
    const pm_line_offset_list_t *lo = pm_parser_line_offsets(parser);
    const pm_location_t *dloc = pm_parser_data_loc(parser);

    printf("mode:        %s\n", stream_mode ? "stream (pm_parse_stream)" : "buffer (pm_parse)");
    printf("parsed:      parsed_size=%zu encoding=%s start_line=%d frozen_lit=%d continuable=%s data_loc=(%u,%u) checksum=0x%016llx\n",
        run->parsed_size,
        pm_parser_encoding_name(parser),
        (int) pm_parser_start_line(parser),
        (int) pm_parser_frozen_string_literal(parser),
        pm_parser_continuable(parser) ? "true" : "false",
        (unsigned) dloc->start,
        (unsigned) dloc->length,
        (unsigned long long) pm_parser_checksum(parser));

    printf("counts:      errors=%zu warnings=%zu comments=%zu magic_comments=%zu constants=%zu line_offsets=%zu\n",
        pm_parser_errors_size(parser),
        pm_parser_warnings_size(parser),
        pm_parser_comments_size(parser),
        pm_parser_magic_comments_size(parser),
        pm_parser_constants_size(parser),
        lo->size);

    size_t lo_limit = cfg->print_line_offsets ? lo->size : (lo->size < 32 ? lo->size : 32);
    printf("offsets:     [");
    for (size_t i = 0; i < lo_limit; i++) {
        if (i > 0) fputs(", ", stdout);
        printf("%u", (unsigned) lo->offsets[i]);
    }
    if (lo_limit < lo->size) {
        printf(", ... (%zu more)", lo->size - lo_limit);
    }
    puts("]");

    if (pm_parser_magic_comments_size(parser) > 0) {
        puts("magic_comments:");
        for (const pm_magic_comment_t *mc = pm_parser_magic_comments_first(parser); mc != NULL; mc = pm_magic_comment_next(mc)) {
            pm_location_t k = pm_magic_comment_key(mc);
            pm_location_t v = pm_magic_comment_value(mc);
            printf("  - key=(%u,%u) \"", (unsigned) k.start, (unsigned) k.length);
            if (fuzz_span_in_bounds(k.start, k.length, run->parsed_size)) {
                explain_print_escaped_slice(stdout, src_buf + k.start, k.length, 64);
            }
            printf("\" value=(%u,%u) \"", (unsigned) v.start, (unsigned) v.length);
            if (fuzz_span_in_bounds(v.start, v.length, run->parsed_size)) {
                explain_print_escaped_slice(stdout, src_buf + v.start, v.length, 64);
            }
            puts("\"");
        }
    }

    if (pm_parser_errors_size(parser) > 0) {
        puts("errors:");
        size_t idx = 0;
        for (const pm_diagnostic_t *d = pm_parser_errors_first(parser); d != NULL; d = pm_diagnostic_next(d), idx++) {
            pm_location_t loc = pm_diagnostic_location(d);
            pm_line_column_t lc = { 0, 0 };
            if (explain_safe_line_column(lo, pm_parser_start_line(parser), run->analysis.line_offsets_can_query, loc.start, &lc)) {
                printf("  [%zu] type=%s level=%s loc=(%u,%u) lc=(%d:%u) msg=\"%s\"\n",
                    idx, pm_diagnostic_type(d), error_level_name(pm_diagnostic_error_level(d)),
                    (unsigned) loc.start, (unsigned) loc.length, (int) lc.line, (unsigned) lc.column,
                    pm_diagnostic_message(d));
            } else {
                printf("  [%zu] type=%s level=%s loc=(%u,%u) lc=(unsafe) msg=\"%s\"\n",
                    idx, pm_diagnostic_type(d), error_level_name(pm_diagnostic_error_level(d)),
                    (unsigned) loc.start, (unsigned) loc.length, pm_diagnostic_message(d));
            }
        }
    }

    if (pm_parser_warnings_size(parser) > 0) {
        puts("warnings:");
        size_t idx = 0;
        for (const pm_diagnostic_t *d = pm_parser_warnings_first(parser); d != NULL; d = pm_diagnostic_next(d), idx++) {
            pm_location_t loc = pm_diagnostic_location(d);
            pm_line_column_t lc = { 0, 0 };
            if (explain_safe_line_column(lo, pm_parser_start_line(parser), run->analysis.line_offsets_can_query, loc.start, &lc)) {
                printf("  [%zu] type=%s level=%s loc=(%u,%u) lc=(%d:%u) msg=\"%s\"\n",
                    idx, pm_diagnostic_type(d), warning_level_name(pm_diagnostic_warning_level(d)),
                    (unsigned) loc.start, (unsigned) loc.length, (int) lc.line, (unsigned) lc.column,
                    pm_diagnostic_message(d));
            } else {
                printf("  [%zu] type=%s level=%s loc=(%u,%u) lc=(unsafe) msg=\"%s\"\n",
                    idx, pm_diagnostic_type(d), warning_level_name(pm_diagnostic_warning_level(d)),
                    (unsigned) loc.start, (unsigned) loc.length, pm_diagnostic_message(d));
            }
        }
    }

    if (pm_parser_comments_size(parser) > 0) {
        puts("comments:");
        size_t idx = 0;
        for (const pm_comment_t *c = pm_parser_comments_first(parser); c != NULL; c = pm_comment_next(c), idx++) {
            pm_location_t loc = pm_comment_location(c);
            const char *ctype = pm_comment_type(c) == PM_COMMENT_EMBDOC ? "embdoc" : "inline";
            printf("  [%zu] %s loc=(%u,%u)\n", idx, ctype, (unsigned) loc.start, (unsigned) loc.length);
        }
    }

    if (cfg->check_anomalies) {
        print_anomalies_section(&run->analysis, parser);
    }

    if (cfg->print_errors_format && pm_parser_errors_size(parser) > 0) {
        if (run->errfmt_buf != NULL && pm_buffer_length(run->errfmt_buf) > 0) {
            puts("errors_format:");
            fwrite(pm_buffer_value(run->errfmt_buf), 1, pm_buffer_length(run->errfmt_buf), stdout);
            if (pm_buffer_value(run->errfmt_buf)[pm_buffer_length(run->errfmt_buf) - 1] != '\n') {
                putchar('\n');
            }
        } else if (!run->analysis.line_offsets_can_query || !run->analysis.errors_locs_safe) {
            puts("errors_format: (skipped: unsafe line_offsets or OOB diagnostic span)");
        }
    }

    if (cfg->print_ast && run->node != NULL) {
        if (run->pretty_buf != NULL) {
            puts("ast:");
            print_annotated_prettyprint(run->pretty_buf, cfg->check_anomalies ? &run->analysis : NULL, NULL);
        } else {
            puts("ast:         (safe fallback: skipped pm_prettyprint due to OOB sub-location or invalid line_offsets)");
            safe_ast_print_ctx_t pctx = { .analysis = &run->analysis, .next_idx = 0 };
            print_safe_ast_node(&pctx, run->node, 0, NULL);
        }
    }

    if (run->json_buf != NULL) {
        puts("json:");
        fwrite(pm_buffer_value(run->json_buf), 1, pm_buffer_length(run->json_buf), stdout);
        if (pm_buffer_length(run->json_buf) > 0 && pm_buffer_value(run->json_buf)[pm_buffer_length(run->json_buf) - 1] != '\n') {
            putchar('\n');
        }
    }

    if (run->ser_buf != NULL) {
        const uint8_t *sb = (const uint8_t *) pm_buffer_value(run->ser_buf);
        size_t slen = pm_buffer_length(run->ser_buf);
        printf("serialize:   %zu bytes\n  hex:", slen);
        size_t show = slen < 128 ? slen : 128;
        for (size_t i = 0; i < show; i++) {
            printf(" %02x", sb[i]);
        }
        if (show < slen) {
            printf(" ... (%zu more bytes)", slen - show);
        }
        putchar('\n');
    }
}

void explain_compare_stream_vs_buffer(
    const uint8_t *src_buf,
    size_t src_len,
    const pm_options_t *options,
    const explain_cfg_t *cfg
) {
    parsed_run_t full_run;
    parsed_run_t stream_run;

    if (!explain_run_parse(&full_run, src_buf, src_len, options, false, false, cfg->check_anomalies, true, true, false, false)) {
        fprintf(stderr, "Failed to allocate buffer parse\n");
        return;
    }
    if (!explain_run_parse(&stream_run, src_buf, src_len, options, true, false, cfg->check_anomalies, true, true, false, false)) {
        fprintf(stderr, "Failed to allocate stream parse\n");
        explain_parsed_run_free(&full_run);
        return;
    }

    const pm_location_t *fdloc = pm_parser_data_loc(full_run.parser);
    const pm_location_t *sdloc = pm_parser_data_loc(stream_run.parser);
    const char *full_pp = full_run.pretty_buf ? pm_buffer_value(full_run.pretty_buf) : "";
    size_t full_pp_len = full_run.pretty_buf ? pm_buffer_length(full_run.pretty_buf) : 0;
    const char *stream_pp = stream_run.pretty_buf ? pm_buffer_value(stream_run.pretty_buf) : "";
    size_t stream_pp_len = stream_run.pretty_buf ? pm_buffer_length(stream_run.pretty_buf) : 0;

    bool pp_eq = (full_run.pretty_buf != NULL) == (stream_run.pretty_buf != NULL) &&
                 (full_pp_len == stream_pp_len) && (full_pp_len == 0 || memcmp(full_pp, stream_pp, full_pp_len) == 0);

    const uint8_t *full_ser = full_run.ser_buf ? (const uint8_t *) pm_buffer_value(full_run.ser_buf) : NULL;
    size_t full_ser_len = full_run.ser_buf ? pm_buffer_length(full_run.ser_buf) : 0;
    const uint8_t *stream_ser = stream_run.ser_buf ? (const uint8_t *) pm_buffer_value(stream_run.ser_buf) : NULL;
    size_t stream_ser_len = stream_run.ser_buf ? pm_buffer_length(stream_run.ser_buf) : 0;
    bool ser_eq = (full_ser_len == stream_ser_len) &&
                  (full_ser_len == 0 || (full_ser != NULL && stream_ser != NULL && memcmp(full_ser, stream_ser, full_ser_len) == 0));

    puts("stream_compare:");
    printf("  parsed_size: buffer=%zu stream=%zu\n", full_run.parsed_size, stream_run.parsed_size);
    printf("  data_loc:    buffer=(%u,%u) stream=(%u,%u)\n",
        (unsigned) fdloc->start, (unsigned) fdloc->length,
        (unsigned) sdloc->start, (unsigned) sdloc->length);
    printf("  errors:      buffer=%zu stream=%zu\n",
        pm_parser_errors_size(full_run.parser), pm_parser_errors_size(stream_run.parser));
    printf("  warnings:    buffer=%zu stream=%zu\n",
        pm_parser_warnings_size(full_run.parser), pm_parser_warnings_size(stream_run.parser));
    if (cfg->check_anomalies) {
        printf("  anomalies:   buffer=%zu stream=%zu\n",
            full_run.analysis.count, stream_run.analysis.count);
    }
    printf("  encoding:    buffer=%s stream=%s\n",
        pm_parser_encoding_name(full_run.parser), pm_parser_encoding_name(stream_run.parser));

    if (pp_eq) {
        printf("  prettyprint: EQUAL (%zu bytes)\n", full_pp_len);
    } else {
        size_t idx = explain_first_buffer_diff((const uint8_t *) full_pp, full_pp_len, (const uint8_t *) stream_pp, stream_pp_len);
        printf("  prettyprint: DIFF (buffer=%zu stream=%zu first_diff=%zu)\n", full_pp_len, stream_pp_len, idx);
        puts("  -- buffer prettyprint --");
        if (full_run.pretty_buf != NULL) {
            print_annotated_prettyprint(full_run.pretty_buf, cfg->check_anomalies ? &full_run.analysis : NULL, NULL);
        } else if (full_run.node != NULL) {
            safe_ast_print_ctx_t pctx = { .analysis = &full_run.analysis, .next_idx = 0 };
            print_safe_ast_node(&pctx, full_run.node, 0, NULL);
        }
        puts("  -- stream prettyprint --");
        if (stream_run.pretty_buf != NULL) {
            print_annotated_prettyprint(stream_run.pretty_buf, cfg->check_anomalies ? &stream_run.analysis : NULL, NULL);
        } else if (stream_run.node != NULL) {
            safe_ast_print_ctx_t pctx = { .analysis = &stream_run.analysis, .next_idx = 0 };
            print_safe_ast_node(&pctx, stream_run.node, 0, NULL);
        }
    }

    if (ser_eq) {
        printf("  serialize:   EQUAL (%zu bytes)\n", full_ser_len);
    } else {
        size_t idx = explain_first_buffer_diff(full_ser ? full_ser : (const uint8_t *) "", full_ser_len,
                                               stream_ser ? stream_ser : (const uint8_t *) "", stream_ser_len);
        unsigned b_buf = (full_ser != NULL && idx < full_ser_len) ? (unsigned) full_ser[idx] : 0;
        unsigned b_str = (stream_ser != NULL && idx < stream_ser_len) ? (unsigned) stream_ser[idx] : 0;
        printf("  serialize:   DIFF (buffer=%zu stream=%zu first_diff=%zu buf=0x%02x stream=0x%02x)\n",
            full_ser_len, stream_ser_len, idx, b_buf, b_str);
    }

    if (stream_run.parsed_size < src_len) {
        parsed_run_t prefix_run;
        if (explain_run_parse(&prefix_run, src_buf, stream_run.parsed_size, options, false, false, false, false, true, false, false)) {
            const uint8_t *pfx_ser = prefix_run.ser_buf ? (const uint8_t *) pm_buffer_value(prefix_run.ser_buf) : NULL;
            size_t pfx_len = prefix_run.ser_buf ? pm_buffer_length(prefix_run.ser_buf) : 0;
            bool pfx_eq = (pfx_len == stream_ser_len) &&
                          (pfx_len == 0 || (pfx_ser != NULL && stream_ser != NULL && memcmp(pfx_ser, stream_ser, pfx_len) == 0));
            if (pfx_eq) {
                printf("  prefix_ser:  EQUAL (%zu bytes on source[0..%zu))\n", pfx_len, stream_run.parsed_size);
            } else {
                size_t idx = explain_first_buffer_diff(pfx_ser ? pfx_ser : (const uint8_t *) "", pfx_len,
                                                       stream_ser ? stream_ser : (const uint8_t *) "", stream_ser_len);
                printf("  prefix_ser:  DIFF (prefix=%zu stream=%zu first_diff=%zu)\n", pfx_len, stream_ser_len, idx);
            }
            explain_parsed_run_free(&prefix_run);
        }
    }

    explain_parsed_run_free(&stream_run);
    explain_parsed_run_free(&full_run);
}
