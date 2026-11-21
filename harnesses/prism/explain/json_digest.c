#include "explain.h"
#include "../include/fuzz_json.h"

#include <string.h>

static void print_json_string(FILE *out, const char *s) {
    fuzz_json_write_string(out, s, s != NULL ? strlen(s) : 0);
}

void explain_emit_digest_json(
    const parsed_run_t *run,
    const char *label,
    const fuzz_options_t *opts,
    const pm_options_t *options,
    const uint8_t *src_buf,
    size_t src_len,
    bool compare_stream
) {
    const pm_parser_t *parser = run->parser;

    putchar('{');
    fputs("\"label\":", stdout);
    print_json_string(stdout, label);
    printf(",\"parsed_size\":%zu", run->parsed_size);
    fputs(",\"encoding\":", stdout);
    print_json_string(stdout, pm_parser_encoding_name(parser));
    printf(",\"stream_mode\":%s", opts->stream_mode ? "true" : "false");
    printf(",\"continuable\":%s", pm_parser_continuable(parser) ? "true" : "false");
    printf(",\"errors\":%zu", pm_parser_errors_size(parser));
    printf(",\"warnings\":%zu", pm_parser_warnings_size(parser));

    fputs(",\"top_errors\":[", stdout);
    const char *seen_err_types[5] = { 0 };
    size_t seen_err_count = 0;
    for (const pm_diagnostic_t *d = pm_parser_errors_first(parser); d != NULL && seen_err_count < 5; d = pm_diagnostic_next(d)) {
        const char *dtype = pm_diagnostic_type(d);
        if (dtype == NULL || dtype[0] == '\0') continue;
        bool dup = false;
        for (size_t k = 0; k < seen_err_count; k++) {
            if (strcmp(seen_err_types[k], dtype) == 0) {
                dup = true;
                break;
            }
        }
        if (dup) continue;
        if (seen_err_count > 0) putchar(',');
        print_json_string(stdout, dtype);
        seen_err_types[seen_err_count++] = dtype;
    }
    putchar(']');

    printf(",\"anomaly_count\":%zu", run->analysis.count);
    fputs(",\"anomalies\":[", stdout);
    size_t emitted_anom[16];
    size_t emitted_count = 0;
    for (size_t i = 0; i < run->analysis.count && emitted_count < 16; i++) {
        const anomaly_t *e = &run->analysis.items[i];
        const char *node_type_str = NULL;
        if (e->scope != ANOMALY_SCOPE_GENERAL && e->node_idx < run->analysis.node_count) {
            node_type_str = explain_safe_node_name(run->analysis.nodes[e->node_idx].node->type);
        }
        bool dup = false;
        for (size_t j = 0; j < emitted_count; j++) {
            const anomaly_t *prev = &run->analysis.items[emitted_anom[j]];
            const char *prev_node = (prev->scope != ANOMALY_SCOPE_GENERAL && prev->node_idx < run->analysis.node_count)
                ? explain_safe_node_name(run->analysis.nodes[prev->node_idx].node->type)
                : NULL;
            if (strcmp(prev->category, e->category) == 0 &&
                strcmp(prev->kind, e->kind) == 0 &&
                ((prev_node == NULL && node_type_str == NULL) ||
                 (prev_node != NULL && node_type_str != NULL && strcmp(prev_node, node_type_str) == 0)) &&
                ((prev->field_name == NULL && e->field_name == NULL) ||
                 (prev->field_name != NULL && e->field_name != NULL && strcmp(prev->field_name, e->field_name) == 0))) {
                dup = true;
                break;
            }
        }
        if (dup) continue;
        if (emitted_count > 0) putchar(',');
        putchar('{');
        fputs("\"category\":", stdout);
        print_json_string(stdout, e->category);
        fputs(",\"kind\":", stdout);
        print_json_string(stdout, e->kind);
        if (node_type_str != NULL) {
            fputs(",\"node\":", stdout);
            print_json_string(stdout, node_type_str);
        }
        if (e->field_name != NULL) {
            fputs(",\"field\":", stdout);
            print_json_string(stdout, e->field_name);
        }
        putchar('}');
        emitted_anom[emitted_count++] = i;
    }
    putchar(']');

    if (run->ser_buf != NULL) {
        printf(",\"serialize_bytes\":%zu", pm_buffer_length(run->ser_buf));
    }

    if (compare_stream) {
        parsed_run_t full_run;
        parsed_run_t stream_run;
        if (explain_run_parse(&full_run, src_buf, src_len, options, false, false, false, true, true, false, false)) {
            if (explain_run_parse(&stream_run, src_buf, src_len, options, true, false, false, true, true, false, false)) {
                const char *full_pp = full_run.pretty_buf ? pm_buffer_value(full_run.pretty_buf) : "";
                size_t full_pp_len = full_run.pretty_buf ? pm_buffer_length(full_run.pretty_buf) : 0;
                const char *stream_pp = stream_run.pretty_buf ? pm_buffer_value(stream_run.pretty_buf) : "";
                size_t stream_pp_len = stream_run.pretty_buf ? pm_buffer_length(stream_run.pretty_buf) : 0;
                bool pp_eq = (full_run.pretty_buf != NULL) == (stream_run.pretty_buf != NULL) &&
                             (full_pp_len == stream_pp_len) &&
                             (full_pp_len == 0 || memcmp(full_pp, stream_pp, full_pp_len) == 0);

                const uint8_t *full_ser = full_run.ser_buf ? (const uint8_t *) pm_buffer_value(full_run.ser_buf) : NULL;
                size_t full_ser_len = full_run.ser_buf ? pm_buffer_length(full_run.ser_buf) : 0;
                const uint8_t *stream_ser = stream_run.ser_buf ? (const uint8_t *) pm_buffer_value(stream_run.ser_buf) : NULL;
                size_t stream_ser_len = stream_run.ser_buf ? pm_buffer_length(stream_run.ser_buf) : 0;
                bool ser_eq = (full_ser_len == stream_ser_len) &&
                              (full_ser_len == 0 || (full_ser != NULL && stream_ser != NULL && memcmp(full_ser, stream_ser, full_ser_len) == 0));

                printf(",\"stream_compare\":{\"parsed_size\":[%zu,%zu],\"prettyprint_equal\":%s,\"serialize_equal\":%s",
                    full_run.parsed_size, stream_run.parsed_size,
                    pp_eq ? "true" : "false",
                    ser_eq ? "true" : "false");
                if (!ser_eq) {
                    size_t idx = explain_first_buffer_diff(full_ser ? full_ser : (const uint8_t *) "", full_ser_len,
                                                           stream_ser ? stream_ser : (const uint8_t *) "", stream_ser_len);
                    printf(",\"serialize_diff_offset\":%zu", idx);
                }
                putchar('}');
                explain_parsed_run_free(&stream_run);
            }
            explain_parsed_run_free(&full_run);
        }
    }

    puts("}");
}
