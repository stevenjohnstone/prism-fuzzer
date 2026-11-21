#ifndef PRISM_EXPLAIN_H
#define PRISM_EXPLAIN_H

#include <prism.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifndef EXPLAIN_NEED_FUZZ_OPTIONS_IMPL
#define PRISM_FUZZ_NO_STREAM 1
#define PRISM_FUZZ_NO_SHEBANG_CALLBACK 1
#endif
#include "../include/fuzz_options.h"

#define EXPLAIN_MAX_VISIT_DEPTH 4096u

typedef struct {
    bool raw_mode;
    bool snippet_mode;
    bool has_header_hex;
    uint8_t header_hex_bytes[4];
    bool force_stream;
    bool compare_stream;
    bool print_ast;
    bool check_anomalies;
    bool print_json;
    bool print_digest;
    bool print_serialize;
    bool print_line_offsets;
    bool print_errors_format;
} explain_cfg_t;

typedef struct {
    const char *label;
    uint8_t *data;
    size_t size;
    bool is_inline;
} explain_input_t;

typedef enum {
    ANOMALY_SCOPE_GENERAL = 0,
    ANOMALY_SCOPE_NODE,
    ANOMALY_SCOPE_SUB_LOC
} anomaly_scope_t;

typedef struct {
    anomaly_scope_t scope;
    size_t node_idx;
    const char *category;
    const char *kind;
    const char *field_name;
    char detail[256];
} anomaly_t;

typedef struct {
    const pm_node_t *node;
    char camel_name[64];
    pm_node_type_t parent_type;
    size_t raw_depth;
    size_t non_iter_depth;
    bool loc_valid;
    bool is_heredoc;
    bool subtree_has_heredoc;
} visited_node_t;

typedef struct {
    anomaly_t *items;
    size_t count;
    size_t cap;
    visited_node_t *nodes;
    size_t node_count;
    size_t node_cap;
    bool analyzed;
    bool line_offsets_can_query;
    bool prettyprint_locs_safe;
    bool errors_locs_safe;
    bool reported_depth_cap;
    bool reported_non_iter_depth;
    bool oom;
} parse_analysis_t;

typedef struct {
    const pm_node_t **items;
    size_t count;
    size_t cap;
    bool oom;
} node_ptr_vec_t;

typedef struct {
    pm_arena_t *arena;
    pm_parser_t *parser;
    pm_source_t *stream_src;
    pm_node_t *node;
    size_t parsed_size;
    pm_buffer_t *pretty_buf;
    pm_buffer_t *ser_buf;
    pm_buffer_t *json_buf;
    pm_buffer_t *errfmt_buf;
    parse_analysis_t analysis;
} parsed_run_t;

/* analysis.c */
void explain_decode_options(const uint8_t hdr[4], fuzz_options_t *opts);
void explain_populate_options(
    pm_options_t *options,
    const fuzz_options_t *opts,
    const uint8_t *src_buf,
    size_t src_len
);
const char *explain_safe_node_name(pm_node_type_t type);
void explain_node_camel_name(pm_node_type_t type, char *out, size_t cap);
bool explain_safe_line_column(
    const pm_line_offset_list_t *lo,
    int32_t start_line,
    bool lo_can_query,
    uint32_t offset,
    pm_line_column_t *out
);
pm_visit_result_t explain_collect_direct_child_cb(const pm_node_t *child, void *data);
void explain_parse_analysis_free(parse_analysis_t *a);
void explain_run_parse_analysis(
    parse_analysis_t *a,
    const pm_parser_t *parser,
    const pm_node_t *node,
    const uint8_t *source,
    size_t parsed_size,
    bool check_comment_order
);
void explain_parsed_run_free(parsed_run_t *run);
bool explain_run_parse(
    parsed_run_t *out,
    const uint8_t *src_buf,
    size_t src_len,
    const pm_options_t *options,
    bool stream_mode,
    bool check_comment_order,
    bool check_anomalies,
    bool want_ast,
    bool want_ser,
    bool want_json,
    bool want_errfmt
);
size_t explain_first_buffer_diff(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen);

/* prettyprint.c */
void explain_print_escaped_slice(FILE *out, const uint8_t *buf, size_t len, size_t max_chars);
void explain_print_decoded_options(const uint8_t hdr[4], const fuzz_options_t *opts, size_t src_len);
void explain_print_single_parse_details(
    const parsed_run_t *run,
    const uint8_t *src_buf,
    bool stream_mode,
    const explain_cfg_t *cfg
);
void explain_compare_stream_vs_buffer(
    const uint8_t *src_buf,
    size_t src_len,
    const pm_options_t *options,
    const explain_cfg_t *cfg
);

/* json_digest.c */
void explain_emit_digest_json(
    const parsed_run_t *run,
    const char *label,
    const fuzz_options_t *opts,
    const pm_options_t *options,
    const uint8_t *src_buf,
    size_t src_len,
    bool compare_stream
);

#endif
