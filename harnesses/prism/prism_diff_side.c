#define _GNU_SOURCE

#include <prism.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PRISM_FUZZ_ALLOW_STREAM_WITH_IJON 1
#include "fuzz_options.h"
#include "fuzz_serialize_scan.h"
#ifdef PRISM_FUZZ_IJON
#include "prism_ijon.h"
#endif
#include "prism_diff_side.h"

#ifndef FUZZ_IJON_SIDE_SALT
#define FUZZ_IJON_SIDE_SALT 0U
#endif

#define FUZZ_STR_HELPER(x) #x
#define FUZZ_STR(x) FUZZ_STR_HELPER(x)

#ifndef FUZZ_GIT_COMMIT
#define FUZZ_GIT_COMMIT unknown
#endif

#ifndef FUZZ_GIT_DIRTY
#define FUZZ_GIT_DIRTY unknown
#endif

static uint8_t *fuzz_dup_bytes(const char *src, size_t len) {
    uint8_t *copy = (uint8_t *) malloc(len > 0 ? len : 1);
    if (copy == NULL) abort();
    if (len > 0 && src != NULL) memcpy(copy, src, len);
    return copy;
}

__attribute__((visibility("default")))
fuzz_prism_side_info_t fuzz_prism_side_info(void) {
    return (fuzz_prism_side_info_t) {
        .version = pm_version(),
        .git_commit = FUZZ_STR(FUZZ_GIT_COMMIT),
        .git_dirty = FUZZ_STR(FUZZ_GIT_DIRTY),
    };
}

__attribute__((visibility("default")))
void fuzz_prism_side_free(fuzz_prism_side_result_t *res) {
    if (res == NULL) return;
    free(res->serialized);
    free(res->prettyprint);
    memset(res, 0, sizeof(*res));
}

__attribute__((visibility("default")))
void fuzz_prism_side_locate_serialize(
    const uint8_t *buf,
    size_t len,
    size_t query_off,
    fuzz_prism_serialize_loc_t *out
) {
    if (out == NULL) return;
    memset(out, 0, sizeof(*out));
    fuzz_serialize_layout_t layout;
    bool ok = fuzz_serialize_locate_offset(
        buf,
        len,
        true,
        query_off,
        &layout,
        out->section,
        sizeof(out->section),
        out->node_type,
        sizeof(out->node_type)
    );
    out->valid = ok && layout.valid;
    out->meta_end = layout.meta_end;
    out->ast_start = layout.ast_start;
    out->cpool_offset = layout.cpool_offset;
    out->cpool_size = layout.cpool_size;
    out->cpool_str_start = layout.cpool_str_start;
}

__attribute__((visibility("default")))
void fuzz_prism_side_run(const uint8_t *input, size_t size, fuzz_prism_side_result_t *out) {
    memset(out, 0, sizeof(*out));
    if (input == NULL || size < 4) return;

    fuzz_options_t opts;
    fuzz_options_decode(input, &opts);

    const uint8_t *body = input + 4;
    size_t body_len = size - 4;
    uint8_t *source_buf = (uint8_t *) malloc(body_len > 0 ? body_len : 1);
    if (source_buf == NULL) abort();
    if (body_len > 0) memcpy(source_buf, body, body_len);

    pm_options_t *options = pm_options_new();
    if (options == NULL) abort();
    fuzz_options_populate(options, &opts, source_buf, body_len, true);

    pm_arena_t *arena = pm_arena_new();
    if (arena == NULL) abort();

    pm_parser_t *parser = NULL;
    pm_node_t *node = NULL;
    size_t parsed_size = body_len;
#if !defined(PRISM_FUZZ_NO_STREAM)
    pm_source_t *stream_src = NULL;
    fuzz_stream_t stream_state = {
        .data = source_buf,
        .size = body_len,
        .pos = 0,
        .eof = false,
    };
    if (opts.stream_mode) {
        stream_src = pm_source_stream_new(&stream_state, fuzz_stream_fgets, fuzz_stream_feof);
        if (stream_src == NULL) abort();
        node = pm_parse_stream(&parser, arena, stream_src, options);
        if (parser == NULL) abort();
        parsed_size = pm_source_length(stream_src);
    } else
#endif
    {
        parser = pm_parser_new(arena, source_buf, body_len, options);
        if (parser == NULL) abort();
        node = pm_parse(parser);
#ifdef PRISM_FUZZ_IJON
        fuzz_ijon_post_parse(arena, parser, node, FUZZ_IJON_SIDE_SALT);
#endif
        const uint8_t *pstart = pm_parser_start(parser);
        const uint8_t *pend = pm_parser_end(parser);
        parsed_size = (pend != NULL && pstart != NULL && pend >= pstart) ? (size_t) (pend - pstart) : body_len;
    }

    out->parsed_size = parsed_size <= UINT32_MAX ? (uint32_t) parsed_size : UINT32_MAX;
    out->continuable = pm_parser_continuable(parser);

    const pm_location_t *dloc = pm_parser_data_loc(parser);
    if (dloc != NULL && dloc->length > 0) {
        out->has_data_loc = true;
        out->data_loc_start = dloc->start;
        out->data_loc_length = dloc->length;
    }

    out->error_count = (uint32_t) pm_parser_errors_size(parser);
    out->warning_count = (uint32_t) pm_parser_warnings_size(parser);
    out->comment_count = (uint32_t) pm_parser_comments_size(parser);
    out->magic_comment_count = (uint32_t) pm_parser_magic_comments_size(parser);

    const pm_diagnostic_t *first_err = pm_parser_errors_first(parser);
    if (first_err != NULL) {
        const char *etype = pm_diagnostic_type(first_err);
        if (etype != NULL) {
            snprintf(out->first_error_type, sizeof(out->first_error_type), "%s", etype);
        }
        pm_location_t eloc = pm_diagnostic_location(first_err);
        out->first_error_start = eloc.start;
        out->first_error_length = eloc.length;
    }

    if (node != NULL) {
        pm_buffer_t *ser_buf = pm_buffer_new();
        if (ser_buf == NULL) abort();
        pm_serialize(parser, node, ser_buf);
        out->serialized_len = pm_buffer_length(ser_buf);
        out->serialized = fuzz_dup_bytes(pm_buffer_value(ser_buf), out->serialized_len);
        pm_buffer_free(ser_buf);

        pm_buffer_t *pp_buf = pm_buffer_new();
        if (pp_buf == NULL) abort();
        pm_prettyprint(pp_buf, parser, node);
        out->prettyprint_len = pm_buffer_length(pp_buf);
        out->prettyprint = (char *) fuzz_dup_bytes(pm_buffer_value(pp_buf), out->prettyprint_len);
        pm_buffer_free(pp_buf);
    }

    pm_parser_free(parser);
#if !defined(PRISM_FUZZ_NO_STREAM)
    if (stream_src != NULL) {
        pm_source_free(stream_src);
    }
#endif
    pm_arena_free(arena);
    pm_options_free(options);
    free(source_buf);
}
