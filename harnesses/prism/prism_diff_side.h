#ifndef PRISM_FUZZER_PRISM_DIFF_SIDE_H
#define PRISM_FUZZER_PRISM_DIFF_SIDE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t parsed_size;
    bool continuable;
    bool has_data_loc;
    uint32_t data_loc_start;
    uint32_t data_loc_length;
    uint32_t error_count;
    uint32_t warning_count;
    uint32_t comment_count;
    uint32_t magic_comment_count;
    char first_error_type[64];
    uint32_t first_error_start;
    uint32_t first_error_length;
    uint8_t *serialized;
    size_t serialized_len;
    char *prettyprint;
    size_t prettyprint_len;
} fuzz_prism_side_result_t;

typedef struct {
    const char *version;
    const char *git_commit;
    const char *git_dirty;
} fuzz_prism_side_info_t;

void fuzz_prism_side_a_run(const uint8_t *input, size_t size, fuzz_prism_side_result_t *out);
void fuzz_prism_side_a_free(fuzz_prism_side_result_t *res);
fuzz_prism_side_info_t fuzz_prism_side_a_info(void);

void fuzz_prism_side_b_run(const uint8_t *input, size_t size, fuzz_prism_side_result_t *out);
void fuzz_prism_side_b_free(fuzz_prism_side_result_t *res);
fuzz_prism_side_info_t fuzz_prism_side_b_info(void);

#endif
