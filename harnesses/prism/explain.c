#include "explain/explain.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

static void print_usage(FILE *out, const char *prog) {
    fprintf(out,
        "Usage: %s [OPTIONS] [FILE ...]\n"
        "\n"
        "Inspect Prism fuzzer inputs (4-byte header + Ruby payload) or Ruby snippets.\n"
        "\n"
        "Input selection:\n"
        "  -e, --code CODE        Inline Ruby snippet (repeatable)\n"
        "      --raw              Treat FILE or '-' stdin as raw fuzzer input (default for files)\n"
        "  -s, --snippet          Treat FILE or '-' stdin as plain Ruby source (no 4-byte header)\n"
        "      --header HEX       8-hex-digit fuzz options header override (e.g. 40000301)\n"
        "      --stream           Force stream_mode (pm_parse_stream)\n"
        "\n"
        "Diagnostics & output:\n"
        "      --compare-stream   Parse with both pm_parse and pm_parse_stream and diff results\n"
        "      --no-ast           Omit pm_prettyprint AST dump\n"
        "      --no-anomalies     Disable AST span/relation/invariant anomaly checks & annotations\n"
        "      --json             Print pm_dump_json output\n"
        "      --digest           Emit compact single-line JSON digest per input\n"
        "      --serialize        Print pm_serialize byte length and hex dump\n"
        "      --line-offsets     Print every line offset entry (default prints up to 32)\n"
        "      --no-errors-format Omit pm_errors_format source snippet block\n"
        "  -h, --help             Show this help message\n",
        prog);
}

static int hex_nibble(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static bool parse_header_hex(const char *hex, uint8_t out[4]) {
    if (hex == NULL || strlen(hex) != 8) return false;
    for (size_t i = 0; i < 4; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t) ((hi << 4) | lo);
    }
    return true;
}

static uint8_t *read_stream_all(FILE *fp, size_t *out_size) {
    size_t cap = 4096;
    size_t len = 0;
    uint8_t *buf = malloc(cap);
    if (buf == NULL) return NULL;

    for (;;) {
        if (len == cap) {
            if (cap > SIZE_MAX / 2) {
                free(buf);
                return NULL;
            }
            size_t next_cap = cap * 2;
            uint8_t *grown = realloc(buf, next_cap);
            if (grown == NULL) {
                free(buf);
                return NULL;
            }
            buf = grown;
            cap = next_cap;
        }
        size_t n = fread(buf + len, 1, cap - len, fp);
        len += n;
        if (n == 0) break;
    }

    *out_size = len;
    return buf;
}

static uint8_t *read_file_all(const char *path, size_t *out_size) {
    if (strcmp(path, "-") == 0) {
        return read_stream_all(stdin, out_size);
    }
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) return NULL;
    uint8_t *buf = read_stream_all(fp, out_size);
    fclose(fp);
    return buf;
}

static bool explain_one_input(const explain_input_t *in, const explain_cfg_t *cfg) {
    uint8_t hdr[4] = { 0x00, 0x00, 0x03, 0x01 };
    const uint8_t *src_buf = (const uint8_t *) "";
    size_t src_len = 0;

    bool treat_as_snippet = in->is_inline || cfg->snippet_mode;
    if (cfg->raw_mode && !in->is_inline) {
        treat_as_snippet = false;
    }

    if (treat_as_snippet) {
        src_buf = (in->size > 0 && in->data != NULL) ? in->data : (const uint8_t *) "";
        src_len = in->size;
    } else {
        if (in->size < 4) {
            fprintf(stderr, "Error: '%s' is %zu bytes (< 4-byte fuzzer header; pass --snippet for plain Ruby source)\n",
                in->label, in->size);
            return false;
        }
        memcpy(hdr, in->data, 4);
        src_len = in->size - 4;
        src_buf = (src_len > 0) ? (in->data + 4) : (const uint8_t *) "";
    }

    if (cfg->has_header_hex) {
        memcpy(hdr, cfg->header_hex_bytes, 4);
    }
    if (cfg->force_stream) {
        hdr[0] |= 0x40U;
    }

    fuzz_options_t opts;
    explain_decode_options(hdr, &opts);

    pm_options_t *options = pm_options_new();
    explain_populate_options(options, &opts, src_buf, src_len);

    if (cfg->print_digest) {
        parsed_run_t run;
        if (!explain_run_parse(&run, src_buf, src_len, options, opts.stream_mode, opts.attach_comments,
                               true, false, cfg->print_serialize, false, false)) {
            fprintf(stderr, "Error: failed to initialize parser for '%s'\n", in->label);
            pm_options_free(options);
            return false;
        }
        explain_emit_digest_json(&run, in->label, &opts, options, src_buf, src_len, cfg->compare_stream);
        explain_parsed_run_free(&run);
        pm_options_free(options);
        return true;
    }

    printf("== %s (%zu source bytes) ==\n", in->label, src_len);
    explain_print_decoded_options(hdr, &opts, src_len);
    fputs("source:      ", stdout);
    explain_print_escaped_slice(stdout, src_buf, src_len, 240);
    putchar('\n');

    parsed_run_t run;
    if (!explain_run_parse(&run, src_buf, src_len, options, opts.stream_mode, opts.attach_comments,
                           cfg->check_anomalies, cfg->print_ast, cfg->print_serialize, cfg->print_json, cfg->print_errors_format)) {
        fprintf(stderr, "Error: failed to initialize parser for '%s'\n", in->label);
        pm_options_free(options);
        return false;
    }

    explain_print_single_parse_details(&run, src_buf, opts.stream_mode, cfg);
    explain_parsed_run_free(&run);

    if (cfg->compare_stream) {
        explain_compare_stream_vs_buffer(src_buf, src_len, options, cfg);
    }

    pm_options_free(options);
    return true;
}

int main(int argc, char **argv) {
    explain_cfg_t cfg = {
        .raw_mode = false,
        .snippet_mode = false,
        .has_header_hex = false,
        .header_hex_bytes = { 0x00, 0x00, 0x03, 0x01 },
        .force_stream = false,
        .compare_stream = false,
        .print_ast = true,
        .check_anomalies = true,
        .print_json = false,
        .print_digest = false,
        .print_serialize = false,
        .print_line_offsets = false,
        .print_errors_format = true,
    };

    size_t cap = (size_t) (argc > 1 ? argc : 1);
    explain_input_t *inputs = calloc(cap, sizeof(explain_input_t));
    if (inputs == NULL) return 2;
    size_t count = 0;

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            print_usage(stdout, argv[0]);
            free(inputs);
            return 0;
        } else if (strcmp(arg, "--raw") == 0) {
            cfg.raw_mode = true;
            cfg.snippet_mode = false;
        } else if (strcmp(arg, "-s") == 0 || strcmp(arg, "--snippet") == 0) {
            cfg.snippet_mode = true;
            cfg.raw_mode = false;
        } else if (strcmp(arg, "--stream") == 0) {
            cfg.force_stream = true;
        } else if (strcmp(arg, "--compare-stream") == 0) {
            cfg.compare_stream = true;
        } else if (strcmp(arg, "--no-ast") == 0) {
            cfg.print_ast = false;
        } else if (strcmp(arg, "--no-anomalies") == 0) {
            cfg.check_anomalies = false;
        } else if (strcmp(arg, "--json") == 0) {
            cfg.print_json = true;
        } else if (strcmp(arg, "--digest") == 0) {
            cfg.print_digest = true;
        } else if (strcmp(arg, "--serialize") == 0) {
            cfg.print_serialize = true;
        } else if (strcmp(arg, "--line-offsets") == 0) {
            cfg.print_line_offsets = true;
        } else if (strcmp(arg, "--no-errors-format") == 0) {
            cfg.print_errors_format = false;
        } else if (strcmp(arg, "--header") == 0) {
            if (i + 1 >= argc || !parse_header_hex(argv[i + 1], cfg.header_hex_bytes)) {
                fprintf(stderr, "Error: --header requires an 8-hex-digit string (e.g. 40000301)\n");
                free(inputs);
                return 2;
            }
            cfg.has_header_hex = true;
            i++;
        } else if (strcmp(arg, "-e") == 0 || strcmp(arg, "--code") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: %s requires an argument\n", arg);
                free(inputs);
                return 2;
            }
            const char *code = argv[++i];
            size_t len = strlen(code);
            uint8_t *copy = len > 0 ? malloc(len) : NULL;
            if (len > 0 && copy == NULL) {
                free(inputs);
                return 2;
            }
            if (len > 0) memcpy(copy, code, len);
            inputs[count++] = (explain_input_t) {
                .label = "<inline>",
                .data = copy,
                .size = len,
                .is_inline = true,
            };
        } else {
            size_t flen = 0;
            uint8_t *fdata = read_file_all(arg, &flen);
            if (fdata == NULL) {
                fprintf(stderr, "Error: could not read '%s'\n", arg);
                for (size_t k = 0; k < count; k++) free(inputs[k].data);
                free(inputs);
                return 2;
            }
            inputs[count++] = (explain_input_t) {
                .label = strcmp(arg, "-") == 0 ? "<stdin>" : arg,
                .data = fdata,
                .size = flen,
                .is_inline = false,
            };
        }
    }

    if (count == 0) {
        print_usage(stderr, argv[0]);
        free(inputs);
        return 2;
    }

    bool all_ok = true;
    for (size_t i = 0; i < count; i++) {
        if (i > 0) putchar('\n');
        if (!explain_one_input(&inputs[i], &cfg)) {
            all_ok = false;
        }
    }

    for (size_t i = 0; i < count; i++) {
        free(inputs[i].data);
    }
    free(inputs);
    return all_ok ? 0 : 1;
}
