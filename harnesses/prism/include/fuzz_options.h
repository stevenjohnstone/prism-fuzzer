#ifndef PRISM_FUZZ_OPTIONS_H
#define PRISM_FUZZ_OPTIONS_H

#include <limits.h>
/* Requires <prism.h> to be included by the enclosing translation unit first. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    int8_t start_line;
    uint8_t cmd_flags;
    bool main_script;
    bool freeze;
    bool partial_script;
    bool attach_comments;
    bool encoding_locked;
    const char *version;
    bool has_frozen_string_literal;
    bool frozen_string_literal;
    uint8_t scopes_count;
    uint8_t forwarding;
    bool stream_mode;
    bool has_encoding_opts;
    bool has_limit_opts;
    uint8_t aux_byte;
} fuzz_options_t;

#if (!defined(PRISM_FUZZ_IJON) || defined(PRISM_FUZZ_ALLOW_STREAM_WITH_IJON)) && !defined(PRISM_FUZZ_NO_STREAM)
#define PRISM_FUZZ_STREAM_ENABLED 1
#else
#define PRISM_FUZZ_STREAM_ENABLED 0
#endif

#if PRISM_FUZZ_STREAM_ENABLED || (defined(SLOW) && !defined(PRISM_FUZZ_NO_STREAM))
typedef struct {
    const uint8_t *data;
    size_t size;
    size_t pos;
    bool eof;
} fuzz_stream_t;

static char *fuzz_stream_fgets(char *buf, int n, void *vp) {
    fuzz_stream_t *s = (fuzz_stream_t *) vp;
    if (n <= 0) return NULL;
    if (s->pos >= s->size) {
        s->eof = true;
        return NULL;
    }
    size_t count = 0;
    size_t limit = (size_t) (n - 1);
    while (count < limit && s->pos < s->size) {
        uint8_t ch = s->data[s->pos++];
        buf[count++] = (char) ch;
        if (ch == '\n') break;
    }
    if (count < limit && (count == 0 || buf[count - 1] != '\n') && s->pos >= s->size) {
        s->eof = true;
    }
    buf[count] = '\0';
    return buf;
}

static int fuzz_stream_feof(void *vp) {
    return ((const fuzz_stream_t *) vp)->eof ? 1 : 0;
}
#endif

static inline void fuzz_string_view_init(pm_string_t *str, const uint8_t *buf, size_t len) {
#ifdef PRISM_FUZZ_LEGACY_STRING_INIT
    pm_string_constant_init(str, (const char *) buf, len);
#else
    pm_string_init(str, buf, len);
#endif
}

#ifndef PRISM_FUZZ_NO_SHEBANG_CALLBACK
static void fuzz_shebang_cb(pm_options_t *options, const uint8_t *source, size_t length, void *shebang_data) {
    (void) options;
    (void) source;
    (void) length;
    (void) shebang_data;
}
#endif

/**
 * Decode the 4-byte fuzz option header shared by all Prism fuzz harnesses.
 * Caller must ensure `input` has at least 4 readable bytes.
 */
static inline void fuzz_options_decode(const uint8_t *input, fuzz_options_t *out) {
    static const char * const versions[] = {
        "3.3",
        "3.4",
        "3.5",
        "4.1",
    };

    uint8_t opt_flags = input[0];
    *out = (fuzz_options_t) {
        .start_line = (int8_t) input[3],
        .cmd_flags = input[1] & 0x3f,
        .main_script = (input[1] & 0x40) != 0,
        .freeze = (opt_flags & 1) != 0,
        .partial_script = (opt_flags & 2) != 0,
        .attach_comments = (opt_flags & 4) != 0,
        .encoding_locked = (opt_flags & 8) != 0,
        .version = versions[input[2] & 0x03],
        .has_frozen_string_literal = (opt_flags & 16) != 0,
        .frozen_string_literal = (opt_flags & 32) != 0,
        .scopes_count = (input[2] >> 2) & 0x03,
        .forwarding = (input[2] >> 4) & 0x0f,
#if !PRISM_FUZZ_STREAM_ENABLED
        .stream_mode = false,
#else
        .stream_mode = (opt_flags & 0x40) != 0,
#endif
        .has_encoding_opts = (opt_flags & 0x80) != 0,
        .has_limit_opts = (input[1] & 0x80) != 0,
        .aux_byte = input[3],
    };
}

static inline const char *fuzz_option_encoding_name(uint8_t idx) {
    static const char * const encodings[8] = {
        "UTF-8",
        "ASCII-8BIT",
        "US-ASCII",
        "Windows-31J",
        "EUC-JP",
        "UTF-8-MAC",
        "ISO-8859-1",
        "Shift_JIS",
    };
    return encodings[idx & 0x07];
}

static inline int32_t fuzz_option_extreme_line_info(uint8_t aux_byte, const char **name_out) {
    static const struct {
        int32_t value;
        const char *name;
    } extreme_lines[4] = {
        { INT32_MAX, "INT32_MAX" },
        { INT32_MAX - 4, "INT32_MAX-4" },
        { INT32_MIN, "INT32_MIN" },
        { 0, "0" },
    };
    const unsigned idx = (unsigned) ((aux_byte >> 4) & 0x03);
    if (name_out != NULL) *name_out = extreme_lines[idx].name;
    return extreme_lines[idx].value;
}

static inline int32_t fuzz_option_extreme_line(uint8_t aux_byte) {
    return fuzz_option_extreme_line_info(aux_byte, NULL);
}

static inline const char *fuzz_option_extreme_line_name(uint8_t aux_byte) {
    const char *name = NULL;
    (void) fuzz_option_extreme_line_info(aux_byte, &name);
    return name;
}

static inline int32_t fuzz_option_effective_start_line(const fuzz_options_t *opts) {
    return opts->has_limit_opts
        ? fuzz_option_extreme_line(opts->aux_byte)
        : (int32_t) opts->start_line;
}

static inline size_t fuzz_option_stack_budget_info(uint8_t aux_byte, const char **name_out) {
    static const struct {
        size_t value;
        const char *name;
    } budgets[4] = {
        { SIZE_MAX, "SIZE_MAX" },
        { 0, "0" },
        { 512, "512" },
        { 4096, "4096" },
    };
    const unsigned idx = (unsigned) ((aux_byte >> 6) & 0x03);
    if (name_out != NULL) *name_out = budgets[idx].name;
    return budgets[idx].value;
}

static inline size_t fuzz_option_stack_budget(uint8_t aux_byte) {
    return fuzz_option_stack_budget_info(aux_byte, NULL);
}

static inline const char *fuzz_option_stack_budget_name(uint8_t aux_byte) {
    const char *name = NULL;
    (void) fuzz_option_stack_budget_info(aux_byte, &name);
    return name;
}

static inline size_t fuzz_option_forwarding_scope(const fuzz_options_t *opts) {
    if (opts->scopes_count == 0) {
        return 0;
    }
    return opts->has_encoding_opts
        ? (size_t) (opts->aux_byte % opts->scopes_count)
        : (size_t) (opts->scopes_count - 1);
}

/**
 * Populate an allocated `pm_options_t` from decoded fuzz options.
 * When `clamp_stack_budget` is true (cross-ABI oracle vs target comparison),
 * keep `stack_budget` at `SIZE_MAX` so stack frame size differences between
 * architectures/sanitizers cannot trigger spurious PM_ERR_STACK_EXHAUSTED mismatches.
 */
static inline void fuzz_options_populate(
    pm_options_t *options,
    const fuzz_options_t *opts,
    const uint8_t *source_buf,
    size_t size,
    bool clamp_stack_budget
) {
    pm_options_line_set(options, opts->start_line);
#ifndef PRISM_FUZZ_NO_COMMAND_LINE
    pm_options_command_line_set(options, opts->cmd_flags);
#endif
#ifndef PRISM_FUZZ_NO_MAIN_SCRIPT
    pm_options_main_script_set(options, opts->main_script);
#endif
#ifndef PRISM_FUZZ_NO_FREEZE
    pm_options_freeze_set(options, opts->freeze);
#endif
#ifndef PRISM_FUZZ_NO_PARTIAL_SCRIPT
    pm_options_partial_script_set(options, opts->partial_script);
#endif
#ifndef PRISM_FUZZ_NO_ATTACH_COMMENTS
    pm_options_attach_comments_set(options, opts->attach_comments);
#endif
#ifndef PRISM_FUZZ_NO_ENCODING_LOCKED
    pm_options_encoding_locked_set(options, opts->encoding_locked);
#endif
#ifndef PRISM_FUZZ_NO_VERSION_SET
    pm_options_version_set(options, opts->version, strlen(opts->version));
#endif

#ifndef PRISM_FUZZ_NO_FROZEN_STRING_LITERAL
    if (opts->has_frozen_string_literal) {
        pm_options_frozen_string_literal_set(options, opts->frozen_string_literal);
    }
#endif

    if (opts->has_encoding_opts) {
        pm_options_encoding_set(options, fuzz_option_encoding_name(opts->aux_byte));
        pm_options_filepath_set(options, "fuzz.rb");
#ifndef PRISM_FUZZ_NO_SHEBANG_CALLBACK
        if ((opts->aux_byte & 0x08) != 0) {
            pm_options_shebang_callback_set(options, fuzz_shebang_cb, NULL);
        }
#endif
    }

    if (opts->has_limit_opts) {
        pm_options_line_set(options, fuzz_option_extreme_line(opts->aux_byte));
#ifndef PRISM_FUZZ_NO_STACK_BUDGET
        if (clamp_stack_budget) {
            pm_options_stack_budget_set(options, SIZE_MAX);
        } else {
            pm_options_stack_budget_set(options, fuzz_option_stack_budget(opts->aux_byte));
        }
#else
        (void) clamp_stack_budget;
#endif
    }

    if (opts->scopes_count > 0) {
#ifdef PRISM_FUZZ_VOID_SCOPES_INIT
        pm_options_scopes_init(options, opts->scopes_count);
        bool scopes_ok = true;
#else
        bool scopes_ok = pm_options_scopes_init(options, opts->scopes_count);
#endif
        if (scopes_ok) {
            static const char * const scope_locals[][2] = {
                { "a", "foo" },
                { "b", "it" },
                { "c", "_1" },
            };
#ifndef PRISM_FUZZ_NO_SCOPE_FORWARDING
            size_t forwarding_scope = fuzz_option_forwarding_scope(opts);
#endif

            for (size_t i = 0; i < opts->scopes_count; i++) {
#ifdef PRISM_FUZZ_SCOPE_DIRECT
                pm_options_scope_t *scope = &options->scopes[i];
#elif defined(PRISM_FUZZ_SCOPE_GET_MUT)
                pm_options_scope_t *scope = pm_options_scope_get_mut(options, i);
#else
                pm_options_scope_t *scope = pm_options_scope_mut(options, i);
#endif
                size_t locals_count = (i == 0 && size > 0) ? 3 : 2;
                if (i == 0 && opts->has_encoding_opts && (opts->aux_byte & 0x10) != 0) {
                    locals_count = 0;
                }
                pm_options_scope_init(scope, locals_count);
#ifndef PRISM_FUZZ_NO_SCOPE_FORWARDING
                pm_options_scope_forwarding_set(scope, (i == forwarding_scope) ? opts->forwarding : PM_OPTIONS_SCOPE_FORWARDING_NONE);
#endif

                for (size_t j = 0; j < 2 && j < locals_count; j++) {
                    const char *name = scope_locals[i][j];
#ifdef PRISM_FUZZ_LOCAL_DIRECT
                    pm_string_t *local = &scope->locals[j];
#elif defined(PRISM_FUZZ_LOCAL_GET_MUT)
                    pm_string_t *local = pm_options_scope_local_get_mut(scope, j);
#else
                    pm_string_t *local = pm_options_scope_local_mut(scope, j);
#endif
                    fuzz_string_view_init(local, (const uint8_t *) name, strlen(name));
                }
                if (locals_count == 3) {
                    size_t len = size < 4 ? size : 4;
#ifdef PRISM_FUZZ_LOCAL_DIRECT
                    pm_string_t *local = &scope->locals[2];
#elif defined(PRISM_FUZZ_LOCAL_GET_MUT)
                    pm_string_t *local = pm_options_scope_local_get_mut(scope, 2);
#else
                    pm_string_t *local = pm_options_scope_local_mut(scope, 2);
#endif
                    fuzz_string_view_init(local, source_buf, len);
                }
            }
        }
    }
}

static inline void fuzz_options_dispose(pm_options_t *options) {
#if defined(PRISM_FUZZ_LEGACY_OPTIONS_STRUCT) && defined(PRISM_FUZZ_OPTIONS_CLEANUP)
    pm_options_cleanup(options);
#elif !defined(PRISM_FUZZ_LEGACY_OPTIONS_STRUCT)
    pm_options_free(options);
#else
    (void) options;
#endif
}

static inline uint32_t fuzz_read_u32_le(const uint8_t *p) {
    return ((uint32_t) p[0]) |
           (((uint32_t) p[1]) << 8) |
           (((uint32_t) p[2]) << 16) |
           (((uint32_t) p[3]) << 24);
}

static inline void fuzz_write_u32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t) (v & 0xffU);
    p[1] = (uint8_t) ((v >> 8) & 0xffU);
    p[2] = (uint8_t) ((v >> 16) & 0xffU);
    p[3] = (uint8_t) ((v >> 24) & 0xffU);
}

#endif
