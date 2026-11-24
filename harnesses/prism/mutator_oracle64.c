#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <prism.h>
#ifndef PRISM_FUZZ_NO_INTERNAL_BUFFER
#include "prism/internal/buffer.h"
#endif
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/fuzz_options.h"

#ifdef ORACLE64_REPLAY_MAIN

#ifndef ORACLE_REPLAY_QEMU_BIN
#define ORACLE_REPLAY_QEMU_BIN "/usr/bin/qemu-arm"
#endif

#ifndef ORACLE_REPLAY_QEMU_ARGV0
#define ORACLE_REPLAY_QEMU_ARGV0 "qemu-arm"
#endif

#ifndef ORACLE_REPLAY_SYSROOT
#define ORACLE_REPLAY_SYSROOT "/usr/arm-linux-gnueabihf"
#endif

#ifndef ORACLE_REPLAY_TARGET_NAME
#define ORACLE_REPLAY_TARGET_NAME "fuzz.arm32"
#endif

#ifndef ORACLE_REPLAY_TARGET_ENV
#define ORACLE_REPLAY_TARGET_ENV "FUZZ_ARM32_BIN"
#endif
#include <fcntl.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#define ORACLE64_MAGIC 0x504D3634U /* "PM64" little-endian */
#define ORACLE64_ENV_HEADER_SIZE 8U

#ifndef FUZZ_MAX_INPUT_SIZE
#define FUZZ_MAX_INPUT_SIZE 1024U
#endif

#if FUZZ_MAX_INPUT_SIZE > 1024
#if ((FUZZ_MAX_INPUT_SIZE + 4) * 256) > 1048576
#define ORACLE64_MAX_ENVELOPE_SIZE 1048576U
#else
#define ORACLE64_MAX_ENVELOPE_SIZE (((size_t) FUZZ_MAX_INPUT_SIZE + 4U) * 256U)
#endif
#else
#define ORACLE64_MAX_ENVELOPE_SIZE 262144U
#endif

typedef struct {
    pm_buffer_t *ast_buf;
    uint8_t *out_buf;
    size_t out_cap;
} oracle64_state_t;

static void oracle64_state_init(oracle64_state_t *st) {
    memset(st, 0, sizeof(*st));
    st->ast_buf = pm_buffer_new();
    st->out_cap = 65536;
    st->out_buf = malloc(st->out_cap);
}

static void oracle64_state_cleanup(oracle64_state_t *st) {
    if (st == NULL) return;
    if (st->ast_buf != NULL) {
        pm_buffer_free(st->ast_buf);
        st->ast_buf = NULL;
    }
    free(st->out_buf);
    st->out_buf = NULL;
    st->out_cap = 0;
}

static const uint8_t *oracle64_build_envelope(
    oracle64_state_t *st,
    const uint8_t *raw,
    size_t raw_size,
    size_t *out_len
) {
    *out_len = 0;
    if (st == NULL || st->ast_buf == NULL || raw == NULL || raw_size < 4 || (raw_size - 4) > (size_t) FUZZ_MAX_INPUT_SIZE) {
        return NULL;
    }

    fuzz_options_t opts;
    fuzz_options_decode(raw, &opts);

    const uint8_t *src = raw + 4;
    size_t src_len = raw_size - 4;
    const uint8_t *src_buf = (src_len == 0) ? (const uint8_t *) "" : src;

    pm_options_t *options = pm_options_new();
    pm_arena_t *arena = pm_arena_new();
    if (options == NULL || arena == NULL) {
        if (arena != NULL) pm_arena_free(arena);
        if (options != NULL) pm_options_free(options);
        return NULL;
    }
    fuzz_options_populate(options, &opts, src_buf, src_len, true);

    pm_source_t *stream_src = NULL;
    pm_parser_t *parser = NULL;
    pm_node_t *node = NULL;

    if (opts.stream_mode) {
        fuzz_stream_t stream_state = {
            .data = src_buf,
            .size = src_len,
            .pos = 0,
            .eof = false,
        };
        stream_src = pm_source_stream_new(&stream_state, fuzz_stream_fgets, fuzz_stream_feof);
        if (stream_src == NULL) {
            pm_arena_free(arena);
            pm_options_free(options);
            return NULL;
        }
        node = pm_parse_stream(&parser, arena, stream_src, options);
    } else {
        parser = pm_parser_new(arena, src_buf, src_len, options);
        if (parser != NULL) {
            node = pm_parse(parser);
        }
    }

    if (parser == NULL || node == NULL) {
        if (parser != NULL) pm_parser_free(parser);
        if (stream_src != NULL) pm_source_free(stream_src);
        pm_arena_free(arena);
        pm_options_free(options);
        return NULL;
    }

    pm_buffer_clear(st->ast_buf);
    pm_serialize(parser, node, st->ast_buf);

    size_t olen = pm_buffer_length(st->ast_buf);
    const char *oval = pm_buffer_value(st->ast_buf);

    if (stream_src != NULL) {
        pm_source_free(stream_src);
    }
    pm_parser_free(parser);
    pm_arena_free(arena);
    pm_options_free(options);

    if (olen < 9 || olen > UINT32_MAX || oval == NULL) {
        return NULL;
    }
    if (raw_size > (size_t) ORACLE64_MAX_ENVELOPE_SIZE - ORACLE64_ENV_HEADER_SIZE ||
        olen > (size_t) ORACLE64_MAX_ENVELOPE_SIZE - ORACLE64_ENV_HEADER_SIZE - raw_size) {
        return NULL;
    }

    size_t need = ORACLE64_ENV_HEADER_SIZE + olen + raw_size;
    if (need > st->out_cap) {
        size_t new_cap = st->out_cap ? st->out_cap : 65536;
        while (new_cap < need) {
            if (new_cap > (size_t) ORACLE64_MAX_ENVELOPE_SIZE / 2) {
                new_cap = need;
                break;
            }
            new_cap *= 2;
        }
        uint8_t *grown = realloc(st->out_buf, new_cap);
        if (grown == NULL) {
            return NULL;
        }
        st->out_buf = grown;
        st->out_cap = new_cap;
    }

    if (st->out_buf == NULL) {
        return NULL;
    }

    fuzz_write_u32_le(st->out_buf, ORACLE64_MAGIC);
    fuzz_write_u32_le(st->out_buf + 4, (uint32_t) olen);
    memcpy(st->out_buf + ORACLE64_ENV_HEADER_SIZE, oval, olen);
    memcpy(st->out_buf + ORACLE64_ENV_HEADER_SIZE + olen, raw, raw_size);

    *out_len = need;
    return st->out_buf;
}

#ifdef ORACLE64_REPLAY_MAIN

static int write_all(int fd, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t) n;
    }
    return 0;
}

static uint8_t *read_fd_all(FILE *fp, size_t *out_len) {
    size_t cap = 4096;
    size_t len = 0;
    uint8_t *buf = malloc(cap);
    if (buf == NULL) return NULL;

    for (;;) {
        if (len == cap) {
            cap *= 2;
            uint8_t *next = realloc(buf, cap);
            if (next == NULL) {
                free(buf);
                return NULL;
            }
            buf = next;
        }
        size_t n = fread(buf + len, 1, cap - len, fp);
        len += n;
        if (n == 0) {
            if (ferror(fp)) {
                free(buf);
                return NULL;
            }
            break;
        }
    }
    *out_len = len;
    return buf;
}

static uint8_t *read_input_bytes(const char *path, size_t *out_len, bool *from_stdin) {
    if (path == NULL || strcmp(path, "-") == 0) {
        *from_stdin = true;
        return read_fd_all(stdin, out_len);
    }
    *from_stdin = false;
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) return NULL;
    struct stat st;
    if (fstat(fileno(fp), &st) == 0 && S_ISREG(st.st_mode) && st.st_size >= 0) {
        size_t sz = (size_t) st.st_size;
        uint8_t *buf = malloc(sz > 0 ? sz : 1);
        if (buf == NULL) {
            fclose(fp);
            return NULL;
        }
        size_t rd = sz > 0 ? fread(buf, 1, sz, fp) : 0;
        int err = ferror(fp);
        fclose(fp);
        if (err || rd != sz) {
            free(buf);
            return NULL;
        }
        *out_len = rd;
        return buf;
    }
    uint8_t *buf = read_fd_all(fp, out_len);
    fclose(fp);
    return buf;
}

static void resolve_arm32_binary(char *out, size_t out_cap) {
    const char *env_bin = getenv(ORACLE_REPLAY_TARGET_ENV);
    if (env_bin != NULL && env_bin[0] != '\0') {
        snprintf(out, out_cap, "%s", env_bin);
        return;
    }

    char self_buf[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", self_buf, sizeof(self_buf) - 1);
    if (len > 0) {
        self_buf[len] = '\0';
        char *slash = strrchr(self_buf, '/');
        if (slash != NULL) {
            size_t dir_len = (size_t) (slash - self_buf);
            size_t tail_len = sizeof("/" ORACLE_REPLAY_TARGET_NAME);
            if (dir_len + tail_len <= out_cap) {
                memcpy(out, self_buf, dir_len);
                memcpy(out + dir_len, "/" ORACLE_REPLAY_TARGET_NAME, tail_len);
                if (access(out, X_OK) == 0) return;
            }
        }
    }
    snprintf(out, out_cap, "./tmp/fuzz/build/" ORACLE_REPLAY_TARGET_NAME);
}

static void ensure_qemu_asan_options(void) {
    const char *cur = getenv("ASAN_OPTIONS");
    if (cur == NULL || cur[0] == '\0') {
        setenv("ASAN_OPTIONS", "detect_leaks=0:abort_on_error=1:handle_abort=1:symbolize=0", 1);
        return;
    }
    if (strstr(cur, "detect_leaks=0") != NULL) {
        return;
    }
    size_t cur_len = strlen(cur);
    const char *suffix = ":detect_leaks=0";
    char *updated = malloc(cur_len + strlen(suffix) + 1);
    if (updated != NULL) {
        memcpy(updated, cur, cur_len);
        memcpy(updated + cur_len, suffix, strlen(suffix) + 1);
        setenv("ASAN_OPTIONS", updated, 1);
        free(updated);
    }
}

int main(int argc, char **argv) {
    const char *input_path = (argc >= 2) ? argv[1] : NULL;
    size_t raw_size = 0;
    bool from_stdin = false;
    uint8_t *raw = read_input_bytes(input_path, &raw_size, &from_stdin);
    if (raw == NULL) {
        fprintf(stderr, ORACLE_REPLAY_TARGET_NAME ".repro: failed to read input '%s'\n", input_path ? input_path : "<stdin>");
        return 2;
    }

    oracle64_state_t st;
    oracle64_state_init(&st);

    size_t env_len = 0;
    const uint8_t *env = oracle64_build_envelope(&st, raw, raw_size, &env_len);

    const uint8_t *memfd_data = env ? env : raw;
    size_t memfd_len = env ? env_len : raw_size;

    char fd_path[64];
    const char *target_arg = input_path;
    if (env != NULL || from_stdin) {
        int mfd = memfd_create("pm64_oracle", 0);
        if (mfd < 0 || write_all(mfd, memfd_data, memfd_len) != 0 || lseek(mfd, 0, SEEK_SET) < 0) {
            perror(ORACLE_REPLAY_TARGET_NAME ".repro: memfd_create");
            oracle64_state_cleanup(&st);
            free(raw);
            return 2;
        }
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", mfd);
        target_arg = fd_path;
    }

    oracle64_state_cleanup(&st);
    free(raw);

    char arm32_bin[PATH_MAX];
    resolve_arm32_binary(arm32_bin, sizeof(arm32_bin));
    ensure_qemu_asan_options();

    char *qemu_argv[] = {
        (char *) ORACLE_REPLAY_QEMU_ARGV0,
        (char *) "-L",
        (char *) ORACLE_REPLAY_SYSROOT,
        arm32_bin,
        (char *) target_arg,
        NULL
    };
    execv(ORACLE_REPLAY_QEMU_BIN, qemu_argv);
    perror(ORACLE_REPLAY_TARGET_NAME ".repro: execv " ORACLE_REPLAY_QEMU_ARGV0);
    return 127;
}

#else

__attribute__((visibility("default")))
void *afl_custom_init(void *afl, unsigned int seed) {
    (void) afl;
    (void) seed;
    oracle64_state_t *st = malloc(sizeof(*st));
    if (st != NULL) {
        oracle64_state_init(st);
    }
    return st;
}

__attribute__((visibility("default")))
size_t afl_custom_post_process(void *data, unsigned char *buf, size_t buf_size, unsigned char **out_buf) {
    oracle64_state_t *st = (oracle64_state_t *) data;
    size_t out_len = 0;
    const uint8_t *res = oracle64_build_envelope(st, buf, buf_size, &out_len);
    if (res == NULL || out_len == 0) {
        *out_buf = NULL;
        return 0;
    }
    *out_buf = st->out_buf;
    return out_len;
}

__attribute__((visibility("default")))
void afl_custom_deinit(void *data) {
    oracle64_state_t *st = (oracle64_state_t *) data;
    oracle64_state_cleanup(st);
    free(st);
}

#endif
