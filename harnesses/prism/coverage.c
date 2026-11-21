#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef PROFILE
#include <signal.h>
#include <unistd.h>

static volatile sig_atomic_t coverage_stop_requested = 0;

static void handle_stop_signal(int signum) {
    (void) signum;
    coverage_stop_requested = 1;
}

static void handle_crash_signal(int signum) {
    _exit(128 + signum);
}

static void setup_signal_handlers(void) {
    struct sigaction crash_sa;
    memset(&crash_sa, 0, sizeof(crash_sa));
    crash_sa.sa_handler = handle_crash_signal;
    sigemptyset(&crash_sa.sa_mask);
    crash_sa.sa_flags = SA_RESETHAND;
    sigaction(SIGSEGV, &crash_sa, NULL);
    sigaction(SIGABRT, &crash_sa, NULL);
    sigaction(SIGBUS,  &crash_sa, NULL);
    sigaction(SIGILL,  &crash_sa, NULL);
    sigaction(SIGFPE,  &crash_sa, NULL);

    struct sigaction stop_sa;
    memset(&stop_sa, 0, sizeof(stop_sa));
    stop_sa.sa_handler = handle_stop_signal;
    sigemptyset(&stop_sa.sa_mask);
    stop_sa.sa_flags = SA_RESTART;
    sigaction(SIGTERM, &stop_sa, NULL);
    sigaction(SIGINT,  &stop_sa, NULL);
}
#endif

extern void harness(const uint8_t *input, size_t size);

static int run_file(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        return 1;
    }

    struct stat st;
    if (fstat(fileno(fp), &st) != 0 || st.st_size < 0) {
        fclose(fp);
        return 1;
    }

    size_t size = (size_t) st.st_size;
    uint8_t *buf = (uint8_t *) malloc(size > 0 ? size : 1);
    if (buf == NULL) {
        fclose(fp);
        return 1;
    }

    size_t read_bytes = size > 0 ? fread(buf, 1, size, fp) : 0;
    int had_error = ferror(fp);
    fclose(fp);

    if (!had_error) {
        harness(buf, read_bytes);
    }

    free(buf);
    return had_error ? 1 : 0;
}

static int run_stdin(void) {
    size_t cap = 4096;
    size_t len = 0;
    uint8_t *buf = (uint8_t *) malloc(cap);
    if (buf == NULL) {
        return EXIT_FAILURE;
    }

    size_t n;
    while ((n = fread(buf + len, 1, cap - len, stdin)) > 0) {
        len += n;
        if (len == cap) {
            cap *= 2;
            uint8_t *next = (uint8_t *) realloc(buf, cap);
            if (next == NULL) {
                free(buf);
                return EXIT_FAILURE;
            }
            buf = next;
        }
    }

    if (ferror(stdin)) {
        perror("Error reading from stdin");
        free(buf);
        return EXIT_FAILURE;
    }

    harness(buf, len);
    free(buf);
    return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
#ifdef PROFILE
    setup_signal_handlers();
#endif

    if (argc <= 1) {
        return run_stdin();
    }

    int status = EXIT_SUCCESS;
    for (int i = 1; i < argc; i++) {
#ifdef PROFILE
        if (coverage_stop_requested) {
            break;
        }
#endif
        if (run_file(argv[i]) != 0) {
            status = EXIT_FAILURE;
        }
    }
    return status;
}
