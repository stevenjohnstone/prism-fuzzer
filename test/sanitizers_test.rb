# frozen_string_literal: true

require_relative "lib/autorun"

require "fileutils"
require "json"

require_relative "../runtime/topology"
require_relative "../triage/triage"

# End-to-end fault-injection regression suite verifying that compiled fuzzers,
# patched AFL++ passes (SanitizerCoverageLTO.so / SanitizerCoveragePCGUARD.so),
# PM_XALLOCATOR, verify_bucket.sh profiles, and triage.rb actually catch:
# - ASan memory-safety bugs (arena heap-buffer-overflow, heap-use-after-free, stack-buffer-overflow)
# - UBSan undefined behavior (signed integer overflow, invalid shift exponent)
# - MSan uninitialized reads (while keeping fuzzer input buffers unpoisoned)
# - LSan memory leaks
# - PM_XALLOCATOR balance leaks, sized-free / sized-realloc mismatches, and allocation-cap exhaustion
class SanitizersTest < Minitest::Test
  CLEAN_ENV = {
    "CAMPAIGN" => nil,
    "TOPOLOGY" => nil,
    "TOPOLOGY_FILE" => nil,
    "TOPOLOGY_RESOLVED" => nil,
    "FUZZ_DIR" => nil,
    "FUZZ_BUILD_DIR" => nil,
    "TRIAGE_DIR" => nil,
    "TRIAGE_OUTPUT_DIRS" => nil,
    "TRIAGE_COVERAGE_BIN" => nil,
    "TRIAGE_COVERAGE_IDS" => nil,
    "TRIAGE_DIFF_COVERAGE_BIN" => nil,
    "TRIAGE_DIFF_COVERAGE_IDS" => nil,
    "TRIAGE_CORPUS_DIR" => nil,
    "TRIAGE_MINIMIZE" => nil,
    "ASAN_OPTIONS" => nil,
    "UBSAN_OPTIONS" => nil,
    "MSAN_OPTIONS" => nil,
    "LSAN_OPTIONS" => nil
  }.freeze

  AFL_TRAP_HARNESS_C = <<~'C'
    #include <limits.h>
    #include <stddef.h>
    #include <stdint.h>
    #include <stdlib.h>
    #include <string.h>

    static volatile uintptr_t g_trap_sink = 0;

    __attribute__((noinline))
    static void do_unreachable_leak(uint8_t tag) {
        uint8_t * volatile ptr = (uint8_t *) malloc(96);
        if (ptr != NULL) {
            ptr[0] = tag;
            g_trap_sink ^= ((uintptr_t) ptr ^ (uintptr_t) 0x55aa55aaUL);
            ptr = NULL;
        }
    }

    __attribute__((noinline))
    static void scrub_call_stack(void) {
        volatile char scratch[512];
        for (size_t i = 0; i < sizeof(scratch); i++) {
            scratch[i] = 0;
        }
    }

    void harness(const uint8_t *data, size_t size) {
        /* Exercise reading every input byte so MSan fails if fuzz.c forgot __msan_unpoison. */
        uint32_t acc = 0;
        for (size_t i = 0; i < size; i++) {
            acc = (acc * 33U) ^ data[i];
        }
        g_trap_sink ^= (uintptr_t) acc;

        if (size >= 13 && memcmp(data, "HEAP_OOB_READ", 13) == 0) {
            uint8_t * volatile p = (uint8_t *) malloc(11);
            if (p != NULL) {
                memset(p, 1, 11);
                g_trap_sink = (uintptr_t) p[11];
                free(p);
            }
        } else if (size >= 14 && memcmp(data, "HEAP_OOB_WRITE", 14) == 0) {
            uint8_t * volatile p = (uint8_t *) malloc(11);
            if (p != NULL) {
                p[11] = 0x7fU;
                free(p);
            }
        } else if (size >= 8 && memcmp(data, "HEAP_UAF", 8) == 0) {
            uint8_t * volatile p = (uint8_t *) malloc(24);
            if (p != NULL) {
                p[0] = 0x33U;
                free(p);
                g_trap_sink = (uintptr_t) p[0];
            }
        } else if (size >= 9 && memcmp(data, "STACK_OOB", 9) == 0) {
            uint8_t sbuf[8];
            for (size_t i = 0; i < sizeof(sbuf); i++) sbuf[i] = (uint8_t) i;
            uint8_t * volatile sp = sbuf;
            g_trap_sink = (uintptr_t) sp[8];
        } else if (size >= 15 && memcmp(data, "UB_ARRAY_BOUNDS", 15) == 0) {
            volatile uint8_t sbuf[8];
            for (size_t i = 0; i < sizeof(sbuf); i++) sbuf[i] = (uint8_t) i;
            volatile size_t idx = 8;
            g_trap_sink = (uintptr_t) sbuf[idx];
        } else if (size >= 18 && memcmp(data, "UB_SIGNED_OVERFLOW", 18) == 0) {
            volatile int32_t hi = INT32_MAX;
            volatile int32_t step = (int32_t) (size & 3U) + 1;
            volatile int32_t res = hi + step;
            g_trap_sink = (uintptr_t) (uint32_t) res;
        } else if (size >= 8 && memcmp(data, "UB_SHIFT", 8) == 0) {
            volatile int32_t sh = 35;
            volatile int32_t res = 1 << sh;
            g_trap_sink = (uintptr_t) (uint32_t) res;
        } else if (size >= 11 && memcmp(data, "MSAN_UNINIT", 11) == 0) {
            uint8_t *raw = (uint8_t *) malloc(16);
            if (raw != NULL) {
                uint8_t * volatile opaque = raw;
                if (opaque[5] == 0x42U) {
                    g_trap_sink ^= 1U;
                }
                free(raw);
            }
        } else if (size >= 9 && memcmp(data, "LSAN_LEAK", 9) == 0) {
            do_unreachable_leak(data[0]);
            scrub_call_stack();
        }
    }
  C

  PRISM_FAULT_INJECTION_C = <<~'C'
    static volatile uintptr_t prism_fuzz_fault_sink = 0;

    __attribute__((noinline))
    static void prism_fuzz_do_leak(uint8_t seed_byte) {
        uint8_t * volatile leaked = (uint8_t *) xmalloc(64);
        if (leaked != NULL) {
            leaked[0] = seed_byte;
            prism_fuzz_fault_sink ^= ((uintptr_t) leaked ^ (uintptr_t) 0x5a5a5a5aUL);
            leaked = NULL;
        }
    }

    __attribute__((noinline))
    static void prism_fuzz_scrub_stack(void) {
        volatile char buf[512];
        for (size_t i = 0; i < sizeof(buf); i++) {
            buf[i] = 0;
        }
    }

    static void
    prism_fuzz_inject_fault(pm_parser_t *parser) {
        if (parser == NULL || parser->start == NULL || parser->end <= parser->start) return;
        const uint8_t *s = parser->start;
        size_t n = (size_t) (parser->end - parser->start);

        if (n >= 16 && memcmp(s, "#FAULT_ARENA_OOB", 16) == 0) {
            uint8_t * volatile abuf = (uint8_t *) pm_arena_alloc(parser->arena, 13, 1);
            abuf[0] = 1U;
            prism_fuzz_fault_sink = (uintptr_t) abuf[13];
        } else if (n >= 10 && memcmp(s, "#FAULT_UAF", 10) == 0) {
            uint8_t * volatile ubuf = (uint8_t *) xmalloc(24);
            if (ubuf != NULL) {
                ubuf[0] = 7U;
                xfree(ubuf);
                prism_fuzz_fault_sink = (uintptr_t) ubuf[0];
            }
        } else if (n >= 21 && memcmp(s, "#FAULT_UBSAN_OVERFLOW", 21) == 0) {
            volatile int32_t big = INT32_MAX;
            int32_t delta = (int32_t) (n & 7U) + 1;
            volatile int32_t sum = big + delta;
            prism_fuzz_fault_sink = (uintptr_t) (uint32_t) sum;
        } else if (n >= 18 && memcmp(s, "#FAULT_MSAN_UNINIT", 18) == 0) {
            uint8_t *raw = (uint8_t *) xmalloc(16);
            if (raw != NULL) {
                uint8_t * volatile opaque = raw;
                if (opaque[7] == 0x5aU) {
                    prism_fuzz_fault_sink ^= 1U;
                }
                xfree_sized(raw, 16);
            }
        } else if (n >= 11 && memcmp(s, "#FAULT_LEAK", 11) == 0) {
            prism_fuzz_do_leak(s[0]);
            prism_fuzz_scrub_stack();
        } else if (n >= 26 && memcmp(s, "#FAULT_XFREE_SIZE_MISMATCH", 26) == 0) {
            void *p = xmalloc(32);
            if (p != NULL) {
                xfree_sized(p, 16);
            }
        } else if (n >= 29 && memcmp(s, "#FAULT_XREALLOC_SIZE_MISMATCH", 29) == 0) {
            void *p = xmalloc(32);
            if (p != NULL) {
                void *q = xrealloc_sized(p, 64, 16);
                if (q != NULL) xfree_sized(q, 64);
            }
        } else if (n >= 25 && memcmp(s, "#FAULT_XFREE_NULL_NONZERO", 25) == 0) {
            xfree_sized(NULL, 8);
        } else if (n >= 20 && memcmp(s, "#FAULT_XALLOC_BUDGET", 20) == 0) {
            void * volatile huge = xmalloc((size_t) 3U * 1024U * 1024U);
            if (huge != NULL) {
                prism_fuzz_fault_sink ^= (uintptr_t) huge;
                xfree_sized(huge, (size_t) 3U * 1024U * 1024U);
            }
        } else if (n >= 23 && memcmp(s, "#FAULT_XCALLOC_OVERFLOW", 23) == 0) {
            volatile size_t half_max = (SIZE_MAX / 2U) + 2U;
            void *ov = xcalloc(half_max, 4U);
            if (ov != NULL) xfree(ov);
        } else if (n >= 22 && memcmp(s, "#ASSERT_BUMP_ARENA_ON", 21) == 0) {
            void *probe = pm_arena_alloc(parser->arena, 16, 8);
            prism_fuzz_fault_sink ^= (uintptr_t) probe;
            if (parser->arena->current == NULL) abort();
        } else if (n >= 23 && memcmp(s, "#ASSERT_BUMP_ARENA_OFF", 22) == 0) {
            void *probe = pm_arena_alloc(parser->arena, 16, 8);
            prism_fuzz_fault_sink ^= (uintptr_t) probe;
            if (parser->arena->current != NULL) abort();
        }
    }
  C

  def test_patched_afl_passes_preserve_asan_ubsan_msan_and_lsan_traps
    skip "requires Linux with patched AFL++ LTO and PCGUARD passes" unless afl_lto_ready? && afl_pcguard_ready?

    with_tmpdir("san-afl-traps-") do |workdir|
      harness_c = File.join(workdir, "afl_trap_probe.c")
      File.write(harness_c, AFL_TRAP_HARNESS_C)
      fuzz_c = repo_path("harnesses", "prism", "fuzz.c")
      afl_dir = afl_build_dir

      lto_asan_ubsan = File.join(workdir, "probe_lto_asan_ubsan")
      pcg_asan_ubsan = File.join(workdir, "probe_pcguard_asan_ubsan")
      lto_msan = File.join(workdir, "probe_lto_msan")
      lto_lsan = File.join(workdir, "probe_lto_lsan")

      assert_cmd(
        "afl-clang-lto", "-O1", "-g", "-std=c99", "-fsanitize=address,fuzzer",
        harness_c, fuzz_c, "-o", lto_asan_ubsan,
        env: CLEAN_ENV.merge("AFL_PATH" => afl_dir, "AFL_USE_UBSAN" => "1", "AFL_UBSAN_VERBOSE" => "1")
      )
      assert_cmd(
        "afl-clang-fast", "-O1", "-g", "-std=c99", "-fsanitize=address,fuzzer",
        harness_c, fuzz_c, "-o", pcg_asan_ubsan,
        env: CLEAN_ENV.merge(
          "AFL_PATH" => afl_dir,
          "AFL_LLVM_INSTRUMENT" => "PCGUARD",
          "AFL_USE_UBSAN" => "1",
          "AFL_UBSAN_VERBOSE" => "1"
        )
      )
      assert_cmd(
        "afl-clang-lto", "-O1", "-g", "-std=c99", "-fsanitize=fuzzer",
        harness_c, fuzz_c, "-o", lto_msan,
        env: CLEAN_ENV.merge("AFL_PATH" => afl_dir, "AFL_USE_MSAN" => "1")
      )
      assert_cmd(
        "afl-clang-lto", "-O1", "-g", "-std=c99", "-fsanitize=fuzzer",
        harness_c, fuzz_c, "-o", lto_lsan,
        env: CLEAN_ENV.merge("AFL_PATH" => afl_dir, "AFL_USE_LSAN" => "1")
      )

      inputs = write_probe_inputs(workdir, {
        "clean" => "CLEAN_OK\n",
        "oob_r" => "HEAP_OOB_READ\n",
        "oob_w" => "HEAP_OOB_WRITE\n",
        "uaf" => "HEAP_UAF\n",
        "soob" => "STACK_OOB\n",
        "ub_bnd" => "UB_ARRAY_BOUNDS\n",
        "ub_ovf" => "UB_SIGNED_OVERFLOW\n",
        "ub_shf" => "UB_SHIFT\n",
        "msan" => "MSAN_UNINIT\n",
        "lsan" => "LSAN_LEAK\n"
      })

      [
        ["LTO ASan+UBSan", lto_asan_ubsan],
        ["PCGUARD ASan+UBSan", pcg_asan_ubsan]
      ].each do |label, bin|
        assert_cmd(bin, inputs["clean"], env: CLEAN_ENV, msg: "#{label} failed on clean input")
        assert_crash_diagnostic(bin, inputs["oob_r"], /AddressSanitizer: heap-buffer-overflow.*READ of size 1/m, label: "#{label} heap OOB read")
        assert_crash_diagnostic(bin, inputs["oob_w"], /AddressSanitizer: heap-buffer-overflow.*WRITE of size 1/m, label: "#{label} heap OOB write")
        assert_crash_diagnostic(bin, inputs["uaf"], /AddressSanitizer: heap-use-after-free/, label: "#{label} heap UAF")
        assert_crash_diagnostic(bin, inputs["soob"], /AddressSanitizer: stack-buffer-overflow/, label: "#{label} stack OOB")
        assert_crash_diagnostic(bin, inputs["ub_bnd"], /runtime error: index 8 out of bounds/, label: "#{label} UBSan array bounds")
        assert_crash_diagnostic(bin, inputs["ub_ovf"], /runtime error: signed integer overflow/, label: "#{label} UBSan signed overflow")
        assert_crash_diagnostic(bin, inputs["ub_shf"], /runtime error: shift exponent 35/, label: "#{label} UBSan shift")
      end

      assert_cmd(lto_msan, inputs["clean"], env: CLEAN_ENV, msg: "LTO MSan falsely flagged clean input (__msan_unpoison regression)")
      assert_crash_diagnostic(lto_msan, inputs["msan"], /MemorySanitizer: use-of-uninitialized-value/, label: "LTO MSan uninitialized branch")

      assert_cmd(lto_lsan, inputs["clean"], env: CLEAN_ENV, msg: "LTO LSan falsely flagged clean input")
      assert_crash_diagnostic(lto_lsan, inputs["lsan"], /LeakSanitizer: detected memory leaks/, label: "LTO LSan leak")
    end
  end

  def test_prism_fault_injection_xallocator_sanitizers_verify_and_triage
    prism_a = require_prism_a!

    with_tmpdir("san-prism-e2e-") do |workdir|
      faulty_prism = prepare_faulty_prism(prism_a, File.join(workdir, "faulty_prism"))
      vbuild_faulty = File.join(workdir, "vbuild_faulty")
      vbuild_clean = File.join(workdir, "vbuild_clean")

      # 1. Verify gen_api_compat.rb --cflags emits -DPM_ARENA_INITIAL_SIZE=0 even when
      #    #ifndef PM_ARENA_INITIAL_SIZE lives in src/arena.c rather than include/.
      compat_cflags, = assert_ruby_cmd(
        repo_path("harnesses/prism/gen_api_compat.rb"),
        "--include-dir", File.join(prism_a, "include"),
        "--output", File.join(workdir, "probe_compat.h"),
        "--cflags"
      )
      assert_includes compat_cflags.lines.map(&:strip), "-DPM_ARENA_INITIAL_SIZE=0",
                      "expected gen_api_compat.rb --cflags to emit -DPM_ARENA_INITIAL_SIZE=0 for modern Prism"

      # 2. Verify PM_XALLOCATOR catches leaks, sized-free/realloc mismatches, NULL nonzero free,
      #    budget exhaustion (FUZZ_MAX_ALLOCATED=2), and calloc overflow while passing clean Ruby + stream parses.
      check_xallocator_faults(prism_a, faulty_prism, workdir, vbuild_faulty, vbuild_clean)

      # 3. Verify ASan (13-byte pm_arena_alloc OOB proving unslabbed arena redzones + UAF) and UBSan via verify_bucket.sh.
      check_asan_ubsan_verify_bucket(prism_a, faulty_prism, workdir, vbuild_faulty, vbuild_clean)

      # 4. On Linux/Docker, verify msan_slow and lsan_slow profiles in verify_bucket.sh AND full
      #    Topology.build_plan! + FuzzTriage.run_triage_pipeline + generated bucket verify.sh round-trip.
      if linux?
        check_msan_and_lsan_verify_bucket(prism_a, faulty_prism, workdir, vbuild_faulty, vbuild_clean)
        if afl_lto_ready?
          check_campaign_build_and_triage_round_trip(prism_a, faulty_prism, workdir, vbuild_faulty, vbuild_clean)
        end
      end
    end
  end

  private

  def require_prism_a!
    pa = prism_a_dir
    skip "missing Prism A target (run 'make targets-sync' first)" unless pa && File.directory?(File.join(pa, "src"))
    pa
  end

  def write_probe_inputs(workdir, map)
    dir = File.join(workdir, "inputs")
    FileUtils.mkdir_p(dir)
    map.transform_values do |payload|
      path = File.join(dir, "#{ payload.hash.abs }.bin")
      File.binwrite(path, payload.b)
      path
    end
  end

  def assert_crash_diagnostic(bin, input_path, pattern, label:)
    out, err, st = run_cmd(bin, input_path, env: CLEAN_ENV)
    combined = "#{out}\n#{err}"
    refute st.success?, "expected #{label} to fail, but exited 0:\n#{combined}"
    assert_match pattern, combined, "unexpected diagnostic for #{label} (status=#{st.exitstatus || st.termsig}):\n#{combined}"
  end

  def prepare_faulty_prism(prism_a, dst)
    FileUtils.mkdir_p(dst)
    %w[include src config.yml].each do |entry|
      src_entry = File.join(prism_a, entry)
      FileUtils.cp_r(src_entry, File.join(dst, entry), preserve: true) if File.exist?(src_entry)
    end

    prism_c_path = File.join(dst, "src", "prism.c")
    src = File.read(prism_c_path, encoding: "BINARY")
    anchor = "pm_node_t *\npm_parse(pm_parser_t *parser) {\n"
    assert_includes src, anchor, "could not find pm_parse anchor in #{prism_c_path}"

    patched = src.sub(
      anchor,
      "#{PRISM_FAULT_INJECTION_C.b}\n#{anchor.b}    prism_fuzz_inject_fault(parser);\n"
    )
    File.binwrite(prism_c_path, patched)
    dst
  end

  def run_verify_bucket_case(repo_root:, profile:, bucket_dir:, input_bytes:, verify_build_dir:, extra_env: {})
    FileUtils.mkdir_p(bucket_dir)
    File.binwrite(File.join(bucket_dir, "input.min"), input_bytes)
    out, err, st = run_cmd(
      repo_path("triage/verify_bucket.sh"),
      "--repo-root", repo_root,
      "--fuzz-root", root_dir,
      "--bucket-dir", bucket_dir,
      "--profile", profile,
      "--json",
      env: CLEAN_ENV.merge("VERIFY_BUILD_DIR" => verify_build_dir).merge(extra_env)
    )
    [out, err, st]
  end

  def assert_verify_fails_then_passes(faulty_prism:, clean_prism:, profile:, name:, bytes:, pattern:, workdir:, vbuild_faulty:, vbuild_clean:, extra_env: {})
    bdir = File.join(workdir, "buckets", "#{profile}_#{name}")
    out_f, err_f, st_f = run_verify_bucket_case(
      repo_root: faulty_prism, profile: profile, bucket_dir: bdir,
      input_bytes: bytes, verify_build_dir: vbuild_faulty, extra_env: extra_env
    )
    assert_equal 1, st_f.exitstatus,
                 "expected #{profile} (#{name}) to FAIL (exit 1) on faulty Prism, got #{st_f.exitstatus}:\nstdout=#{out_f}\nstderr=#{err_f}"
    rep_f = JSON.parse(out_f)
    assert_equal 1, rep_f["failed"], "expected failed=1 for #{profile} (#{name}): #{rep_f.inspect}"
    fail_output = rep_f.dig("failures", 0, "output").to_s
    assert_match pattern, fail_output, "missing expected diagnostic for #{profile} (#{name}):\n#{fail_output}"

    out_c, err_c, st_c = run_verify_bucket_case(
      repo_root: clean_prism, profile: profile, bucket_dir: bdir,
      input_bytes: bytes, verify_build_dir: vbuild_clean, extra_env: extra_env
    )
    assert_equal 0, st_c.exitstatus,
                 "expected #{profile} (#{name}) to PASS (exit 0) on clean Prism, got #{st_c.exitstatus}:\nstdout=#{out_c}\nstderr=#{err_c}"
    rep_c = JSON.parse(out_c)
    assert_equal 1, rep_c["passed"]
    assert_equal 0, rep_c["failed"]
    rep_f
  end

  def check_xallocator_faults(prism_a, faulty_prism, workdir, vbuild_faulty, vbuild_clean)
    xenv = { "FUZZ_MAX_ALLOCATED" => "2" }

    # Clean buffer, stream, and bump-arena assertions must pass under unsanitized xallocator
    # (confirming xallocator keeps Prism's bump slab active while checking exact leak/size balance).
    [
      ["clean_expr", seed_bytes("def greet(x)\n  [x, \"hi \#{x}\", 1 + 2]\nend\n")],
      ["clean_stream", seed_bytes("a = <<~EOF\n  hello\nEOF\na\n", header: "\x40\x00\x03\x01")],
      ["bump_arena_active", seed_bytes("#ASSERT_BUMP_ARENA_ON\n1 + 2\n")]
    ].each do |label, bytes|
      bdir = File.join(workdir, "buckets", "xalloc_#{label}")
      out, err, st = run_verify_bucket_case(
        repo_root: faulty_prism, profile: "xallocator", bucket_dir: bdir,
        input_bytes: bytes, verify_build_dir: vbuild_faulty, extra_env: xenv
      )
      assert_equal 0, st.exitstatus, "expected clean xallocator case #{label} to pass:\n#{out}\n#{err}"
    end

    {
      "leak" => [seed_bytes("#FAULT_LEAK\n1 + 1\n"), /allocated == 0/],
      "xfree_size" => [seed_bytes("#FAULT_XFREE_SIZE_MISMATCH\n"), /stored_size == expected_size/],
      "xrealloc_size" => [seed_bytes("#FAULT_XREALLOC_SIZE_MISMATCH\n"), /stored_size == expected_old_size/],
      "xfree_null" => [seed_bytes("#FAULT_XFREE_NULL_NONZERO\n"), /expected_size == 0/],
      "budget" => [seed_bytes("#FAULT_XALLOC_BUDGET\n"), /FUZZ_MAX_ALLOCATED_BYTES/],
      "calloc_ovf" => [seed_bytes("#FAULT_XCALLOC_OVERFLOW\n"), /FUZZ_MAX_ALLOCATED_BYTES/]
    }.each do |name, (bytes, pat)|
      assert_verify_fails_then_passes(
        faulty_prism: faulty_prism, clean_prism: prism_a, profile: "xallocator",
        name: name, bytes: bytes, pattern: pat, workdir: workdir,
        vbuild_faulty: vbuild_faulty, vbuild_clean: vbuild_clean, extra_env: xenv
      )
    end
  end

  def check_asan_ubsan_verify_bucket(prism_a, faulty_prism, workdir, vbuild_faulty, vbuild_clean)
    # 13-byte pm_arena_alloc OOB proves BOTH -DPM_ARENA_INITIAL_SIZE=0 AND pm_arena_reserve unslabbing.
    {
      "arena_oob" => [seed_bytes("#FAULT_ARENA_OOB\n1 + 2\n"), /AddressSanitizer: heap-buffer-overflow/],
      "uaf" => [seed_bytes("#FAULT_UAF\n1 + 2\n"), /AddressSanitizer: heap-use-after-free/],
      "ubsan_ovf" => [seed_bytes("#FAULT_UBSAN_OVERFLOW\n1 + 2\n"), /runtime error: signed integer overflow/]
    }.each do |name, (bytes, pat)|
      assert_verify_fails_then_passes(
        faulty_prism: faulty_prism, clean_prism: prism_a, profile: "asan_ubsan",
        name: name, bytes: bytes, pattern: pat, workdir: workdir,
        vbuild_faulty: vbuild_faulty, vbuild_clean: vbuild_clean
      )
    end

    # Uninitialized read without out-of-bounds or leak does NOT falsely trip asan_ubsan,
    # and sanitized builds keep arena->current == NULL (unslabbed per-allocation blocks).
    [
      ["asan_ignores_msan_only", seed_bytes("#FAULT_MSAN_UNINIT\n1 + 2\n")],
      ["asan_bump_arena_off", seed_bytes("#ASSERT_BUMP_ARENA_OFF\n1 + 2\n")]
    ].each do |label, bytes|
      bdir = File.join(workdir, "buckets", label)
      out_m, err_m, st_m = run_verify_bucket_case(
        repo_root: faulty_prism, profile: "asan_ubsan", bucket_dir: bdir,
        input_bytes: bytes, verify_build_dir: vbuild_faulty
      )
      assert_equal 0, st_m.exitstatus,
                   "expected #{label} to pass under asan_ubsan:\nstdout=#{out_m}\nstderr=#{err_m}"
    end
  end

  def check_msan_and_lsan_verify_bucket(prism_a, faulty_prism, workdir, vbuild_faulty, vbuild_clean)
    clean_slow = seed_bytes("class Demo\n  def f(a = 1)\n    a + 2\n  end\nend\n")
    %w[msan_slow lsan_slow].each do |prof|
      cdir = File.join(workdir, "buckets", "#{prof}_clean")
      out, err, st = run_verify_bucket_case(
        repo_root: faulty_prism, profile: prof, bucket_dir: cdir,
        input_bytes: clean_slow, verify_build_dir: vbuild_faulty
      )
      assert_equal 0, st.exitstatus, "expected clean slow seed to pass #{prof}:\nstdout=#{out}\nstderr=#{err}"
    end

    assert_verify_fails_then_passes(
      faulty_prism: faulty_prism, clean_prism: prism_a, profile: "msan_slow",
      name: "uninit", bytes: seed_bytes("#FAULT_MSAN_UNINIT\n1 + 2\n"),
      pattern: /MemorySanitizer: use-of-uninitialized-value/,
      workdir: workdir, vbuild_faulty: vbuild_faulty, vbuild_clean: vbuild_clean
    )

    assert_verify_fails_then_passes(
      faulty_prism: faulty_prism, clean_prism: prism_a, profile: "lsan_slow",
      name: "leak", bytes: seed_bytes("#FAULT_LEAK\n1 + 2\n"),
      pattern: /LeakSanitizer: detected memory leaks/,
      workdir: workdir, vbuild_faulty: vbuild_faulty, vbuild_clean: vbuild_clean
    )
  end

  def check_campaign_build_and_triage_round_trip(prism_a, faulty_prism, workdir, vbuild_faulty, vbuild_clean)
    ws = File.join(workdir, "campaign_ws")
    build_dir = File.join(ws, "build")
    afl_dir = File.join(ws, "afl")
    triage_dir = File.join(ws, "report", "triage")
    campaign_rb = File.join(workdir, "san_campaign.rb")

    File.write(campaign_rb, <<~RB)
      PrismFuzzer.campaign "sanitizer-regression-fleet" do
        workspace #{ws.inspect}
        defaults max_input_size: 1024, max_allocated_mb: 2
        prism :prism_a, dir: #{faulty_prism.inspect}, patches: "none", templates: "never"

        fuzzer "fuzz",      shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
        fuzzer "fuzz.msan", shape: :prism_parse, source: :prism_a, sanitizers: %i[msan],       mode: :slow, afl: :lto
        fuzzer "fuzz.lsan", shape: :prism_parse, source: :prism_a, sanitizers: %i[lsan],       mode: :slow, afl: :lto
        fuzzer "fuzz.ijon", shape: :prism_parse, source: :prism_a, sanitizers: [],             mode: :fast, afl: :lto, ijon: true, xallocator: true

        sync_group :afl, dir: "afl", primary: true
        worker :main, fuzzer: "fuzz",      sync_group: :afl, afl_role: :main
        worker :msan, fuzzer: "fuzz.msan", sync_group: :afl, afl_role: :secondary
        worker :lsan, fuzzer: "fuzz.lsan", sync_group: :afl, afl_role: :secondary
        worker :ijon, fuzzer: "fuzz.ijon", sync_group: :afl, afl_role: :secondary
      end
    RB

    with_env(CLEAN_ENV) do
      ir, = PrismFuzzer::Topology.load_ir(campaign_rb, fuzz_root: root_dir)
      plan = PrismFuzzer::Topology.compile_plan(ir, fuzz_root: root_dir, build_dir: build_dir)
      capture_io do
        resolved = PrismFuzzer::Topology.sync_plan!(plan, fuzz_root: root_dir, build_dir: build_dir)
        PrismFuzzer::Topology.build_plan!(resolved, fuzz_root: root_dir, build_dir: build_dir)
      end

      bump_on_in = File.join(workdir, "camp_bump_on.bin")
      bump_off_in = File.join(workdir, "camp_bump_off.bin")
      File.binwrite(bump_on_in, seed_bytes("#ASSERT_BUMP_ARENA_ON\n1 + 2\n"))
      File.binwrite(bump_off_in, seed_bytes("#ASSERT_BUMP_ARENA_OFF\n1 + 2\n"))
      assert_cmd(File.join(build_dir, "fuzz.ijon"), bump_on_in, env: CLEAN_ENV, msg: "expected fuzz.ijon (xallocator, unsanitized) to keep bump arena active")
      assert_cmd(File.join(build_dir, "fuzz"), bump_off_in, env: CLEAN_ENV, msg: "expected fuzz (asan+ubsan) to keep arena unslabbed")

      worker_crashes = {
        "main" => [
          ["fuzz", "id:000000,sig:06", seed_bytes("#FAULT_ARENA_OOB\n1 + 2\n")],
          ["fuzz", "id:000001,sig:06", seed_bytes("#FAULT_UAF\n1 + 2\n")],
          ["fuzz", "id:000002,sig:06", seed_bytes("#FAULT_UBSAN_OVERFLOW\n1 + 2\n")]
        ],
        "msan" => [
          ["fuzz.msan", "id:000000,sig:06", seed_bytes("#FAULT_MSAN_UNINIT\n1 + 2\n")]
        ],
        "lsan" => [
          ["fuzz.lsan", "id:000000,sig:06", seed_bytes("#FAULT_LEAK\n1 + 2\n")]
        ],
        "ijon" => [
          ["fuzz.ijon", "id:000000,sig:06", seed_bytes("#FAULT_XFREE_SIZE_MISMATCH\n")]
        ]
      }

      worker_crashes.each do |wid, items|
        wdir = File.join(afl_dir, wid)
        cdir = File.join(wdir, "crashes")
        FileUtils.mkdir_p(cdir)
        bin_path = File.join(build_dir, items.first.first)
        File.write(File.join(wdir, "cmdline"), "#{bin_path}\n")
        items.each do |_bname, fname, payload|
          File.binwrite(File.join(cdir, fname), payload)
        end
      end

      with_env("TRIAGE_MINIMIZE" => "0", "FUZZ_DIR" => ws, "FUZZ_BUILD_DIR" => build_dir, "TOPOLOGY" => campaign_rb) do
        capture_io do
          FuzzTriage.run_triage_pipeline(
            output_dirs: [afl_dir],
            testcases_dir: triage_dir,
            coverage_bin: "",
            diff_coverage_bin: "",
            threads: 4
          )
        end
      end

      index = JSON.parse(File.read(File.join(triage_dir, "metadata.json")))
      buckets = index.fetch("buckets")
      assert_equal 6, buckets.size, "expected 6 distinct triaged buckets, got #{buckets.map { |b| [b['bucket_id'], b['verify_profile']] }.inspect}"

      expected = [
        ["heap-buffer-overflow", "asan_ubsan", /AddressSanitizer: heap-buffer-overflow/],
        ["heap-use-after-free", "asan_ubsan", /AddressSanitizer: heap-use-after-free/],
        ["undefined-behavior", "asan_ubsan", /signed integer overflow/],
        ["use-of-uninitialized-value", "msan_slow", /MemorySanitizer: use-of-uninitialized-value/],
        ["memory-leak", "lsan_slow", /LeakSanitizer: detected memory leaks/],
        ["ABRT", "xallocator", /stored_size == expected_size/]
      ]

      expected.each do |exp_reason, exp_profile, headline_re|
        matched = buckets.find { |b| b["reason"] == exp_reason && b["verify_profile"] == exp_profile }
        refute_nil matched,
                   "missing triaged bucket reason=#{exp_reason} profile=#{exp_profile} in #{buckets.map { |b| [b['reason'], b['verify_profile'], b.dig('symptom', 'headline')] }.inspect}"
        assert_match headline_re, matched.dig("symptom", "headline").to_s

        vsh = File.join(triage_dir, matched.fetch("bucket_id"), "verify.sh")
        assert File.executable?(vsh), "expected executable verify.sh at #{vsh}"

        # Generated verify.sh fails against faulty_prism (with matching diagnostic) and passes against clean prism_a.
        of_json, ef_err, st_fail = run_cmd(
          vsh, "--repo-root", faulty_prism, "--json",
          env: CLEAN_ENV.merge(
            "FUZZ_ROOT" => root_dir,
            "VERIFY_BUILD_DIR" => vbuild_faulty,
            "FUZZ_MAX_ALLOCATED" => "2"
          )
        )
        assert_equal 1, st_fail.exitstatus,
                     "expected generated #{vsh} to FAIL against faulty_prism:\nstdout=#{of_json}\nstderr=#{ef_err}"
        vf_rep = JSON.parse(of_json)
        assert_equal 2, vf_rep["total"]
        assert_equal 2, vf_rep["failed"]
        assert_match headline_re, vf_rep.dig("failures", 0, "output").to_s

        assert_cmd(
          vsh, "--repo-root", prism_a, "--quiet",
          env: CLEAN_ENV.merge(
            "FUZZ_ROOT" => root_dir,
            "VERIFY_BUILD_DIR" => vbuild_clean,
            "FUZZ_MAX_ALLOCATED" => "2"
          ),
          msg: "expected generated #{vsh} to PASS against clean prism_a"
        )
      end
    end
  end
end
