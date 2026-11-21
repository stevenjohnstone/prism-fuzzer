# frozen_string_literal: true

require_relative "../lib/autorun"

require "digest"
require "fileutils"
require "json"
require "rubygems/package"
require "zlib"

require_relative "../../triage/triage"
require_relative "../../triage/verify"
require_relative "../../triage/retriage"

# Isolated tests for verify_runner.c crash/timeout/leak isolation, padded tar
# streaming, verify_bucket.sh input selection and survivor extraction, real Prism
# verify_runner builds, profile inference, and verify.rb PASS/PARTIAL/FAIL workflow.
class TriageVerifyTest < Minitest::Test
  MOCK_FUZZ_TARGET_C = <<~'C'
    #include <stdint.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>

    static volatile uintptr_t leak_sink = 0;
    static int atexit_fail_armed = 0;
    static int atexit_handler_registered = 0;

    static void check_atexit_fail(void) {
        if (atexit_fail_armed) {
            fprintf(stderr, "ERROR: simulated atexit leak check failure\n");
            _exit(1);
        }
    }

    __attribute__((noinline)) static void do_leak(void) {
        void *p = malloc(128);
        if (!p) abort();
        leak_sink = ((uintptr_t)p) ^ (uintptr_t)0x5555;
    }

    __attribute__((noinline)) static void scrub_stack(void) {
        volatile char buf[512];
        for (size_t i = 0; i < sizeof(buf); i++) buf[i] = 0;
    }

    int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        if (size >= 5 && memcmp(data, "CRASH", 5) == 0) {
            fprintf(stderr, "INVARIANT[mock]: kind=crash\n");
            abort();
        }
        if (size >= 4 && memcmp(data, "HANG", 4) == 0) {
            for (;;) {}
        }
        if (size >= 4 && memcmp(data, "LEAK", 4) == 0) {
            do_leak();
        }
        if (size >= 11 && memcmp(data, "ATEXIT_FAIL", 11) == 0) {
            if (!atexit_handler_registered) {
                atexit(check_atexit_fail);
                atexit_handler_registered = 1;
            }
            atexit_fail_armed = 1;
        }
        scrub_stack();
        return 0;
    }
  C

  def test_verify_runner_crash_timeout_pass_max_failures_and_extract
    with_tmpdir("triage-verify-") do |workdir|
      mock_verify = compile_mock_verify(workdir)

      mixed_tar = File.join(workdir, "mixed.tar.gz")
      write_tar_gz(mixed_tar, [
        ["ok_0", "ok_zero"],
        ["bad_crash", "CRASH_1"],
        ["ok_1", "ok_one"],
        ["bad_hang", "HANG_forever"],
        ["ok_2", "ok_two"],
        ["bad_crash2", "CRASH_2"],
        ["ok_3", "ok_three"]
      ])

      out, err, st = run_cmd(mock_verify, "--tar", "-", "--timeout", "1", "--json", input: gunzip_bytes(mixed_tar))
      assert_equal 1, st.exitstatus, "expected mixed verify_runner run to exit 1\nstdout=#{out}\nstderr=#{err}"

      res = JSON.parse(out)
      assert_equal 7, res["total"], "unexpected total: #{res.inspect}"
      assert_equal 7, res["checked"], "unexpected checked: #{res.inspect}"
      assert_equal 4, res["passed"], "unexpected passed: #{res.inspect}"
      assert_equal 3, res["failed"], "unexpected failed: #{res.inspect}"
      assert_equal 1, res["timed_out"], "unexpected timed_out: #{res.inspect}"
      assert_equal %w[bad_crash bad_hang bad_crash2], res["failures"].map { |f| f["name"] }
      assert_equal false, res["failures"][0]["timed_out"]
      assert_includes res["failures"][0]["headline"].to_s, "INVARIANT[mock]: kind=crash"
      assert_equal true, res["failures"][1]["timed_out"]
      assert_equal false, res["failures"][2]["timed_out"]

      pass_tar = File.join(workdir, "pass.tar.gz")
      write_tar_gz(pass_tar, [["ok_a", "clean_a"], ["ok_b", "clean_b"]])
      pass_out, = assert_cmd(mock_verify, "--tar", "-", "--timeout", "2", input: gunzip_bytes(pass_tar))
      assert_includes pass_out, "PASS: 2/2 inputs passed"

      extract_dir = File.join(workdir, "extracted")
      lim_out, lim_err, lim_st = run_cmd(
        mock_verify, "--tar", "-", "--timeout", "1", "--max-failures", "2",
        "--extract-dir", extract_dir, "--json",
        input: gunzip_bytes(mixed_tar)
      )
      assert_equal 1, lim_st.exitstatus, "expected bounded verify_runner run to exit 1\nstdout=#{lim_out}\nstderr=#{lim_err}"
      lim = JSON.parse(lim_out)
      assert_equal 4, lim["checked"]
      assert_equal 2, lim["passed"]
      assert_equal 2, lim["failed"]
      assert_equal 1, lim["timed_out"]
      assert_equal %w[bad_crash bad_hang], lim["failures"].map { |f| f["name"] }
      assert_equal "CRASH_1", File.binread(File.join(extract_dir, "bad_crash"))
      assert_equal "HANG_forever", File.binread(File.join(extract_dir, "bad_hang"))
      refute_path_exists File.join(extract_dir, "bad_crash2")
    end
  end

  def test_verify_runner_lsan_and_atexit_bisection_isolation
    with_tmpdir("triage-verify-") do |workdir|
      mock_verify = compile_mock_verify(workdir)

      atexit_tar = File.join(workdir, "atexit_bisect.tar.gz")
      write_tar_gz(atexit_tar, Array.new(10) { |i| ["item_#{i}", i == 6 ? "ATEXIT_FAIL_6" : "clean_#{i}"] })
      ax_out, ax_err, ax_st = run_cmd(mock_verify, "--tar", "-", "--timeout", "5", "--json", input: gunzip_bytes(atexit_tar))
      assert_equal 1, ax_st.exitstatus, "expected atexit bisection run to exit 1\nstdout=#{ax_out}\nstderr=#{ax_err}"
      ax_res = JSON.parse(ax_out)
      assert_equal 10, ax_res["checked"], "unexpected atexit bisect checked: #{ax_res.inspect}"
      assert_equal 9, ax_res["passed"], "unexpected atexit bisect passed: #{ax_res.inspect}"
      assert_equal 1, ax_res["failed"], "unexpected atexit bisect failed: #{ax_res.inspect}"
      assert_equal ["item_6"], ax_res["failures"].map { |f| f["name"] }

      multi_atexit_tar = File.join(workdir, "multi_atexit_bisect.tar.gz")
      write_tar_gz(multi_atexit_tar, Array.new(10) { |i| ["item_#{i}", [2, 7].include?(i) ? "ATEXIT_FAIL_#{i}" : "clean_#{i}"] })
      mx_out, mx_err, mx_st = run_cmd(mock_verify, "--tar", "-", "--timeout", "5", "--json", input: gunzip_bytes(multi_atexit_tar))
      assert_equal 1, mx_st.exitstatus, "expected multi-atexit bisection run to exit 1\nstdout=#{mx_out}\nstderr=#{mx_err}"
      mx_res = JSON.parse(mx_out)
      assert_equal 10, mx_res["checked"]
      assert_equal 8, mx_res["passed"]
      assert_equal 2, mx_res["failed"]
      assert_equal %w[item_2 item_7], mx_res["failures"].map { |f| f["name"] }

      leak_tar = File.join(workdir, "leak.tar.gz")
      write_tar_gz(leak_tar, Array.new(10) { |i| ["item_#{i}", i == 6 ? "LEAK_here" : "clean_#{i}"] })

      if linux?
        leak_out, leak_err, leak_st = run_cmd(
          mock_verify, "--tar", "-", "--timeout", "5", "--json",
          env: { "ASAN_OPTIONS" => "detect_leaks=1" },
          input: gunzip_bytes(leak_tar)
        )
        assert_equal 1, leak_st.exitstatus, "expected LSan bisection run to exit 1\nstdout=#{leak_out}\nstderr=#{leak_err}"
        leak_res = JSON.parse(leak_out)
        assert_equal 10, leak_res["checked"], "expected LSan bisect to check all 10 items: #{leak_res.inspect}"
        assert_equal 1, leak_res["failed"], "expected LSan bisect to isolate 1 failure: #{leak_res.inspect}"
        assert_equal "item_6", leak_res.dig("failures", 0, "name")
      end
    end
  end

  def test_padded_tar_streaming_pipefail_and_verify_bucket_edge_cases
    prism_dir = require_prism_a!

    with_tmpdir("triage-verify-") do |workdir|
      mock_verify = compile_mock_verify(workdir)

      padded_tar = File.join(workdir, "padded_pass.tar.gz")
      write_tar_gz(
        padded_tar,
        [["ok_1", "good"], ["ok_2", "fine"]],
        extra_zero_padding: 256 * 1024
      )

      pipe_out, pipe_err, pipe_st = run_cmd(
        "bash", "-c", 'set -o pipefail; gzip -dc "$1" | "$2" --tar - --json',
        "_", padded_tar, mock_verify
      )
      assert_equal 0, pipe_st.exitstatus,
                   "expected padded tar pipe under pipefail to exit 0 without SIGPIPE 141\nstdout=#{pipe_out}\nstderr=#{pipe_err}"
      pipe_res = JSON.parse(pipe_out)
      assert_equal 2, pipe_res["checked"], "unexpected padded tar checked: #{pipe_res.inspect}"
      assert_equal 2, pipe_res["passed"], "unexpected padded tar passed: #{pipe_res.inspect}"
      assert_equal 0, pipe_res["failed"], "unexpected padded tar failed: #{pipe_res.inspect}"

      pipe_bucket = File.join(workdir, "pipe_bucket")
      FileUtils.mkdir_p(pipe_bucket)
      FileUtils.cp(padded_tar, File.join(pipe_bucket, "inputs.tar.gz"))

      early2 = write_executable(File.join(workdir, "mock_early_exit2.sh"), "#!/usr/bin/env bash\nexit 2\n")
      early0 = write_executable(File.join(workdir, "mock_early_exit0.sh"), "#!/usr/bin/env bash\nexit 0\n")

      verify_bucket_sh = repo_path("triage/verify_bucket.sh")
      _o2, _e2, st2 = run_cmd(
        verify_bucket_sh, "--repo-root", prism_dir, "--fuzz-root", root_dir,
        "--bucket-dir", pipe_bucket, "--runner", early2
      )
      assert_equal 2, st2.exitstatus, "expected runner exit 2 (not SIGPIPE 141) from verify_bucket.sh"

      _o0, _e0, st0 = run_cmd(
        verify_bucket_sh, "--repo-root", prism_dir, "--fuzz-root", root_dir,
        "--bucket-dir", pipe_bucket, "--runner", early0
      )
      assert_equal 0, st0.exitstatus, "expected runner exit 0 (not SIGPIPE 141) from verify_bucket.sh"

      File.write(File.join(pipe_bucket, "inputs.tar.gz"), "not-a-gzip")
      _ogz, _egz, st_gz = run_cmd(
        verify_bucket_sh, "--repo-root", prism_dir, "--fuzz-root", root_dir,
        "--bucket-dir", pipe_bucket, "--runner", mock_verify
      )
      assert_equal 2, st_gz.exitstatus, "expected corrupt gzip archive to exit 2 from verify_bucket.sh"

      # Verify verify_bucket.sh input.min / .inputs.pending / inputs.tar.gz selection and survivor extraction
      sel_bucket = File.join(workdir, "sel_bucket")
      FileUtils.mkdir_p(sel_bucket)
      File.binwrite(File.join(sel_bucket, "input.min"), "CRASH_min")
      write_pack_file(File.join(sel_bucket, ".inputs.pending"), [
        ["pend_ok", "clean_pend"],
        ["pend_bad", "CRASH_pend"]
      ])
      write_tar_gz(File.join(sel_bucket, "inputs.tar.gz"), [
        ["arch_ok", "clean_arch"],
        ["arch_bad", "CRASH_arch"]
      ])

      all_out, _all_err, all_st = run_cmd(
        verify_bucket_sh, "--repo-root", prism_dir, "--fuzz-root", root_dir,
        "--bucket-dir", sel_bucket, "--runner", mock_verify, "--json"
      )
      assert_equal 1, all_st.exitstatus
      all_res = JSON.parse(all_out)
      assert_equal 5, all_res["total"]
      assert_equal 5, all_res["checked"]
      assert_equal 2, all_res["passed"]
      assert_equal 3, all_res["failed"]
      assert_equal %w[input.min pend_bad arch_bad], all_res["failures"].map { |f| f["name"] }

      min_out, _min_err, min_st = run_cmd(
        verify_bucket_sh, "--repo-root", prism_dir, "--fuzz-root", root_dir,
        "--bucket-dir", sel_bucket, "--runner", mock_verify, "--input-min-only", "--json"
      )
      assert_equal 1, min_st.exitstatus
      min_res = JSON.parse(min_out)
      assert_equal 1, min_res["total"]
      assert_equal 1, min_res["failed"]
      assert_equal ["input.min"], min_res["failures"].map { |f| f["name"] }

      skip_out, _skip_err, skip_st = run_cmd(
        verify_bucket_sh, "--repo-root", prism_dir, "--fuzz-root", root_dir,
        "--bucket-dir", sel_bucket, "--runner", mock_verify, "--skip-min", "--json"
      )
      assert_equal 1, skip_st.exitstatus
      skip_res = JSON.parse(skip_out)
      assert_equal 4, skip_res["total"]
      assert_equal 2, skip_res["passed"]
      assert_equal 2, skip_res["failed"]
      assert_equal %w[pend_bad arch_bad], skip_res["failures"].map { |f| f["name"] }

      surv_dir = File.join(workdir, "bucket_survivors")
      maxf_out, _maxf_err, maxf_st = run_cmd(
        verify_bucket_sh, "--repo-root", prism_dir, "--fuzz-root", root_dir,
        "--bucket-dir", sel_bucket, "--runner", mock_verify,
        "--max-failures", "2", "--extract-survivors", surv_dir, "--json"
      )
      assert_equal 1, maxf_st.exitstatus
      maxf_res = JSON.parse(maxf_out)
      assert_equal 2, maxf_res["failed"]
      assert_equal "CRASH_min", File.binread(File.join(surv_dir, "input.min"))
      assert_equal "CRASH_pend", File.binread(File.join(surv_dir, "pend_bad"))
      refute_path_exists File.join(surv_dir, "arch_bad")

      _bad_out, _bad_err, bad_st = run_cmd(
        verify_bucket_sh, "--repo-root", prism_dir, "--fuzz-root", root_dir,
        "--bucket-dir", sel_bucket, "--runner", mock_verify, "--input-min-only", "--skip-min"
      )
      assert_equal 2, bad_st.exitstatus
    end
  end

  def test_real_prism_verify_runner_verify_sh_and_slow_profile
    prism_dir = require_prism_a!

    with_tmpdir("triage-verify-") do |workdir|
      real_verify_build, prebuilt_readonly_dir = resolve_real_verify_build_dir(workdir)

      real_triage = File.join(workdir, "real_verify_triage")
      real_pass_dir = File.join(real_triage, "ABRT/real_pass_sig")
      FileUtils.mkdir_p(real_pass_dir)

      File.binwrite(File.join(real_pass_dir, "input.min"), seed_bytes("2 + 2\n"))
      ok_a = seed_bytes("puts 42\n")
      ok_b = seed_bytes("x = [1, 2]\n")
      write_tar_gz(File.join(real_pass_dir, "inputs.tar.gz"), [
        [Digest::SHA256.hexdigest(ok_a), ok_a],
        [Digest::SHA256.hexdigest(ok_b), ok_b]
      ])
      write_verify_sh(real_pass_dir, prism_dir: prism_dir, profile: "asan_ubsan")

      if prebuilt_readonly_dir
        ro_runner = File.join(prebuilt_readonly_dir, "verify_runner.asan_ubsan")
        assert_cmd(File.join(real_pass_dir, "verify.sh"), "--runner", ro_runner, "--quiet") if File.executable?(ro_runner)

        ro_slow = File.join(prebuilt_readonly_dir, "verify_runner.asan_ubsan_slow")
        assert_cmd(File.join(real_pass_dir, "verify.sh"), "--runner", ro_slow, "--quiet") if File.executable?(ro_slow)
      end

      verify_env = { "VERIFY_BUILD_DIR" => real_verify_build, "PRISM_A_DIR" => prism_dir }
      assert_cmd(File.join(real_pass_dir, "verify.sh"), "--quiet", env: verify_env)
      assert_ruby_cmd(repo_path("triage/verify.rb"), "--triage-dir", real_triage, "--quiet", env: verify_env)

      # Also exercise FuzzTriage.ensure_bucket_verify_script generated verify.sh end-to-end
      gen_triage = File.join(workdir, "gen_verify_triage")
      gen_pass_dir = File.join(gen_triage, "ABRT/gen_pass_sig")
      FileUtils.mkdir_p(gen_pass_dir)
      FileUtils.cp(File.join(real_pass_dir, "input.min"), File.join(gen_pass_dir, "input.min"))
      FileUtils.cp(File.join(real_pass_dir, "inputs.tar.gz"), File.join(gen_pass_dir, "inputs.tar.gz"))
      FuzzTriage.ensure_bucket_verify_script(
        gen_pass_dir,
        reason: "ABRT",
        executable: "./build/fuzz",
        triage_dir: gen_triage
      )
      assert_path_exists File.join(gen_pass_dir, "verify.sh")
      assert_cmd(
        File.join(gen_pass_dir, "verify.sh"), "--quiet",
        env: verify_env.merge("FUZZ_ROOT" => root_dir)
      )

      # Verify asan_ubsan_slow auto-detection from build.sh (-DSLOW)
      real_slow_triage = File.join(workdir, "real_slow_triage")
      real_slow_dir = File.join(real_slow_triage, "ABRT/slow_pass_sig")
      FileUtils.mkdir_p(real_slow_dir)
      FileUtils.cp(File.join(real_pass_dir, "input.min"), File.join(real_slow_dir, "input.min"))
      FileUtils.cp(File.join(real_pass_dir, "inputs.tar.gz"), File.join(real_slow_dir, "inputs.tar.gz"))
      write_executable(File.join(real_slow_dir, "build.sh"), "#!/usr/bin/env bash\nclang -DSLOW -fsanitize=address,undefined\n")

      assert_cmd(
        repo_path("triage/verify_bucket.sh"),
        "--repo-root", prism_dir, "--fuzz-root", root_dir, "--bucket-dir", real_slow_dir, "--quiet",
        env: verify_env
      )
      slow_runner = File.join(real_verify_build, "verify_runner.asan_ubsan_slow")
      assert File.executable?(slow_runner), "expected verify_runner.asan_ubsan_slow to be built via -DSLOW auto-detection at #{slow_runner}"

      assert_ruby_cmd(repo_path("triage/verify.rb"), "--triage-dir", real_slow_triage, "--quiet", env: verify_env)
    end
  end

  def test_profile_inference_executable_resolution_and_crash_classification
    with_tmpdir("triage-verify-") do |workdir|
      slow_dir = File.join(workdir, "ABRT/slow_pass_sig")
      FileUtils.mkdir_p(slow_dir)
      write_executable(File.join(slow_dir, "build.sh"), "#!/usr/bin/env bash\nclang -DSLOW -fsanitize=address,undefined\n")

      assert_equal "asan_ubsan_slow", FuzzVerify.infer_bucket_profile(slow_dir, { "reproduced_by" => "./build/fuzz.slow" })
      assert_equal "asan_ubsan_slow", FuzzVerify.infer_bucket_profile(slow_dir, {})
      assert_equal "./tmp/fuzz/build/fuzz.slow", FuzzRetriage.resolve_reclassify_executable({}, "asan_ubsan_slow")

      comp_dir = File.join(workdir, "companion_bin")
      FileUtils.mkdir_p(comp_dir)
      comp_fuzz = write_executable(File.join(comp_dir, "fuzz"), "#!/bin/sh\nexit 0\n")
      comp_slow = write_executable(File.join(comp_dir, "fuzz.slow"), "#!/bin/sh\nexit 0\n")
      comp_diff = write_executable(File.join(comp_dir, "fuzz.diff"), "#!/bin/sh\nexit 0\n")

      dummy_in = File.join(workdir, "dummy.in")
      File.write(dummy_in, "")

      t_mod = Module.new
      t_mod.extend(FuzzTriage)

      t_mod.define_singleton_method(:run_testcase) do |exe, _input|
        if exe == comp_fuzz
          ["AddressSanitizer: heap-buffer-overflow in pm_parse\nSUMMARY: AddressSanitizer: heap-buffer-overflow src/prism.c:1\n", true, false]
        else
          ["slow fallback unexpected", false, false]
        end
      end
      dedup_res = t_mod.classify_crash_execution("crashes", dummy_in, comp_slow)
      assert_equal comp_fuzz, dedup_res[:executable]
      assert_equal "heap-buffer-overflow", dedup_res[:reason]

      t_mod.define_singleton_method(:run_testcase) do |exe, _input|
        if exe == comp_fuzz
          ["", false, false]
        else
          ["SUMMARY: UndefinedBehaviorSanitizer: signed-integer-overflow src/prettyprint.c:10\n", true, false]
        end
      end
      slow_res = t_mod.classify_crash_execution("crashes", dummy_in, comp_slow)
      assert_equal comp_slow, slow_res[:executable]
      assert_equal "signed-integer-overflow", slow_res[:reason]

      t_mod.define_singleton_method(:run_testcase) do |exe, _input|
        if exe == comp_fuzz
          ["", false, false]
        else
          ["CRASH[diff_parse_y]: signal=SIGSEGV (11)\n/prism/build/fuzz.diff(rb_st_free_table+0x14) [0x1] /opt/ruby/st.c:667\n", true, false]
        end
      end
      diff_crash_res = t_mod.classify_crash_execution("crashes", dummy_in, comp_diff)
      assert_equal comp_diff, diff_crash_res[:executable]
      assert_equal "SEGV", diff_crash_res[:reason]

      real_segv_src = File.join(workdir, "real_segv.c")
      real_segv_bin = File.join(workdir, "real_segv")
      File.write(real_segv_src, "#include <signal.h>\nint main(void) { raise(SIGSEGV); return 0; }\n")
      assert_cmd(default_cc, real_segv_src, "-o", real_segv_bin)
      silent_segv_res = FuzzTriage.classify_crash_execution("crashes", dummy_in, real_segv_bin)
      assert_equal "SEGV", silent_segv_res[:reason]
      assert_equal true, silent_segv_res[:crashed]

      nonutf8_src = File.join(workdir, "nonutf8_inv.c")
      nonutf8_bin = File.join(workdir, "nonutf8_inv")
      File.write(nonutf8_src, <<~'C')
        #include <stdio.h>
        #include <stdlib.h>
        int main(void) {
          static const char msg[] = "INVARIANT[diff_parse_y]: kind=syntax_mismatch sub=prism_ok_cruby_err nul=0 utf8=0 prism=ok cruby=ArgumentError:unknown_encoding [detail: prism_errs=0 cruby=ArgumentError: unknown encoding name: Windows-31J\xbb\xff]\n";
          fwrite(msg, 1, sizeof(msg) - 1, stderr);
          fflush(stderr);
          abort();
        }
      C
      assert_cmd(default_cc, nonutf8_src, "-o", nonutf8_bin)
      nonutf8_cls = FuzzTriage.classify_crash_execution("crashes", dummy_in, nonutf8_bin)
      assert_equal "ABRT", nonutf8_cls[:reason]
      assert_equal true, nonutf8_cls[:crashed]

      t_mod.define_singleton_method(:run_testcase) do |_exe, _input|
        ["INVARIANT[diff_parse_y]: kind=syntax_mismatch sub=prism_ok_cruby_err nul=0 utf8=0 prism=ok cruby=ArgumentError:unknown_encoding [detail: Windows-31J\xBB]\n".b, true, false]
      end
      mock_nonutf8 = t_mod.classify_crash_execution("crashes", dummy_in, comp_diff)
      assert_equal "ABRT", mock_nonutf8[:reason]
      assert_equal true, mock_nonutf8[:crashed]

      diff_calls = Hash.new(0)
      t_mod.define_singleton_method(:run_testcase) do |exe, _input|
        diff_calls[exe] += 1
        if exe == comp_fuzz
          ["", false, false]
        elsif diff_calls[exe] == 1
          ["", false, true]
        else
          ["CRASH[diff_parse_y]: signal=SIGSEGV (11)\n", true, false]
        end
      end
      retry_diff = t_mod.classify_crash_execution("crashes", dummy_in, comp_diff)
      assert_equal "SEGV", retry_diff[:reason]
      assert_equal false, retry_diff[:unreproducible]
      assert_equal false, retry_diff[:timed_out]
      assert_equal 2, diff_calls[comp_diff]

      sig_raw = FuzzTriage.testcase_output_signature(nonutf8_cls[:testcase_output], nonutf8_cls[:sig_lines])
      sig_clean = FuzzTriage.testcase_output_signature(
        "INVARIANT[diff_parse_y]: kind=syntax_mismatch sub=prism_ok_cruby_err nul=0 utf8=0 prism=ok cruby=ArgumentError:unknown_encoding [detail: other]\n",
        nonutf8_cls[:sig_lines]
      )
      assert_equal sig_clean, sig_raw
    end
  end

  def test_verify_sh_and_verify_rb_partial_fix_and_survivor_extraction
    prism_dir = require_prism_a!

    with_tmpdir("triage-verify-") do |workdir|
      mock_verify = compile_mock_verify(workdir)
      mock_verify_build = File.join(workdir, "mock_verify_build")
      stage_mock_verify_runner(mock_verify, mock_verify_build, profile: "asan_ubsan")

      mock_triage = File.join(workdir, "mock_verify_triage")
      partial_dir = File.join(mock_triage, "ABRT/partial_sig")
      pass_dir = File.join(mock_triage, "ABRT/pass_sig")
      FileUtils.mkdir_p([partial_dir, pass_dir])

      File.binwrite(File.join(partial_dir, "input.min"), "fixed_representative")
      File.binwrite(File.join(pass_dir, "input.min"), "clean_representative")

      bad_bytes = "CRASH_rare_sibling".b
      bad_sha = Digest::SHA256.hexdigest(bad_bytes)
      ok_a = "clean_a".b
      ok_b = "clean_b".b

      write_tar_gz(File.join(partial_dir, "inputs.tar.gz"), [
        [Digest::SHA256.hexdigest(ok_a), ok_a],
        [bad_sha, bad_bytes],
        [Digest::SHA256.hexdigest(ok_b), ok_b]
      ])
      write_tar_gz(File.join(pass_dir, "inputs.tar.gz"), [
        [Digest::SHA256.hexdigest(ok_a), ok_a]
      ])

      write_verify_sh(partial_dir, prism_dir: prism_dir, profile: "asan_ubsan")
      write_verify_sh(pass_dir, prism_dir: prism_dir, profile: "asan_ubsan")

      verify_env = { "VERIFY_BUILD_DIR" => mock_verify_build, "PRISM_A_DIR" => prism_dir }
      assert_cmd(File.join(pass_dir, "verify.sh"), "--quiet", env: verify_env)

      _pout, _perr, pst = run_cmd(File.join(partial_dir, "verify.sh"), "--quiet", env: verify_env)
      refute pst.success?, "expected verify.sh to catch surviving archived crasher when input.min passes"

      surv_dir = File.join(workdir, "survivors")
      report_path = File.join(workdir, "verify_report.json")
      v_out, v_err, v_st = run_cmd(
        RbConfig.ruby, repo_path("triage/verify.rb"),
        "--triage-dir", mock_triage,
        "--extract-survivors", surv_dir,
        "--json", report_path,
        env: verify_env,
        chdir: root_dir
      )
      assert_equal 1, v_st.exitstatus, "expected verify.rb to exit 1 on PARTIAL bucket\nstdout=#{v_out}\nstderr=#{v_err}"

      report = JSON.parse(File.read(report_path))
      summary = report["summary"]
      assert_equal 1, summary["pass"], "unexpected summary: #{summary.inspect}"
      assert_equal 1, summary["partial"], "unexpected summary: #{summary.inspect}"
      assert_equal 0, summary["fail"], "unexpected summary: #{summary.inspect}"
      assert_equal 6, summary["inputs_checked"], "unexpected summary: #{summary.inspect}"
      assert_equal 1, summary["inputs_failed"], "unexpected summary: #{summary.inspect}"

      partial_bucket = report["buckets"].find { |b| b["bucket_id"] == "ABRT/partial_sig" }
      refute_nil partial_bucket
      assert_equal true, partial_bucket["min_passed"]

      surv_file = File.join(surv_dir, "ABRT/partial_sig", bad_sha)
      assert_path_exists surv_file
      assert_equal "CRASH_rare_sibling".b, File.binread(surv_file)
      refute_path_exists File.join(surv_dir, "ABRT/pass_sig")
    end
  end

  def test_verify_rb_lifecycle_fail_partial_pass_invert_and_fail_fast
    prism_dir = require_prism_a!

    with_tmpdir("triage-verify-") do |workdir|
      mock_verify = compile_mock_verify(workdir)
      mock_verify_build = File.join(workdir, "mock_verify_build")
      stage_mock_verify_runner(mock_verify, mock_verify_build, profile: "asan_ubsan")

      triage_dir = File.join(workdir, "lifecycle_triage")
      bucket_a = File.join(triage_dir, "ABRT/bucket_a")
      bucket_b = File.join(triage_dir, "ABRT/bucket_b")
      FileUtils.mkdir_p([bucket_a, bucket_b])

      arch_bad_bytes = "CRASH_arch_a".b
      arch_bad_sha = Digest::SHA256.hexdigest(arch_bad_bytes)
      ok_a_bytes = "clean_a".b
      ok_a_sha = Digest::SHA256.hexdigest(ok_a_bytes)
      ok_b_bytes = "clean_b".b
      ok_b_sha = Digest::SHA256.hexdigest(ok_b_bytes)

      File.binwrite(File.join(bucket_a, "input.min"), "CRASH_min_a")
      write_tar_gz(File.join(bucket_a, "inputs.tar.gz"), [[arch_bad_sha, arch_bad_bytes], [ok_a_sha, ok_a_bytes]])
      File.binwrite(File.join(bucket_b, "input.min"), "CRASH_min_b")
      write_tar_gz(File.join(bucket_b, "inputs.tar.gz"), [[ok_b_sha, ok_b_bytes]])

      verify_env = { "VERIFY_BUILD_DIR" => mock_verify_build, "PRISM_A_DIR" => prism_dir }
      verify_rb = repo_path("triage/verify.rb")

      # 1. FAIL state
      fail_json = File.join(workdir, "fail.json")
      _o1, _e1, st1 = run_cmd(RbConfig.ruby, verify_rb, "--triage-dir", triage_dir, "--json", fail_json, env: verify_env, chdir: root_dir)
      assert_equal 1, st1.exitstatus
      fail_rep = JSON.parse(File.read(fail_json))
      assert_equal 2, fail_rep.dig("summary", "fail")
      assert_equal 0, fail_rep.dig("summary", "partial")
      assert_equal 0, fail_rep.dig("summary", "pass")
      ba_fail = fail_rep["buckets"].find { |b| b["bucket_id"] == "ABRT/bucket_a" }
      assert_equal "FAIL", ba_fail["status"]
      assert_equal false, ba_fail["min_passed"]

      # --invert exits 0 on FAIL
      assert_ruby_cmd(verify_rb, "--triage-dir", triage_dir, "--invert", "--quiet", env: verify_env)

      # --fail-fast stops after first failing bucket
      ff_json = File.join(workdir, "fail_fast.json")
      _off, _eff, st_ff = run_cmd(
        RbConfig.ruby, verify_rb, "--triage-dir", triage_dir, "--fail-fast", "--json", ff_json,
        env: verify_env, chdir: root_dir
      )
      assert_equal 1, st_ff.exitstatus
      ff_rep = JSON.parse(File.read(ff_json))
      assert_equal 1, ff_rep.dig("summary", "buckets_checked")
      assert_equal 1, ff_rep.dig("summary", "fail")

      ff_inv_json = File.join(workdir, "fail_fast_inv.json")
      assert_ruby_cmd(
        verify_rb, "--triage-dir", triage_dir, "--invert", "--fail-fast", "--json", ff_inv_json,
        env: verify_env
      )
      ff_inv_rep = JSON.parse(File.read(ff_inv_json))
      assert_equal 1, ff_inv_rep.dig("summary", "buckets_checked")
      assert_equal 1, ff_inv_rep.dig("summary", "fail")

      # 2. PARTIAL state (bucket_a input.min fixed, archived still fails; bucket_b fixed completely)
      File.binwrite(File.join(bucket_a, "input.min"), "fixed_min_a")
      File.binwrite(File.join(bucket_b, "input.min"), "fixed_min_b")

      surv_partial = File.join(workdir, "surv_partial")
      partial_json = File.join(workdir, "partial.json")
      _o2, _e2, st2 = run_cmd(
        RbConfig.ruby, verify_rb, "--triage-dir", triage_dir,
        "--extract-survivors", surv_partial, "--json", partial_json,
        env: verify_env, chdir: root_dir
      )
      assert_equal 1, st2.exitstatus
      part_rep = JSON.parse(File.read(partial_json))
      assert_equal 1, part_rep.dig("summary", "pass")
      assert_equal 1, part_rep.dig("summary", "partial")
      assert_equal 0, part_rep.dig("summary", "fail")
      assert_equal arch_bad_bytes, File.binread(File.join(surv_partial, "ABRT/bucket_a", arch_bad_sha))
      refute_path_exists File.join(surv_partial, "ABRT/bucket_b")

      # --invert exits 0 on PARTIAL
      assert_ruby_cmd(verify_rb, "--triage-dir", triage_dir, "--invert", "--quiet", env: verify_env)

      # --input-min-only vs --skip-min vs conflict on PARTIAL bucket_a
      min_only_json = File.join(workdir, "min_only.json")
      assert_ruby_cmd(
        verify_rb, "--triage-dir", triage_dir, "--bucket", "ABRT/bucket_a",
        "--input-min-only", "--json", min_only_json,
        env: verify_env
      )
      mo_rep = JSON.parse(File.read(min_only_json))
      assert_equal 1, mo_rep.dig("summary", "pass")
      assert_equal 1, mo_rep.dig("summary", "inputs_checked")

      skip_min_json = File.join(workdir, "skip_min.json")
      _osm, _esm, st_sm = run_cmd(
        RbConfig.ruby, verify_rb, "--triage-dir", triage_dir, "--bucket", "ABRT/bucket_a",
        "--skip-min", "--json", skip_min_json,
        env: verify_env, chdir: root_dir
      )
      assert_equal 1, st_sm.exitstatus
      sm_bucket = JSON.parse(File.read(skip_min_json)).fetch("buckets").first
      assert_equal "FAIL", sm_bucket["status"]
      assert_nil sm_bucket["min_passed"]
      assert_equal 1, sm_bucket["failed"]

      _ocf, _ecf, st_cf = run_cmd(
        RbConfig.ruby, verify_rb, "--triage-dir", triage_dir, "--input-min-only", "--skip-min",
        env: verify_env, chdir: root_dir
      )
      assert_equal 2, st_cf.exitstatus

      # 3. PASS state (archived crasher fixed)
      write_tar_gz(File.join(bucket_a, "inputs.tar.gz"), [[ok_a_sha, ok_a_bytes]])
      surv_pass = File.join(workdir, "surv_pass")
      pass_json = File.join(workdir, "pass.json")
      assert_ruby_cmd(
        verify_rb, "--triage-dir", triage_dir, "--extract-survivors", surv_pass, "--json", pass_json,
        env: verify_env
      )
      pass_rep = JSON.parse(File.read(pass_json))
      assert_equal 2, pass_rep.dig("summary", "pass")
      assert_equal 0, pass_rep.dig("summary", "partial")
      assert_equal 0, pass_rep.dig("summary", "fail")
      assert_equal 0, pass_rep.dig("summary", "inputs_failed")
      refute_path_exists File.join(surv_pass, "ABRT/bucket_a")

      # --invert exits 1 on PASS
      _oinv, _einv, st_inv = run_cmd(
        RbConfig.ruby, verify_rb, "--triage-dir", triage_dir, "--invert", "--quiet",
        env: verify_env, chdir: root_dir
      )
      assert_equal 1, st_inv.exitstatus

      # 4. EMPTY bucket with --invert exits 125
      empty_triage = File.join(workdir, "empty_triage")
      empty_bucket = File.join(empty_triage, "ABRT/empty_sig")
      FileUtils.mkdir_p(empty_bucket)
      File.write(File.join(empty_bucket, "meta.json"), "{}\n")
      _oemp, _eemp, st_emp = run_cmd(
        RbConfig.ruby, verify_rb, "--triage-dir", empty_triage, "--invert", "--quiet",
        env: verify_env, chdir: root_dir
      )
      assert_equal 125, st_emp.exitstatus
    end
  end

  private

  def default_cc
    cc = ENV["CC"].to_s.strip
    cc.empty? ? "clang" : cc
  end

  def require_prism_a!
    pa = prism_a_dir
    skip "missing Prism A target (run 'make targets-sync' first)" unless pa && File.directory?(File.join(pa, "src"))
    pa
  end

  def compile_mock_verify(workdir)
    src = File.join(workdir, "mock_fuzz_target.c")
    bin = File.join(workdir, "mock_verify")
    File.write(src, MOCK_FUZZ_TARGET_C)
    assert_cmd(
      default_cc, "-O1", "-g", "-std=c99", "-fsanitize=address",
      repo_path("triage/verify_runner.c"), src,
      "-o", bin
    )
    bin
  end

  def stage_mock_verify_runner(mock_verify, build_dir, profile: "asan_ubsan")
    FileUtils.mkdir_p(build_dir)
    dst = File.join(build_dir, "verify_runner.#{profile}")
    FileUtils.cp(mock_verify, dst)
    File.chmod(0o755, dst)
    # Ensure mtime exceeds source files so verify_bucket.sh does not overwrite the mock runner.
    future = Time.now + 2
    File.utime(future, future, dst)
    dst
  end

  def write_tar_gz(path, entries, extra_zero_padding: 0)
    Zlib::GzipWriter.open(path) do |gz|
      Gem::Package::TarWriter.new(gz) do |tar|
        entries.each do |name, body|
          bytes = body.b
          tar.add_file_simple(name, 0o644, bytes.bytesize) { |io| io.write(bytes) }
        end
      end
      gz.write("\0" * extra_zero_padding) if extra_zero_padding > 0
    end
  end

  def write_pack_file(path, entries)
    File.open(path, "wb") do |io|
      entries.each do |name, body|
        bytes = body.b
        io.write("#{name}\t#{bytes.bytesize}\n")
        io.write(bytes)
        io.write("\n")
      end
    end
  end

  def gunzip_bytes(path)
    Zlib::GzipReader.open(path, &:read)
  end

  def write_verify_sh(bucket_dir, prism_dir:, profile: "asan_ubsan")
    verify_sh = File.join(bucket_dir, "verify.sh")
    write_executable(verify_sh, <<~SH)
      #!/usr/bin/env bash
      set -euo pipefail
      exec #{Shellwords.escape(repo_path("triage/verify_bucket.sh"))} --repo-root #{Shellwords.escape(prism_dir)} --fuzz-root #{Shellwords.escape(root_dir)} --bucket-dir #{Shellwords.escape(bucket_dir)} --profile #{Shellwords.escape(profile)} "$@"
    SH
  end

  def resolve_real_verify_build_dir(workdir)
    fallback = File.join(workdir, "real_verify_build")
    env_dir = ENV["REAL_VERIFY_BUILD_DIR"].to_s.strip
    if env_dir.empty?
      FileUtils.mkdir_p(fallback)
      return [fallback, nil]
    end

    if dir_writable?(env_dir)
      [env_dir, nil]
    else
      FileUtils.mkdir_p(fallback)
      [fallback, File.directory?(env_dir) ? env_dir : nil]
    end
  end

  def dir_writable?(dir)
    FileUtils.mkdir_p(dir) unless File.exist?(dir)
    return false unless File.directory?(dir)

    probe = File.join(dir, ".write_probe_#{Process.pid}_#{Thread.current.object_id}")
    File.write(probe, "")
    File.delete(probe)
    true
  rescue SystemCallError
    false
  end
end
