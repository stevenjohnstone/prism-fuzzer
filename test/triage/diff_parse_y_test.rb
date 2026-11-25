# frozen_string_literal: true

require_relative "../lib/autorun"

require "fileutils"
require "json"
require "open3"
require "rubygems/package"
require "zlib"

require_relative "../../runtime/provenance"
require_relative "../../triage/triage"

# Migrated from stage_diff_parse_y of test/test_triage.sh.
# Verifies differential parse.y signature deduplication (signature.sh and
# FuzzTriage), live verify_bucket.sh --profile diff_parse_y against /opt/ruby
# and synthetic Prism/CRuby failure injections (zero error recovery, unfiltered
# AST mismatch, SIGSEGV backtrace, FUZZ_DIFF_BACKTRACE=0, locked-stderr signal
# safety, and tightened AST parity), oracle metadata detection, build_diff.sh
# dirty-git provenance, and dual-domain afl-showmap edge coverage.
class TriageDiffParseYTest < Minitest::Test
  FILTERED_DIVERGENCE_SOURCES = [
    "foo(bar baz do end)".b,
    "/[/".b,
    "/\x8e/".b,
    "#coding:Window\x00-31J".b,
    "/(?<\r/".b,
    "%r (#$ ".b,
    "while def d;break end\nend ".b,
    "(unless def ! =s then end.o,(((::B,))))=unless{}then end::B{}end".b
  ].freeze

  def test_diff_parse_y_signature_deduplication
    # Differential INVARIANT[diff_parse_y] signature deduplication across details,
    # sub kinds, hygiene/cruby tags, utf8 flags, scope, and raw non-UTF-8 bytes.
    ds1 = run_signature("INVARIANT[diff_parse_y]: kind=syntax_mismatch sub=prism_ok_cruby_err nul=1 utf8=0 prism=ok cruby=ArgumentError:unknown_encoding [detail: prism_errs=0 cruby=ArgumentError: unknown encoding name: foo]\n")
    ds2 = run_signature("INVARIANT[diff_parse_y]: kind=syntax_mismatch sub=prism_ok_cruby_err nul=1 utf8=0 prism=ok cruby=ArgumentError:unknown_encoding [detail: prism_errs=0 cruby=ArgumentError: unknown encoding name: bar]\n")
    ds3 = run_signature("INVARIANT[diff_parse_y]: kind=syntax_mismatch sub=prism_err_cruby_ok nul=0 utf8=1 prism=expect_rparen cruby=ok [detail: prism_errs=1 cruby=ok]\n")
    ds4 = run_signature("INVARIANT[diff_parse_y]: kind=syntax_mismatch sub=prism_ok_cruby_err nul=0 utf8=1 prism=ok cruby=SyntaxError:unexpected_do_block [detail: a]\n")
    ds5 = run_signature("INVARIANT[diff_parse_y]: kind=syntax_mismatch sub=prism_ok_cruby_err nul=1 utf8=1 prism=ok cruby=ArgumentError:unknown_encoding [detail: a]\n")
    ds6 = run_signature("INVARIANT[diff_parse_y]: kind=ast_block_owner_mismatch sub=operator [detail: idx=0 prism=r cruby=&]\n")
    ds7 = run_signature("INVARIANT[diff_parse_y]: kind=ast_block_owner_mismatch sub=operator [detail: idx=1 prism=foo cruby=+]\n")
    ds8 = run_signature("INVARIANT[diff_parse_y]: kind=ast_block_owner_mismatch sub=method [detail: idx=0 prism=a cruby=b]\n")
    ds9 = run_signature("INVARIANT[diff_parse_y]: kind=locals_count_mismatch scope=def [detail: scope_idx=1 prism=1 cruby=0]\n")
    ds10 = run_signature("INVARIANT[diff_parse_y]: kind=locals_count_mismatch scope=program [detail: scope_idx=0 prism=1 cruby=0]\n")
    ds11 = run_signature("INVARIANT[diff_parse_y]: kind=syntax_mismatch sub=prism_ok_cruby_err nul=0 utf8=0 prism=ok cruby=SyntaxError:invalid_multibyte_utf8 [detail: \xff\xfe]\n".b)
    ds12 = run_signature("INVARIANT[diff_parse_y]: kind=syntax_mismatch sub=prism_ok_cruby_err nul=0 utf8=0 prism=ok cruby=SyntaxError:invalid_multibyte_utf8 [detail: a]\n")
    ds13 = run_signature("INVARIANT[diff_parse_y]: kind=ast_tree_mismatch sub=label prism=CALL:+ cruby=CALL:* [detail: idx=1 prism_len=46 cruby_len=46]\n")
    ds14 = run_signature("INVARIANT[diff_parse_y]: kind=ast_tree_mismatch sub=label prism=CALL:+ cruby=CALL:* [detail: idx=9 prev=SCOPE:def prism_len=80 cruby_len=80]\n")
    ds15 = run_signature("INVARIANT[diff_parse_y]: kind=ast_tree_mismatch sub=tag prism=INT cruby=ARRAY [detail: idx=2 prism_len=6 cruby_len=10]\n")

    assert_equal ds1, ds2, "expected identical diff signature across details, got #{ds1} vs #{ds2}"
    refute_equal ds1, ds3, "expected distinct diff signatures across sub kinds (#{ds1} == #{ds3})"
    refute_equal ds1, ds4, "expected distinct diff signatures across cruby/hygiene tags (#{ds1} == #{ds4})"
    refute_equal ds1, ds5, "expected distinct diff signatures across utf8 flag (#{ds1} == #{ds5})"
    assert_equal ds6, ds7, "expected identical ast_block_owner_mismatch signatures across details (#{ds6} vs #{ds7})"
    refute_equal ds6, ds8, "expected distinct ast_block_owner_mismatch signatures across sub (#{ds6} == #{ds8})"
    refute_equal ds9, ds10, "expected distinct locals_count_mismatch signatures across scope (#{ds9} == #{ds10})"
    assert_equal ds11, ds12, "expected identical diff signature when [detail: ...] contains non-UTF-8 bytes (#{ds11} != #{ds12})"
    assert_equal ds13, ds14, "expected identical ast_tree_mismatch signatures across details (#{ds13} vs #{ds14})"
    refute_equal ds13, ds15, "expected distinct ast_tree_mismatch signatures across sub/tags (#{ds13} == #{ds15})"

    # Differential CRASH[diff_parse_y] backtrace normalization across ASLR, paths, and signals.
    dc1 = run_signature(<<~TRACE)
      CRASH[diff_parse_y]: signal=SIGSEGV (11)
      /prism/build/fuzz.diff(diff_fatal_signal_handler+0x4c) [0xaaaa1000] /prism/harnesses/prism/diff.c:96
      linux-vdso.so.1(__kernel_rt_sigreturn+0x0) [0xffff0000]
      /prism/build/fuzz.diff(rb_st_free_table+0x14) [0xaaaa2000] /opt/ruby/st.c:667
    TRACE
    dc2 = run_signature(<<~TRACE)
      CRASH[diff_parse_y]: signal=SIGSEGV (11)
      /other/build/fuzz.diff(diff_fatal_signal_handler+0x99) [0xbbbb1000] /other/harnesses/prism/diff.c:96
      /other/build/fuzz.diff(rb_st_free_table+0x28) [0xbbbb2000] /opt/ruby/st.c:667
    TRACE
    dc3 = run_signature(<<~TRACE)
      CRASH[diff_parse_y]: signal=SIGSEGV (11)
      /prism/build/fuzz.diff(other_cruby_fn+0x10) [0xaaaa3000] /opt/ruby/parse.y:999
    TRACE
    assert_equal dc1, dc2, "expected identical diff crash signature across ASLR/paths, got #{dc1} vs #{dc2}"
    refute_equal dc1, dc3, "expected distinct diff crash signatures for distinct frames (#{dc1} == #{dc3})"

    dc4 = run_signature(<<~TRACE)
      CRASH[diff_parse_y]: signal=SIGTRAP (5)
      /prism/build/fuzz.diff(rb_print_backtrace+0x28) [0xaaaa0800] /opt/ruby/vm_dump.c:1108
      /prism/build/fuzz.diff(diff_fatal_signal_handler+0x4c) [0xaaaa1000] /prism/harnesses/prism/diff.c:1509
      linux-vdso.so.1(__kernel_rt_sigreturn+0x0) [0xffff0000]
      /prism/build/fuzz.diff(rb_parser_enc_cr_str_buf_cat+0x3b8) [0xaaaa2000] /prism/parse.y:2400
    TRACE
    dc5 = run_signature(<<~TRACE)
      CRASH[diff_parse_y]: signal=SIGTRAP (5)
      /other/build/fuzz.diff(diff_fatal_signal_handler+0x99) [0xbbbb1000] /other/harnesses/prism/diff.c:1509
      /other/build/fuzz.diff(rb_parser_enc_cr_str_buf_cat+0x97c) [0xbbbb2000] /prism/parse.y:2400
    TRACE
    assert_equal dc4, dc5, "expected identical diff SIGTRAP signature across ASLR/paths, got #{dc4} vs #{dc5}"
    refute_equal dc4, dc1, "expected distinct diff signature for SIGTRAP vs SIGSEGV (#{dc4} == #{dc1})"
  end

  def test_showmap_env_disables_diff_backtrace
    senv = FuzzTriage.showmap_env
    assert_equal "0", senv["FUZZ_DIFF_BACKTRACE"],
                 "expected showmap_env to set FUZZ_DIFF_BACKTRACE=0"
    assert_includes senv.fetch("ASAN_OPTIONS"), "detect_stack_use_after_return=0"
  end

  def test_ruby_oracle_version_detection_and_diff_metadata
    require_ruby_oracle!

    oracle = FuzzTriage.detect_oracle_dir_versions
    assert oracle && oracle[:version] && oracle[:revision] && oracle[:release_date],
           "expected detect_oracle_dir_versions from /opt/ruby, got: #{oracle.inspect}"

    diff_probe_bin = [
      repo_path("tmp/fuzz/build/fuzz.diff"),
      repo_path("build/fuzz.diff")
    ].find { |p| File.executable?(p) }

    if diff_probe_bin
      ver_out, = assert_cmd(diff_probe_bin, "--version")
      assert_includes ver_out, "prism=", "expected prism= line from #{diff_probe_bin} --version, got:\n#{ver_out}"
      assert_includes ver_out, "ruby_version=", "expected ruby_version= line from #{diff_probe_bin} --version, got:\n#{ver_out}"

      probed = FuzzTriage.probe_diff_binary_versions(diff_probe_bin)
      assert probed && probed["prism"] && probed["ruby_version"] && probed["ruby_release_date"] && probed["ruby_description"],
             "expected probe_diff_binary_versions(#{diff_probe_bin}) to parse all 4 keys, got: #{probed.inspect}"
    end

    Dir.chdir(root_dir) do
      vmeta = FuzzTriage.resolve_versions_metadata(executable: "fuzz.diff", is_diff: true, target_ruby_version: "4.1")
      assert vmeta && vmeta.dig("prism", "version") && vmeta.dig("ruby_parse_y", "version") && vmeta.dig("ruby_parse_y", "revision"),
             "expected prism + ruby_parse_y metadata for diff oracle, got: #{vmeta.inspect}"
    end
  end

  def test_verify_bucket_diff_parse_y_filtered_failures_signals_and_tighten_parity
    require_ruby_oracle!
    prism_dir = require_prism_a!

    with_tmpdir("diff-parse-y-verify-") do |workdir|
      diff_verify_build = resolve_env_or_tmp_dir(
        "DIFF_VERIFY_BUILD_DIR",
        File.join(workdir, "diff_verify_build")
      )
      verify_bucket_sh = repo_path("triage/verify_bucket.sh")

      diff_bucket = File.join(workdir, "diff_triage_test/ABRT/diff_bucket")
      FileUtils.mkdir_p(diff_bucket)

      # Known filtered parse.y/Onigmo/NUL divergences pass verify_bucket.sh --profile diff_parse_y.
      FILTERED_DIVERGENCE_SOURCES.each_with_index do |filtered_src, idx|
        File.binwrite(File.join(diff_bucket, "input.min"), seed_bytes(filtered_src))
        out, = assert_cmd(
          verify_bucket_sh,
          "--repo-root", prism_dir,
          "--fuzz-root", root_dir,
          "--bucket-dir", diff_bucket,
          "--profile", "diff_parse_y",
          "--json",
          env: { "VERIFY_BUILD_DIR" => diff_verify_build },
          msg: "filtered divergence ##{idx} (#{filtered_src.inspect}) unexpectedly failed diff_parse_y"
        )
        rep = JSON.parse(out)
        assert_equal 1, rep["passed"], "expected filtered divergence ##{idx} to pass: #{rep.inspect}"
        assert_equal 0, rep["failed"], "expected filtered divergence ##{idx} failed=0: #{rep.inspect}"
      end

      # Mock Prism zero-error-recovery failure (and verify_profile inference via meta.json).
      mock_diff_prism = prepare_mock_diff_prism(workdir, prism_dir)
      mock_prism_verify_build = File.join(workdir, "mock_diff_prism_verify_build")
      seed_oracle_cache(diff_verify_build, mock_prism_verify_build)

      File.binwrite(File.join(diff_bucket, "input.min"), seed_bytes("MOCK_DIFF_ZERO_ER\n"))
      File.write(File.join(diff_bucket, "meta.json"), "{\"verify_profile\":\"diff_parse_y\",\"reason\":\"ABRT\"}\n")

      zero_er_out, zero_er_err, zero_er_st = run_cmd(
        verify_bucket_sh,
        "--repo-root", mock_diff_prism,
        "--fuzz-root", root_dir,
        "--bucket-dir", diff_bucket,
        "--json",
        env: { "VERIFY_BUILD_DIR" => mock_prism_verify_build }
      )
      assert_equal 1, zero_er_st.exitstatus,
                   "expected verify_bucket.sh diff_parse_y ast_zero_error_recovery FAIL exit 1, got #{zero_er_st.exitstatus}\nstdout=#{zero_er_out}\nstderr=#{zero_er_err}"
      zero_er_rep = JSON.parse(zero_er_out)
      assert_equal 1, zero_er_rep["failed"], "expected failed=1 for MOCK_DIFF_ZERO_ER: #{zero_er_rep.inspect}"
      assert_includes zero_er_rep.dig("failures", 0, "output").to_s, "ast_zero_error_recovery"

      # Unfiltered ast_block_owner_mismatch fails verify_runner under diff_parse_y.
      File.binwrite(File.join(diff_bucket, "input.min"), seed_bytes("BEGIN{E{}\nBEGIN{N{}}}\n"))
      fail_out, fail_err, fail_st = run_cmd(
        verify_bucket_sh,
        "--repo-root", prism_dir,
        "--fuzz-root", root_dir,
        "--bucket-dir", diff_bucket,
        "--json",
        env: { "VERIFY_BUILD_DIR" => diff_verify_build }
      )
      assert_equal 1, fail_st.exitstatus,
                   "expected verify_bucket.sh diff_parse_y FAIL exit 1, got #{fail_st.exitstatus}\nstdout=#{fail_out}\nstderr=#{fail_err}"
      fail_rep = JSON.parse(fail_out)
      assert_equal 1, fail_rep["failed"], "expected failed=1 for unfiltered divergence: #{fail_rep.inspect}"

      # Fatal CRuby parse.y signals must report WIFSIGNALED cleanly with CRASH[diff_parse_y]
      # instead of silently swallowing signals, respect FUZZ_DIFF_BACKTRACE=0, and stay
      # async-signal-safe when stderr stdio lock is held.
      mock_diff_fuzz = prepare_mock_diff_fuzz(workdir)
      mock_fuzz_verify_build = File.join(workdir, "mock_diff_verify_build")
      seed_oracle_cache(diff_verify_build, mock_fuzz_verify_build)
      mock_verify_sh = File.join(mock_diff_fuzz, "triage/verify_bucket.sh")

      File.binwrite(File.join(diff_bucket, "input.min"), seed_bytes("MOCK_DIFF_SEGV"))
      segv_out, segv_err, segv_st = run_cmd(
        mock_verify_sh,
        "--repo-root", prism_dir,
        "--fuzz-root", mock_diff_fuzz,
        "--bucket-dir", diff_bucket,
        "--json",
        env: { "VERIFY_BUILD_DIR" => mock_fuzz_verify_build }
      )
      assert_equal 1, segv_st.exitstatus,
                   "expected verify_bucket.sh diff_parse_y SEGV FAIL exit 1, got #{segv_st.exitstatus}\nstdout=#{segv_out}\nstderr=#{segv_err}"
      segv_rep = JSON.parse(segv_out)
      segv_fail = segv_rep.dig("failures", 0)
      assert segv_fail &&
               segv_fail["signal"] == 11 &&
               segv_fail["output"].to_s.start_with?("CRASH[diff_parse_y]: signal=SIGSEGV (11)") &&
               segv_fail["output"].to_s.include?("mock_ruby_yyparse"),
             "expected signaled SIGSEGV CRASH[diff_parse_y] failure with backtrace, got: #{segv_rep.inspect}"

      nobt_out, nobt_err, nobt_st = run_cmd(
        mock_verify_sh,
        "--repo-root", prism_dir,
        "--fuzz-root", mock_diff_fuzz,
        "--bucket-dir", diff_bucket,
        "--json",
        env: {
          "FUZZ_DIFF_BACKTRACE" => "0",
          "VERIFY_BUILD_DIR" => mock_fuzz_verify_build
        }
      )
      assert_equal 1, nobt_st.exitstatus,
                   "expected verify_bucket.sh diff_parse_y FUZZ_DIFF_BACKTRACE=0 SEGV FAIL exit 1, got #{nobt_st.exitstatus}\nstdout=#{nobt_out}\nstderr=#{nobt_err}"
      nobt_rep = JSON.parse(nobt_out)
      nobt_fail = nobt_rep.dig("failures", 0)
      assert nobt_fail &&
               nobt_fail["signal"] == 11 &&
               nobt_fail["output"].to_s.strip == "CRASH[diff_parse_y]: signal=SIGSEGV (11)",
             "expected FUZZ_DIFF_BACKTRACE=0 to omit CRuby backtrace, got: #{nobt_rep.inspect}"

      File.binwrite(File.join(diff_bucket, "input.min"), seed_bytes("MOCK_DIFF_STDLOCK_SEGV"))
      stdlock_out, stdlock_err, stdlock_st = run_cmd_with_timeout(
        5,
        mock_verify_sh,
        "--repo-root", prism_dir,
        "--fuzz-root", mock_diff_fuzz,
        "--bucket-dir", diff_bucket,
        "--json",
        env: { "VERIFY_BUILD_DIR" => mock_fuzz_verify_build }
      )
      assert_equal 1, stdlock_st.exitstatus,
                   "expected verify_bucket.sh diff_parse_y locked-stderr SEGV FAIL exit 1 without deadlock, got #{stdlock_st.exitstatus}\nstdout=#{stdlock_out}\nstderr=#{stdlock_err}"
      stdlock_rep = JSON.parse(stdlock_out)
      stdlock_fail = stdlock_rep.dig("failures", 0)
      assert stdlock_fail &&
               stdlock_fail["signal"] == 11 &&
               stdlock_fail["output"].to_s.start_with?("CRASH[diff_parse_y]: signal=SIGSEGV (11)") &&
               stdlock_fail["output"].to_s.include?("mock_ruby_yyparse"),
             "expected async-signal-safe SIGSEGV CRASH[diff_parse_y] under held stderr lock, got: #{stdlock_rep.inspect}"

      # Stack overflow in non-ASan diff_parse_y runs on diff_signal_altstack (SA_ONSTACK)
      # rather than double-faulting with 0 bytes of stderr.
      File.binwrite(File.join(diff_bucket, "input.min"), seed_bytes("MOCK_DIFF_STACK_OVERFLOW"))
      so_nonasan_out, so_nonasan_err, so_nonasan_st = run_cmd_with_timeout(
        10,
        mock_verify_sh,
        "--repo-root", prism_dir,
        "--fuzz-root", mock_diff_fuzz,
        "--bucket-dir", diff_bucket,
        "--json",
        env: { "VERIFY_BUILD_DIR" => mock_fuzz_verify_build }
      )
      assert_equal 1, so_nonasan_st.exitstatus,
                   "expected non-ASan stack-overflow FAIL exit 1, got #{so_nonasan_st.exitstatus}\nstdout=#{so_nonasan_out}\nstderr=#{so_nonasan_err}"
      so_nonasan_fail = JSON.parse(so_nonasan_out).dig("failures", 0)
      assert so_nonasan_fail &&
               so_nonasan_fail["signal"] == 11 &&
               so_nonasan_fail["output"].to_s.start_with?("CRASH[diff_parse_y]: signal=SIGSEGV (11)"),
             "expected non-ASan stack-overflow to report CRASH[diff_parse_y] via sigaltstack, got: #{so_nonasan_out}"

      # ASan diff_parse_y buckets (including silent legacy SEGV buckets) automatically build
      # verify_runner.diff_parse_y_asan and keep ASan's SA_ONSTACK stack-overflow handler active.
      asan_so_bucket = File.join(workdir, "diff_triage_test/SEGV/silent_stack_overflow")
      FileUtils.mkdir_p(asan_so_bucket)
      File.binwrite(File.join(asan_so_bucket, "input.min"), seed_bytes("MOCK_DIFF_STACK_OVERFLOW"))
      File.write(File.join(asan_so_bucket, "meta.json"), "{\"verify_profile\":\"diff_parse_y\",\"reason\":\"SEGV\",\"symptom\":{\"headline\":null}}\n")
      so_asan_out, so_asan_err, so_asan_st = run_cmd_with_timeout(
        60,
        mock_verify_sh,
        "--repo-root", prism_dir,
        "--fuzz-root", mock_diff_fuzz,
        "--bucket-dir", asan_so_bucket,
        "--json",
        env: { "VERIFY_BUILD_DIR" => mock_fuzz_verify_build }
      )
      assert_equal 1, so_asan_st.exitstatus,
                   "expected ASan stack-overflow FAIL exit 1, got #{so_asan_st.exitstatus}\nstdout=#{so_asan_out}\nstderr=#{so_asan_err}"
      so_asan_fail = JSON.parse(so_asan_out).dig("failures", 0)
      assert so_asan_fail &&
               so_asan_fail["output"].to_s.include?("AddressSanitizer: stack-overflow"),
             "expected ASan stack-overflow diagnostic from diff_parse_y_asan, got: #{so_asan_out}"

      # Valid `1 + 2` passes diff_parse_y verification.
      File.binwrite(File.join(diff_bucket, "input.min"), seed_bytes("1 + 2"))
      pass_out, = assert_cmd(
        verify_bucket_sh,
        "--repo-root", prism_dir,
        "--fuzz-root", root_dir,
        "--bucket-dir", diff_bucket,
        "--json",
        env: { "VERIFY_BUILD_DIR" => diff_verify_build }
      )
      pass_rep = JSON.parse(pass_out)
      assert_equal 1, pass_rep["passed"]
      assert_equal 0, pass_rep["failed"]

      # Tightened diff.c parity checks: top-level BEGIN{} hoisting, unsorted block_owners
      # traversal order, and break/next/redo/retry/postexe/case3/in/resbody/ensure counts.
      tighten_dir = File.join(workdir, "diff_tighten_pass")
      FileUtils.mkdir_p(tighten_dir)
      File.binwrite(File.join(tighten_dir, "input.min"), seed_bytes("->do end;BEGIN{b{}} "))
      write_tar_gz(File.join(tighten_dir, "inputs.tar.gz"), [
        ["multi_begin.rb", seed_bytes("BEGIN { a {} }; -> do end; BEGIN { b {} }\n")],
        ["block_owners.rb", seed_bytes("m { a {} }; b {}\na {}.b {}\nf(g {}) {}\na, b {} = c {}\n")],
        ["extra_counts.rb", seed_bytes("while 1; break; next; redo; end\nbegin; rescue A; rescue B; retry; ensure; end\n1 rescue 2\nEND {}\ncase 1; in 1; end\n1 in 1\n1 => a\ndef f; ensure; end\n")]
      ])

      tighten_out, = assert_cmd(
        verify_bucket_sh,
        "--repo-root", prism_dir,
        "--fuzz-root", root_dir,
        "--bucket-dir", tighten_dir,
        "--profile", "diff_parse_y",
        "--json",
        env: { "VERIFY_BUILD_DIR" => diff_verify_build }
      )
      tighten_rep = JSON.parse(tighten_out)
      assert_equal 4, tighten_rep["total"], "expected diff_tighten PASS on 4 inputs: #{tighten_rep.inspect}"
      assert_equal 4, tighten_rep["checked"], "expected diff_tighten PASS on 4 inputs: #{tighten_rep.inspect}"
      assert_equal 4, tighten_rep["passed"], "expected diff_tighten PASS on 4 inputs: #{tighten_rep.inspect}"
      assert_equal 0, tighten_rep["failed"], "expected diff_tighten PASS on 4 inputs: #{tighten_rep.inspect}"
      assert_empty tighten_rep["failures"], "expected diff_tighten PASS on 4 inputs: #{tighten_rep.inspect}"

      # Verify summary.c token normalization (<id> vs operators/specials) and nested SLOT -> parent ctx
      tok_test_c = File.join(workdir, "tok_sig_test.c")
      tok_test_bin = File.join(workdir, "tok_sig_test")
      File.write(tok_test_c, <<~'C')
        #include <assert.h>
        #include <stdio.h>
        #include <string.h>
        #include "diff/summary.h"

        int main(int argc, char **argv) {
            if (argc < 2) return 2;
            diff_summary_t a, b;
            diff_summary_init(&a);
            diff_summary_init(&b);
            if (strcmp(argv[1], "call_ident") == 0) {
                diff_tree_open_cstr(&a, DIFF_TOK_SCOPE, "program");
                diff_tree_open_cstr(&a, DIFF_TOK_CALL, "foo_bar");
                diff_tree_close(&a);
                diff_tree_close(&a);

                diff_tree_open_cstr(&b, DIFF_TOK_SCOPE, "program");
                diff_tree_open_cstr(&b, DIFF_TOK_CALL, "baz_qux");
                diff_tree_close(&b);
                diff_tree_close(&b);
            } else if (strcmp(argv[1], "call_op") == 0) {
                diff_tree_open_cstr(&a, DIFF_TOK_CALL, "+");
                diff_tree_close(&a);
                diff_tree_open_cstr(&b, DIFF_TOK_CALL, "*");
                diff_tree_close(&b);
            } else if (strcmp(argv[1], "nested_slot") == 0) {
                diff_tree_open_cstr(&a, DIFF_TOK_CALL, "f");
                diff_tree_open_cstr(&a, DIFF_TOK_SLOT, "args");
                diff_tree_open_cstr(&a, DIFF_TOK_SLOT, "arg");
                diff_tree_open_cstr(&a, DIFF_TOK_SPLAT, NULL);
                diff_tree_close(&a);
                diff_tree_close(&a);
                diff_tree_close(&a);
                diff_tree_close(&a);

                diff_tree_open_cstr(&b, DIFF_TOK_CALL, "f");
                diff_tree_open_cstr(&b, DIFF_TOK_SLOT, "args");
                diff_tree_open_cstr(&b, DIFF_TOK_SLOT, "arg");
                diff_tree_open_cstr(&b, DIFF_TOK_ARRAY, NULL);
                diff_tree_close(&b);
                diff_tree_close(&b);
                diff_tree_close(&b);
                diff_tree_close(&b);
            } else if (strcmp(argv[1], "preexe") == 0) {
                a.has_nested_preexe = true;
                diff_tree_open_cstr(&a, DIFF_TOK_SCOPE, "program");
                diff_tree_open_cstr(&a, DIFF_TOK_UNDEF, NULL);
                diff_tree_close(&a);
                diff_tree_close(&a);

                diff_tree_open_cstr(&b, DIFF_TOK_SCOPE, "program");
                diff_tree_open_cstr(&b, DIFF_TOK_INT, NULL);
                diff_tree_close(&b);
                diff_tree_close(&b);
            }
            diff_compare_asts(&a, &b);
            diff_summary_free(&a);
            diff_summary_free(&b);
            return 0;
        }
      C
      assert_cmd(
        ENV.fetch("CC", "clang"), "-O1", "-std=c99", "-Wall", "-Werror",
        "-I#{repo_path('harnesses/prism')}",
        tok_test_c, repo_path("harnesses/prism/diff/summary.c"),
        "-o", tok_test_bin
      )
      _, err_ident, st_ident = run_cmd(tok_test_bin, "call_ident")
      refute st_ident.success?
      assert_includes err_ident, "INVARIANT[diff_parse_y]: kind=ast_tree_mismatch sub=label ctx=SCOPE.program prism=CALL:<id> cruby=CALL:<id> [detail:"
      assert_includes err_ident, "prism_tok=CALL:foo_bar cruby_tok=CALL:baz_qux"

      _, err_op, st_op = run_cmd(tok_test_bin, "call_op")
      refute st_op.success?
      assert_includes err_op, "INVARIANT[diff_parse_y]: kind=ast_tree_mismatch sub=label ctx=ROOT prism=CALL:+ cruby=CALL:* [detail:"

      _, err_slot, st_slot = run_cmd(tok_test_bin, "nested_slot")
      refute st_slot.success?
      assert_includes err_slot, "INVARIANT[diff_parse_y]: kind=ast_tree_mismatch sub=tag ctx=CALL.arg prism=SPLAT cruby=ARRAY [detail:"

      _, err_pre, st_pre = run_cmd(tok_test_bin, "preexe")
      refute st_pre.success?
      assert_includes err_pre, "INVARIANT[diff_parse_y]: kind=ast_preexe_order_mismatch sub=tree [detail:"

      # Encoding mismatch surfaces enc=<name> and ctx=<node> while moving utf8/nul into [detail: ...]
      File.binwrite(File.join(diff_bucket, "input.min"), seed_bytes("# encoding: CESU-8\n1 + 2\n"))
      enc_out, _, enc_st = run_cmd(
        verify_bucket_sh,
        "--repo-root", prism_dir,
        "--fuzz-root", root_dir,
        "--bucket-dir", diff_bucket,
        "--profile", "diff_parse_y",
        "--json",
        env: { "VERIFY_BUILD_DIR" => diff_verify_build }
      )
      if enc_st.exitstatus == 1
        enc_hl = JSON.parse(enc_out).dig("failures", 0, "headline").to_s
        assert_match(/\benc=CESU-8\b/, enc_hl)
        assert_match(/\bctx=program\b/, enc_hl)
        refute_includes enc_hl.sub(/\s*\[detail:.*$/, ""), "utf8="

        # Large (> 1024 B) diff_parse_y crash must auto-clamp FUZZ_MAX_INPUT_SIZE in verify_bucket.sh
        # instead of silently passing via diff.c's size guard when FUZZ_MAX_INPUT_SIZE is unset:
        File.binwrite(
          File.join(diff_bucket, "input.min"),
          seed_bytes("# encoding: CESU-8\n#{"#" * 1500}\n1 + 2\n")
        )
        big_diff_out, big_diff_err, big_diff_st = run_cmd(
          verify_bucket_sh,
          "--repo-root", prism_dir,
          "--fuzz-root", root_dir,
          "--bucket-dir", diff_bucket,
          "--profile", "diff_parse_y",
          "--json",
          env: { "VERIFY_BUILD_DIR" => diff_verify_build, "FUZZ_MAX_INPUT_SIZE" => nil }
        )
        assert_equal 1, big_diff_st.exitstatus,
                     "expected >1024B diff_parse_y input to reproduce without FUZZ_MAX_INPUT_SIZE env:\nstdout=#{big_diff_out}\nstderr=#{big_diff_err}"
      end

      # Stress CRuby GC under ASan (both verify_bucket.sh default ASAN_OPTIONS and
      # caller-supplied ASAN_OPTIONS without detect_stack_use_after_return=0) to ensure
      # -fsanitize-address-use-after-return=never + entry-frame ruby_init_stack hold.
      gc_stress_dir = File.join(workdir, "diff_gc_stress")
      FileUtils.mkdir_p(gc_stress_dir)
      gc_src = seed_bytes("def f(a = 1); [1, 2, 3].map { |x| { k: x.to_s } }; end\nclass C < Array; BEGIN { @x = 1 }; end\n")
      File.binwrite(File.join(gc_stress_dir, "input.min"), gc_src)
      write_tar_gz(File.join(gc_stress_dir, "inputs.tar.gz"), Array.new(32) { |i| ["s#{i}.rb", gc_src] })
      gc_env_base = {
        "VERIFY_BUILD_DIR" => diff_verify_build,
        "RUBY_GC_MALLOC_LIMIT" => "1024",
        "RUBY_GC_MALLOC_LIMIT_MAX" => "2048",
        "RUBY_GC_OLDMALLOC_LIMIT" => "1024",
        "RUBY_GC_OLDMALLOC_LIMIT_MAX" => "2048"
      }
      [nil, "detect_leaks=0:abort_on_error=1:symbolize=0"].each do |asan_override|
        gc_out, = assert_cmd(
          verify_bucket_sh,
          "--repo-root", prism_dir,
          "--fuzz-root", root_dir,
          "--bucket-dir", gc_stress_dir,
          "--profile", "diff_parse_y",
          "--json",
          env: gc_env_base.merge("ASAN_OPTIONS" => asan_override)
        )
        gc_rep = JSON.parse(gc_out)
        assert_equal 33, gc_rep["passed"], "expected CRuby GC stress PASS (ASAN_OPTIONS=#{asan_override.inspect}): #{gc_rep.inspect}"
        assert_equal 0, gc_rep["failed"], "expected CRuby GC stress zero failures (ASAN_OPTIONS=#{asan_override.inspect}): #{gc_rep.inspect}"
      end
    end
  end

  def test_build_diff_fuzz_dirty_provenance_and_dual_domain_showmap
    require_ruby_oracle!
    prism_dir = require_prism_a!
    skip "requires AFL PCGUARD toolchain (afl-clang-fast + SanitizerCoveragePCGUARD.so)" unless afl_pcguard_ready?
    skip "requires git executable" unless find_executable("git")

    with_tmpdir("diff-parse-y-fuzz-") do |workdir|
      mock_diff_prism = prepare_mock_diff_prism(workdir, prism_dir)
      oracle_dir = resolve_env_or_tmp_dir(
        "DIFF_TC_ORACLE_DIR",
        File.join(workdir, "mock_diff_fuzz_oracle")
      )
      mock_fuzz_diff = File.join(workdir, "mock_fuzz_diff")

      assert_cmd(
        repo_path("harnesses/prism/build_diff.sh"),
        "--mode", "fuzz",
        "--prism-root", mock_diff_prism,
        "--ruby-dir", "/opt/ruby",
        "--fuzz-root", root_dir,
        "--oracle-dir", oracle_dir,
        "--afl-path", afl_build_dir,
        "--output", mock_fuzz_diff,
        env: {
          "FUZZ_GIT_COMMIT" => "",
          "FUZZ_GIT_DIRTY" => ""
        }
      )

      diff_ver_out, = assert_cmd(mock_fuzz_diff, "--version")
      assert_match(/^git_dirty=1$/, diff_ver_out,
                   "expected dirty mock_diff_prism/src/prism.c to record git_dirty=1: #{diff_ver_out}")
      assert_includes diff_ver_out, "prism="
      assert_includes diff_ver_out, "ruby_version="

      probed = FuzzTriage.probe_diff_binary_versions(mock_fuzz_diff)
      assert probed && probed["prism"] && probed["ruby_version"] && probed["ruby_release_date"] && probed["ruby_description"],
             "expected probe_diff_binary_versions(#{mock_fuzz_diff}) to parse all 4 keys, got: #{probed.inspect}"

      emb = FuzzProvenance.read_embedded_binary_provenance(mock_fuzz_diff)
      assert_equal true, emb&.dig("prism", "git_dirty"),
                   "expected embedded prism.git_dirty == true from build_diff.sh, got: #{emb.inspect}"

      ids_path = "#{mock_fuzz_diff}.ids"
      assert_path_exists ids_path
      ids_info = FuzzTriage.load_coverage_ids(ids_path)
      assert_equal true, ids_info[:available], "expected load_coverage_ids(#{ids_path}) to succeed"
      assert_operator ids_info[:edge_count_total], :>, 0
      domains = ids_info[:edge_domains].values.uniq
      assert_includes domains, "prism", "expected prism domain in #{ids_path}, got: #{domains.inspect}"
      assert_includes domains, "parse_y", "expected parse_y domain in #{ids_path}, got: #{domains.inspect}"
      assert_includes domains, "harness", "expected harness domain in #{ids_path}, got: #{domains.inspect}"

      if (showmap_bin = find_executable("afl-showmap"))
        sample_path = File.join(workdir, "sample_diff.rb")
        File.binwrite(sample_path, seed_bytes("def foo(x); x + 1; end\n"))
        batch = FuzzTriage.collect_showmap_batch({ "sample" => sample_path }, mock_fuzz_diff, showmap_bin)
        assert_equal true, batch[:ok], "expected dual-domain afl-showmap batch to succeed: #{batch.inspect}"
        edges = batch.dig(:maps, "sample")
        refute_empty edges, "expected non-empty edge map from mock_fuzz_diff"
        hit_domains = edges.keys.filter_map { |eid| ids_info[:edge_domains][eid] }.uniq
        assert_includes hit_domains, "prism", "expected afl-showmap hits in prism domain: #{hit_domains.inspect}"
        assert_includes hit_domains, "parse_y", "expected afl-showmap hits in parse_y domain: #{hit_domains.inspect}"
      end
    end
  end

  def test_diff_parse_y_disables_leak_detection_in_triage_and_minimizer
    diff_san = FuzzTriage.env_sanitizer_env(executable: "/tmp/ws/bin/fuzz.diff")
    assert_includes diff_san.fetch("ASAN_OPTIONS"), "detect_leaks=0"
    assert_includes diff_san.fetch("ASAN_OPTIONS"), "detect_stack_use_after_return=0"
    assert_includes diff_san.fetch("ASAN_OPTIONS"), "handle_segv=2:use_sigaltstack=1"

    prism_san = FuzzTriage.env_sanitizer_env(executable: "/tmp/ws/bin/fuzz")
    refute_includes prism_san.fetch("ASAN_OPTIONS"), "detect_leaks=0"
    refute_includes prism_san.fetch("ASAN_OPTIONS"), "detect_stack_use_after_return=0"
    assert_includes prism_san.fetch("ASAN_OPTIONS"), "handle_segv=2:use_sigaltstack=1"

    with_tmpdir("triage-diff-lsan-") do |workdir|
      tdir = File.join(workdir, "triage")
      crash_dir = File.join(workdir, "afl/diff/crashes")
      FileUtils.mkdir_p([tdir, crash_dir])
      crash_in = File.join(crash_dir, "id:000001,sig:06")
      File.binwrite(crash_in, seed_bytes("A::B\n"))

      mock_diff = write_executable(File.join(workdir, "bin/fuzz.diff"), <<~'SH')
        #!/bin/sh
        case ":${ASAN_OPTIONS:-}:" in
          *":detect_leaks=0:"*) ;;
          *)
            echo "==99==ERROR: LeakSanitizer: detected memory leaks" >&2
            exit 23
            ;;
        esac
        case ":${ASAN_OPTIONS:-}:" in
          *":detect_stack_use_after_return=0:"*) exit 0 ;;
          *)
            echo "==99==ERROR: AddressSanitizer: heap-use-after-free" >&2
            exit 1
            ;;
        esac
      SH

      classified = FuzzTriage.classify_crash_execution(crash_dir, crash_in, mock_diff, triage_dir: tdir)
      assert_equal true, classified[:unreproducible], "expected clean fuzz.diff replay without LSan: #{classified.inspect}"
      assert_equal false, classified[:crashed]
      refute_equal "memory-leak", classified[:reason]
    end
  end

  def test_cruby_compile_build_fuzz_triage_and_verify
    compile_san = FuzzTriage.env_sanitizer_env(executable: "/tmp/ws/bin/fuzz.compile")
    assert_includes compile_san.fetch("ASAN_OPTIONS"), "detect_leaks=0"
    assert_includes compile_san.fetch("ASAN_OPTIONS"), "detect_stack_use_after_return=0"
    assert_equal "cruby_compile", FuzzVerifyProfile.bucket_verify_profile(reason: "SEGV", executable: "./build/fuzz.compile")

    require_ruby_oracle!
    skip "requires AFL PCGUARD toolchain (afl-clang-fast + SanitizerCoveragePCGUARD.so)" unless afl_pcguard_ready?

    with_tmpdir("cruby-compile-e2e-") do |workdir|
      oracle_dir = resolve_env_or_tmp_dir(
        "COMPILE_TC_ORACLE_DIR",
        File.join(workdir, "compile-oracle")
      )
      verify_build_dir = resolve_env_or_tmp_dir(
        "COMPILE_VERIFY_BUILD_DIR",
        File.join(workdir, "verify-build")
      )
      fuzz_compile = File.join(workdir, "build", "fuzz.compile")
      FileUtils.mkdir_p([oracle_dir, verify_build_dir, File.dirname(fuzz_compile)])

      assert_cmd(
        repo_path("harnesses/prism/build_cruby_compile.sh"),
        "--mode", "fuzz",
        "--ruby-dir", "/opt/ruby",
        "--fuzz-root", root_dir,
        "--oracle-dir", oracle_dir,
        "--afl-path", afl_build_dir,
        "--output", fuzz_compile
      )
      assert File.executable?(fuzz_compile), "expected executable #{fuzz_compile}"

      ver_out, = assert_cmd(fuzz_compile, "--version")
      assert_includes ver_out, "ruby_version="

      ids_path = "#{fuzz_compile}.ids"
      assert_path_exists ids_path
      ids_info = FuzzTriage.load_coverage_ids(ids_path)
      assert_equal true, ids_info[:available]
      domains = ids_info[:edge_domains].values.uniq
      assert_includes domains, "cruby_compile", "expected cruby_compile domain in #{ids_path}: #{domains.inspect}"
      assert_includes domains, "harness", "expected harness domain in #{ids_path}: #{domains.inspect}"

      # Syntax errors (Prism syntax error and parse.y-only invalid UTF-8) and clean valid Ruby
      # across compile_option bitmasks must exit 0 without stderr noise.
      inputs_ok = {
        "prism_err.bin" => seed_bytes("def broken(\n"),
        "parse_y_utf8_err.bin" => "\x00\x00\x03\x01\"\xff\"\n".b,
        "valid_default.bin" => seed_bytes("def add(a, k: 1); a + k; end; add(2)\n"),
        "valid_opt_mask.bin" => "\x3f\x00\x03\x01def fact(n); n <= 1 ? 1 : fact(n - 1); end\n".b
      }
      inputs_ok.each do |name, payload|
        in_path = File.join(workdir, name)
        File.binwrite(in_path, payload)
        out, err = assert_cmd(fuzz_compile, in_path)
        assert_equal "", out + err, "expected silent exit 0 for #{name}"
      end

      if (showmap_bin = find_executable("afl-showmap"))
        valid_path = File.join(workdir, "valid_default.bin")
        batch = FuzzTriage.collect_showmap_batch({ "valid" => valid_path }, fuzz_compile, showmap_bin)
        assert_equal true, batch[:ok]
        hit_domains = batch.dig(:maps, "valid").keys.filter_map { |eid| ids_info[:edge_domains][eid] }.uniq
        assert_includes hit_domains, "cruby_compile", "expected afl-showmap hits in cruby_compile domain: #{hit_domains.inspect}"
      end

      # Dual-valid Ruby input (accepted by both Prism and parse.y) triggering CRuby 4.1 compile_keyword_arg SEGV
      # (if fixed in a future /opt/ruby bump, verify clean execution; otherwise verify full triage + verify_bucket.sh flow).
      kw_crash_bytes = seed_bytes("s = 1; m c, *[s: 1], *[*y]\n")
      kw_path = File.join(workdir, "kw_crash.bin")
      File.binwrite(kw_path, kw_crash_bytes)
      _cout, cerr, cst = run_cmd(fuzz_compile, kw_path)
      if !cst.success?
        assert_includes cerr, "CRASH[cruby_compile]: signal=SIGSEGV"
        sig1 = run_signature(cerr)
        assert_match(/\A[0-9a-f]{16}\z/, sig1)

        afl_crashes = File.join(workdir, "afl", "compile-main", "crashes")
        triage_dir = File.join(workdir, "triage")
        FileUtils.mkdir_p([afl_crashes, triage_dir])
        File.write(File.join(File.dirname(afl_crashes), "cmdline"), "#{fuzz_compile}\n")
        File.binwrite(File.join(afl_crashes, "id:000000,sig:11"), kw_crash_bytes)

        with_env("TRIAGE_MINIMIZE" => "0", "FUZZ_DIR" => workdir, "FUZZ_BUILD_DIR" => File.join(workdir, "build")) do
          capture_io do
            FuzzTriage.run_triage_pipeline(
              output_dirs: [File.join(workdir, "afl")],
              testcases_dir: triage_dir,
              coverage_bin: "",
              diff_coverage_bin: "",
              threads: 1
            )
          end
        end

        segv_buckets = Dir.glob(File.join(triage_dir, "SEGV", "*")).select { |d| File.directory?(d) }
        assert_equal 1, segv_buckets.size, "expected 1 triaged SEGV bucket under #{triage_dir}"
        bdir = segv_buckets.first
        meta = JSON.parse(File.read(File.join(bdir, "meta.json")))
        assert_equal "cruby_compile", meta["verify_profile"]
        assert_equal "cruby_crash", FuzzClustering.oracle_family(meta)

        # Verify verify_bucket.sh auto-infers cruby_compile and reproduces WITHOUT --repo-root!
        v_out, _v_err, v_st = run_cmd(
          repo_path("triage/verify_bucket.sh"),
          "--fuzz-root", root_dir,
          "--bucket-dir", bdir,
          "--json",
          env: {
            "VERIFY_BUILD_DIR" => verify_build_dir,
            "PRISM_A_DIR" => nil,
            "PRISM_DIR" => nil,
            "PRISM_ROOT" => nil,
            "FUZZ_BUILD_DIR" => File.join(workdir, "build")
          }
        )
        assert_equal 1, v_st.exitstatus, "expected verify_bucket.sh to reproduce cruby_compile SEGV: #{v_out}"
        v_rep = JSON.parse(v_out)
        assert_equal 0, v_rep["passed"]
        assert_equal 2, v_rep["failed"], "expected both input.min and archived raw input to fail: #{v_rep.inspect}"
        assert_includes v_rep.dig("failures", 0, "headline").to_s, "CRASH[cruby_compile]: signal=SIGSEGV"
      end
    end
  end

  private

  def run_signature(trace_bytes, siglines: 10)
    out, err, st = run_cmd(
      repo_path("triage/signature.sh"),
      env: { "SIGLINES" => siglines.to_s },
      input: trace_bytes
    )
    assert st.success?, "signature.sh failed (status=#{st.exitstatus || st.termsig}): #{err}"
    sig = out.strip
    assert_match(/\A[0-9a-f]{16}\z/, sig, "expected 16-char hex signature, got: #{out.inspect}")
    assert_equal sig, FuzzTriage.testcase_output_signature(trace_bytes, siglines)
    sig
  end

  def require_ruby_oracle!
    return if File.file?("/opt/ruby/libruby-static.a") && File.file?("/opt/ruby/parse.c")

    skip "missing /opt/ruby static oracle (/opt/ruby/libruby-static.a or /opt/ruby/parse.c)"
  end

  def require_prism_a!
    pa = prism_a_dir
    skip "missing Prism A target (run 'make targets-sync' first)" unless pa && File.directory?(File.join(pa, "src"))
    pa
  end

  def resolve_env_or_tmp_dir(env_key, fallback)
    env_dir = ENV[env_key].to_s.strip
    if !env_dir.empty? && dir_writable?(env_dir)
      env_dir
    else
      FileUtils.mkdir_p(fallback)
      fallback
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

  def seed_oracle_cache(src_build_dir, dst_build_dir)
    src_oracle = File.join(src_build_dir, "diff-oracle")
    src_archive = File.join(src_oracle, "libcruby_oracle.a")
    src_stamp = File.join(src_oracle, ".oracle.stamp")
    return unless File.file?(src_archive) && File.file?(src_stamp)

    dst_oracle = File.join(dst_build_dir, "diff-oracle")
    dst_archive = File.join(dst_oracle, "libcruby_oracle.a")
    dst_stamp = File.join(dst_oracle, ".oracle.stamp")
    return if File.file?(dst_archive) && File.file?(dst_stamp)

    FileUtils.mkdir_p(dst_oracle)
    FileUtils.cp(src_stamp, dst_stamp)
    begin
      File.link(src_archive, dst_archive)
    rescue SystemCallError
      FileUtils.cp(src_archive, dst_archive)
    end
  end

  def prepare_mock_diff_prism(workdir, prism_dir)
    mock_diff_prism = File.join(workdir, "mock_diff_prism")
    FileUtils.mkdir_p(mock_diff_prism)
    Dir.children(prism_dir).each do |entry|
      next if entry == ".git" || entry == ".fuzz-target-state.json"

      FileUtils.cp_r(File.join(prism_dir, entry), File.join(mock_diff_prism, entry))
    end

    if find_executable("git")
      assert_cmd("git", "-C", mock_diff_prism, "init", "-q")
      assert_cmd("git", "-C", mock_diff_prism, "config", "user.email", "test@example.com")
      assert_cmd("git", "-C", mock_diff_prism, "config", "user.name", "Test")
      assert_cmd("git", "-C", mock_diff_prism, "config", "commit.gpgsign", "false")
      assert_cmd("git", "-C", mock_diff_prism, "add", "-A")
      assert_cmd("git", "-C", mock_diff_prism, "commit", "-qm", "base")
    end

    prism_c_path = File.join(mock_diff_prism, "src/prism.c")
    src = File.read(prism_c_path)
    anchor = "pm_node_t *\npm_parse(pm_parser_t *parser) {"
    idx = src.index(anchor)
    refute_nil idx, "anchor not found in #{prism_c_path}"
    ret = "    return node;\n}"
    ridx = src.index(ret, idx)
    refute_nil ridx, "return statement not found in pm_parse in #{prism_c_path}"

    inject = <<~'C'
          if (node != NULL && parser->end - parser->start >= 17 && memcmp(parser->start, "MOCK_DIFF_ZERO_ER", 17) == 0 && PM_NODE_TYPE_P(node, PM_PROGRAM_NODE)) {
              pm_program_node_t *prog = (pm_program_node_t *) node;
              if (prog->statements != NULL && prog->statements->body.size > 0) {
                  static pm_error_recovery_node_t mock_er = { .base = { .type = PM_ERROR_RECOVERY_NODE, .location = { .start = 0, .length = 1 } }, .unexpected = NULL };
                  prog->statements->body.nodes[0] = &mock_er.base;
              }
          }
    C
    File.write(prism_c_path, src[0...ridx] + inject + src[ridx..])
    mock_diff_prism
  end

  def prepare_mock_diff_fuzz(workdir)
    mock_diff_fuzz = File.join(workdir, "mock_diff_fuzz")
    FileUtils.mkdir_p(mock_diff_fuzz)
    %w[harnesses triage runtime].each do |sub|
      FileUtils.cp_r(repo_path(sub), File.join(mock_diff_fuzz, sub))
    end

    cruby_vm_path = File.join(mock_diff_fuzz, "harnesses/prism/diff/cruby_vm.c")
    src = File.read(cruby_vm_path)
    anchor = "VALUE diff_run_cruby("
    idx = src.index(anchor)
    refute_nil idx, "anchor not found in #{cruby_vm_path}"
    brace_idx = src.index("{\n", idx)
    refute_nil brace_idx, "opening brace not found for diff_run_cruby in #{cruby_vm_path}"

    patched =
      src[0...idx] +
      "__attribute__((noinline)) void mock_ruby_yyparse(void) { volatile int *volatile p = (volatile int *) 0; *p = 1; }\n" +
      "__attribute__((noinline)) int mock_deep_stack(int n) { volatile char buf[4096]; buf[0] = (char) n; buf[4095] = (char) (n ^ 0x55); int r = (n > 0) ? mock_deep_stack(n - 1) : 0; return r + buf[0] + buf[4095]; }\n" +
      src[idx...(brace_idx + 2)] +
      "    if (size >= 14 && memcmp(source, \"MOCK_DIFF_SEGV\", 14) == 0) { mock_ruby_yyparse(); }\n" +
      "    if (size >= 22 && memcmp(source, \"MOCK_DIFF_STDLOCK_SEGV\", 22) == 0) { flockfile(stderr); mock_ruby_yyparse(); }\n" +
      "    if (size >= 24 && memcmp(source, \"MOCK_DIFF_STACK_OVERFLOW\", 24) == 0) { (void) mock_deep_stack(4096); }\n" +
      src[(brace_idx + 2)..]
    File.write(cruby_vm_path, patched)
    mock_diff_fuzz
  end

  def write_tar_gz(path, entries)
    Zlib::GzipWriter.open(path) do |gz|
      Gem::Package::TarWriter.new(gz) do |tar|
        entries.each do |name, body|
          bytes = body.b
          tar.add_file_simple(name, 0o644, bytes.bytesize) { |io| io.write(bytes) }
        end
      end
    end
  end

  def run_cmd_with_timeout(timeout_sec, *cmd, env: {}, chdir: nil)
    string_env = {}
    env.each { |k, v| string_env[k.to_s] = v.nil? ? nil : v.to_s }
    out_r, out_w = IO.pipe
    err_r, err_w = IO.pipe
    opts = { out: out_w, err: err_w, pgroup: true }
    opts[:chdir] = chdir if chdir
    pid = Process.spawn(string_env, *cmd.map(&:to_s), **opts)
    out_w.close
    err_w.close
    out_t = Thread.new { out_r.read }
    err_t = Thread.new { err_r.read }

    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout_sec
    status = nil
    loop do
      _, st = Process.waitpid2(pid, Process::WNOHANG)
      if st
        status = st
        break
      end
      if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
        begin
          Process.kill("-KILL", pid)
        rescue Errno::ESRCH
          nil
        end
        _, status = Process.waitpid2(pid)
        flunk "Command timed out after #{timeout_sec}s: #{cmd.inspect}\n--- stdout ---\n#{out_t.value}\n--- stderr ---\n#{err_t.value}"
      end
      sleep 0.05
    end
    [out_t.value, err_t.value, status]
  ensure
    [out_r, out_w, err_r, err_w].each { |io| io.close if io && !io.closed? }
  end
end
