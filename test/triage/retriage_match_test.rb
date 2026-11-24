# frozen_string_literal: true

require_relative "../lib/autorun"

require "digest"
require "fileutils"
require "json"
require "rubygems/package"
require "zlib"

# Isolated integration tests for triage/retriage.rb (dry-run, scoped cluster
# PARTIAL splits, occurrence provenance preservation, #skip sentinels, full PASS
# cleanup, external TOPOLOGY= workspace discovery) and triage/match.rb (inline,
# file, stdin, --raw, fuzz.diff -> fuzz promotion, stream_diff / diff_parse_y
# matching, --all-fuzzers, --expect-cluster, batch JSON, and ConfigError checks).
class TriageRetriageAndMatchTest < Minitest::Test
  def test_retriage_dry_run_partial_split_occurrences_skip_cleanup_and_external_workspace
    with_tmpdir("triage-retriage-") do |workdir|
      target_c = File.join(workdir, "mock_retriage_target.c")
      File.write(target_c, <<~'C')
        #include <stdint.h>
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>

        static int contains_token(const uint8_t *data, size_t size, const char *tok) {
            size_t tlen = strlen(tok);
            if (size < tlen) return 0;
            for (size_t i = 0; i <= size - tlen; i++) {
                if (memcmp(data + i, tok, tlen) == 0) return 1;
            }
            return 0;
        }

        int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
            if (contains_token(data, size, "CRASH_ALPHA")) {
                fprintf(stderr, "INVARIANT[alpha]: kind=one\n");
                abort();
            }
            if (contains_token(data, size, "CRASH_BETA")) {
                fprintf(stderr, "INVARIANT[beta]: kind=two\n");
                abort();
            }
            return 0;
        }

        #ifdef STANDALONE_MAIN
        int main(int argc, char **argv) {
            if (argc < 2) return 0;
            FILE *f = fopen(argv[1], "rb");
            if (!f) return 0;
            fseek(f, 0, SEEK_END);
            long sz = ftell(f);
            fseek(f, 0, SEEK_SET);
            if (sz <= 0) {
                fclose(f);
                return 0;
            }
            uint8_t *buf = (uint8_t *) malloc((size_t) sz);
            if (!buf) {
                fclose(f);
                return 0;
            }
            size_t n = fread(buf, 1, (size_t) sz, f);
            fclose(f);
            LLVMFuzzerTestOneInput(buf, n);
            free(buf);
            return 0;
        }
        #endif
      C

      mock_build = File.join(workdir, "mock_retriage_build")
      FileUtils.mkdir_p(mock_build)
      runner_bin = File.join(mock_build, "verify_runner.asan_ubsan")
      mock_fuzz = File.join(workdir, "mock_retriage_fuzz")

      cc = default_cc
      assert_cmd(
        cc, "-O1", "-g", "-std=c99", "-fsanitize=address",
        repo_path("triage/verify_runner.c"), target_c,
        "-o", runner_bin
      )
      assert_cmd(
        cc, "-O1", "-g", "-std=c99", "-fsanitize=address", "-DSTANDALONE_MAIN",
        target_c, "-o", mock_fuzz
      )
      # Keep mock verify_runner newer than repo sources so verify_bucket.sh uses it without rebuilding.
      future_mtime = Time.now + 60
      File.utime(future_mtime, future_mtime, runner_bin)

      base_env = {
        "VERIFY_BUILD_DIR" => mock_build,
        "TRIAGE_COVERAGE_BIN" => ""
      }
      if prism_a_dir.nil?
        stub_prism = File.join(workdir, "stub_prism")
        create_stub_prism_root(stub_prism)
        base_env["PRISM_A_DIR"] = stub_prism
      end

      retriage_dir = File.join(workdir, "retriage_work")
      FileUtils.mkdir_p([
        File.join(retriage_dir, ".processed"),
        File.join(retriage_dir, "ABRT/old_c1_pass"),
        File.join(retriage_dir, "ABRT/old_c1_part"),
        File.join(retriage_dir, "ABRT/old_c2_keep")
      ])

      mk = lambda do |bytes, worker = "fuzz01"|
        b = bytes.b
        { bytes: b, sha: Digest::SHA256.hexdigest(b), worker: worker }
      end

      c1_pass_inputs = [
        mk.call("\x00\x00\x03\x01cured_bucket_a\n"),
        mk.call("\x00\x00\x03\x01cured_bucket_b\n")
      ]
      c1_part_inputs = [
        mk.call("\x00\x00\x03\x01cured_in_partial\n", "fuzz02"),
        mk.call("\x00\x00\x03\x01padding_prefix CRASH_ALPHA padding_suffix\n", "fuzz03"),
        mk.call("\x00\x00\x03\x01padding_prefix CRASH_BETA padding_suffix\n", "fuzz04")
      ]
      c2_keep_inputs = [
        mk.call("\x00\x00\x03\x01untouched CRASH_ALPHA\n", "fuzz09")
      ]

      hashes = {
        "c1_pass" => c1_pass_inputs.map { |i| i[:sha] },
        "c1_part_cured" => c1_part_inputs[0][:sha],
        "c1_part_alpha" => c1_part_inputs[1][:sha],
        "c1_part_beta" => c1_part_inputs[2][:sha],
        "c2_keep" => c2_keep_inputs.map { |i| i[:sha] }
      }

      m1 = write_retriage_bucket(retriage_dir, "old_c1_pass", c1_pass_inputs, mock_fuzz,
                                 edges: { "10" => 1, "11" => 1 }, frame: "parse_heredoc")
      m2 = write_retriage_bucket(retriage_dir, "old_c1_part", c1_part_inputs, mock_fuzz,
                                 edges: { "10" => 1, "11" => 1 }, frame: "parse_heredoc")
      m3 = write_retriage_bucket(retriage_dir, "old_c2_keep", c2_keep_inputs, mock_fuzz,
                                 edges: { "20" => 1 }, frame: "parse_for")

      metadata = {
        "schema_version" => 1,
        "corpus" => {
          "available" => true,
          "corpus_count" => 100,
          "edge_df" => { "10" => 0, "11" => 0, "20" => 0 },
          "edge_functions" => { "10" => "parse_heredoc", "11" => "parse_heredoc", "20" => "parse_for" }
        },
        "buckets" => [m2, m1, m3]
      }
      File.write(File.join(retriage_dir, "metadata.json"), JSON.pretty_generate(metadata))

      # 1) --dry-run must inspect cluster-01 without deleting/modifying anything on disk.
      #    Also verify new primary flag names (--skip-fuzzer-build / --rebuild-verifiers) in --help and execution.
      help_out, = assert_ruby_cmd("triage/retriage.rb", "--help")
      assert_includes help_out, "--rebuild-verifiers"
      assert_includes help_out, "--skip-fuzzer-build"
      refute_includes help_out, "--no-build"

      dry_out, = assert_ruby_cmd(
        "triage/retriage.rb",
        "--triage-dir", retriage_dir,
        "--cluster", "cluster-01",
        "--skip-fuzzer-build",
        "--dry-run",
        env: base_env
      )
      assert_includes dry_out, "1 bucket(s) cured/empty"
      assert_includes dry_out, "2 surviving inputs to re-triage"
      assert File.directory?(File.join(retriage_dir, "ABRT/old_c1_pass")), "dry-run must not remove cured bucket"
      assert File.directory?(File.join(retriage_dir, "ABRT/old_c1_part")), "dry-run must not remove partial bucket"
      assert_equal "ABRT/old_c1_pass", File.read(File.join(retriage_dir, ".processed", hashes["c1_pass"].first)).strip

      # 2) Scoped retriage of cluster-01 removes cured old_c1_pass, splits old_c1_part
      #    into 2 fresh buckets with preserved worker provenance, and leaves cluster-02 untouched.
      assert_ruby_cmd(
        "triage/retriage.rb",
        "--triage-dir", retriage_dir,
        "--cluster", "cluster-01",
        "--no-build",
        env: base_env.merge("TRIAGE_MINIMIZE" => "0")
      )

      refute_path_exists File.join(retriage_dir, "ABRT/old_c1_pass"), "expected cured old_c1_pass bucket to be removed"
      refute_path_exists File.join(retriage_dir, "ABRT/old_c1_part"), "expected stale old_c1_part bucket to be removed"
      assert File.directory?(File.join(retriage_dir, "ABRT/old_c2_keep")), "expected unscoped cluster-02 bucket to remain"

      (hashes["c1_pass"] + [hashes["c1_part_cured"]]).each do |sha|
        sentinel = File.join(retriage_dir, ".processed", sha)
        assert_path_exists sentinel
        assert_equal "#skip", File.read(sentinel).strip, "expected #skip sentinel for cured input #{sha}"
      end

      alpha_bucket = File.read(File.join(retriage_dir, ".processed", hashes["c1_part_alpha"])).strip
      beta_bucket = File.read(File.join(retriage_dir, ".processed", hashes["c1_part_beta"])).strip
      refute alpha_bucket.start_with?("#"), "expected valid bucket sentinel for alpha survivor, got #{alpha_bucket.inspect}"
      refute beta_bucket.start_with?("#"), "expected valid bucket sentinel for beta survivor, got #{beta_bucket.inspect}"
      refute_equal alpha_bucket, beta_bucket, "expected survivors from distinct bugs to split into separate buckets"
      refute_includes [alpha_bucket, beta_bucket], "ABRT/old_c1_part", "survivors must not reuse removed old_c1_part"

      alpha_meta = JSON.parse(File.read(File.join(retriage_dir, alpha_bucket, "meta.json")))
      beta_meta = JSON.parse(File.read(File.join(retriage_dir, beta_bucket, "meta.json")))
      assert_equal 1, alpha_meta.dig("occurrences", "by_worker", "fuzz03"),
                   "expected preserved fuzz03 provenance: #{alpha_meta['occurrences'].inspect}"
      assert_equal 1, beta_meta.dig("occurrences", "by_worker", "fuzz04"),
                   "expected preserved fuzz04 provenance: #{beta_meta['occurrences'].inspect}"

      idx = JSON.parse(File.read(File.join(retriage_dir, "metadata.json")))
      assert_equal 3, idx.dig("summary", "bucket_count"), "expected 2 new buckets + 1 kept old_c2_keep"
      clusters = JSON.parse(File.read(File.join(retriage_dir, "clusters.json")))
      assert_equal 1, clusters["schema_version"]

      # 3) All-PASS retriage cleans up 100% of cured buckets and prunes empty reason directories.
      all_pass_dir = File.join(workdir, "retriage_all_pass")
      FileUtils.mkdir_p([
        File.join(all_pass_dir, ".processed"),
        File.join(all_pass_dir, "ABRT/only_cured")
      ])
      File.binwrite(File.join(all_pass_dir, "ABRT/only_cured/input.min"), "\x00\x00\x03\x01completely_fixed\n".b)

      assert_ruby_cmd(
        "triage/retriage.rb",
        "--triage-dir", all_pass_dir,
        "--no-build",
        env: base_env
      )
      refute_path_exists File.join(all_pass_dir, "ABRT"), "expected empty ABRT/ directory to be pruned when all buckets PASS"
      all_pass_idx = JSON.parse(File.read(File.join(all_pass_dir, "metadata.json")))
      all_pass_cl = JSON.parse(File.read(File.join(all_pass_dir, "clusters.json")))
      assert_equal 0, all_pass_idx.dig("summary", "bucket_count")
      assert_equal 0, all_pass_cl.dig("summary", "cluster_count")

      # 4) Regression (Bug #31): retriage.rb must pass fuzz_root (NOT prism repo_root)
      #    to Topology.discover and workspace_paths when TOPOLOGY= points to an external workspace.
      ext_ws = File.join(workdir, "retriage_ext_ws")
      ext_build = File.join(ext_ws, "custom_build")
      ext_triage = File.join(ext_ws, "custom_triage")
      decoy_repo = File.join(workdir, "retriage_decoy_prism")

      FileUtils.mkdir_p([
        ext_build,
        File.join(ext_triage, ".processed"),
        File.join(ext_triage, "ABRT/ext_surv"),
        File.join(decoy_repo, "include"),
        File.join(decoy_repo, "src")
      ])

      create_stub_prism_root(decoy_repo, source_prism: prism_a_dir)

      File.write(File.join(decoy_repo, "topology.json"), JSON.generate({
        "schema_version" => 2,
        "name" => "decoy-repo-topo",
        "workspace" => { "dir" => File.join(decoy_repo, "wrong_ws"), "build_dir" => File.join(decoy_repo, "wrong_build") },
        "sources" => { "prism_a" => { "kind" => "prism", "repo" => "https://example.invalid/prism.git", "ref" => "main" } },
        "fuzzers" => { "fuzz" => { "shape" => "prism_parse", "source" => "prism_a" } },
        "sync_groups" => { "afl" => { "dir" => "afl", "primary" => true } },
        "workers" => [{ "id" => "main", "kind" => "afl", "fuzzer" => "fuzz", "sync_group" => "afl", "afl_role" => "main" }]
      }))
      ext_topo_path = File.join(ext_ws, "topology.json")
      File.write(ext_topo_path, JSON.generate({
        "schema_version" => 2,
        "name" => "ext-retriage-topo",
        "workspace" => { "dir" => ext_ws, "build_dir" => ext_build, "triage_dir" => ext_triage },
        "sources" => { "prism_a" => { "kind" => "prism", "repo" => "https://example.invalid/prism.git", "ref" => "main" } },
        "fuzzers" => { "fuzz" => { "shape" => "prism_parse", "source" => "prism_a" } },
        "sync_groups" => { "afl" => { "dir" => "afl", "primary" => true } },
        "workers" => [{ "id" => "main", "kind" => "afl", "fuzzer" => "fuzz", "sync_group" => "afl", "afl_role" => "main" }]
      }))
      File.binwrite(File.join(ext_triage, "ABRT/ext_surv/input.min"), "\x00\x00\x03\x01CRASH_ALPHA".b)

      File.utime(future_mtime, future_mtime, runner_bin)
      write_executable(File.join(ext_build, "fuzz"), <<~'SH')
        #!/usr/bin/env bash
        echo "Assertion `ext_surv_boom' failed." >&2
        exit 134
      SH

      # Intentionally unset TRIAGE_COVERAGE_BIN so retriage.rb relies on ws_build_rel/fuzz.
      ext_out, = assert_ruby_cmd(
        "triage/retriage.rb",
        "--no-build",
        env: {
          "TRIAGE_COVERAGE_BIN" => nil,
          "PRISM_A_DIR" => decoy_repo,
          "TOPOLOGY" => ext_topo_path,
          "VERIFY_BUILD_DIR" => mock_build,
          "TRIAGE_MINIMIZE" => "0"
        }
      )
      assert_includes ext_out, "replaced 1 failing bucket(s)"
      ext_meta = JSON.parse(File.read(File.join(ext_triage, "metadata.json")))
      assert_equal 1, ext_meta.dig("summary", "bucket_count")
    end
  end

  def test_match_rb_snippet_file_stdin_diff_promotion_all_fuzzers_expect_cluster_and_json
    with_tmpdir("triage-retriage-match-") do |workdir|
      suite = File.join(workdir, "match_suite")
      bin_dir = File.join(suite, "bin")
      triage_dir = File.join(suite, "triage")
      inputs_dir = File.join(suite, "inputs")
      FileUtils.mkdir_p([bin_dir, triage_dir, inputs_dir])

      write_executable(File.join(bin_dir, "fuzz.diff"), <<~'RB')
        #!/usr/bin/env ruby
        data = File.binread(ARGV.fetch(0))
        hdr = data.byteslice(0, 4)
        text = data.byteslice(4..).to_s.strip
        if text.include?("diff_known")
          raise "unexpected header: #{hdr.inspect}" unless hdr == "\x00\x00\x03\x01".b
          warn "INVARIANT[diff_parse_y]: ast_mismatch ...\n    #0 0x100 in parse_expression src/parser.c:100"
          exit 6
        elsif text.include?("diff_custom_hdr")
          raise "expected custom header" if hdr == "\x00\x00\x03\x01".b
          warn "INVARIANT[diff_parse_y]: ast_mismatch ...\n    #0 0x100 in parse_expression src/parser.c:100"
          exit 6
        elsif text.include?("diff_new")
          warn "INVARIANT[diff_parse_y]: diagnostics_mismatch ...\n    #0 0x200 in pm_novel_diag_bug src/parser.c:999"
          exit 6
        elsif text.include?("prism_via_diff")
          warn "CRASH[diff_parse_y]: signal=SIGSEGV\n    #0 0x300 in sigsegv parse_y_shim.c:1"
          exit 139
        elsif text.include?("cruby_only")
          warn "CRASH[diff_parse_y]: signal=SIGSEGV\n    #0 0x400 in rb_parse_y_crash parse.y:12"
          exit 139
        end
        exit 0
      RB

      write_executable(File.join(bin_dir, "fuzz"), <<~'RB')
        #!/usr/bin/env ruby
        text = File.binread(ARGV.fetch(0)).byteslice(4..).to_s
        if text.include?("prism_via_diff")
          warn "================================================================="
          warn "SUMMARY: AddressSanitizer: SEGV on unknown address 0x0000"
          warn "    #0 0x500 in pm_prism_crash_fn src/prism.c:50"
          exit 1
        end
        exit 0
      RB

      write_executable(File.join(bin_dir, "fuzz.msan"), <<~'RB')
        #!/usr/bin/env ruby
        text = File.binread(ARGV.fetch(0)).byteslice(4..).to_s
        if text.include?("msan_only") || text.include?("prism_via_diff")
          warn "SUMMARY: MemorySanitizer: use-of-uninitialized-value"
          warn "    #0 0x600 in pm_msan_helper src/prism.c:77"
          exit 86
        end
        exit 0
      RB

      write_executable(File.join(bin_dir, "fuzz.slow"), <<~'RB')
        #!/usr/bin/env ruby
        text = File.binread(ARGV.fetch(0)).byteslice(4..).to_s
        if text.include?("sd_known")
          warn "INVARIANT[stream_diff]: kind=spurious_stop\n    #0 0x700 in pm_stream_helper src/prism.c:88"
          exit 6
        elsif text.include?("sd_novel")
          warn "INVARIANT[stream_diff]: kind=tokens_mismatch\n    #0 0x710 in pm_stream_other src/prism.c:99"
          exit 6
        end
        exit 0
      RB

      metadata = {
        "schema_version" => 1,
        "corpus" => { "available" => false, "corpus_count" => 0, "edge_df" => {}, "edge_functions" => {} },
        "diff_corpus" => { "available" => false, "corpus_count" => 0, "edge_df" => {}, "edge_functions" => {} },
        "buckets" => [
          {
            "schema_version" => 1,
            "bucket_id" => "ABRT/diff_ast_seed",
            "reason" => "ABRT",
            "signature" => "diffseed0001",
            "reproducible" => true,
            "reproduced_by" => "bin/fuzz.diff",
            "verify_profile" => "diff_parse_y",
            "occurrences" => { "count" => 5 },
            "symptom" => {
              "headline" => "INVARIANT[diff_parse_y]: ast_mismatch ...",
              "invariant" => { "namespace" => "diff_parse_y", "fields" => { "mismatch" => "ast_mismatch" }, "detail" => {} }
            },
            "frames" => [{ "depth" => 0, "scope" => "prism", "func" => "parse_expression", "file" => "src/parser.c", "line" => 100 }],
            "coverage" => { "available" => false },
            "diff_coverage" => { "available" => false }
          },
          {
            "schema_version" => 1,
            "bucket_id" => "SEGV/prism_seed",
            "reason" => "SEGV",
            "signature" => "prismseed001",
            "reproducible" => true,
            "reproduced_by" => "bin/fuzz",
            "verify_profile" => "asan_ubsan",
            "occurrences" => { "count" => 3 },
            "symptom" => { "headline" => "SUMMARY: AddressSanitizer: SEGV on unknown address 0x0000" },
            "frames" => [{ "depth" => 0, "scope" => "prism", "func" => "pm_prism_crash_fn", "file" => "src/prism.c", "line" => 50 }],
            "coverage" => { "available" => false }
          },
          {
            "schema_version" => 1,
            "bucket_id" => "SEGV/cruby_seed",
            "reason" => "SEGV",
            "signature" => "crubyseed001",
            "reproducible" => true,
            "reproduced_by" => "bin/fuzz.diff",
            "verify_profile" => "diff_parse_y",
            "occurrences" => { "count" => 2 },
            "symptom" => { "headline" => "CRASH[diff_parse_y]: signal=SIGSEGV" },
            "frames" => [{ "depth" => 0, "scope" => "external", "func" => "rb_parse_y_crash", "file" => "parse.y", "line" => 12 }],
            "coverage" => { "available" => false }
          },
          {
            "schema_version" => 1,
            "bucket_id" => "use-of-uninitialized-value/msan_seed",
            "reason" => "use-of-uninitialized-value",
            "signature" => "msanseed0001",
            "reproducible" => true,
            "reproduced_by" => "bin/fuzz.msan",
            "verify_profile" => "msan_slow",
            "occurrences" => { "count" => 1 },
            "symptom" => { "headline" => "SUMMARY: MemorySanitizer: use-of-uninitialized-value" },
            "frames" => [{ "depth" => 0, "scope" => "prism", "func" => "pm_msan_helper", "file" => "src/prism.c", "line" => 77 }],
            "coverage" => { "available" => false }
          },
          {
            "schema_version" => 1,
            "bucket_id" => "ABRT/stream_diff_seed",
            "reason" => "ABRT",
            "signature" => "streamsd0001",
            "reproducible" => true,
            "reproduced_by" => "bin/fuzz.slow",
            "verify_profile" => "asan_ubsan_slow",
            "occurrences" => { "count" => 2 },
            "symptom" => {
              "headline" => "INVARIANT[stream_diff]: kind=spurious_stop",
              "invariant" => { "namespace" => "stream_diff", "fields" => { "kind" => "spurious_stop" }, "detail" => {} }
            },
            "frames" => [{ "depth" => 0, "scope" => "prism", "func" => "pm_stream_helper", "file" => "src/prism.c", "line" => 88 }],
            "coverage" => { "available" => false }
          }
        ]
      }
      File.write(File.join(triage_dir, "metadata.json"), JSON.pretty_generate(metadata))

      file_diff = File.join(inputs_dir, "repro.rb")
      file_clean = File.join(inputs_dir, "clean.rb")
      file_raw = File.join(inputs_dir, "input.min")
      file_raw_rb = File.join(inputs_dir, "raw_with_rb_ext.rb")
      File.write(file_diff, "diff_known\n")
      File.write(file_clean, "1 + 2\n")
      File.binwrite(file_raw, "\x00\x00\x03\x01msan_only\n".b)
      File.binwrite(file_raw_rb, "\x00\x00\x03\x01diff_known\n".b)

      match_env = { "TRIAGE_COVERAGE_BIN" => "", "TRIAGE_DIFF_COVERAGE_BIN" => "" }

      # 1) Inline snippet matching INVARIANT[diff_parse_y] cluster + in-memory clustering
      out1, = assert_ruby_cmd(
        "triage/match.rb", "--triage-dir", triage_dir, "--json", "-e", "diff_known",
        env: match_env
      )
      r1 = JSON.parse(out1)
      assert_equal "computed-in-memory", r1["clusters_source"]
      res1 = r1["results"].first
      assert_equal "00000301", res1.dig("header", "hex")
      assert_equal "matched", res1["status"]
      assert_equal true, res1["suspected_duplicate"]
      assert_equal "fuzz.diff", res1.dig("findings", 0, "name")
      assert_equal "diff_parse_y", res1.dig("findings", 0, "placement", "probe", "oracle")
      assert_equal "ABRT/diff_ast_seed", res1.dig("findings", 0, "placement", "best_cluster", "representative", "bucket_id")

      # 2) Promotion: fuzz.diff CRASH[diff_parse_y] -> fuzz (prism_flaw) vs cruby_only staying on fuzz.diff
      out2, = assert_ruby_cmd(
        "triage/match.rb", "--triage-dir", triage_dir, "--json", "-e", "prism_via_diff", "-e", "cruby_only",
        env: match_env
      )
      r2 = JSON.parse(out2)
      p_res, c_res = r2["results"]
      assert_equal "fuzz", p_res.dig("findings", 0, "name")
      assert_equal "SEGV/prism_seed", p_res.dig("findings", 0, "placement", "best_cluster", "representative", "bucket_id")
      assert_equal %w[fuzz.diff fuzz], c_res["attempts"].map { |a| a["name"] }
      assert_equal "fuzz.diff", c_res.dig("findings", 0, "name")
      assert_equal "SEGV/cruby_seed", c_res.dig("findings", 0, "placement", "best_cluster", "representative", "bucket_id")

      # 3) Batch check (raw input.min + preserve.rb + clean.rb), non-destructive --json-file
      preserve_rb = File.join(inputs_dir, "preserve.rb")
      FileUtils.cp(file_diff, preserve_rb)
      batch_json = File.join(suite, "batch.json")
      batch_stdout, = assert_ruby_cmd(
        "triage/match.rb", "--triage-dir", triage_dir, "--json", "--json-file", batch_json,
        file_raw, preserve_rb, file_clean,
        env: match_env
      )
      assert_equal "diff_known\n", File.read(preserve_rb), "--json must not modify input file contents"
      assert_equal File.read(batch_json), batch_stdout, "--json-file and --json stdout must match"

      rbatch = JSON.parse(batch_stdout)
      assert_equal 3, rbatch["results"].size
      raw_res, diff_res, cln_res = rbatch["results"]
      assert_equal "raw", raw_res["mode"]
      assert_equal "fuzz.msan", raw_res.dig("findings", 0, "name")
      assert_equal "matched", raw_res["status"]
      assert_equal "snippet", diff_res["mode"]
      assert_equal "fuzz.diff", diff_res.dig("findings", 0, "name")
      assert_equal "matched", diff_res["status"]
      assert_equal "pass", cln_res["status"]
      assert_equal false, cln_res["suspected_duplicate"]
      assert_equal 2, rbatch.dig("summary", "matched_inputs")
      assert_equal 1, rbatch.dig("summary", "passed_inputs")

      # 4) Explicit --raw flag on a .rb-named file and on --stdin avoids double-prepending header
      raw_rb_out, = assert_ruby_cmd(
        "triage/match.rb", "--triage-dir", triage_dir, "--raw", "--json", file_raw_rb,
        env: match_env
      )
      raw_rb_res = JSON.parse(raw_rb_out).fetch("results").first
      assert_equal "raw", raw_rb_res["mode"]
      assert_equal raw_rb_res["source_size_bytes"], raw_rb_res["wire_size_bytes"]
      assert_equal "00000301", raw_rb_res.dig("header", "hex")
      assert_equal "matched", raw_rb_res["status"]
      assert_equal "ABRT/diff_ast_seed", raw_rb_res.dig("findings", 0, "placement", "best_cluster", "representative", "bucket_id")

      raw_stdin_out, = assert_ruby_cmd(
        "triage/match.rb", "--triage-dir", triage_dir, "--raw", "--json", "--stdin",
        env: match_env,
        input: "\x00\x00\x03\x01msan_only\n".b
      )
      raw_stdin_res = JSON.parse(raw_stdin_out).fetch("results").first
      assert_equal "raw", raw_stdin_res["mode"]
      assert_equal "matched", raw_stdin_res["status"]
      assert_equal "use-of-uninitialized-value/msan_seed",
                   raw_stdin_res.dig("findings", 0, "placement", "best_cluster", "representative", "bucket_id")

      # 5) Custom-header --stdin snippet probing
      stdin_out, = assert_ruby_cmd(
        "triage/match.rb", "--triage-dir", triage_dir,
        "--ruby-version", "3.4", "--encoding", "UTF-8", "--partial-script",
        "--json", "--stdin",
        env: match_env,
        input: "diff_custom_hdr\n"
      )
      s_res = JSON.parse(stdin_out).fetch("results").first
      assert_equal "matched", s_res["status"]
      assert_equal "snippet", s_res["mode"]
      assert_equal "3.4", s_res.dig("header", "ruby_version")
      assert_equal "UTF-8", s_res.dig("header", "encoding")
      assert_equal true, s_res.dig("header", "partial_script")

      # 6) INVARIANT[stream_diff] oracle isolation and matching vs novel stream_diff
      sd_out, = assert_ruby_cmd(
        "triage/match.rb", "--triage-dir", triage_dir, "--stream", "--json",
        "-e", "sd_known", "-e", "sd_novel",
        env: match_env
      )
      sd_known, sd_novel = JSON.parse(sd_out).fetch("results")
      assert_equal true, sd_known.dig("header", "stream_mode")
      assert_equal "matched", sd_known["status"]
      assert_equal "fuzz.slow", sd_known.dig("findings", 0, "name")
      assert_equal "stream_diff", sd_known.dig("findings", 0, "placement", "probe", "oracle")
      assert_equal "ABRT/stream_diff_seed",
                   sd_known.dig("findings", 0, "placement", "best_cluster", "representative", "bucket_id")
      assert(
        sd_known.dig("findings", 0, "placement", "candidates").all? do |c|
          c.dig("representative", "bucket_id") == "ABRT/stream_diff_seed"
        end,
        "stream_diff probe must only compare against stream_diff clusters"
      )
      assert_equal "unmatched", sd_novel["status"]
      assert_equal "stream_diff", sd_novel.dig("findings", 0, "placement", "probe", "oracle")
      refute_empty sd_novel.dig("findings", 0, "placement", "candidates")

      # 7) --all-fuzzers on prism_via_diff catches both promoted fuzz and fuzz.msan; diff_new is unmatched
      all_out, = assert_ruby_cmd(
        "triage/match.rb", "--triage-dir", triage_dir, "--all-fuzzers", "--json",
        "-e", "prism_via_diff", "-e", "diff_new",
        env: match_env
      )
      both_res, novel_res = JSON.parse(all_out).fetch("results")
      finding_names = both_res["findings"].map { |f| f["name"] }
      assert_includes finding_names, "fuzz"
      assert_includes finding_names, "fuzz.msan"
      assert_equal "unmatched", novel_res["status"]
      refute_empty novel_res.dig("findings", 0, "placement", "candidates")

      # 8) --expect-cluster / --cluster exit 0/1 checks
      expect_ok_out, = assert_ruby_cmd(
        "triage/match.rb", "--triage-dir", triage_dir,
        "--expect-cluster", "ABRT/diff_ast_seed", "--quiet", file_diff,
        env: match_env
      )
      assert_includes expect_ok_out, "[expect: PASS]"

      [
        ["--cluster", "SEGV/prism_seed", "--quiet", file_diff],
        ["--expect-cluster", "ABRT/diff_ast_seed", "--quiet", file_clean],
        ["--expect-cluster", "ABRT/diff_ast_seed", "--quiet", "-e", "diff_new"]
      ].each do |fail_args|
        _o, _e, st = run_cmd(
          RbConfig.ruby, repo_path("triage/match.rb"), "--triage-dir", triage_dir, *fail_args,
          env: match_env, chdir: root_dir
        )
        assert_equal 1, st.exitstatus, "expected exit 1 for match.rb #{fail_args.join(' ')}"
      end

      # 9) Clean ConfigError (exit 2) handling for empty/missing/invalid options
      empty_triage = File.join(suite, "empty_triage")
      FileUtils.mkdir_p(empty_triage)
      [
        { args: ["--triage-dir", triage_dir], err_sub: "No input specified" },
        { args: ["--triage-dir", triage_dir, File.join(inputs_dir, "missing.rb")], err_sub: "Input file not found" },
        { args: ["--triage-dir", empty_triage, "-e", "1 + 1"], err_sub: "Metadata file not found" },
        { args: ["--triage-dir", triage_dir, "--raw", "--snippet", file_raw], err_sub: "--raw and --snippet" },
        { args: ["--triage-dir", triage_dir, "--raw", "--ruby-version", "3.4", file_raw], err_sub: "--raw cannot be combined" },
        { args: ["--triage-dir", triage_dir, "--header", "badhex", "-e", "1"], err_sub: "Invalid --header" },
        { args: ["--triage-dir", triage_dir, "--quiet", "--verbose", "-e", "1"], err_sub: "--quiet and --verbose" }
      ].each do |cfg_case|
        out, err, st = run_cmd(
          RbConfig.ruby, repo_path("triage/match.rb"), *cfg_case[:args],
          env: match_env, chdir: root_dir
        )
        assert_equal 2, st.exitstatus, "expected exit 2 for #{cfg_case[:args].inspect}\nstdout=#{out}\nstderr=#{err}"
        assert_includes err, "match.rb:"
        assert_includes err, cfg_case[:err_sub]
      end
    end
  end

  private

  def default_cc
    cc = ENV["CC"].to_s.strip
    cc.empty? ? "clang" : cc
  end

  def create_stub_prism_root(dir, source_prism: nil)
    inc_dir = File.join(dir, "include")
    src_dir = File.join(dir, "src")
    FileUtils.mkdir_p([inc_dir, src_dir])
    dst_hdr = File.join(inc_dir, "prism.h")
    if source_prism && File.file?(File.join(source_prism, "include/prism.h"))
      FileUtils.cp(File.join(source_prism, "include/prism.h"), dst_hdr)
    else
      File.write(dst_hdr, <<~'C')
        #ifndef PRISM_H
        #define PRISM_H
        /* pm_parser_new() pm_parse() */
        #endif
      C
    end
    old_time = Time.utc(2020, 1, 1)
    [dst_hdr, src_dir, inc_dir, dir].each { |p| File.utime(old_time, old_time, p) }
    dir
  end

  def write_retriage_bucket(triage_dir, sig, raw_inputs, mock_fuzz, edges:, frame:, headline: "old assert")
    dir = File.join(triage_dir, "ABRT", sig)
    File.binwrite(File.join(dir, "input.min"), raw_inputs.first[:bytes])
    File.write(File.join(dir, "testcase.c"), "/* old #{sig} */\n")

    Zlib::GzipWriter.open(File.join(dir, "inputs.tar.gz")) do |gz|
      Gem::Package::TarWriter.new(gz) do |tar|
        raw_inputs.each do |item|
          tar.add_file_simple(item[:sha], 0o644, item[:bytes].bytesize) { |io| io.write(item[:bytes]) }
        end
      end
    end

    File.open(File.join(dir, "occurrences.jsonl"), "w") do |f|
      raw_inputs.each_with_index do |item, idx|
        rec = {
          "sha256" => item[:sha],
          "path" => "/orig/afl/fuzz01/crashes/id:#{format('%06d', idx)}",
          "filename" => "id:#{format('%06d', idx)},sig:06",
          "fuzzer" => "afl",
          "worker" => item[:worker] || "fuzz01",
          "queue" => "crashes",
          "size_bytes" => item[:bytes].bytesize,
          "mtime" => "2026-11-01T00:00:00Z"
        }
        f.puts(JSON.generate(rec))
        File.write(File.join(triage_dir, ".processed", item[:sha]), "ABRT/#{sig}\n")
      end
    end

    meta = {
      "schema_version" => 1,
      "bucket_id" => "ABRT/#{sig}",
      "reason" => "ABRT",
      "signature" => sig,
      "reproducible" => true,
      "reproduced_by" => mock_fuzz,
      "verify_profile" => "asan_ubsan",
      "occurrences" => { "count" => raw_inputs.size },
      "input" => { "min_size_bytes" => raw_inputs.first[:bytes].bytesize, "raw_sha256" => raw_inputs.first[:sha] },
      "symptom" => { "headline" => headline },
      "frames" => [{ "function" => frame, "scope" => "prism" }],
      "coverage" => { "available" => true, "edges" => edges }
    }
    File.write(File.join(dir, "meta.json"), JSON.pretty_generate(meta))
    meta
  end
end
