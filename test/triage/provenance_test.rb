# frozen_string_literal: true

require_relative "../lib/autorun"

require "fileutils"
require "json"
require "open3"
require "rbconfig"
require "stringio"

require_relative "../../runtime/common"
require_relative "../../runtime/provenance"
require_relative "../../triage/cluster"
require_relative "../../triage/retriage"
require_relative "../../triage/triage"
require_relative "../../triage/verify"
require_relative "../../report/lib/coverage_view"
require_relative "../../report/lib/lineage"

# Migrated from stage_provenance of test/test_triage.sh.
# Verifies non-native --version probe guards, compiled diff version probing,
# non-diff version metadata, finalize_triage_metadata backfill/preservation,
# cluster.rb provenance formatting, Makefile report/clean semantics, embedded
# binary provenance, script snapshot isolation, and corrupt JSON diagnostics.
class TriageProvenanceTest < Minitest::Test
  STUB_FUZZ_DIFF_C = <<~'C'
    #include <stdio.h>
    #include <string.h>

    int main(int argc, char **argv) {
      if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        puts("prism=2.9.9");
        puts("ruby_version=4.1.0");
        puts("ruby_release_date=2027-01-02");
        puts("ruby_description=ruby 4.1.0 (2027-01-02 revision deadbeef01)");
        return 0;
      }
      return 1;
    }
  C

  SNAP_MAIN_STUB_C = <<~'C'
    #include <stddef.h>
    #include <stdint.h>

    int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
    void harness(const uint8_t *input, size_t size) { (void)input; (void)size; }

    int main(void) {
      const uint8_t buf[4] = {0, 0, 3, 1};
      return LLVMFuzzerTestOneInput(buf, 4);
    }
  C

  UNMAKE_ENV = {
    "MAKEFLAGS" => nil,
    "MFLAGS" => nil,
    "MAKELEVEL" => nil,
    "CAMPAIGN" => nil,
    "TOPOLOGY" => nil,
    "TOPOLOGY_FILE" => nil,
    "TOPOLOGY_RESOLVED" => nil,
    "FUZZ_DIR" => nil
  }.freeze

  EXPECTED_SNAPSHOT_RELS = %w[
    dict/prism.dict
    harnesses/prism/parse.c
    harnesses/prism/diff.c
    runtime/grammar.rb
    runtime/kill.sh
    triage/triage.rb
    triage/signature.sh
    triage/halfempty.sh
    triage/halfempty_compare.sh
    lib/prism_fuzzer.rb
    campaigns/default.rb
    topology.schema.json
  ].freeze

  def test_non_native_script_guard_and_stub_version_probe
    with_tmpdir("triage-provenance-probe-") do |workdir|
      # 1. Non-native scripts must never be executed by --version probe
      script_probe = write_executable(File.join(workdir, "mock_non_native.sh"), "#!/bin/sh\nexit 99\n")
      refute FuzzTriage.native_executable_magic?(script_probe),
             "expected native_executable_magic? == false for shell script"
      assert_nil FuzzTriage.probe_diff_binary_versions(script_probe),
                 "expected nil probe_diff_binary_versions for shell script"

      # 2. Compiled native binary stub --version probe (when clang/cc/gcc is available)
      cc = find_c_compiler
      skip "no C compiler available" unless cc

      stub_bin = compile_diff_version_stub(workdir, cc: cc)
      assert FuzzTriage.native_executable_magic?(stub_bin),
             "expected native_executable_magic? == true for compiled binary"

      probed_stub = FuzzTriage.probe_diff_binary_versions(stub_bin)
      expected = {
        "prism" => "2.9.9",
        "ruby_version" => "4.1.0",
        "ruby_release_date" => "2027-01-02",
        "ruby_description" => "ruby 4.1.0 (2027-01-02 revision deadbeef01)"
      }
      assert_equal expected, probed_stub, "unexpected stub probe result: #{probed_stub.inspect}"
    end
  end

  def test_non_diff_metadata_finalize_backfill_preservation_and_clustering
    with_tmpdir("triage-provenance-meta-") do |workdir|
      empty_corpus = File.join(workdir, "version_empty_corpus")
      FileUtils.mkdir_p(empty_corpus)

      triage_env = {
        "TRIAGE_COVERAGE_BIN" => "/nonexistent/fuzz",
        "TRIAGE_COVERAGE_IDS" => nil,
        "TRIAGE_DIFF_COVERAGE_BIN" => nil,
        "TRIAGE_DIFF_COVERAGE_IDS" => nil,
        "TRIAGE_CORPUS_DIR" => empty_corpus
      }

      with_prism_env(workdir, triage_env) do
        # 3. Non-diff bucket omits ruby_parse_y and captures prism version + git + target_ruby_version
        header_ver = FuzzTriage.read_prism_header_version(ENV["PRISM_A_DIR"] || FuzzTriage.locate_version_repo_root)
        refute_nil header_ver, "expected read_prism_header_version from include/prism/version.h"
        refute_empty header_ver

        v_nondiff = FuzzTriage.resolve_versions_metadata(
          executable: "/nonexistent/fuzz",
          is_diff: false,
          target_ruby_version: "3.4"
        )
        assert v_nondiff, "expected prism metadata for non-diff bucket"
        assert_equal header_ver, v_nondiff.dig("prism", "version"), "unexpected non-diff prism version: #{v_nondiff.inspect}"
        assert_equal "3.4", v_nondiff.dig("prism", "target_ruby_version")
        refute v_nondiff.key?("ruby_parse_y"), "non-diff bucket must not populate ruby_parse_y unless oracle requested"

        # 4. finalize_triage_metadata backfills missing versions on legacy buckets while preserving historical versions
        triage_dir = File.join(workdir, "version_triage_dir")
        b1_dir = File.join(triage_dir, "ABORT", "sig_backfill")
        b2_dir = File.join(triage_dir, "ABORT", "sig_historical")
        FileUtils.mkdir_p([b1_dir, b2_dir])

        sample_min = seed_bytes("1 + 2")
        b1_min = File.join(b1_dir, "input.min")
        b2_min = File.join(b2_dir, "input.min")
        File.binwrite(b1_min, sample_min)
        File.binwrite(b2_min, sample_min)
        File.write(
          File.join(b1_dir, "occurrences.jsonl"),
          JSON.generate(
            "sha256" => "aaa111",
            "path" => "crashes/id:000001",
            "filename" => "id:000001,time:10",
            "fuzzer" => "afl",
            "worker" => "main",
            "queue" => "crashes",
            "size_bytes" => sample_min.bytesize,
            "mtime" => 1_700_000_000,
            "time_ms" => 10
          ) + "\n"
        )
        File.write(
          File.join(b2_dir, "occurrences.jsonl"),
          JSON.generate(
            "sha256" => "bbb222",
            "path" => "crashes/id:000002",
            "filename" => "id:000002,time:20",
            "fuzzer" => "afl",
            "worker" => "diff-1",
            "queue" => "crashes",
            "size_bytes" => sample_min.bytesize,
            "mtime" => 1_700_000_001,
            "time_ms" => 20
          ) + "\n"
        )

        meta1 = FuzzTriage.build_bucket_metadata(
          bucket_id: "ABORT/sig_backfill",
          reason: "ABORT",
          signature: "sig_backfill",
          reproducible: true,
          timed_out: false,
          executable: "/nonexistent/fuzz",
          crash_output: "Assertion failed: x != 0\n  #0 pm_parse_stream src/prism.c:100\n",
          minimized_input: b1_min,
          raw_size_bytes: sample_min.bytesize,
          raw_sha256: "aaa111",
          minimized_matches_signature: true,
          occurrences: {
            "count" => 1,
            "by_fuzzer" => { "afl" => 1 },
            "by_worker" => { "main" => 1 },
            "by_queue" => { "crashes" => 1 },
            "first_seen" => 1_700_000_000,
            "first_elapsed_ms" => 10,
            "last_seen" => 1_700_000_000,
            "sample_crashes" => []
          }
        )
        assert_equal header_ver, meta1.dig("versions", "prism", "version"),
                     "expected build_bucket_metadata to populate versions"
        meta1.delete("versions")
        File.write(File.join(b1_dir, "meta.json"), JSON.pretty_generate(meta1))

        cc = find_c_compiler
        stub_bin = cc ? compile_diff_version_stub(workdir, cc: cc) : "./build/fuzz.diff"

        historical_versions = {
          "prism" => {
            "version" => "1.9.0",
            "git_short" => "111111111",
            "git_dirty" => false,
            "target_ruby_version" => "3.3"
          },
          "ruby_parse_y" => {
            "version" => "3.4.1",
            "revision" => "abcdef0123",
            "release_date" => "2024-12-25"
          }
        }
        meta2 = FuzzTriage.build_bucket_metadata(
          bucket_id: "ABORT/sig_historical",
          reason: "ABORT",
          signature: "sig_historical",
          reproducible: true,
          timed_out: false,
          executable: stub_bin,
          crash_output: "INVARIANT[diff_parse_y]: kind=syntax_mismatch sub=prism_ok_cruby_err nul=0 utf8=1 prism=ok cruby=SyntaxError:foo\n  #0 diff_parse harnesses/prism/diff.c:200\n",
          minimized_input: b2_min,
          raw_size_bytes: sample_min.bytesize,
          raw_sha256: "bbb222",
          minimized_matches_signature: true,
          occurrences: {
            "count" => 1,
            "by_fuzzer" => { "afl" => 1 },
            "by_worker" => { "diff-1" => 1 },
            "by_queue" => { "crashes" => 1 },
            "first_seen" => 1_700_000_001,
            "first_elapsed_ms" => 20,
            "last_seen" => 1_700_000_001,
            "sample_crashes" => []
          }
        )
        if cc
          assert_equal "2.9.9", meta2.dig("versions", "prism", "version"),
                       "expected stub_bin prism=2.9.9 in meta2: #{meta2['versions'].inspect}"
          assert_equal "4.1.0", meta2.dig("versions", "ruby_parse_y", "version"),
                       "expected stub_bin ruby_version=4.1.0 in meta2: #{meta2['versions'].inspect}"
        end
        meta2["versions"] = historical_versions
        File.write(File.join(b2_dir, "meta.json"), JSON.pretty_generate(meta2))

        FuzzTriage.finalize_triage_metadata(triage_dir)
        index_data = JSON.parse(File.read(File.join(triage_dir, "metadata.json")))
        written_clusters = JSON.parse(File.read(File.join(triage_dir, "clusters.json")))

        assert_equal header_ver, index_data.dig("versions", "prism", "version"),
                     "expected metadata.json root versions.prism.version"
        assert_equal header_ver, written_clusters.dig("versions", "prism", "version"),
                     "expected clusters.json written by finalize_triage_metadata to contain prism version"
        assert_equal [historical_versions["ruby_parse_y"]],
                     written_clusters.dig("versions", "observed", "ruby_parse_y"),
                     "expected clusters.json observed ruby_parse_y versions"

        reloaded_b1 = JSON.parse(File.read(File.join(b1_dir, "meta.json")))
        reloaded_b2 = JSON.parse(File.read(File.join(b2_dir, "meta.json")))
        assert_equal header_ver, reloaded_b1.dig("versions", "prism", "version"),
                     "expected finalize_triage_metadata to backfill versions on b1"
        assert_equal historical_versions, reloaded_b2["versions"],
                     "expected finalize_triage_metadata to preserve historical versions on b2"

        # 5. Clustering propagates root, observed, per-cluster, and per-bucket versions without altering clusters
        report = FuzzClustering.cluster_metadata(index_data, metadata_path: File.join(triage_dir, "metadata.json"))
        assert_equal header_ver, report.dig("versions", "prism", "version")
        assert_equal [historical_versions["ruby_parse_y"]], report.dig("versions", "observed", "ruby_parse_y")
        assert(
          report["clusters"].all? { |c| c["versions"].is_a?(Hash) && c["buckets"].all? { |b| b["versions"].is_a?(Hash) } },
          "expected every cluster and bucket to include versions"
        )

        summary_text = FuzzClustering.format_summary_table(report)
        assert_includes summary_text, "Versions:"
        assert_includes summary_text, "prism="
        assert_includes summary_text, "1.9.0 (111111111)"
        assert_includes summary_text, "ruby_parse_y="
        assert_includes summary_text, "3.4.1 (abcdef0123)"

        stripped_index = JSON.parse(JSON.generate(index_data))
        stripped_index.delete("versions")
        stripped_index["buckets"].each { |b| b.delete("versions") }
        stripped_report = FuzzClustering.cluster_metadata(stripped_index)
        refute stripped_report.key?("versions"), "expected stripped report to omit versions"
        assert_equal(
          report["clusters"].map { |c| c["buckets"].map { |b| b["bucket_id"] } },
          stripped_report["clusters"].map { |c| c["buckets"].map { |b| b["bucket_id"] } },
          "expected version metadata not to alter cluster assignments"
        )

        stripped_summary = FuzzClustering.format_summary_table(stripped_report)
        refute_includes stripped_summary, "Versions:"
        refute_includes stripped_summary, "Container:"
      end
    end
  end

  def test_signature_normalization_make_report_no_rebuild_and_make_clean
    sig_sh = repo_path("triage/signature.sh")
    snap_sig1, = assert_cmd(
      sig_sh,
      chdir: root_dir,
      input: "CRASH[diff_parse_y]: signal=SIGSEGV (11)\n/prism/build/fuzz.diff(rb_st_free_table+0x14) [0x1] /opt/ruby/st.c:667\n"
    )
    snap_sig2, = assert_cmd(
      sig_sh,
      chdir: root_dir,
      input: "CRASH[diff_parse_y]: signal=SIGSEGV (11)\n/prism/tmp/fuzz/bin/fuzz.diff(rb_st_free_table+0x28) [0x2] /opt/ruby/st.c:667\n"
    )
    refute_empty snap_sig1.strip
    assert_equal snap_sig1.strip, snap_sig2.strip,
                 "expected identical signature for build/fuzz.diff and tmp/fuzz/bin/fuzz.diff"

    triage_plan, = assert_cmd(
      "make", "-n", "-o", "./build/.fuzz.docker.stamp", "report",
      env: UNMAKE_ENV,
      chdir: root_dir
    )
    refute_includes triage_plan, "_build-all",
                    "make report must not rebuild fuzz binaries"
    assert_includes triage_plan, "./tmp/fuzz/snapshot/triage/triage.rb"
    assert_includes triage_plan, "TRIAGE_LIVE_SCRIPTS"

    with_tmpdir("triage-provenance-clean-") do |workdir|
      clean_dir = File.join(workdir, "clean_test")
      FileUtils.mkdir_p([
        File.join(clean_dir, "afl/w"),
        File.join(clean_dir, "afl-ijon/ijon"),
        File.join(clean_dir, "bin"),
        File.join(clean_dir, "snapshot/harnesses"),
        File.join(clean_dir, "corpus"),
        File.join(clean_dir, "report/triage/ABRT/sig1"),
        File.join(clean_dir, "report/coverage")
      ])
      [
        ".dotfile",
        "bin/fuzz",
        "snapshot/harnesses/parse.c",
        "report/triage/ABRT/sig1/meta.json",
        "report/index.html",
        "report/coverage/summary.txt"
      ].each { |rel| FileUtils.touch(File.join(clean_dir, rel)) }

      assert_cmd("make", "clean", "FUZZ_DIR=#{clean_dir}", env: UNMAKE_ENV, chdir: root_dir, input: "")
      assert_path_exists File.join(clean_dir, "report/triage/ABRT/sig1/meta.json"),
                         "make clean must preserve tmp/fuzz/report/triage"
      %w[afl afl-ijon bin snapshot corpus .dotfile report/index.html report/coverage].each do |deleted|
        refute_path_exists File.join(clean_dir, deleted),
                           "make clean failed to remove #{deleted}"
      end
    end
  end

  def test_embedded_provenance_snapshot_isolation_and_fuzz_vs_triage_split
    cc = find_c_compiler
    skip "no C compiler available" unless cc

    with_tmpdir("triage-provenance-embedded-") do |workdir|
      snap_empty_corpus = File.join(workdir, "snap_empty_corpus")
      FileUtils.mkdir_p(snap_empty_corpus)

      snap_env = {
        "TRIAGE_COVERAGE_BIN" => nil,
        "TRIAGE_COVERAGE_IDS" => nil,
        "TRIAGE_DIFF_COVERAGE_BIN" => nil,
        "TRIAGE_DIFF_COVERAGE_IDS" => nil,
        "TRIAGE_CORPUS_DIR" => snap_empty_corpus
      }

      with_prism_env(workdir, snap_env) do
        src_dir = File.join(workdir, "snap_build")
        bin_dir = File.join(workdir, "snap_campaign", "bin")
        triage_dir = File.join(workdir, "snap_campaign", "triage")
        afl_dir = File.join(workdir, "snap_campaign", "afl")
        FileUtils.mkdir_p([src_dir, File.join(afl_dir, "w1", "crashes")])

        harness_stub = File.join(workdir, "snap_main_stub.c")
        File.write(harness_stub, SNAP_MAIN_STUB_C)

        prism_inc = File.join(FuzzTriage.locate_version_repo_root, "include")
        snap_fuzz = File.join(src_dir, "fuzz")
        assert_cmd(
          cc, "-O2", "-std=c99", "-Wall", "-Werror", "-I#{prism_inc}",
          "-DFUZZ_GIT_COMMIT=#{'a' * 40}",
          "-DFUZZ_GIT_DIRTY=0",
          repo_path("harnesses/prism/fuzz.c"), harness_stub, "-o", snap_fuzz,
          msg: "failed to compile harnesses/prism/fuzz.c provenance stub"
        )
        File.write(File.join(src_dir, "fuzz.ids"), "1\tpm_parse\n")
        File.write(
          File.join(src_dir, "fuzz.diff.ids"),
          "Domain=prism Source=prism.c Function=pm_parse edgeID=5\nDomain=parse_y Source=parse.c Function=ruby_yyparse edgeID=6\n"
        )

        emb = FuzzProvenance.read_embedded_binary_provenance(snap_fuzz)
        assert emb, "expected embedded provenance from compiled fuzz.c"
        assert_equal "a" * 40, emb.dig("prism", "git_commit")
        assert_equal false, emb.dig("prism", "git_dirty")
        assert_equal FuzzTriage.read_prism_header_version(FuzzTriage.locate_version_repo_root),
                     emb.dig("prism", "version")

        manifest_path = FuzzProvenance.write_build_manifest(src_dir, repo_root: root_dir)
        assert_path_exists manifest_path, "expected build manifest at #{manifest_path}"

        snap_manifest = FuzzProvenance.snapshot_build_to_bin(src_dir, bin_dir, repo_root: root_dir)
        assert_path_exists snap_manifest, "expected snapshot versions.json at #{snap_manifest}"
        assert File.executable?(File.join(bin_dir, "fuzz")), "expected executable fuzz in #{bin_dir}"
        assert_path_exists File.join(bin_dir, "fuzz.ids")
        assert_path_exists File.join(bin_dir, "fuzz.diff.ids")

        # Simulate rebuilding/wiping ./build after campaign started: snapshot remains intact & self-contained
        FileUtils.rm_rf(src_dir)

        snap_fuzz_bin = File.join(bin_dir, "fuzz")
        snap_diff_bin = write_executable(File.join(bin_dir, "fuzz.diff"), "#!/bin/sh\nexit 0\n")
        assert_equal snap_fuzz_bin, FuzzTriage.companion_executable(snap_diff_bin, "fuzz"),
                     "expected companion_executable to resolve snapshot sibling fuzz"

        cov_resolved, ids_resolved = FuzzTriage.resolve_coverage_target(triage_dir: triage_dir, output_dirs: [afl_dir])
        assert_equal [snap_fuzz_bin, "#{snap_fuzz_bin}.ids"], [cov_resolved, ids_resolved],
                     "expected resolve_coverage_target to pick snapshot fuzz"

        diff_resolved, diff_ids_resolved = FuzzTriage.resolve_diff_coverage_target(
          triage_dir: triage_dir,
          output_dirs: [afl_dir]
        )
        assert_equal [snap_diff_bin, "#{snap_diff_bin}.ids"], [diff_resolved, diff_ids_resolved],
                     "expected resolve_diff_coverage_target to pick snapshot fuzz.diff"

        loaded_diff_ids = FuzzTriage.load_coverage_ids(diff_ids_resolved)
        assert loaded_diff_ids[:available]
        assert_equal({ "5" => "pm_parse", "6" => "ruby_yyparse" }, loaded_diff_ids[:edge_functions])
        assert_equal({ "5" => "prism", "6" => "parse_y" }, loaded_diff_ids[:edge_domains])

        # Simulate retriage where a rebuilt binary (commit bbbb..., dirty=1) classifies a survivor found by snap_fuzz
        retriage_dir = File.join(workdir, "retriage_build")
        FileUtils.mkdir_p(retriage_dir)
        rebuilt_fuzz = File.join(retriage_dir, "fuzz")
        assert_cmd(
          cc, "-O2", "-std=c99", "-Wall", "-Werror", "-I#{prism_inc}",
          "-DFUZZ_GIT_COMMIT=#{'b' * 40}",
          "-DFUZZ_GIT_DIRTY=1",
          repo_path("harnesses/prism/fuzz.c"), harness_stub, "-o", rebuilt_fuzz,
          msg: "failed to compile rebuilt fuzz.c provenance stub"
        )

        orig_fuzz_prov = FuzzProvenance.resolve_binary_provenance(snap_fuzz_bin, is_diff: false, repo_root: root_dir)
        v_split = FuzzTriage.resolve_versions_metadata(
          executable: rebuilt_fuzz,
          worker_executable: rebuilt_fuzz,
          is_diff: false,
          fuzz_versions_override: orig_fuzz_prov,
          coverage_bin: rebuilt_fuzz
        )
        assert_equal "aaaaaaaaa", v_split.dig("fuzz", "prism", "git_short")
        assert_equal false, v_split.dig("fuzz", "prism", "git_dirty")
        assert_equal "bbbbbbbbb", v_split.dig("triage", "prism", "git_short")
        assert_equal true, v_split.dig("triage", "prism", "git_dirty")

        if find_executable("git")
          prism_dirty_repo = File.join(workdir, "prism_dirty_repo")
          FileUtils.mkdir_p([File.join(prism_dirty_repo, "src"), File.join(prism_dirty_repo, "harnesses")])
          File.write(File.join(prism_dirty_repo, "src", "prism.c"), "int ok = 1;\n")
          File.write(File.join(prism_dirty_repo, "harnesses", "stub.c"), "int stub = 1;\n")
          assert_cmd("git", "-C", prism_dirty_repo, "init", "-q")
          assert_cmd("git", "-C", prism_dirty_repo, "config", "user.email", "test@example.com")
          assert_cmd("git", "-C", prism_dirty_repo, "config", "user.name", "Test")
          assert_cmd("git", "-C", prism_dirty_repo, "config", "commit.gpgsign", "false")
          assert_cmd("git", "-C", prism_dirty_repo, "config", "tag.gpgsign", "false")
          assert_cmd("git", "-C", prism_dirty_repo, "add", "-A")
          assert_cmd("git", "-C", prism_dirty_repo, "commit", "-qm", "base")

          clean_state = FuzzProvenance.detect_git_state(prism_dirty_repo, paths: FuzzProvenance::PRISM_DIRTY_PATHS)
          assert clean_state, "expected clean git state"
          assert_equal false, clean_state["git_dirty"],
                       "expected clean PRISM_DIRTY_PATHS state to be git_dirty=false"

          File.write(File.join(prism_dirty_repo, "harnesses", "stub.c"), "int stub = 2;\n")
          clear_git_state_cache(prism_dirty_repo)
          non_prism_dirty = FuzzProvenance.detect_git_state(prism_dirty_repo, paths: FuzzProvenance::PRISM_DIRTY_PATHS)
          assert non_prism_dirty
          assert_equal false, non_prism_dirty["git_dirty"],
                       "expected non-Prism path edit to leave PRISM_DIRTY_PATHS git_dirty=false"

          File.write(File.join(prism_dirty_repo, "src", "prism.c"), "int ok = 2;\n")
          clear_git_state_cache(prism_dirty_repo)
          src_dirty = FuzzProvenance.detect_git_state(prism_dirty_repo, paths: FuzzProvenance::PRISM_DIRTY_PATHS)
          assert src_dirty
          assert_equal true, src_dirty["git_dirty"],
                       "expected src/prism.c edit to mark PRISM_DIRTY_PATHS git_dirty=true"
        end

        if File.file?("/etc/os-release")
          cont = FuzzProvenance.collect_container_provenance(repo_root: root_dir)
          assert cont, "expected container provenance in Docker"
          %w[os arch clang aflplusplus afl_patch_sha256 ruby lrama_fuzz].each do |key|
            assert cont[key], "expected container provenance key #{key.inspect} in Docker, got: #{cont.inspect}"
          end
        end

        split_report = FuzzClustering.cluster_metadata(
          {
            "versions" => v_split,
            "buckets" => [
              {
                "bucket_id" => "ABORT/sig_split",
                "reason" => "ABORT",
                "signature" => "sig_split",
                "reproducible" => true,
                "occurrences" => { "count" => 1 },
                "input" => { "min_size_bytes" => 8 },
                "versions" => v_split
              }
            ]
          }
        )
        split_summary = FuzzClustering.format_summary_table(split_report)
        assert_includes split_summary, "aaaaaaaaa"
        assert_includes split_summary, "triage_prism="
        assert_includes split_summary, "bbbbbbbbb-dirty"
        assert_includes split_summary, "Container:"
      end
    end
  end

  def test_script_snapshot_isolation_and_cli_prism_root_guards
    with_tmpdir("triage-provenance-scripts-") do |workdir|
      clean_topo_env = {
        "CAMPAIGN" => nil,
        "TOPOLOGY" => nil,
        "TOPOLOGY_FILE" => nil,
        "TOPOLOGY_RESOLVED" => nil
      }

      with_env(clean_topo_env) do
        snap_src = File.join(workdir, "script_snap_src")
        snap_bin = File.join(workdir, "script_snap_camp", "bin")
        snap_dir = File.join(workdir, "script_snap_camp", "snapshot")
        FileUtils.mkdir_p(snap_src)
        write_executable(
          File.join(snap_src, "fuzz"),
          "#!/bin/sh\necho 'Assertion `boom'\\'' failed.' >&2\nexit 134\n"
        )

        ver_path = FuzzProvenance.snapshot_build_to_bin(
          snap_src,
          snap_bin,
          dst_snapshot_dir: snap_dir,
          repo_root: root_dir
        )
        manifest = JSON.parse(File.read(ver_path))
        assert_equal FuzzProvenance::SNAPSHOT_PATHS, manifest["snapshot_paths"]

        EXPECTED_SNAPSHOT_RELS.each do |rel|
          p = File.join(snap_dir, rel)
          assert File.file?(p), "expected #{p} in snapshot"
          assert File.executable?(p), "expected #{p} to remain executable" if rel.end_with?(".sh")
        end

        active_prism = ENV["PRISM_A_DIR"] || prism_a_dir
        if active_prism && File.directory?(File.join(active_prism, "lib")) &&
           File.file?(File.join(active_prism, "lib", "prism.rb"))
          assert_path_exists File.join(snap_bin, "prism_lib", "prism.rb"),
                             "expected prism_lib/prism.rb in #{snap_bin}"
        end

        marker_file = File.join(workdir, "snap_signature_marker")
        snap_sig_sh = File.join(snap_dir, "triage/signature.sh")
        orig_sig_src = File.read(snap_sig_sh)
        File.write(snap_sig_sh, orig_sig_src.sub("set -euo pipefail\n", "set -euo pipefail\n: > #{marker_file.dump}\n"))
        File.chmod(0o755, snap_sig_sh)

        snap_triage_rb = File.join(snap_dir, "triage/triage.rb")
        snap_crash = File.join(workdir, "snap_crash.bin")
        File.binwrite(snap_crash, seed_bytes("1 + 2"))
        snap_min = File.join(workdir, "snap_min.bin")

        child_script = <<~RUBY
          require #{snap_triage_rb.dump}
          raise "expected TRIAGE_FILE_DIR to resolve to snapshot triage dir" unless FuzzTriage::TRIAGE_FILE_DIR == #{File.dirname(snap_triage_rb).dump}
          raise "expected triage/lib/* to resolve from snapshot dir" unless FuzzTriage.method(:minimize).source_location.first.start_with?(#{File.dirname(snap_triage_rb).dump})
          raise "expected snapshotted parse.c" unless File.file?(#{File.join(snap_dir, "harnesses/prism/parse.c").dump})
          sig = FuzzTriage.testcase_output_signature("Assertion `boom' failed.\\n", 10)
          raise "expected non-empty signature" if sig.empty?
          FuzzTriage.minimize(#{snap_crash.dump}, "ABRT", #{snap_min.dump}, #{File.join(snap_bin, "fuzz").dump}, 10)
        RUBY
        assert_ruby_cmd("-e", child_script, msg: "snapshotted triage.rb child check failed")
        assert_path_exists marker_file,
                           "expected snapshotted signature.sh to execute via snapshot triage.rb/halfempty.sh"

        # Verify CLI `provenance.rb snapshot` snapshots prism-fuzzer scripts even when PRISM_A_DIR is active
        mock_prism = File.join(workdir, "cli_mock_prism")
        FileUtils.mkdir_p([
          File.join(mock_prism, "include/prism"),
          File.join(mock_prism, "bin"),
          File.join(mock_prism, "lib")
        ])
        File.write(File.join(mock_prism, "include/prism/version.h"), "#define PRISM_VERSION \"9.9.9\"\n")

        cli_src = File.join(workdir, "cli_snap_build")
        cli_bin = File.join(workdir, "cli_snap_bin")
        cli_snap = File.join(workdir, "cli_snap_out")
        FileUtils.mkdir_p(cli_src)
        write_executable(File.join(cli_src, "fuzz"), "#!/bin/sh\nexit 0\n")

        cli_env = clean_topo_env.merge("PRISM_A_DIR" => mock_prism)
        assert_ruby_cmd(
          repo_path("runtime/provenance.rb"), "snapshot", cli_src, cli_bin, cli_snap,
          env: cli_env,
          msg: "provenance.rb snapshot CLI failed"
        )

        cli_manifest = JSON.parse(File.read(File.join(cli_bin, "versions.json")))
        assert_equal FuzzProvenance::SNAPSHOT_PATHS, cli_manifest["snapshot_paths"]
        assert_path_exists File.join(cli_snap, "runtime/kill.sh")
        assert File.executable?(File.join(cli_snap, "runtime/kill.sh"))
        assert_path_exists File.join(cli_snap, "triage/triage.rb"),
                           "CLI snapshot leaked Prism mock tree instead of prism-fuzzer"

        # Also verify explicit repo_root pointing at a Prism checkout is guarded safely
        guard_snap = File.join(workdir, "cli_snap_guard")
        FuzzProvenance.snapshot_build_to_bin(
          cli_src,
          File.join(workdir, "cli_snap_guard_bin"),
          dst_snapshot_dir: guard_snap,
          repo_root: mock_prism
        )
        assert_path_exists File.join(guard_snap, "runtime/kill.sh"),
                           "snapshot_build_to_bin with Prism repo_root missed runtime/kill.sh"
      end
    end
  end

  def test_corrupt_json_diagnostics_and_silent_missing_files
    with_tmpdir("triage-provenance-json-") do |workdir|
      json_dir = File.join(workdir, "json_diag_check")
      bin_dir = File.join(json_dir, "bin")
      triage_dir = File.join(json_dir, "triage")
      missing_bdir = File.join(triage_dir, "ABRT", "missing_meta")
      corrupt_bdir = File.join(triage_dir, "ABRT", "corrupt_meta")
      FileUtils.mkdir_p([bin_dir, missing_bdir, corrupt_bdir])

      not_a_dir_file = File.join(json_dir, "plain_file")
      File.write(not_a_dir_file, "x")
      corrupt_meta = File.join(corrupt_bdir, "meta.json")
      corrupt_versions = File.join(bin_dir, "versions.json")
      File.write(corrupt_meta, "{not valid json\n")
      File.write(corrupt_versions, "{broken versions\n")

      with_env("FUZZ_QUIET" => nil) do
        err_missing = capture_stderr do
          assert_equal({}, PrismFuzzer::Common.read_json(File.join(json_dir, "absent.json"), default: {}))
          assert_nil PrismFuzzer::Common.read_json(File.join(not_a_dir_file, "child.json"))
          assert_nil FuzzProvenance.find_manifest_for_bin_dir(File.join(json_dir, "missing_bin"))

          entry = FuzzVerify.build_bucket_entry(missing_bdir, "ABRT", "ABRT/missing_meta")
          assert_nil entry[:meta]
          assert_equal "asan_ubsan", entry[:profile]

          prov = FuzzRetriage.collect_bucket_provenance(missing_bdir)
          assert_nil prov[:meta]

          cov = PrismFuzzerReport::CoverageView.ingest_coverage(
            cov_json_path: File.join(json_dir, "missing_cov.json"),
            out_dir_abs: json_dir,
            fuzzers: []
          )
          assert_empty cov[:cov_pairs]
        end
        assert_equal "", err_missing, "expected zero stderr warnings for missing JSON files"

        corrupt_cov = File.join(json_dir, "corrupt_cov.json")
        File.write(corrupt_cov, "{bad coverage\n")
        corrupt_occ = File.join(corrupt_bdir, "occurrences.jsonl")
        File.write(corrupt_occ, "{bad jsonl\n")

        err_corrupt = capture_stderr do
          assert_nil FuzzProvenance.find_manifest_for_bin_dir(bin_dir)

          entry = FuzzVerify.build_bucket_entry(corrupt_bdir, "ABRT", "ABRT/corrupt_meta")
          assert_nil entry[:meta]
          assert_equal "asan_ubsan", entry[:profile]

          assert_equal "asan_ubsan", FuzzVerifyProfile.infer_bucket_profile(corrupt_bdir)

          prov = FuzzRetriage.collect_bucket_provenance(corrupt_bdir)
          assert_nil prov[:meta]

          cov = PrismFuzzerReport::CoverageView.ingest_coverage(
            cov_json_path: corrupt_cov,
            out_dir_abs: json_dir,
            fuzzers: []
          )
          assert_empty cov[:cov_pairs]

          PrismFuzzerReport::Lineage.load_lineage_triage_crashes(triage_dir)

          assert_raises(TypeError, "expected PrismFuzzer::Common.read_json(123) not to swallow TypeError") do
            PrismFuzzer::Common.read_json(123)
          end
        end

        assert_includes err_corrupt, "FuzzProvenance: failed to parse JSON #{corrupt_versions}"
        assert_includes err_corrupt, "FuzzVerify: failed to parse JSON #{corrupt_meta}"
        assert_includes err_corrupt, "FuzzVerifyProfile: failed to parse JSON #{corrupt_meta}"
        assert_includes err_corrupt, "FuzzRetriage: failed to parse JSON #{corrupt_meta}"
        assert_includes err_corrupt, "FuzzRetriage: malformed JSONL line in #{corrupt_occ}"
        assert_includes err_corrupt, "CoverageView: failed to parse JSON #{corrupt_cov}"
        assert_includes err_corrupt, "Lineage: failed to parse JSON #{corrupt_meta}"
        assert_includes err_corrupt, "Lineage: malformed JSONL line in #{corrupt_occ}"
      end
    end
  end

  private

  def find_c_compiler
    %w[clang cc gcc].find { |c| find_executable(c) }
  end

  def compile_diff_version_stub(workdir, cc:)
    stub_c = File.join(workdir, "stub_fuzz_diff.c")
    stub_bin = File.join(workdir, "stub_fuzz_diff")
    File.write(stub_c, STUB_FUZZ_DIFF_C)
    assert_cmd(cc, stub_c, "-o", stub_bin, msg: "failed to compile #{stub_c}")
    stub_bin
  end

  def with_prism_env(workdir, extra_env)
    pa = prism_a_dir
    if pa && File.file?(File.join(pa, "include/prism/version.h"))
      with_env(extra_env) { yield }
    else
      stub_prism = File.join(workdir, "stub_prism_root")
      FileUtils.mkdir_p(File.join(stub_prism, "include/prism"))
      File.write(File.join(stub_prism, "include/prism/version.h"), "#define PRISM_VERSION \"1.9.0\"\n")
      File.write(File.join(stub_prism, "include/prism.h"), "#include \"prism/version.h\"\n")
      with_env(extra_env.merge("PRISM_A_DIR" => stub_prism)) { yield }
    end
  end

  def clear_git_state_cache(repo_path)
    expanded = File.expand_path(repo_path)
    FuzzProvenance::CACHE_MUTEX.synchronize do
      FuzzProvenance::GIT_STATE_CACHE.delete_if { |key, _| key.first == expanded }
    end
  end

  def capture_stderr
    prev = $stderr
    buf = StringIO.new
    $stderr = buf
    yield
    buf.string
  ensure
    $stderr = prev
  end
end
