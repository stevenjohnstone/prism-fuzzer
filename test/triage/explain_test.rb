# frozen_string_literal: true

require_relative "../lib/autorun"

require "digest"
require "fileutils"
require "json"
require "rbconfig"

require_relative "../../triage/explain"
require_relative "../../triage/triage"

# Migrated from inspect.rb and stage_explain of test/test_triage.sh.
# Verifies triage/inspect.rb cluster digests, input.min fallback, filters, and
# --since snapshot diffs; triage/explain.rb cluster/member resolution, C AST
# anomaly diagnostics, CRuby parse.y vs prism comparison, disasm diff, mock
# driver fallback, regression #32 fixes, cross-arch arm32 (qemu-arm) explain,
# and triage.rb finalize_triage_metadata digest enrichment.
class TriageExplainTest < Minitest::Test
  CLEAN_INSPECT_ENV = {
    "CAMPAIGN" => nil,
    "TOPOLOGY" => nil,
    "TOPOLOGY_FILE" => nil,
    "TOPOLOGY_RESOLVED" => nil,
    "TRIAGE_DIR" => nil,
    "CLUSTERS_FILE" => nil,
    "CLUSTER" => nil,
    "BUCKET" => nil
  }.freeze

  CLEAN_EXPLAIN_ENV = CLEAN_INSPECT_ENV.merge(
    "FUZZ_DIR" => nil,
    "FUZZ_BUILD_DIR" => nil,
    "EXPLAIN_BIN" => nil,
    "EXPLAIN_B_BIN" => nil,
    "EXPLAIN_NO_DOCKER" => nil,
    "EXPLAIN_HOST_RUBY" => nil,
    "EXPLAIN_ARM32_BIN" => nil,
    "EXPLAIN_PPC_BIN" => nil,
    "COMPARE_RUBY" => nil,
    "TRIAGE_EXPLAIN_BIN" => nil,
    "TRIAGE_COVERAGE_BIN" => nil,
    "TRIAGE_DIFF_COVERAGE_BIN" => nil,
    "TRIAGE_CORPUS_DIR" => nil,
    "TRIAGE_RECOUNT" => nil,
    "TRIAGE_DIGEST" => nil,
    "TRIAGE_DIFF_RUBY" => nil,
    "MAKEFLAGS" => nil,
    "MFLAGS" => nil,
    "MAKELEVEL" => nil
  ).freeze

  def test_inspect_digests_input_min_fallback_filters_and_since_diffs
    with_tmpdir("triage-inspect-") do |workdir|
      inspect_suite = File.join(workdir, "inspect_suite")
      cur_dir = File.join(inspect_suite, "cur")
      prev_path = File.join(inspect_suite, "prev_clusters.json")

      FileUtils.mkdir_p([
        File.join(cur_dir, "ABRT/1111222233334444"),
        File.join(cur_dir, "ABRT/aaaa2222bbbb3333")
      ])
      File.binwrite(File.join(cur_dir, "ABRT/1111222233334444/input.min"), "\x40\x00\x03\x01puts 1\n__END__\n".b)
      File.binwrite(File.join(cur_dir, "ABRT/aaaa2222bbbb3333/input.min"), "\x00\x00\x03\x01super (){}\n".b)

      cur_meta = {
        "schema_version" => 1,
        "corpus" => { "available" => false, "corpus_count" => 0, "edge_df" => {}, "edge_functions" => {} },
        "buckets" => [
          {
            "schema_version" => 1,
            "bucket_id" => "ABRT/1111222233334444",
            "reason" => "ABRT",
            "signature" => "1111222233334444",
            "reproducible" => true,
            "reproduced_by" => "fuzz.msan",
            "verify_profile" => "msan_slow",
            "occurrences" => { "count" => 12, "first_elapsed_ms" => 5000 },
            "input" => {
              "min_size_bytes" => 18,
              "header_hex" => "40000301",
              "loupe_url" => "https://stevenjohnstone.github.io/prism-loupe/?code=cHV0cyAxCl9fRU5EX18K&stream=1"
            },
            "options" => {
              "ruby_version" => "4.1",
              "start_line" => 1,
              "stream_mode" => true,
              "stack_budget" => "SIZE_MAX",
              "scopes_count" => 0
            },
            "symptom" => {
              "headline" => "INVARIANT[stream_diff]: kind=spurious_stop",
              "invariant" => { "namespace" => "stream_diff", "fields" => { "kind" => "spurious_stop" } }
            },
            "frames" => [
              { "scope" => "harness", "func" => "LLVMFuzzerTestOneInput", "file" => "fuzz.c", "line" => 10 },
              { "scope" => "prism", "func" => "parse_expression", "file" => "src/prism.c", "line" => 14010 },
              { "scope" => "prism", "func" => "pm_parse_stream", "file" => "src/prism.c", "line" => 24010 }
            ],
            "digest" => {
              "parsed_size" => 14,
              "stream_mode" => true,
              "errors" => 1,
              "anomaly_count" => 1,
              "anomalies" => [
                { "category" => "node_location", "kind" => "length_underflow", "node" => "PM_EMBEDDED_STATEMENTS_NODE" }
              ],
              "stream_compare" => {
                "parsed_size" => [14, 6],
                "prettyprint_equal" => false,
                "serialize_equal" => false,
                "serialize_diff_offset" => 12
              }
            },
            "coverage" => { "available" => false }
          },
          {
            "schema_version" => 1,
            "bucket_id" => "ABRT/aaaa2222bbbb3333",
            "reason" => "ABRT",
            "signature" => "aaaa2222bbbb3333",
            "reproducible" => true,
            "reproduced_by" => "fuzz.diff",
            "verify_profile" => "diff_parse_y",
            "occurrences" => { "count" => 4, "first_elapsed_ms" => 12000 },
            "input" => {
              "min_size_bytes" => 14,
              "header_hex" => "00000301",
              "payload_sha256" => Digest::SHA256.hexdigest("super (){}\n"),
              "source_preview" => "super (){}\\n"
            },
            "options" => {
              "ruby_version" => "4.1",
              "start_line" => 1,
              "stream_mode" => false,
              "stack_budget" => "SIZE_MAX",
              "scopes_count" => 0
            },
            "symptom" => {
              "headline" => "INVARIANT[diff_parse_y]: kind=syntax_mismatch sub=prism_ok_cruby_err",
              "invariant" => {
                "namespace" => "diff_parse_y",
                "fields" => { "kind" => "syntax_mismatch", "sub" => "prism_ok_cruby_err" }
              }
            },
            "digest" => {
              "syntax_status" => "both_ok",
              "iseq_status" => "disasm_diff",
              "disasm_diff_preview" => "-0000 putnil | +0000 putself"
            },
            "frames" => [],
            "coverage" => { "available" => false }
          }
        ]
      }
      File.write(File.join(cur_dir, "metadata.json"), JSON.pretty_generate(cur_meta))

      prev_clusters = {
        "schema_version" => 1,
        "clusters" => [
          {
            "cluster_id" => "cluster-01",
            "group" => "prism_flaw",
            "bucket_count" => 1,
            "occurrences" => 5,
            "reasons" => { "ABRT" => 1 },
            "representative" => {
              "bucket_id" => "ABRT/1111222233334444",
              "headline" => "INVARIANT[stream_diff]: kind=spurious_stop"
            },
            "buckets" => [
              { "bucket_id" => "ABRT/1111222233334444", "signature" => "1111222233334444", "occurrences" => 5 }
            ]
          },
          {
            "cluster_id" => "cluster-02",
            "group" => "prism_flaw",
            "bucket_count" => 1,
            "occurrences" => 2,
            "reasons" => { "ABRT" => 1 },
            "representative" => {
              "bucket_id" => "SEGV/9999888877776666",
              "headline" => "SUMMARY: AddressSanitizer: SEGV"
            },
            "buckets" => [
              { "bucket_id" => "SEGV/9999888877776666", "signature" => "9999888877776666", "occurrences" => 2 }
            ]
          }
        ]
      }
      File.write(prev_path, JSON.pretty_generate(prev_clusters))

      insp_json, = assert_ruby_cmd(
        repo_path("triage/inspect.rb"),
        "--triage-dir", cur_dir,
        "--since", prev_path,
        "--buckets", "--json",
        env: CLEAN_INSPECT_ENV
      )
      assert_path_exists File.join(cur_dir, "clusters.json"), "expected clusters.json auto-created under cur/"

      d = JSON.parse(insp_json)
      assert_equal 2, d.dig("summary", "total_clusters")
      c_opt = d["clusters"].find { |c| c.dig("representative", "bucket_id") == "ABRT/1111222233334444" }
      c_diff = d["clusters"].find { |c| c.dig("representative", "bucket_id") == "ABRT/aaaa2222bbbb3333" }
      refute_nil c_opt
      refute_nil c_diff

      assert_equal "puts 1\\n__END__\\n", c_opt.dig("representative", "source_preview"),
                   "expected input.min fallback source_preview on c_opt: #{c_opt.inspect}"
      assert_equal "grown", c_opt.dig("diff", "status"), "expected grown diff on c_opt: #{c_opt['diff'].inspect}"
      assert_equal 7, c_opt.dig("diff", "delta_occurrences"), "expected +7 occ diff on c_opt: #{c_opt['diff'].inspect}"
      assert_equal "new", c_diff.dig("diff", "status"), "expected new diff on c_diff: #{c_diff['diff'].inspect}"
      assert_equal 1, d["resolved_clusters"].size
      assert_equal "SEGV/9999888877776666", d.dig("resolved_clusters", 0, "representative", "bucket_id")
      assert_equal ["parse_expression@src/prism.c:14010", "pm_parse_stream@src/prism.c:24010"],
                   c_opt.dig("representative", "prism_trace"),
                   "expected prism_trace filtering boilerplate frames on c_opt: #{c_opt.inspect}"
      assert_equal 1, c_opt.dig("digest_summary", "anomaly_kinds", "length_underflow")
      assert_equal 1, c_diff.dig("digest_summary", "iseq_statuses", "disasm_diff")

      iseq_json, = assert_ruby_cmd(
        repo_path("triage/inspect.rb"),
        "--triage-dir", cur_dir,
        "--iseq", "disasm_diff", "--syntax", "both_ok", "--json",
        env: CLEAN_INSPECT_ENV
      )
      ij = JSON.parse(iseq_json)
      assert_equal 1, ij.dig("summary", "matched_clusters")
      assert_equal "ABRT/aaaa2222bbbb3333", ij.dig("clusters", 0, "representative", "bucket_id")

      anom_json, = assert_ruby_cmd(
        repo_path("triage/inspect.rb"),
        "--triage-dir", cur_dir,
        "--anomaly", "length_underflow", "--json",
        env: CLEAN_INSPECT_ENV
      )
      aj = JSON.parse(anom_json)
      assert_equal 1, aj.dig("summary", "matched_clusters")
      assert_equal "ABRT/1111222233334444", aj.dig("clusters", 0, "representative", "bucket_id")

      insp_text, = assert_ruby_cmd(
        repo_path("triage/inspect.rb"),
        "--triage-dir", cur_dir,
        "--buckets",
        env: CLEAN_INSPECT_ENV
      )
      assert_includes insp_text, "trace:    parse_expression@src/prism.c:14010 <- pm_parse_stream@src/prism.c:24010"
      assert_match(
        /digest:   parsed=14B\(stream\).*anomalies=length_underflow@PM_EMBEDDED_STATEMENTS_NODE.*stream_compare=mismatch\(size=14\/6,pp,ser@12\)/,
        insp_text
      )
      assert_includes insp_text, "digest:   syntax=both_ok  iseq=disasm_diff"
      assert_includes insp_text, "[iseq=disasm_diff]"

      insp_brief, = assert_ruby_cmd(
        repo_path("triage/inspect.rb"),
        "--triage-dir", cur_dir,
        "--brief",
        env: CLEAN_INSPECT_ENV
      )
      refute_match(/^  digest:|^  variants:/, insp_brief)

      opts_json, = assert_ruby_cmd(
        repo_path("triage/inspect.rb"),
        "--triage-dir", cur_dir,
        "--non-default-options", "--json",
        env: CLEAN_INSPECT_ENV
      )
      opts_d = JSON.parse(opts_json)
      assert_equal 1, opts_d.dig("summary", "matched_clusters")
      assert_equal "ABRT/1111222233334444", opts_d.dig("clusters", 0, "representative", "bucket_id")

      only_new_json, = assert_ruby_cmd(
        repo_path("triage/inspect.rb"),
        "--triage-dir", cur_dir,
        "--since", prev_path,
        "--only-new", "--json",
        env: CLEAN_INSPECT_ENV
      )
      only_new_d = JSON.parse(only_new_json)
      assert_equal 1, only_new_d.dig("summary", "matched_clusters")
      assert_equal "ABRT/aaaa2222bbbb3333", only_new_d.dig("clusters", 0, "representative", "bucket_id")
    end
  end

  def test_explain_cluster_member_resolution_and_c_ast_diagnostics
    with_tmpdir("triage-explain-local-") do |workdir|
      explain_suite = File.join(workdir, "explain_suite")
      triage_dir = setup_explain_suite_triage(explain_suite)
      explain_bin = ensure_explain_suite_bin(workdir)
      explain_env = CLEAN_EXPLAIN_ENV.merge("EXPLAIN_BIN" => explain_bin)

      # Cluster member listing
      members_json, = assert_ruby_cmd(
        repo_path("triage/explain.rb"),
        "--triage-dir", triage_dir, "cluster-01", "--list-members", "--json",
        env: explain_env
      )
      ms = JSON.parse(members_json).dig("clusters", 0, "members")
      refute_nil ms
      assert_equal 2, ms.size
      assert ms[0]["representative"]
      refute ms[1]["representative"]
      assert_equal "ABRT/fedcba0987654321", ms[1]["bucket_id"]

      # Cluster-first default (representative), --member, direct bucket resolution, and --all-buckets locally
      local_env = explain_env.merge("EXPLAIN_NO_DOCKER" => "1")
      rep_local, = assert_ruby_cmd(
        repo_path("triage/explain.rb"),
        "--triage-dir", triage_dir, "cluster-01", "--no-compare", "--json",
        env: local_env
      )
      mem2_local, = assert_ruby_cmd(
        repo_path("triage/explain.rb"),
        "--triage-dir", triage_dir, "cluster-01", "--member", "2", "--no-compare", "--json",
        env: local_env
      )
      bkt2_local, = assert_ruby_cmd(
        repo_path("triage/explain.rb"),
        "--triage-dir", triage_dir, "ABRT/fedcba0987654321", "--no-compare", "--json",
        env: local_env
      )
      all_local, = assert_ruby_cmd(
        repo_path("triage/explain.rb"),
        "--triage-dir", triage_dir, "cluster-01", "--all-buckets", "--no-compare", "--json",
        env: local_env
      )

      rep = JSON.parse(rep_local).dig("results", 0)
      m2 = JSON.parse(mem2_local).dig("results", 0)
      b2 = JSON.parse(bkt2_local).dig("results", 0)
      all = JSON.parse(all_local)["results"]

      assert_equal "ABRT/1234567890abcdef", rep["bucket_id"]
      assert rep["is_representative"]
      assert_equal 1, rep["member_index"]
      assert rep.dig("c_explain", "ok")

      assert_equal "ABRT/fedcba0987654321", m2["bucket_id"]
      refute m2["is_representative"]
      assert_equal 2, m2["member_index"]

      assert_equal "ABRT/fedcba0987654321", b2["bucket_id"]
      assert_equal 2, all.size

      # Verify explain.c agrees with parse.c on \v/\f/\r inline whitespace in \u{...} mixed_encoding checks and option decoding.
      [0x0b, 0x0c, 0x0d].each do |ws_byte|
        snippet = "#encoding:ascii\n\"\\u{41".b + ws_byte.chr.b + "de}\"\n".b
        ws_digest, = assert_cmd(explain_bin, "--snippet", "--digest", "-", input: snippet)
        d = JSON.parse(ws_digest)
        assert_equal 0, d["anomaly_count"],
                     "expected anomaly_count=0 for \\u{41...de} ws=0x#{format('%02x', ws_byte)}, got #{d.inspect}"
      end

      opt_explain_out, = assert_cmd(explain_bin, "--header", "80800c80", "-e", "1")
      assert_match(
        /start_line=2147483647 stack_budget=512 encoding=UTF-8 filepath=fuzz\.rb .*scopes=3\(fwd_scope=2,fwd=0x0,src_len=1\)/,
        opt_explain_out
      )

      # Regression (Bug #32 #1): -e (0x02) and full 0x3f cmd_flags decoded in strip_fuzz_header
      e_only_json, = assert_ruby_cmd(
        repo_path("triage/explain.rb"),
        "--stdin", "--raw", "--no-compare", "--json",
        input: "\x00\x02\x03\x01puts 1\n".b,
        env: explain_env
      )
      all_flags_json, = assert_ruby_cmd(
        repo_path("triage/explain.rb"),
        "--stdin", "--raw", "--no-compare", "--json",
        input: "\x00\x3f\x03\x01puts 1\n".b,
        env: explain_env
      )
      r_e = JSON.parse(e_only_json).dig("results", 0)
      r_all = JSON.parse(all_flags_json).dig("results", 0)
      assert_equal ["e"], r_e["cmd_flags"], "expected cmd_flags=[\"e\"] for 0x02 header, got #{r_e.inspect}"
      assert_equal %w[a e l n p x], r_all["cmd_flags"],
                   "expected cmd_flags=%w[a e l n p x] for 0x3f header, got #{r_all.inspect}"
    end
  end

  def test_explain_live_cruby_parse_y_vs_prism_comparison
    skip "CRuby does not support --parser=parse.y on this host" unless ruby_supports_parse_y?

    with_tmpdir("triage-explain-cruby-") do |workdir|
      explain_suite = File.join(workdir, "explain_suite")
      triage_dir = setup_explain_suite_triage(explain_suite)
      explain_bin = ensure_explain_suite_bin(workdir)
      explain_env = CLEAN_EXPLAIN_ENV.merge("EXPLAIN_BIN" => explain_bin)

      cmp_ok, = assert_ruby_cmd(
        repo_path("triage/explain.rb"),
        "-e", "def foo(a=1); a + 2; end", "--compare", "--fail-on-mismatch", "--json",
        env: explain_env
      )
      res_ok = JSON.parse(cmp_ok).dig("results", 0)
      refute_nil res_ok
      assert_equal "match", res_ok["parity"]
      assert_equal "both_ok", res_ok.dig("syntax", "status")
      assert_equal "match", res_ok.dig("iseq", "status")
      assert_includes res_ok.dig("c_explain", "stdout").to_s, "ProgramNode"

      cmp_diff, cmp_err, cmp_st = run_cmd(
        RbConfig.ruby,
        repo_path("triage/explain.rb"),
        "--triage-dir", triage_dir, "cluster-01",
        "--disasm", "--eval", "--fail-on-mismatch", "--json",
        env: explain_env,
        chdir: root_dir
      )
      assert_equal 1, cmp_st.exitstatus,
                   "expected --fail-on-mismatch exit 1 on super (){}, got #{cmp_st.exitstatus}: #{cmp_diff}\n#{cmp_err}"
      res_diff = JSON.parse(cmp_diff).dig("results", 0)
      refute_nil res_diff
      assert_equal "mismatch", res_diff["parity"]
      assert_equal "prism_ok_parse_y_err", res_diff.dig("syntax", "status")
      assert_equal "prism_ok_parse_y_compile_err", res_diff.dig("iseq", "status")
      assert_equal "prism", res_diff.dig("iseq", "disasm_parser")
      assert_includes res_diff.dig("iseq", "disasm").to_s, "disasm:"
      refute_equal "match", res_diff.dig("eval", "status")

      cmp_cmd_raw, = assert_ruby_cmd(
        repo_path("triage/explain.rb"),
        "--stdin", "--raw", "--compare", "--json",
        input: "\x00\x04\x03\x01puts 1\n".b,
        env: explain_env
      )
      res_raw = JSON.parse(cmp_cmd_raw).dig("results", 0)
      refute_nil res_raw
      assert_equal "match", res_raw["parity"]
      assert res_raw["source_preview"].start_with?("puts 1"),
             "expected stdin --raw header strip -> puts 1, got #{res_raw.inspect}"
    end
  end

  def test_explain_mock_ruby_driver_disasm_diff
    with_tmpdir("triage-explain-mock-ruby-") do |workdir|
      explain_bin = ensure_explain_suite_bin(workdir)
      mock_ruby = File.join(workdir, "mock_ruby.rb")
      write_executable(mock_ruby, <<~RUBY)
        #!#{RbConfig.ruby}
        require "json"
        parser = ARGV.find { |a| a.start_with?("--parser=") }&.split("=", 2)&.last
        rest = ARGV.reject { |a| a.start_with?("--parser=") }
        if rest == ["-e", ""]
          exit(parser == "parse.y" || parser == "prism" ? 0 : 2)
        elsif rest == ["-v"]
          puts "mock ruby 4.1.0dev"
          exit 0
        elsif rest.first == "-c"
          puts "Syntax OK"
          exit 0
        else
          disasm = parser == "parse.y" ? "0000 putnil\\n0001 leave\\n" : "0000 putself\\n0001 leave\\n"
          puts JSON.generate("compile" => { "ok" => true, "disasm" => disasm }, "prism_parse" => { "errors" => [], "warnings" => [] })
          exit 0
        end
      RUBY

      mock_cmp, = assert_ruby_cmd(
        repo_path("triage/explain.rb"),
        "--ruby", mock_ruby, "-e", "puts :hi", "--json",
        env: CLEAN_EXPLAIN_ENV.merge("EXPLAIN_BIN" => explain_bin)
      )
      res = JSON.parse(mock_cmp).dig("results", 0)
      refute_nil res
      assert_equal "mismatch", res["parity"]
      assert_equal "disasm_diff", res.dig("iseq", "status")
      assert_includes res.dig("iseq", "disasm_diff").to_s, "-0000 putnil"
      assert_includes res.dig("iseq", "disasm_diff").to_s, "+0000 putself"
    end
  end

  def test_explain_regression_topology_forwarding_and_docker_triage_mounts
    # Regression (Bug #32 #2 & #3):
    # - ensure_c_explain_bin forwards --topology for non-default campaigns when TOPOLOGY env is unset
    # - run_cross_explanations mounts/maps external workspace.dir report/triage without passing unmounted /external/ws_triage_dir
    with_tmpdir("triage-explain-ext-ws-") do |workdir|
      ext_ws = File.join(workdir, "explain_ext_ws")
      ext_build = File.join(ext_ws, "build")
      ext_triage = File.join(ext_ws, "report", "triage")
      FileUtils.mkdir_p([ext_build, ext_triage])

      ir_path = File.join(ext_build, "topology.ir.json")
      ir_doc = {
        "schema_version" => 2,
        "name" => "explain-ext-test",
        "workspace" => { "dir" => ext_ws, "build_dir" => ext_build },
        "sources" => {
          "prism_a" => { "kind" => "prism", "repo" => "https://example.invalid/prism.git", "ref" => "main" }
        },
        "fuzzers" => { "fuzz" => { "shape" => "prism_parse", "source" => "prism_a" } },
        "sync_groups" => { "afl" => { "dir" => "afl", "primary" => true } },
        "workers" => [
          { "id" => "main", "kind" => "afl", "fuzzer" => "fuzz", "sync_group" => "afl", "afl_role" => "main" }
        ]
      }
      File.write(ir_path, JSON.pretty_generate(ir_doc))

      orig_run = FuzzExplain.method(:run_with_timeout)
      captured_cmds = []
      test_self = self

      fake_run = lambda do |cmd, **kwargs|
        captured_cmds << cmd
        if cmd[1] == "./bin/topology.rb" && cmd[2] == "build-explain"
          test_self.write_executable(File.join(ext_build, "fuzz.explain"), "#!/bin/sh\nexit 0\n")
          { stdout: "", stderr: "", exitstatus: 0, timed_out: false, termsig: nil }
        elsif cmd.first == "docker"
          {
            stdout: JSON.generate("results" => { "0" => { "ok" => true, "stdout" => "ok" } }),
            stderr: "",
            exitstatus: 0,
            timed_out: false,
            termsig: nil
          }
        else
          orig_run.call(cmd, **kwargs)
        end
      end

      with_env(CLEAN_EXPLAIN_ENV) do
        stub_singleton_method(FuzzExplain, :run_with_timeout, fake_run) do
          stub_singleton_method(FuzzExplain, :running_in_container?, -> { false }) do
            stub_singleton_method(FuzzExplain, :ensure_docker_image!, ->(*_args, **_kwargs) { true }) do
              opts = FuzzExplain.default_options.merge(
                triage_dir: ext_triage,
                explain_bin: File.join(ext_build, "fuzz.explain"),
                explain_b_bin: File.join(ext_build, "fuzz.explain.b"),
                arch: "arm32"
              )

              built_bin = FuzzExplain.ensure_c_explain_bin(opts, target: :a)
              assert_equal File.join(ext_build, "fuzz.explain"), built_bin
              topo_cmd = captured_cmds.find { |c| c[1] == "./bin/topology.rb" }
              refute_nil topo_cmd
              assert_includes topo_cmd, "--topology"
              assert_equal ir_path, topo_cmd[topo_cmd.index("--topology") + 1]

              entry = {
                label: "b1",
                raw_input: true,
                raw_bytes: "\x00\x00\x03\x011+1".b,
                body: "1+1".b,
                verify_profile: "arm32_oracle",
                headline: ""
              }
              cross_res = FuzzExplain.run_cross_explanations([entry], opts)
              assert cross_res.dig(0, "ok"), "expected docker cross result: #{cross_res.inspect}"
              dcmd = captured_cmds.find { |c| c.first == "docker" }
              refute_nil dcmd
              assert_includes dcmd, "#{ext_ws}:/external/ws_dir"
              t_idx = dcmd.index("--triage-dir")
              refute_nil t_idx
              assert_equal "/external/ws_dir/report/triage", dcmd[t_idx + 1],
                           "expected mapped --triage-dir /external/ws_dir/report/triage, got #{dcmd.inspect}"

              captured_cmds.clear
              adhoc_triage = File.join(workdir, "adhoc_ext_triage")
              FileUtils.mkdir_p(adhoc_triage)
              FuzzExplain.run_cross_explanations([entry], opts.merge(triage_dir: adhoc_triage))
              dcmd2 = captured_cmds.find { |c| c.first == "docker" }
              refute_nil dcmd2
              assert_includes dcmd2, "#{adhoc_triage}:/external/explain_triage:ro"
              assert_equal "/external/explain_triage", dcmd2[dcmd2.index("--triage-dir") + 1]
            end
          end
        end
      end
    end
  end

  def test_explain_cross_arch_arm32_qemu_dual_ast
    if find_executable("arm-linux-gnueabihf-gcc").nil? || find_executable("qemu-arm").nil?
      skip "arm-linux-gnueabihf-gcc and qemu-arm are required for cross-arch arm32 explain"
    end

    with_tmpdir("triage-explain-arm32-") do |workdir|
      explain_bin = ensure_explain_suite_bin(workdir)
      arm32_explain_bin = ensure_arm32_explain_bin(workdir)

      cross_suite = File.join(workdir, "cross_arm32")
      FileUtils.mkdir_p(File.join(cross_suite, "ABRT/c867e29c8d2abea1"))
      File.binwrite(File.join(cross_suite, "ABRT/c867e29c8d2abea1/input.min"), "\x00\x00\x03\x01_END_^   ".b)

      b = {
        "bucket_id" => "ABRT/c867e29c8d2abea1",
        "signature" => "c867e29c8d2abea1",
        "reason" => "ABRT",
        "occurrences" => 10,
        "min_size_bytes" => 13,
        "header_hex" => "00000301",
        "verify_profile" => "arm32_oracle",
        "headline" => "INVARIANT[oracle_arm32]: kind=ast_size_mismatch stream=0 [detail: arm32_len=81 oracle64_len=315 first_diff=30 byte32=0x00 byte64=0x02]"
      }
      File.write(File.join(cross_suite, "clusters.json"), JSON.pretty_generate(
        "schema_version" => 1,
        "clusters" => [{
          "cluster_id" => "cluster-01",
          "group" => "prism_flaw",
          "bucket_count" => 1,
          "occurrences" => 10,
          "reasons" => { "ABRT" => 1 },
          "representative" => b,
          "buckets" => [b]
        }]
      ))

      arm32_json, = assert_ruby_cmd(
        repo_path("triage/explain.rb"),
        "--triage-dir", cross_suite, "cluster-01", "--json",
        env: CLEAN_EXPLAIN_ENV.merge(
          "EXPLAIN_BIN" => explain_bin,
          "EXPLAIN_ARM32_BIN" => arm32_explain_bin
        )
      )
      no_cross_json, = assert_ruby_cmd(
        repo_path("triage/explain.rb"),
        "--triage-dir", cross_suite, "cluster-01", "--no-cross-arch", "--json",
        env: CLEAN_EXPLAIN_ENV.merge("EXPLAIN_BIN" => explain_bin)
      )

      aj = JSON.parse(arm32_json).dig("results", 0)
      nc = JSON.parse(no_cross_json).dig("results", 0)
      ce = aj.dig("c_explain", "stdout").to_s
      xe = aj["cross_explain"]

      assert_includes ce, "serialize:   315 bytes"
      assert_includes ce, "errors=2"
      refute_nil xe, "expected arm32 cross_explain on cluster-01: #{aj.inspect}"
      assert_equal "arm32", xe["arch"]
      assert xe["ok"], "expected arm32 cross_explain ok: #{xe.inspect}"
      assert_includes xe["stdout"].to_s, "name: :_END_^"
      assert_includes xe["stdout"].to_s, "serialize:   81 bytes"
      assert_includes xe["stdout"].to_s, "errors=0"
      refute nc.key?("cross_explain"), "expected --no-cross-arch to omit cross_explain: #{nc.inspect}"
    end
  end

  def test_triage_finalize_metadata_digest_enrichment_and_inspect_samples
    with_tmpdir("triage-explain-digest-") do |workdir|
      explain_bin = ensure_explain_suite_bin(workdir)
      tdir = File.join(workdir, "digest_triage")
      FileUtils.mkdir_p([
        File.join(tdir, "ABRT/1111aaaa2222bbbb"),
        File.join(tdir, "ABRT/3333cccc4444dddd"),
        File.join(tdir, "ABRT/5555eeee6666ffff")
      ])
      File.binwrite(File.join(tdir, "ABRT/1111aaaa2222bbbb/input.min"), "\x00\x00\x03\x01<<C<\n\#{y=>{ ".b)
      File.binwrite(File.join(tdir, "ABRT/3333cccc4444dddd/input.min"), "\x00\x00\x03\x01<<C<\n\#{z=>{ ".b)
      File.binwrite(File.join(tdir, "ABRT/5555eeee6666ffff/input.min"), "\x00\x00\x03\x01super (){}\n".b)

      metas = [
        {
          "schema_version" => 1,
          "bucket_id" => "ABRT/1111aaaa2222bbbb",
          "reason" => "ABRT",
          "signature" => "1111aaaa2222bbbb",
          "reproducible" => true,
          "reproduced_by" => "fuzz",
          "verify_profile" => "asan_ubsan",
          "occurrences" => { "count" => 8, "first_elapsed_ms" => 1000 },
          "input" => { "min_size_bytes" => 16, "header_hex" => "00000301" },
          "options" => {
            "ruby_version" => "4.1",
            "start_line" => 1,
            "stream_mode" => false,
            "stack_budget" => "SIZE_MAX",
            "scopes_count" => 0
          },
          "symptom" => {
            "headline" => "INVARIANT[node_location]: type=PM_EMBEDDED_STATEMENTS_NODE kind=length_underflow",
            "invariant" => {
              "namespace" => "node_location",
              "fields" => { "type" => "PM_EMBEDDED_STATEMENTS_NODE", "kind" => "length_underflow" }
            }
          },
          "frames" => [
            { "scope" => "harness", "func" => "verify_node_locations", "file" => "harnesses/prism/harness.c", "line" => 10 },
            { "scope" => "prism", "func" => "parse_expression", "file" => "src/prism.c", "line" => 1234 },
            { "scope" => "prism", "func" => "pm_parse", "file" => "src/prism.c", "line" => 24000 }
          ],
          "coverage" => { "available" => false }
        },
        {
          "schema_version" => 1,
          "bucket_id" => "ABRT/3333cccc4444dddd",
          "reason" => "ABRT",
          "signature" => "3333cccc4444dddd",
          "reproducible" => true,
          "reproduced_by" => "fuzz",
          "verify_profile" => "asan_ubsan",
          "occurrences" => { "count" => 2, "first_elapsed_ms" => 2000 },
          "input" => { "min_size_bytes" => 16, "header_hex" => "00000301" },
          "options" => {
            "ruby_version" => "4.1",
            "start_line" => 1,
            "stream_mode" => false,
            "stack_budget" => "SIZE_MAX",
            "scopes_count" => 0
          },
          "symptom" => {
            "headline" => "INVARIANT[node_relation]: kind=closing_before_opening",
            "invariant" => { "namespace" => "node_relation", "fields" => { "kind" => "closing_before_opening" } }
          },
          "frames" => [
            { "scope" => "prism", "func" => "parse_expression", "file" => "src/prism.c", "line" => 1234 }
          ],
          "coverage" => { "available" => false }
        },
        {
          "schema_version" => 1,
          "bucket_id" => "ABRT/5555eeee6666ffff",
          "reason" => "ABRT",
          "signature" => "5555eeee6666ffff",
          "reproducible" => true,
          "reproduced_by" => "fuzz.diff",
          "verify_profile" => "diff_parse_y",
          "occurrences" => { "count" => 3, "first_elapsed_ms" => 3000 },
          "input" => { "min_size_bytes" => 15, "header_hex" => "00000301" },
          "options" => {
            "ruby_version" => "4.1",
            "start_line" => 1,
            "stream_mode" => false,
            "stack_budget" => "SIZE_MAX",
            "scopes_count" => 0
          },
          "symptom" => {
            "headline" => "INVARIANT[diff_parse_y]: kind=syntax_mismatch sub=prism_ok_cruby_err",
            "invariant" => {
              "namespace" => "diff_parse_y",
              "fields" => { "kind" => "syntax_mismatch", "sub" => "prism_ok_cruby_err" }
            }
          },
          "frames" => [],
          "coverage" => { "available" => false }
        }
      ]
      metas.each do |m|
        File.write(File.join(tdir, m["bucket_id"], "meta.json"), JSON.pretty_generate(m))
      end

      with_env(CLEAN_EXPLAIN_ENV.merge("TRIAGE_EXPLAIN_BIN" => explain_bin)) do
        in_root_dir do
          FuzzTriage.finalize_triage_metadata(tdir, coverage_bin: "")
        end
      end

      b1 = JSON.parse(File.read(File.join(tdir, "ABRT/1111aaaa2222bbbb/meta.json")))
      kinds = Array(b1.dig("digest", "anomalies")).map { |a| a["kind"] }
      assert_operator b1.dig("digest", "anomaly_count").to_i, :>=, 2,
                      "expected >=2 triage digest anomalies on b1, got #{b1['digest'].inspect}"
      assert_includes kinds, "length_underflow"
      assert_includes kinds, "closing_before_opening"

      b3 = JSON.parse(File.read(File.join(tdir, "ABRT/5555eeee6666ffff/meta.json")))
      if ruby_supports_parse_y?
        assert_equal "prism_ok_parse_y_err", b3.dig("digest", "syntax_status")
        assert_equal "prism_ok_parse_y_compile_err", b3.dig("digest", "iseq_status")
      end

      clusters = JSON.parse(File.read(File.join(tdir, "clusters.json")))
      flaw_cluster = clusters["clusters"].find { |c| c["group"] == "prism_flaw" }
      refute_nil flaw_cluster, "expected merged prism_flaw cluster: #{clusters.inspect}"
      assert_equal 2, flaw_cluster["bucket_count"]
      assert flaw_cluster["variants"], "expected variants on merged prism_flaw cluster: #{flaw_cluster.inspect}"
      assert_equal 2, flaw_cluster.dig("digest_summary", "anomaly_kinds", "length_underflow")

      digest_inspect, = assert_ruby_cmd(
        repo_path("triage/inspect.rb"),
        "--triage-dir", tdir, "--samples", "2",
        env: CLEAN_INSPECT_ENV
      )
      assert_includes digest_inspect, "variants:"
      assert_includes digest_inspect, "sample:   ABRT/3333cccc4444dddd"
    end
  end

  private

  def in_root_dir
    prev = Dir.pwd
    Dir.chdir(root_dir)
    yield
  ensure
    Dir.chdir(prev) if prev && Dir.exist?(prev)
  end

  def ruby_supports_parse_y?
    _, _, st = run_cmd(RbConfig.ruby, "--parser=parse.y", "-e", "")
    st.success?
  end

  def require_prism_a!
    pa = prism_a_dir
    skip "missing Prism A target (run 'make targets-sync' first)" unless pa && File.directory?(File.join(pa, "src"))
    pa
  end

  def resolve_explain_gen_dir(prism_dir, workdir)
    cand = prism_a_gen_dir
    if cand
      locs = File.join(cand, "node_locations.inc")
      walk = File.join(cand, "node_serialize_walk.inc")
      cfg = File.join(prism_dir, "config.yml")
      gen_loc_rb = repo_path("harnesses/prism/gen_node_locations.rb")
      gen_walk_rb = repo_path("harnesses/prism/gen_serialize_walk.rb")
      if File.file?(locs) && File.file?(walk) &&
         (!File.file?(cfg) || (File.mtime(locs) >= File.mtime(cfg) && File.mtime(walk) >= File.mtime(cfg))) &&
         File.mtime(locs) >= File.mtime(gen_loc_rb) &&
         File.mtime(walk) >= File.mtime(gen_walk_rb)
        return cand
      end
    end

    File.join(workdir, "gen")
  end

  def ensure_explain_suite_bin(workdir)
    env_bin = ENV["EXPLAIN_SUITE_BIN"].to_s.strip
    return env_bin if !env_bin.empty? && File.executable?(env_bin)

    pa = require_prism_a!
    out_bin = File.join(workdir, "fuzz.explain")
    gen_dir = resolve_explain_gen_dir(pa, workdir)
    build_dir = File.join(workdir, "explain_build")
    assert_ruby_cmd(
      repo_path("bin/topology.rb"),
      "build-explain",
      "--prism-dir", pa,
      "--gen-dir", gen_dir,
      "--build-dir", build_dir,
      "--output", out_bin,
      env: CLEAN_EXPLAIN_ENV
    )
    assert File.executable?(out_bin), "expected executable fuzz.explain at #{out_bin}"
    out_bin
  end

  def ensure_arm32_explain_bin(workdir)
    env_bin = ENV["EXPLAIN_ARM32_BIN"].to_s.strip
    return env_bin if !env_bin.empty? && File.executable?(env_bin)

    pa = require_prism_a!
    out_bin = File.join(workdir, "fuzz.explain.arm32")
    gen_dir = resolve_explain_gen_dir(pa, workdir)
    build_dir = File.join(workdir, "explain_build")
    assert_ruby_cmd(
      repo_path("bin/topology.rb"),
      "build-explain",
      "--arch", "arm32",
      "--prism-dir", pa,
      "--gen-dir", gen_dir,
      "--build-dir", build_dir,
      "--output", out_bin,
      env: CLEAN_EXPLAIN_ENV
    )
    assert File.executable?(out_bin), "expected executable fuzz.explain.arm32 at #{out_bin}"
    out_bin
  end

  def setup_explain_suite_triage(explain_suite)
    triage_dir = File.join(explain_suite, "triage")
    FileUtils.mkdir_p([
      File.join(triage_dir, "ABRT/1234567890abcdef"),
      File.join(triage_dir, "ABRT/fedcba0987654321")
    ])
    File.binwrite(File.join(triage_dir, "ABRT/1234567890abcdef/input.min"), "\x00\x00\x03\x01super (){}\n".b)
    File.binwrite(File.join(triage_dir, "ABRT/fedcba0987654321/input.min"), "\x00\x00\x03\x01x\"\#{}\":<2\n".b)

    b1 = {
      "bucket_id" => "ABRT/1234567890abcdef",
      "signature" => "1234567890abcdef",
      "reason" => "ABRT",
      "occurrences" => 5,
      "min_size_bytes" => 14,
      "header_hex" => "00000301",
      "verify_profile" => "diff_parse_y",
      "headline" => "INVARIANT[diff_parse_y]: kind=syntax_mismatch sub=prism_ok_cruby_err"
    }
    b2 = {
      "bucket_id" => "ABRT/fedcba0987654321",
      "signature" => "fedcba0987654321",
      "reason" => "ABRT",
      "occurrences" => 2,
      "min_size_bytes" => 13,
      "header_hex" => "00000301",
      "verify_profile" => "diff_parse_y",
      "headline" => "INVARIANT[diff_parse_y]: kind=syntax_mismatch sub=prism_ok_cruby_err"
    }
    clusters_doc = {
      "schema_version" => 1,
      "clusters" => [
        {
          "cluster_id" => "cluster-01",
          "group" => "diff_parse_y",
          "bucket_count" => 2,
          "occurrences" => 7,
          "reasons" => { "ABRT" => 2 },
          "representative" => b1,
          "buckets" => [b1, b2]
        }
      ]
    }
    File.write(File.join(triage_dir, "clusters.json"), JSON.pretty_generate(clusters_doc))
    triage_dir
  end
end
