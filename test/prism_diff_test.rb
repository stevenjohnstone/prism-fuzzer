# frozen_string_literal: true

require_relative "lib/autorun"

require "digest"
require "fileutils"
require "json"
require "rubygems/package"
require "zlib"

require_relative "../runtime/topology"
require_relative "../triage/triage"

# End-to-end tests for Prism-vs-Prism differential fuzzing (fuzz.prism_diff),
# verify_bucket.sh --profile diff_prism, triage metadata/verify.sh synthesis,
# AFL++/IJON/Topology builds, side-by-side explain.rb, and bin/publish.rb.
class PrismDiffTest < Minitest::Test
  DIVERGE_B_ANCHOR = "pm_node_t *\npm_parse(pm_parser_t *parser) {"
  DIVERGE_B_RETURN = "    return node;\n}"
  DIVERGE_B_INJECT =
    "    if (parser->end - parser->start >= 9 && memcmp(parser->start, \"DIVERGE_B\", 9) == 0) {\n" \
    "        pm_parser_err(parser, 0, 9, PM_ERR_EXPECT_EXPRESSION_AFTER_OPERATOR);\n" \
    "    }\n" \
    "    if (node != NULL && parser->end - parser->start >= 9 && memcmp(parser->start, \"SER_DIV_B\", 9) == 0) {\n" \
    "        node->flags ^= 1;\n" \
    "    }\n"

  def test_build_prism_diff_verify_and_verify_bucket_cache_invalidation
    prism_a = require_prism_a!
    skip "objcopy/llvm-objcopy not found on host" unless objcopy_available?

    with_tmpdir("prism-diff-verify-") do |workdir|
      prism_b = prepare_divergent_prism_b(prism_a, workdir)
      verify_bin = File.join(workdir, "verify_prism_diff")

      assert_cmd(
        repo_path("harnesses/prism/build_prism_diff.sh"),
        "--mode", "verify",
        "--prism-a", prism_a,
        "--prism-b", prism_b,
        "--fuzz-root", root_dir,
        "--work-dir", File.join(workdir, "vbuild"),
        "--cc", default_cc,
        "--cflag", "-fsanitize=address,undefined",
        "--cflag", "-fno-sanitize-recover=all",
        "--output", verify_bin
      )
      assert_path_exists verify_bin
      assert File.executable?(verify_bin), "expected executable verify binary at #{verify_bin}"

      bucket_dir = File.join(workdir, "triage/ABRT/diff_prism_bug")
      FileUtils.mkdir_p(bucket_dir)
      File.binwrite(File.join(bucket_dir, "input.min"), seed_bytes("DIVERGE_B + 1\n"))
      create_tar_gz(File.join(bucket_dir, "inputs.tar.gz"), "pass_case" => seed_bytes("1 + 2\n"))

      vcache = File.join(workdir, "vcache")
      verify_env = { "PRISM_B_DIR" => prism_b, "VERIFY_BUILD_DIR" => vcache }
      verify_args = [
        repo_path("triage/verify_bucket.sh"),
        "--repo-root", prism_a,
        "--fuzz-root", root_dir,
        "--bucket-dir", bucket_dir,
        "--profile", "diff_prism",
        "--json"
      ]

      out, err, st = run_cmd(*verify_args, env: verify_env)
      assert_equal 1, st.exitstatus, "expected verify_bucket.sh FAIL exit 1:\nstdout=#{out}\nstderr=#{err}"
      rep = JSON.parse(out)
      assert_equal 2, rep["total"], "unexpected report: #{rep.inspect}"
      assert_equal 1, rep["passed"], "unexpected report: #{rep.inspect}"
      assert_equal 1, rep["failed"], "unexpected report: #{rep.inspect}"
      assert_includes rep.dig("failures", 0, "headline").to_s, "INVARIANT[diff_prism]"

      ser_seed = File.join(workdir, "ser_div.bin")
      File.binwrite(ser_seed, seed_bytes("SER_DIV_B + 1\n"))
      ser_out, ser_err, ser_st = run_cmd(verify_bin, "--json", ser_seed)
      assert_equal 1, ser_st.exitstatus, "expected serialize_mismatch FAIL:\nstdout=#{ser_out}\nstderr=#{ser_err}"
      ser_hl = JSON.parse(ser_out).dig("failures", 0, "headline").to_s
      assert_match(/\AINVARIANT\[diff_prism\]: kind=serialize_mismatch sub=(?:bytes|len) section=ast type=PM_PROGRAM_NODE \[detail:/, ser_hl)

      if File.file?(File.join(prism_b, "templates/template.rb")) && File.file?(File.join(prism_b, "config.yml"))
        stamp = File.join(vcache, "prism-b/.templates.sha256")
        assert_path_exists stamp
        refute_empty File.read(stamp).strip
      end

      # Reverting prism_b/src/prism.c must invalidate verify_runner.diff_prism without --rebuild.
      assert_cmd("git", "-C", prism_b, "checkout", "--", "src/prism.c")
      out_fixed, err_fixed, st_fixed = run_cmd(*verify_args, env: verify_env)
      assert st_fixed.success?,
             "expected cached verify_bucket.sh to rebuild after PRISM_B edit and PASS (exit=#{st_fixed.exitstatus}):\n" \
             "stdout=#{out_fixed}\nstderr=#{err_fixed}"
      rep_fixed = JSON.parse(out_fixed)
      assert_equal 2, rep_fixed["total"], "unexpected report after fix: #{rep_fixed.inspect}"
      assert_equal 2, rep_fixed["passed"], "unexpected report after fix: #{rep_fixed.inspect}"
      assert_equal 0, rep_fixed["failed"], "unexpected report after fix: #{rep_fixed.inspect}"
    end
  end

  def test_triage_diff_prism_profile_verify_sh_and_metadata
    with_tmpdir("prism-diff-triage-") do |workdir|
      triage_dir = File.join(workdir, "triage")
      bdir = File.join(triage_dir, "ABRT/diff_prism_bug")
      FileUtils.mkdir_p(bdir)
      inp = File.join(bdir, "input.min")
      File.binwrite(inp, seed_bytes("DIVERGE_B + 1\n"))

      cout = "INVARIANT[diff_prism]: kind=error_mismatch sub=count a=0 b=1 a_err=none b_err=expect_expression_after_operator\n"
      exe = "./build/fuzz.prism_diff"

      assert FuzzTriage.prism_diff_bucket?(executable: exe, crash_output: cout, triage_dir: triage_dir)
      refute FuzzTriage.diff_bucket?(executable: exe, crash_output: cout, triage_dir: triage_dir)
      assert_equal(
        "diff_prism",
        FuzzTriage.bucket_verify_profile(reason: "ABRT", executable: exe, crash_output: cout, triage_dir: triage_dir)
      )

      vsh = File.join(bdir, "verify.sh")
      File.write(vsh, FuzzTriage.verify_script(reason: "ABRT", executable: exe, crash_output: cout, triage_dir: triage_dir))
      File.chmod(0o755, vsh)
      assert_includes File.read(vsh), '--profile "diff_prism"'

      meta = FuzzTriage.build_bucket_metadata(
        bucket_id: "ABRT/diff_prism_bug",
        reason: "ABRT",
        signature: "diff_prism_bug",
        reproducible: true,
        timed_out: false,
        executable: exe,
        crash_output: cout,
        minimized_input: inp,
        raw_size_bytes: File.size(inp),
        raw_sha256: Digest::SHA256.file(inp).hexdigest,
        minimized_matches_signature: true,
        occurrences: { "count" => 1 },
        triage_dir: triage_dir
      )
      assert_equal "diff_prism", meta["verify_profile"], "unexpected verify_profile in metadata: #{meta.inspect}"
    end
  end

  def test_afl_fuzz_prism_diff_build_ijon_and_topology_build
    prism_a = require_prism_a!
    skip "AFL++ PCGUARD not available in environment" unless afl_pcguard_ready?
    skip "objcopy/llvm-objcopy not found on host" unless objcopy_available?

    with_tmpdir("prism-diff-afl-") do |workdir|
      prism_b = prepare_divergent_prism_b(prism_a, workdir)
      afl_dir = afl_build_dir

      fuzz_pdiff = File.join(workdir, "fuzz.prism_diff")
      assert_cmd(
        repo_path("harnesses/prism/build_prism_diff.sh"),
        "--mode", "fuzz",
        "--prism-a", prism_a,
        "--prism-b", prism_b,
        "--fuzz-root", root_dir,
        "--work-dir", File.join(workdir, "fbuild"),
        "--afl-path", afl_dir,
        "--output", fuzz_pdiff
      )

      ver, = assert_cmd(fuzz_pdiff, "--version")
      assert_match(/^prism_a=/, ver)
      assert_match(/^prism_b=/, ver)
      assert_match(/^prism_b_git_dirty=1$/, ver)

      ids_path = "#{fuzz_pdiff}.ids"
      assert_path_exists ids_path
      ids_txt = File.read(ids_path)
      refute_empty ids_txt
      assert_match(/^Domain=prism_a /, ids_txt)
      assert_match(/^Domain=prism_b /, ids_txt)
      assert_match(/^Domain=harness /, ids_txt)

      fuzz_pdiff_ijon = File.join(workdir, "fuzz.prism_diff.ijon")
      assert_cmd(
        repo_path("harnesses/prism/build_prism_diff.sh"),
        "--mode", "fuzz",
        "--prism-a", prism_a,
        "--prism-b", prism_b,
        "--fuzz-root", root_dir,
        "--work-dir", File.join(workdir, "fbuild_ijon"),
        "--afl-path", afl_dir,
        "--cflag", "-DPRISM_FUZZ_IJON",
        "--output", fuzz_pdiff_ijon,
        env: { "AFL_LLVM_IJON" => "1" }
      )

      probe_bin = File.join(workdir, "ijon_probe.bin")
      File.binwrite(probe_bin, seed_bytes("1 + 1\n"))
      showmap_out, showmap_err, = run_cmd(
        "afl-showmap", "-q", "-o", File.join(workdir, "pdiff_ijon.map"), "--", fuzz_pdiff_ijon, probe_bin,
        env: { "AFL_DEBUG" => "1" }
      )
      assert_includes "#{showmap_out}#{showmap_err}", "Using IJON feature"

      # Verify Topology.build_prism_diff_prism! builds with real ASan/UBSan + defines overrides.
      topo_ws = File.join(workdir, "topo_pdiff_ws")
      topo_bdir = File.join(topo_ws, "build")
      FileUtils.mkdir_p([File.join(topo_bdir, "targets/gen/prism_a"), File.join(topo_bdir, "targets/gen/prism_b")])

      afl_stamp_src = repo_path("build/.fuzz.afl.stamp")
      local_afl_stamp = File.join(topo_bdir, ".fuzz.afl.stamp")
      if File.file?(afl_stamp_src)
        FileUtils.cp(afl_stamp_src, local_afl_stamp)
      else
        FileUtils.touch(local_afl_stamp)
      end
      FileUtils.ln_s(afl_dir, File.join(topo_bdir, "afl"))

      camp_path = File.join(workdir, "topo_pdiff_campaign.rb")
      File.write(camp_path, <<~RUBY)
        PrismFuzzer.campaign "topo-pdiff-san-test" do
          workspace #{topo_ws.inspect}
          prism :prism_a, repo: "https://example.invalid/prism.git", dir: #{prism_a.inspect}, patches: "none", templates: "never"
          prism :prism_b, repo: "https://example.invalid/prism.git", dir: #{prism_b.inspect}, patches: "none", templates: "never"
          fuzzer "fuzz.pdiff_san",
                 shape: :prism_diff_prism,
                 prism_a: :prism_a,
                 prism_b: :prism_b,
                 sanitizers: %i[asan ubsan],
                 afl: :pcguard,
                 defines: { PRISM_DEPTH_MAXIMUM: 16 }
          sync_group :afl, dir: "afl", primary: true
          worker :w1, fuzzer: "fuzz.pdiff_san", sync_group: :afl, afl_role: :main
        end
      RUBY

      ir, = PrismFuzzer::Topology.load_ir(camp_path, fuzz_root: root_dir)
      plan = PrismFuzzer::Topology.compile_plan(ir, fuzz_root: root_dir, build_dir: topo_bdir)
      plan["sources"]["prism_a"]["path"] = prism_a
      plan["sources"]["prism_b"]["path"] = prism_b
      plan["sources"]["prism_a"]["gen_dir"] = File.join(topo_bdir, "targets/gen/prism_a")
      plan["sources"]["prism_b"]["gen_dir"] = File.join(topo_bdir, "targets/gen/prism_b")
      fspec = plan["fuzzers"].fetch("fuzz.pdiff_san")

      PrismFuzzer::Topology.build_prism_diff_prism!(
        "fuzz.pdiff_san", fspec,
        plan: plan, fuzz_root: root_dir, build_dir: topo_bdir,
        afl_path: afl_dir, afl_stamp: local_afl_stamp
      )

      bin = File.join(topo_bdir, "fuzz.pdiff_san")
      assert_path_exists bin
      assert File.executable?(bin), "expected executable fuzz.pdiff_san at #{bin}"

      syms, = assert_cmd("nm", "-n", bin)
      assert_includes syms, "__asan_init"
      assert_includes syms, "__ubsan_handle_"
    end
  end

  def test_cluster_inspect_explain_side_by_side_and_publish
    prism_a = require_prism_a!

    with_tmpdir("prism-diff-publish-") do |workdir|
      prism_b = prepare_divergent_prism_b(prism_a, workdir)

      env_explain_a = ENV["PRISM_DIFF_EXPLAIN_A_BIN"].to_s.strip
      explain_a = if !env_explain_a.empty? && File.executable?(env_explain_a)
                    env_explain_a
                  else
                    compile_explain_bin(prism_a, gen_dir: File.join(workdir, "gen_a"), output: File.join(workdir, "fuzz.explain.a"))
                  end
      explain_b = compile_explain_bin(prism_b, gen_dir: File.join(workdir, "gen_b"), output: File.join(workdir, "fuzz.explain.b"))

      triage_dir = File.join(workdir, "triage")
      bucket_dir = File.join(triage_dir, "ABRT/diff_prism_bug")
      FileUtils.mkdir_p(bucket_dir)
      File.binwrite(File.join(bucket_dir, "input.min"), seed_bytes("DIVERGE_B + 1\n"))

      meta = {
        "schema_version" => 2,
        "buckets" => [
          {
            "bucket_id" => "ABRT/diff_prism_bug",
            "reason" => "ABRT",
            "signature" => "diff_prism_bug",
            "reproducible" => true,
            "timed_out" => false,
            "reproduced_by" => "fuzz.prism_diff",
            "verify_profile" => "diff_prism",
            "occurrences" => {
              "count" => 4,
              "first_seen" => "2026-11-21T10:00:00Z",
              "last_seen" => "2026-11-21T10:05:00Z",
              "by_worker" => { "prism_diff" => 4 }
            },
            "input" => {
              "min_path" => "input.min",
              "min_size_bytes" => 18,
              "source_preview" => "DIVERGE_B + 1"
            },
            "options" => { "header_hex" => "00000301", "ruby_version" => "4.1" },
            "symptom" => {
              "headline" => "INVARIANT[diff_prism]: kind=error_mismatch sub=count a=0 b=1",
              "invariant" => {
                "namespace" => "diff_prism",
                "fields" => { "kind" => "error_mismatch", "sub" => "count" }
              }
            },
            "frames" => [
              {
                "depth" => 0,
                "scope" => "harness",
                "func" => "prism_diff_fail",
                "file" => "harnesses/prism/prism_diff.c",
                "line" => 25
              }
            ]
          }
        ]
      }
      File.write(File.join(triage_dir, "metadata.json"), JSON.pretty_generate(meta))

      clusters_path = File.join(triage_dir, "clusters.json")
      assert_ruby_cmd(
        repo_path("triage/cluster.rb"),
        "--metadata", File.join(triage_dir, "metadata.json"),
        "--output", clusters_path,
        "--quiet"
      )
      assert_path_exists clusters_path

      insp_out, = assert_ruby_cmd(repo_path("triage/inspect.rb"), "--triage-dir", triage_dir, "--group", "diff_prism")
      assert_includes insp_out, "cluster-01 (diff_prism "

      exp_txt, = assert_ruby_cmd(
        repo_path("triage/explain.rb"),
        "--triage-dir", triage_dir,
        "cluster-01",
        "--diff-prism",
        "--no-compare",
        env: { "EXPLAIN_BIN" => explain_a, "EXPLAIN_B_BIN" => explain_b }
      )
      assert_includes exp_txt, "--- prism_a (build/fuzz.explain) ---"
      assert_includes exp_txt, "--- prism_b (build/fuzz.explain.b) ---"
      assert_includes exp_txt, "--- diff (prism_a vs prism_b) ---"
      assert_match(/^-counts:\s+errors=0\b/, exp_txt)
      assert_match(/^\+counts:\s+errors=1\b/, exp_txt)
      assert_match(/^\+errors:/, exp_txt)
      assert_includes exp_txt, "expect_expression_after_operator"

      report_dir = File.join(workdir, "report")
      cov_dir = File.join(workdir, "cov")
      reports_dir = File.join(workdir, "reports")
      FileUtils.mkdir_p([report_dir, cov_dir])
      File.write(File.join(report_dir, "index.html"), "<html>report</html>\n")
      File.write(
        File.join(cov_dir, "coverage.json"),
        '{"data":[{"totals":{"regions":{"covered":800,"count":1000,"percent":80.0},"lines":{"covered":750,"count":1000,"percent":75.0}}}]}'
      )

      assert_ruby_cmd(
        repo_path("bin/publish.rb"),
        "--run-id", "test-run-01",
        "--title", "Prism A vs B test",
        "--report-dir", report_dir,
        "--triage-dir", triage_dir,
        "--coverage-dir", cov_dir,
        "--out-dir", reports_dir
      )

      index_html = File.join(reports_dir, "index.html")
      assert_path_exists index_html
      assert_path_exists File.join(reports_dir, "runs/test-run-01/manifest.json")
      assert_path_exists File.join(reports_dir, "runs/test-run-01/report/index.html")
      assert_path_exists File.join(reports_dir, "runs/test-run-01/report/triage/clusters.json")
      assert_path_exists File.join(reports_dir, "runs/test-run-01/report/coverage/coverage.json")

      index_body = File.read(index_html)
      assert_includes index_body, "test-run-01"
      assert_includes index_body, "report/index.html"
      assert_includes index_body, "80.0%"
    end
  end

  private

  def require_prism_a!
    pa = prism_a_dir
    skip "missing Prism A target (run 'make targets-sync' first)" unless pa && File.directory?(File.join(pa, "src"))
    pa
  end

  def default_cc
    cc = ENV["CC"].to_s.strip
    cc.empty? ? "clang" : cc
  end

  def objcopy_available?
    !find_executable("objcopy").nil? || !find_executable("llvm-objcopy").nil?
  end

  # Creates an isolated Prism B git repo from Prism A with a clean base commit
  # and an uncommitted DIVERGE_B diagnostic injection in src/prism.c so both
  # dirty git provenance and git checkout cache invalidation can be verified.
  def prepare_divergent_prism_b(prism_a, workdir)
    prism_b = File.join(workdir, "prism_b")
    FileUtils.mkdir_p(prism_b)
    Dir.children(prism_a).each do |entry|
      next if entry == ".git" || entry == ".fuzz-target-state.json"

      FileUtils.cp_r(File.join(prism_a, entry), File.join(prism_b, entry))
    end

    assert_cmd("git", "-C", prism_b, "init", "-q")
    assert_cmd("git", "-C", prism_b, "config", "user.email", "test@example.com")
    assert_cmd("git", "-C", prism_b, "config", "user.name", "Test")
    assert_cmd("git", "-C", prism_b, "config", "commit.gpgsign", "false")
    assert_cmd("git", "-C", prism_b, "config", "tag.gpgsign", "false")
    assert_cmd("git", "-C", prism_b, "add", "-A")
    assert_cmd("git", "-C", prism_b, "commit", "-qm", "base")

    prism_c_path = File.join(prism_b, "src/prism.c")
    src = File.read(prism_c_path)
    idx = src.index(DIVERGE_B_ANCHOR)
    assert idx, "could not find pm_parse definition in #{prism_c_path}"
    ridx = src.index(DIVERGE_B_RETURN, idx)
    assert ridx, "could not find return statement inside pm_parse in #{prism_c_path}"
    File.write(prism_c_path, src[0...ridx] + DIVERGE_B_INJECT + src[ridx..])

    prism_b
  end

  def create_tar_gz(archive_path, entries)
    Zlib::GzipWriter.open(archive_path) do |gz|
      Gem::Package::TarWriter.new(gz) do |tar|
        entries.each do |name, content|
          bytes = content.b
          tar.add_file_simple(name, 0o644, bytes.bytesize) { |io| io.write(bytes) }
        end
      end
    end
  end

  def compile_explain_bin(prism_root, gen_dir:, output:)
    FileUtils.mkdir_p(gen_dir)
    assert_ruby_cmd(
      repo_path("harnesses/prism/gen_node_locations.rb"),
      File.join(prism_root, "config.yml"),
      File.join(gen_dir, "node_locations.inc")
    )
    assert_ruby_cmd(
      repo_path("harnesses/prism/gen_api_compat.rb"),
      "--include-dir", File.join(prism_root, "include"),
      "--subloc-inc", File.join(gen_dir, "node_locations.inc"),
      "--output", File.join(gen_dir, "prism_fuzz_compat.h")
    )

    prism_srcs = Dir.glob(File.join(prism_root, "src/**/*.c")).sort
    explain_srcs = [repo_path("harnesses/prism/explain.c"), *Dir.glob(repo_path("harnesses/prism/explain/*.c")).sort]

    assert_cmd(
      default_cc,
      "-O1", "-std=c99",
      "-I#{File.join(prism_root, 'include')}",
      "-I#{gen_dir}",
      "-I#{repo_path('harnesses/prism')}",
      "-DPRISM_DEPTH_MAXIMUM=128",
      "-DPM_INTEGER_DIVIDE_THRESHOLD=8",
      *prism_srcs,
      *explain_srcs,
      "-lm",
      "-o", output
    )
    output
  end
end
