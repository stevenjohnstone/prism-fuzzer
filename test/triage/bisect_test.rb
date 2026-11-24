# frozen_string_literal: true

require_relative "../lib/autorun"

require "fileutils"
require "json"
require "open3"
require "rbconfig"
require "rubygems/package"
require "zlib"

# Isolated tests for harness compatibility macro builds, external Prism target
# template regeneration, 2026 C API shims, verify.rb bisect/invert/fail-fast/min-skip
# flags, git-bisect driver (triage/bisect.rb), and external Docker mount resolution.
class TriageBisectTest < Minitest::Test
  BASE_COMPAT_MACROS = %w[
    -DPRISM_FUZZ_NO_ATTACH_COMMENTS
    -DPRISM_FUZZ_NO_STACK_BUDGET
    -DPRISM_FUZZ_NO_ERRORS_FORMAT
    -DPRISM_FUZZ_NO_STREAM
    -DPRISM_FUZZ_NO_JSON
  ].freeze

  EXTENDED_COMPAT_MACROS = (
    BASE_COMPAT_MACROS + %w[
      -DPRISM_FUZZ_NO_SUB_LOCATIONS
      -DPRISM_FUZZ_NO_COMMAND_LINE
      -DPRISM_FUZZ_NO_MAIN_SCRIPT
      -DPRISM_FUZZ_NO_FREEZE
      -DPRISM_FUZZ_NO_PARTIAL_SCRIPT
      -DPRISM_FUZZ_NO_ENCODING_LOCKED
      -DPRISM_FUZZ_NO_VERSION_SET
      -DPRISM_FUZZ_NO_FROZEN_STRING_LITERAL
      -DPRISM_FUZZ_NO_SHEBANG_CALLBACK
      -DPRISM_FUZZ_NO_SCOPE_FORWARDING
      -DPRISM_FUZZ_NO_DIAGNOSTIC_TYPE
      -DPRISM_FUZZ_NO_VISIT_NODE
      -DPRISM_FUZZ_NO_NODE_RELATIONS
      -DPRISM_FUZZ_NO_PARSER_ERRORS_SIZE
    ]
  ).freeze

  FAKE_DOCKER_SCRIPT = <<~'RUBY'
    #!/usr/bin/env ruby
    # frozen_string_literal: true

    raise "unexpected docker subcommand" unless ARGV.shift == "run"

    mounts = {}
    until ARGV.empty?
      arg = ARGV.shift
      case arg
      when "--rm"
        next
      when "-e", "--tmpfs"
        ARGV.shift
      when "-v"
        spec = ARGV.shift
        host, guest = spec.split(":", 2)
        mounts[guest] = host
        File.open(ENV.fetch("FAKE_DOCKER_LOG"), "a") { |f| f.puts("#{host}=>#{guest}") }
      else
        break
      end
    end

    rewrite = lambda do |val|
      mounts.sort_by { |g, _| -g.length }.each do |g, h|
        return h if val == g
        return File.join(h, val.delete_prefix("#{g}/")) if val.start_with?("#{g}/")
      end
      val
    end

    cmd = ARGV.map { |a| rewrite.call(a) }
    Dir.chdir(mounts.fetch("/prism-fuzzer")) do
      exec(*cmd)
    end
  RUBY

  def test_parse_c_compiles_under_slow_and_fast_compatibility_macros
    prism_a = require_prism_a!

    with_tmpdir("triage-bisect-compat-") do |workdir|
      gen_dir = resolve_prism_gen_dir(prism_a, workdir)
      parse_c = repo_path("harnesses/prism/parse.c")
      inc_flags = ["-I#{File.join(prism_a, 'include')}", "-I#{gen_dir}"]

      [
        ["compat_slow", ["-DSLOW"], BASE_COMPAT_MACROS],
        ["compat_fast", [], BASE_COMPAT_MACROS],
        ["compat_all_slow", ["-DSLOW"], EXTENDED_COMPAT_MACROS],
        ["compat_all_fast", [], EXTENDED_COMPAT_MACROS]
      ].each do |label, mode_flags, compat_flags|
        obj = File.join(workdir, "parse_#{label}.o")
        assert_cmd(
          c_compiler, "-c", "-O1", "-std=c99",
          *inc_flags, *mode_flags, *compat_flags,
          parse_c, "-o", obj,
          msg: "expected parse.c to compile cleanly (#{label})"
        )
        assert_path_exists obj
        assert_operator File.size(obj), :>, 0
      end
    end
  end

  def test_external_prism_target_regenerates_missing_templates_without_touching_host
    prism_a = require_prism_a!
    host_node_c = File.join(prism_a, "src/node.c")
    host_ast_h = File.join(prism_a, "include/prism/ast.h")
    host_mtimes = [host_node_c, host_ast_h].each_with_object({}) do |path, h|
      h[path] = File.file?(path) ? File.stat(path).mtime : nil
    end

    with_tmpdir("triage-bisect-ext-target-") do |workdir|
      ext_target = File.join(workdir, "ext_prism_target")
      FileUtils.mkdir_p(ext_target)
      %w[config.yml templates include src].each do |entry|
        FileUtils.cp_r(File.join(prism_a, entry), File.join(ext_target, entry))
      end

      ext_node_c = File.join(ext_target, "src/node.c")
      ext_ast_h = File.join(ext_target, "include/prism/ast.h")
      FileUtils.rm_f([ext_node_c, ext_ast_h])
      refute_path_exists ext_node_c
      refute_path_exists ext_ast_h

      verify_build_dir = File.join(workdir, "verify_build")
      fuzz_build_dir = File.join(workdir, "fuzz_build")

      with_env(local_verify_env(verify_build_dir, fuzz_build_dir)) do
        out, = assert_cmd(
          repo_path("triage/verify_bucket.sh"),
          "--repo-root", ext_target,
          "--fuzz-root", root_dir,
          "--profile", "asan_ubsan",
          "--build-only",
          msg: "expected external Prism target build-only verification to succeed"
        )
        ext_runner = out.strip
        assert ext_runner.start_with?(verify_build_dir),
               "expected ext_runner (#{ext_runner}) to stay under #{verify_build_dir}"
        assert File.executable?(ext_runner), "expected external verify_runner to be executable at #{ext_runner}"
        assert_path_exists ext_node_c, "expected verify_bucket.sh to regenerate src/node.c under #{ext_target}"
        assert_path_exists ext_ast_h, "expected verify_bucket.sh to regenerate include/prism/ast.h under #{ext_target}"
        assert_path_exists "#{ext_runner}.fingerprint", "expected build fingerprint at #{ext_runner}.fingerprint"
      end

      host_mtimes.each do |path, prev_mtime|
        if prev_mtime
          assert_equal prev_mtime, File.stat(path).mtime, "host template #{path} should not be modified"
        else
          refute_path_exists path, "host template #{path} should not be created"
        end
      end
    end
  end

  def test_bisect_pre_opaque_legacy2026_shims_invert_fail_fast_and_single_bucket
    with_tmpdir("triage-bisect-single-") do |workdir|
      bisect_repo = File.join(workdir, "bisect_mock_repo")
      init_mock_prism_repo(bisect_repo)

      c1_sha = commit_mock_prism!(bisect_repo, mode: :current, crash_on: "NONE", message: "c1_good")
      c2_sha = commit_mock_prism!(bisect_repo, mode: :pre_opaque, crash_on: "NONE", message: "c2_pre_opaque")
      _c3_sha = commit_mock_prism!(bisect_repo, mode: :current, crash_on: "NONE", message: "c3_good_after_opaque")
      c4_sha = commit_mock_prism!(bisect_repo, mode: :legacy2026, crash_on: "CRASH_TOK_INPUT", message: "c4_bad_legacy2026")
      c5_sha = commit_mock_prism!(bisect_repo, mode: :current, crash_on: "CRASH_TOK_INPUT", message: "c5_still_bad")
      c6_sha = commit_mock_prism!(bisect_repo, mode: :current, crash_on: "NONE", message: "c6_first_fixed")
      c7_sha = commit_mock_prism!(bisect_repo, mode: :current, crash_on: "NONE", message: "c7_later_fixed")

      bisect_triage = File.join(workdir, "bisect_triage")
      FileUtils.mkdir_p([File.join(bisect_triage, "ABRT/tok_bug"), File.join(bisect_triage, "ABRT/tok_other")])
      File.binwrite(File.join(bisect_triage, "ABRT/tok_bug/input.min"), seed_bytes("CRASH_TOK_INPUT", header: "\x80\x80\xff\x01"))
      File.binwrite(File.join(bisect_triage, "ABRT/tok_other/input.min"), seed_bytes("PASS_INPUT"))

      verify_rb = repo_path("triage/verify.rb")
      bisect_rb = repo_path("triage/bisect.rb")

      with_env(local_verify_env(File.join(workdir, "verify_build"), File.join(workdir, "fuzz_build"))) do
        # Pre-opaque commit returns exit 125 from verify.rb --bisect.
        git_checkout(bisect_repo, c2_sha)
        _pre_out, _pre_err, pre_st = run_cmd(
          RbConfig.ruby, verify_rb,
          "--triage-dir", bisect_triage,
          "--target", bisect_repo,
          "--bisect", "--quiet",
          chdir: root_dir
        )
        assert_equal 125, pre_st.exitstatus, "expected exit 125 for pre-opaque commit"

        # Legacy 2026 target compiles with probed shims; --invert exits 0 on FAIL; --fail-fast stops after 1 bucket.
        git_checkout(bisect_repo, c4_sha)
        inv_json = File.join(workdir, "bisect_inv.json")
        assert_ruby_cmd(
          verify_rb,
          "--triage-dir", bisect_triage,
          "--target", bisect_repo,
          "--invert", "--fail-fast",
          "--json", inv_json
        )
        rep = JSON.parse(File.read(inv_json))
        assert_equal 1, rep.dig("summary", "buckets_checked"), "expected --fail-fast to stop after 1 bucket: #{rep['summary']}"
        assert_equal 1, rep.dig("summary", "fail"), "expected fail == 1: #{rep['summary']}"

        # Missing triage dir under --bisect exits 128.
        _miss_out, _miss_err, miss_st = run_cmd(
          RbConfig.ruby, verify_rb,
          "--triage-dir", File.join(workdir, "no_such_dir"),
          "--target", bisect_repo,
          "--bisect", "--quiet",
          chdir: root_dir
        )
        assert_equal 128, miss_st.exitstatus, "expected exit 128 for missing triage dir under --bisect"

        git_checkout(bisect_repo, c7_sha)

        # Regression bisect: c1 (good) .. c5 (bad), skipping c2 (125), identifying c4_bad_legacy2026.
        wt_reg = File.join(workdir, "bisect_wt_reg")
        reg_out = run_bisect!(
          bisect_rb,
          "--local", "--git-repo", bisect_repo, "--triage-dir", bisect_triage,
          "--good", c1_sha, "--bad", c5_sha, "--bucket", "ABRT/tok_bug",
          "--worktree", wt_reg,
          label: "regression bisect"
        )
        assert_match(/^#{Regexp.escape(c4_sha)} is the first bad commit$/, reg_out)
        refute_path_exists wt_reg, "expected temporary regression bisect worktree to be cleaned up"

        # Fix bisect: c4 (broken) .. c7 (fixed), identifying c6_first_fixed (not c7_later_fixed).
        wt_fix = File.join(workdir, "bisect_wt_fix")
        fix_out = run_bisect!(
          bisect_rb,
          "--local", "--git-repo", bisect_repo, "--triage-dir", bisect_triage,
          "--broken", c4_sha, "--fixed", c7_sha, "--bucket", "ABRT/tok_bug",
          "--worktree", wt_fix,
          label: "fix bisect"
        )
        assert_match(/^#{Regexp.escape(c6_sha)} is the first fixed commit$/, fix_out)
        refute_path_exists wt_fix, "expected temporary fix bisect worktree to be cleaned up"
      end
    end
  end

  def test_cluster_bisect_attribution_partial_input_min_only_and_skip_min
    with_tmpdir("triage-bisect-cluster-") do |workdir|
      bisect_repo = File.join(workdir, "bisect_mock_repo")
      init_mock_prism_repo(bisect_repo)

      c7_sha = commit_mock_prism!(bisect_repo, mode: :current, crash_on: "NONE", message: "c7_good")
      c8_sha = commit_mock_prism!(bisect_repo, mode: :current, crash_on: "CRASH_TOK_INPUT", message: "c8_cluster_part1")
      c9_sha = commit_mock_prism!(bisect_repo, mode: :current, crash_on: "CRASH_TOK_INPUT,CRASH_TOK2_INPUT,CRASH_ARCH_INPUT", message: "c9_cluster_both")
      c10_sha = commit_mock_prism!(bisect_repo, mode: :current, crash_on: "CRASH_TOK2_INPUT", message: "c10_cluster_fix1")
      c11_sha = commit_mock_prism!(bisect_repo, mode: :current, crash_on: "NONE", message: "c11_cluster_fix_all")
      c12_sha = commit_mock_prism!(bisect_repo, mode: :current, crash_on: "CRASH_ARCH_INPUT", message: "c12_cluster_arch_only")
      c13_sha = commit_mock_prism!(bisect_repo, mode: :current, crash_on: "CRASH_ARCH_INPUT", message: "c13_g_arch_noise")
      c14_sha = commit_mock_prism!(bisect_repo, mode: :current, crash_on: "CRASH_ARCH_INPUT,CRASH_TOK_INPUT", message: "c14_x_b1_min")
      c15_sha = commit_mock_prism!(bisect_repo, mode: :current, crash_on: "CRASH_ARCH_INPUT,CRASH_TOK_INPUT,CRASH_BC1_INPUT", message: "c15_y_bc1_arch")
      c16_sha = commit_mock_prism!(bisect_repo, mode: :current, crash_on: "CRASH_ARCH_INPUT,CRASH_TOK_INPUT,CRASH_BC1_INPUT", message: "c16_z_b2_min_ok")

      cluster_triage = File.join(workdir, "bisect_cluster_triage")
      build_cluster_triage_fixture(cluster_triage)

      verify_rb = repo_path("triage/verify.rb")
      bisect_rb = repo_path("triage/bisect.rb")

      with_env(local_verify_env(File.join(workdir, "verify_build"), File.join(workdir, "fuzz_build"))) do
        # Split cluster regression bisect: c7 .. c9 isolates c8 and attributes tok_bug vs tok2_bug.
        wt_reg = File.join(workdir, "bisect_wt_cluster_reg")
        reg_out = run_bisect!(
          bisect_rb,
          "--local", "--git-repo", bisect_repo, "--triage-dir", cluster_triage,
          "--good", c7_sha, "--bad", c9_sha, "--cluster", "cluster-01",
          "--worktree", wt_reg,
          label: "split cluster regression bisect"
        )
        assert_match(/^#{Regexp.escape(c8_sha)} is the first bad commit$/, reg_out)
        assert_includes reg_out, "Warning: only 1/2 selected buckets transitioned at #{c8_sha[0, 12]}"
        assert_includes reg_out, "ABRT/tok_bug: FAIL (input.min:"
        assert_includes reg_out, "ABRT/tok2_bug: PASS (at #{c9_sha[0, 12]} BAD: FAIL (input.min + 1 archived:"
        refute_path_exists wt_reg

        # Split cluster fix bisect: c9 .. c11 isolates c11 and notes tok_bug already passed at c10.
        wt_fix = File.join(workdir, "bisect_wt_cluster_fix")
        fix_out = run_bisect!(
          bisect_rb,
          "--local", "--git-repo", bisect_repo, "--triage-dir", cluster_triage,
          "--broken", c9_sha, "--fixed", c11_sha, "--cluster", "cluster-01",
          "--worktree", wt_fix,
          label: "split cluster fix bisect"
        )
        assert_match(/^#{Regexp.escape(c11_sha)} is the first fixed commit$/, fix_out)
        assert_includes fix_out, "Warning: #{c11_sha[0, 12]} fixed only 1/2 selected buckets (1 already PASSED at #{c10_sha[0, 12]})"
        assert_includes fix_out, "ABRT/tok2_bug: FAIL (input.min:"
        assert_includes fix_out, "ABRT/tok_bug: PASS (failed at #{c9_sha[0, 12]} BROKEN: FAIL (input.min"
        refute_path_exists wt_fix

        # PARTIAL cluster regression bisect: c11 .. c12 isolates c12 with archived failure detail.
        wt_part = File.join(workdir, "bisect_wt_cluster_part")
        part_out = run_bisect!(
          bisect_rb,
          "--local", "--git-repo", bisect_repo, "--triage-dir", cluster_triage,
          "--good", c11_sha, "--bad", c12_sha, "--cluster", "cluster-01",
          "--worktree", wt_part,
          label: "PARTIAL cluster regression bisect"
        )
        assert_match(/^#{Regexp.escape(c12_sha)} is the first bad commit$/, part_out)
        assert_includes part_out, "ABRT/tok2_bug: PARTIAL (input.min PASSED; 1 archived failed"
        refute_path_exists wt_part

        # Check verify.rb --input-min-only, --skip-min (FAIL, not PARTIAL, min_passed=nil), and mutual exclusion on c12.
        git_checkout(bisect_repo, c12_sha)

        min_only_json = File.join(workdir, "verify_min_only.json")
        assert_ruby_cmd(
          verify_rb,
          "--triage-dir", cluster_triage, "--target", bisect_repo,
          "--cluster", "cluster-01", "--input-min-only", "--json", min_only_json
        )
        mo = JSON.parse(File.read(min_only_json))
        assert_equal 2, mo.dig("summary", "pass"), "expected both buckets PASS under --input-min-only: #{mo['summary']}"
        assert_equal 2, mo.dig("summary", "inputs_checked"), "expected 2 inputs checked under --input-min-only: #{mo['summary']}"

        skip_min_json = File.join(workdir, "verify_skip_min.json")
        _sm_out, _sm_err, sm_st = run_cmd(
          RbConfig.ruby, verify_rb,
          "--triage-dir", cluster_triage, "--target", bisect_repo,
          "--bucket", "ABRT/tok2_bug", "--skip-min", "--json", skip_min_json,
          chdir: root_dir
        )
        assert_equal 1, sm_st.exitstatus, "expected --skip-min on c12 tok2_bug to exit 1"
        b = JSON.parse(File.read(skip_min_json)).fetch("buckets").first
        assert_equal "FAIL", b["status"], "expected FAIL (not PARTIAL) under --skip-min: #{b.inspect}"
        assert_nil b["min_passed"], "expected min_passed=nil under --skip-min: #{b.inspect}"
        assert_equal 1, b["failed"], "expected failed=1 under --skip-min: #{b.inspect}"

        _both_out, _both_err, both_st = run_cmd(
          RbConfig.ruby, verify_rb,
          "--triage-dir", cluster_triage, "--target", bisect_repo,
          "--input-min-only", "--skip-min",
          chdir: root_dir
        )
        assert_equal 2, both_st.exitstatus, "expected --input-min-only --skip-min to exit 2"

        # Model X -> Y -> Z with contaminated GOOD baseline (c13 has pre-existing archive crash on tok2_bug,
        # c14 introduces B_1.min, c15 introduces BC_1 archive inside tok_bug, c16 leaves B_2.min passing).
        git_checkout(bisect_repo, c16_sha)

        wt_xyz_min = File.join(workdir, "bisect_wt_xyz_min")
        xyz_min_out = run_bisect!(
          bisect_rb,
          "--local", "--git-repo", bisect_repo, "--triage-dir", cluster_triage,
          "--good", c13_sha, "--bad", c16_sha, "--cluster", "cluster-01", "--input-min-only",
          "--worktree", wt_xyz_min,
          label: "--input-min-only X->Y->Z bisect"
        )
        assert_match(/^#{Regexp.escape(c14_sha)} is the first bad commit$/, xyz_min_out)
        assert_match(/^== Cluster attribution \(2 buckets at #{Regexp.escape(c14_sha[0, 12])}; input\.min only\) ==$/, xyz_min_out)
        assert_includes xyz_min_out,
                        "ABRT/tok2_bug: PASS (at #{c16_sha[0, 12]} BAD: PARTIAL (input.min PASSED; 1 archived failed — arch_extra"
        refute_path_exists wt_xyz_min

        wt_xyz_skip = File.join(workdir, "bisect_wt_xyz_skip")
        xyz_skip_out = run_bisect!(
          bisect_rb,
          "--local", "--git-repo", bisect_repo, "--triage-dir", cluster_triage,
          "--good", c14_sha, "--bad", c16_sha, "--bucket", "ABRT/tok_bug", "--skip-min",
          "--worktree", wt_xyz_skip,
          label: "--skip-min follow-up bisect"
        )
        assert_match(/^#{Regexp.escape(c15_sha)} is the first bad commit$/, xyz_skip_out)
        refute_path_exists wt_xyz_skip
      end
    end
  end

  def test_docker_mode_external_bisect_mounts_and_attribution
    with_tmpdir("triage-bisect-docker-") do |workdir|
      bisect_repo = File.join(workdir, "bisect_mock_repo")
      init_mock_prism_repo(bisect_repo)

      c13_sha = commit_mock_prism!(bisect_repo, mode: :current, crash_on: "CRASH_ARCH_INPUT", message: "c13_g_arch_noise")
      c14_sha = commit_mock_prism!(bisect_repo, mode: :current, crash_on: "CRASH_ARCH_INPUT,CRASH_TOK_INPUT", message: "c14_x_b1_min")
      _c15_sha = commit_mock_prism!(bisect_repo, mode: :current, crash_on: "CRASH_ARCH_INPUT,CRASH_TOK_INPUT,CRASH_BC1_INPUT", message: "c15_y_bc1_arch")
      c16_sha = commit_mock_prism!(bisect_repo, mode: :current, crash_on: "CRASH_ARCH_INPUT,CRASH_TOK_INPUT,CRASH_BC1_INPUT", message: "c16_z_b2_min_ok")

      ext_ws = File.join(workdir, "ext_bisect_ws")
      ext_triage = File.join(ext_ws, "custom_triage")
      ext_clusters = File.join(ext_ws, "ext_clusters.json")
      ext_campaign = File.join(ext_ws, "campaign.rb")
      FileUtils.mkdir_p(File.join(ext_ws, "build"))
      build_cluster_triage_fixture(ext_triage)
      FileUtils.mv(File.join(ext_triage, "clusters.json"), ext_clusters)

      File.write(ext_campaign, <<~RUBY)
        PrismFuzzer.campaign "ext-bisect-test" do
          workspace #{ext_ws.dump}, triage_dir: #{ext_triage.dump}, build_dir: #{File.join(ext_ws, "build").dump}
          prism :prism_a, repo: "https://example.invalid/prism.git", dir: #{bisect_repo.dump}, patches: "none", templates: "never"
          fuzzer "fuzz", shape: :prism_parse, source: :prism_a
          sync_group :afl, dir: "afl", primary: true
          worker :main, fuzzer: "fuzz", sync_group: :afl, afl_role: :main
        end
      RUBY

      fake_docker_bin = File.join(workdir, "fake_bisect_docker")
      write_executable(File.join(fake_docker_bin, "docker"), FAKE_DOCKER_SCRIPT)
      mount_log_path = File.join(workdir, "bisect_docker_mounts.log")
      File.write(mount_log_path, "")

      docker_env = {
        "PATH" => "#{fake_docker_bin}:#{ENV.fetch('PATH', '')}",
        "FAKE_DOCKER_LOG" => mount_log_path,
        "BISECT_LOCAL" => "0",
        "CAMPAIGN" => ext_campaign,
        "VERIFY_BUILD_DIR" => File.join(ext_ws, "build/verify"),
        "FUZZ_BUILD_DIR" => nil
      }

      wt_docker = File.join(ext_ws, "build/wt_docker")
      with_env(docker_env) do
        docker_out = run_bisect!(
          repo_path("triage/bisect.rb"),
          "--git-repo", bisect_repo,
          "--triage-dir", ext_triage,
          "--clusters-file", ext_clusters,
          "--good", c13_sha,
          "--bad", c16_sha,
          "--cluster", "cluster-01",
          "--input-min-only",
          "--worktree", wt_docker,
          label: "Docker-mode external bisect"
        )
        assert_match(/^#{Regexp.escape(c14_sha)} is the first bad commit$/, docker_out)
        refute_path_exists wt_docker
      end

      mounts_log = File.read(mount_log_path)
      assert_match(%r{=>/external/bisect_triage$}, mounts_log, "expected external triage mount:\n#{mounts_log}")
      assert_match(%r{=>/external/bisect_clusters$}, mounts_log, "expected external clusters mount:\n#{mounts_log}")
      assert_match(%r{=>/external/bisect_reports$}, mounts_log, "expected external report_dir mount:\n#{mounts_log}")
    end
  end

  private

  def require_prism_a!
    pa = prism_a_dir
    skip "missing Prism A target (run 'make targets-sync' first)" unless pa && File.directory?(File.join(pa, "src"))
    pa
  end

  def c_compiler
    cc = ENV["CC"].to_s.strip
    cc.empty? ? "clang" : cc
  end

  def resolve_prism_gen_dir(prism_a, workdir)
    gd = prism_a_gen_dir
    if gd && File.file?(File.join(gd, "node_locations.inc")) && File.file?(File.join(gd, "prism_fuzz_compat.h"))
      return gd
    end

    fallback = File.join(workdir, "gen")
    FileUtils.mkdir_p(fallback)
    assert_ruby_cmd(
      repo_path("harnesses/prism/gen_node_locations.rb"),
      File.join(prism_a, "config.yml"),
      File.join(fallback, "node_locations.inc")
    )
    assert_ruby_cmd(
      repo_path("harnesses/prism/gen_api_compat.rb"),
      "--include-dir", File.join(prism_a, "include"),
      "--subloc-inc", File.join(fallback, "node_locations.inc"),
      "--output", File.join(fallback, "prism_fuzz_compat.h")
    )
    fallback
  end

  def local_verify_env(verify_build_dir, fuzz_build_dir)
    {
      "VERIFY_BUILD_DIR" => verify_build_dir,
      "FUZZ_BUILD_DIR" => fuzz_build_dir,
      "BISECT_LOCAL" => nil,
      "CAMPAIGN" => nil
    }
  end

  def init_mock_prism_repo(repo_dir)
    FileUtils.mkdir_p([File.join(repo_dir, "include/prism"), File.join(repo_dir, "src")])
    assert_cmd("git", "init", "-q", repo_dir)
    assert_cmd("git", "-C", repo_dir, "config", "user.email", "fuzz-test@example.com")
    assert_cmd("git", "-C", repo_dir, "config", "user.name", "Fuzz Test")
    assert_cmd("git", "-C", repo_dir, "config", "commit.gpgsign", "false")
    assert_cmd("git", "-C", repo_dir, "config", "tag.gpgsign", "false")
  end

  def git_checkout(repo_dir, rev)
    assert_cmd("git", "-C", repo_dir, "checkout", "-q", rev)
  end

  def write_mock_prism_files(repo_dir, mode:, crash_on:)
    inc = File.join(repo_dir, "include")
    prism_inc = File.join(inc, "prism")

    if mode == :pre_opaque
      File.write(File.join(inc, "prism.h"), "#include \"prism/arena.h\"\n")
      File.write(File.join(prism_inc, "arena.h"), "typedef struct { int x; } pm_arena_t;\n")
      %w[options.h stringy.h parser.h diagnostic.h].each { |hdr| File.write(File.join(prism_inc, hdr), "") }
      File.write(File.join(repo_dir, "src/stub.c"), "int stub_dummy = 0;\n")
      return
    end

    legacy = (mode == :legacy2026)
    File.write(File.join(inc, "prism.h"), <<~H)
      #include <stddef.h>
      #include <stdint.h>
      #include <stdbool.h>
      #include "prism/arena.h"
      #include "prism/stringy.h"
      #include "prism/options.h"
      #include "prism/diagnostic.h"
      #include "prism/parser.h"
      #include "prism/source.h"
      #include "prism/stream.h"
    H

    File.write(File.join(prism_inc, "arena.h"), <<~H)
      typedef struct pm_arena_t pm_arena_t;
      pm_arena_t *pm_arena_new(void);
      void pm_arena_free(pm_arena_t *arena);
    H

    File.write(File.join(prism_inc, "stringy.h"), <<~H)
      typedef struct { const uint8_t *source; size_t length; } pm_string_t;
      #{legacy ? "void pm_string_constant_init(pm_string_t *s, const char *src, size_t len);" : "void pm_string_init(pm_string_t *s, const uint8_t *src, size_t len);"}
    H

    opts_extra = legacy ? "" : <<~H
      void pm_options_attach_comments_set(pm_options_t *o, bool v);
      void pm_options_stack_budget_set(pm_options_t *o, size_t b);
    H

    File.write(File.join(prism_inc, "options.h"), <<~H)
      typedef struct pm_options_t pm_options_t;
      typedef struct pm_options_scope_t pm_options_scope_t;
      typedef void (*pm_options_shebang_callback_t)(pm_options_t *, const uint8_t *, size_t, void *);
      #define PM_OPTIONS_COMMAND_LINE_X 0x20
      #define PM_OPTIONS_SCOPE_FORWARDING_NONE 0x0
      pm_options_t *pm_options_new(void);
      void pm_options_free(pm_options_t *o);
      void pm_options_line_set(pm_options_t *o, int32_t l);
      void pm_options_command_line_set(pm_options_t *o, uint8_t c);
      void pm_options_main_script_set(pm_options_t *o, bool m);
      void pm_options_freeze_set(pm_options_t *o, bool f);
      void pm_options_partial_script_set(pm_options_t *o, bool p);
      void pm_options_encoding_locked_set(pm_options_t *o, bool e);
      bool pm_options_version_set(pm_options_t *o, const char *v, size_t l);
      void pm_options_frozen_string_literal_set(pm_options_t *o, bool f);
      void pm_options_encoding_set(pm_options_t *o, const char *e);
      void pm_options_filepath_set(pm_options_t *o, const char *f);
      void pm_options_shebang_callback_set(pm_options_t *o, pm_options_shebang_callback_t cb, void *d);
      bool pm_options_scopes_init(pm_options_t *o, size_t c);
      pm_options_scope_t *pm_options_scope_mut(pm_options_t *o, size_t i);
      void pm_options_scope_init(pm_options_scope_t *s, size_t c);
      void pm_options_scope_forwarding_set(pm_options_scope_t *s, uint8_t f);
      pm_string_t *pm_options_scope_local_mut(pm_options_scope_t *s, size_t i);
      #{opts_extra}
    H

    File.write(File.join(prism_inc, "diagnostic.h"), <<~H)
      typedef struct { uint32_t start; uint32_t length; } pm_location_t;
      typedef struct pm_diagnostic_t pm_diagnostic_t;
      typedef struct pm_comment_t pm_comment_t;
      typedef struct pm_magic_comment_t pm_magic_comment_t;
      #define PM_COMMENT_EMBDOC 1
      pm_location_t pm_diagnostic_location(const pm_diagnostic_t *d);
      const char *pm_diagnostic_type(const pm_diagnostic_t *d);
      unsigned pm_diagnostic_error_level(const pm_diagnostic_t *d);
      unsigned pm_diagnostic_warning_level(const pm_diagnostic_t *d);
      pm_location_t pm_comment_location(const pm_comment_t *c);
      int pm_comment_type(const pm_comment_t *c);
      pm_location_t pm_magic_comment_key(const pm_magic_comment_t *mc);
      pm_location_t pm_magic_comment_value(const pm_magic_comment_t *mc);
      const pm_diagnostic_t *pm_diagnostic_next(const pm_diagnostic_t *d);
      const pm_comment_t *pm_comment_next(const pm_comment_t *c);
      const pm_magic_comment_t *pm_magic_comment_next(const pm_magic_comment_t *mc);
    H

    iter_decls = if legacy
                   <<~H
                     typedef void (*pm_comment_callback_t)(const pm_comment_t *, void *);
                     typedef void (*pm_diagnostic_callback_t)(const pm_diagnostic_t *, void *);
                     typedef void (*pm_magic_comment_callback_t)(const pm_magic_comment_t *, void *);
                     void pm_parser_errors_each(const pm_parser_t *, pm_diagnostic_callback_t, void *);
                     void pm_parser_warnings_each(const pm_parser_t *, pm_diagnostic_callback_t, void *);
                     void pm_parser_comments_each(const pm_parser_t *, pm_comment_callback_t, void *);
                     void pm_parser_magic_comments_each(const pm_parser_t *, pm_magic_comment_callback_t, void *);
                   H
                 else
                   <<~H
                     const pm_diagnostic_t *pm_parser_errors_first(const pm_parser_t *);
                     const pm_diagnostic_t *pm_parser_warnings_first(const pm_parser_t *);
                     const pm_comment_t *pm_parser_comments_first(const pm_parser_t *);
                     const pm_magic_comment_t *pm_parser_magic_comments_first(const pm_parser_t *);
                   H
                 end

    visit_decls = if legacy
                    <<~H
                      void pm_visit_node(const pm_node_t *n, bool (*cb)(const pm_node_t *, void *), void *d);
                      void pm_visit_child_nodes(const pm_node_t *n, bool (*cb)(const pm_node_t *, void *), void *d);
                    H
                  else
                    <<~H
                      typedef enum { PM_VISIT_DESCEND = 0, PM_VISIT_SKIP = 1 } pm_visit_result_t;
                      void pm_visit_node(const pm_node_t *n, pm_visit_result_t (*cb)(const pm_node_t *, void *), void *d);
                      void pm_visit_child_nodes(const pm_node_t *n, pm_visit_result_t (*cb)(const pm_node_t *, void *), void *d);
                    H
                  end

    File.write(File.join(prism_inc, "parser.h"), <<~H)
      typedef uint16_t pm_node_type_t;
      typedef struct { pm_node_type_t type; pm_location_t location; } pm_node_t;
      typedef struct { uint32_t start; uint32_t length; } pm_string_loc_dummy;
      typedef struct { pm_node_t base; pm_location_t opening_loc; pm_location_t closing_loc; } pm_string_node_t;
      typedef pm_string_node_t pm_interpolated_string_node_t;
      typedef pm_string_node_t pm_x_string_node_t;
      typedef pm_string_node_t pm_interpolated_x_string_node_t;
      typedef struct { pm_node_t base; pm_location_t opening_loc; } pm_array_node_t;
      enum { PM_STRING_NODE = 1, PM_INTERPOLATED_STRING_NODE, PM_X_STRING_NODE, PM_INTERPOLATED_X_STRING_NODE, PM_SYMBOL_NODE, PM_INTERPOLATED_SYMBOL_NODE, PM_REGULAR_EXPRESSION_NODE, PM_INTERPOLATED_REGULAR_EXPRESSION_NODE, PM_MATCH_LAST_LINE_NODE, PM_INTERPOLATED_MATCH_LAST_LINE_NODE, PM_ARRAY_NODE };
      #define PM_NODE_TYPE(n) ((n)->type)
      typedef struct { size_t size; size_t capacity; uint32_t *offsets; } pm_line_offset_list_t;
      typedef struct pm_parser_t pm_parser_t;
      pm_parser_t *pm_parser_new(pm_arena_t *a, const uint8_t *s, size_t n, const pm_options_t *o);
      void pm_parser_free(pm_parser_t *p);
      pm_node_t *pm_parse(pm_parser_t *p);
      const pm_line_offset_list_t *pm_parser_line_offsets(const pm_parser_t *p);
      const pm_location_t *pm_parser_data_loc(const pm_parser_t *p);
      #{visit_decls}
      const char *pm_node_type(pm_node_type_t t);
      #{iter_decls}
    H

    File.write(
      File.join(prism_inc, "source.h"),
      "typedef struct pm_source_t pm_source_t; typedef char *(pm_source_stream_fgets_t)(char *, int, void *); " \
      "typedef int (pm_source_stream_feof_t)(void *); pm_source_t *pm_source_stream_new(void *, pm_source_stream_fgets_t *, pm_source_stream_feof_t *); " \
      "size_t pm_source_length(const pm_source_t *); void pm_source_free(pm_source_t *);\n"
    )
    File.write(
      File.join(prism_inc, "stream.h"),
      "pm_node_t *pm_parse_stream(pm_parser_t **p, pm_arena_t *a, pm_source_t *s, const pm_options_t *o);\n"
    )

    crash_tokens = crash_on == "NONE" ? [] : crash_on.split(",")
    crash_stmt = crash_tokens.map do |tok|
      <<~C
        for (size_t i = 0; i + #{tok.bytesize} <= len; i++) {
          if (memcmp(src + i, "#{tok}", #{tok.bytesize}) == 0) abort();
        }
      C
    end.join("\n")

    visit_cb_type = legacy ? "bool" : "pm_visit_result_t"
    File.write(File.join(repo_dir, "src/stub.c"), <<~C)
      #include "prism.h"
      #include <stdlib.h>
      #include <string.h>
      struct pm_arena_t { int unused; };
      struct pm_options_scope_t { pm_string_t locals[4]; };
      struct pm_options_t { pm_options_scope_t scopes[4]; };
      struct pm_diagnostic_t { int unused; };
      struct pm_comment_t { int unused; };
      struct pm_magic_comment_t { int unused; };
      struct pm_source_t { size_t len; const uint8_t *src; };
      struct pm_parser_t { const uint8_t *src; size_t len; uint32_t offs[1]; pm_line_offset_list_t lo; pm_location_t data_loc; pm_node_t root; };
      pm_arena_t *pm_arena_new(void) { return calloc(1, sizeof(pm_arena_t)); }
      void pm_arena_free(pm_arena_t *a) { free(a); }
      pm_options_t *pm_options_new(void) { return calloc(1, sizeof(pm_options_t)); }
      void pm_options_free(pm_options_t *o) { free(o); }
      void pm_options_line_set(pm_options_t *o, int32_t l) { (void)o; (void)l; }
      void pm_options_command_line_set(pm_options_t *o, uint8_t c) { (void)o; (void)c; }
      void pm_options_main_script_set(pm_options_t *o, bool m) { (void)o; (void)m; }
      void pm_options_freeze_set(pm_options_t *o, bool f) { (void)o; (void)f; }
      void pm_options_partial_script_set(pm_options_t *o, bool p) { (void)o; (void)p; }
      void pm_options_encoding_locked_set(pm_options_t *o, bool e) { (void)o; (void)e; }
      bool pm_options_version_set(pm_options_t *o, const char *v, size_t l) { (void)o; (void)v; (void)l; return true; }
      void pm_options_frozen_string_literal_set(pm_options_t *o, bool f) { (void)o; (void)f; }
      void pm_options_encoding_set(pm_options_t *o, const char *e) { (void)o; (void)e; }
      void pm_options_filepath_set(pm_options_t *o, const char *f) { (void)o; (void)f; }
      void pm_options_shebang_callback_set(pm_options_t *o, pm_options_shebang_callback_t cb, void *d) { (void)o; (void)cb; (void)d; }
      bool pm_options_scopes_init(pm_options_t *o, size_t c) { (void)o; return c <= 4; }
      pm_options_scope_t *pm_options_scope_mut(pm_options_t *o, size_t i) { return &o->scopes[i]; }
      void pm_options_scope_init(pm_options_scope_t *s, size_t c) { (void)s; (void)c; }
      void pm_options_scope_forwarding_set(pm_options_scope_t *s, uint8_t f) { (void)s; (void)f; }
      pm_string_t *pm_options_scope_local_mut(pm_options_scope_t *s, size_t i) { return &s->locals[i]; }
      void pm_string_init(pm_string_t *s, const uint8_t *src, size_t len) { s->source = src; s->length = len; }
      void pm_string_constant_init(pm_string_t *s, const char *src, size_t len) { s->source = (const uint8_t *)src; s->length = len; }
      void pm_options_attach_comments_set(pm_options_t *o, bool v) { (void)o; (void)v; }
      void pm_options_stack_budget_set(pm_options_t *o, size_t b) { (void)o; (void)b; }
      pm_parser_t *pm_parser_new(pm_arena_t *a, const uint8_t *s, size_t n, const pm_options_t *o) {
        (void)a; (void)o;
        pm_parser_t *p = calloc(1, sizeof(pm_parser_t));
        p->src = s; p->len = n; p->offs[0] = 0; p->lo.size = 1; p->lo.capacity = 1; p->lo.offsets = p->offs;
        p->root.type = 0; p->root.location.start = 0; p->root.location.length = (uint32_t)n;
        return p;
      }
      void pm_parser_free(pm_parser_t *p) { free(p); }
      pm_node_t *pm_parse(pm_parser_t *p) {
        const uint8_t *src = p->src; size_t len = p->len;
        #{crash_stmt}
        return &p->root;
      }
      const pm_line_offset_list_t *pm_parser_line_offsets(const pm_parser_t *p) { return &p->lo; }
      const pm_location_t *pm_parser_data_loc(const pm_parser_t *p) { return &p->data_loc; }
      pm_source_t *pm_source_stream_new(void *st, pm_source_stream_fgets_t *fg, pm_source_stream_feof_t *fe) { (void)st; (void)fg; (void)fe; return calloc(1, sizeof(pm_source_t)); }
      pm_node_t *pm_parse_stream(pm_parser_t **p, pm_arena_t *a, pm_source_t *s, const pm_options_t *o) { (void)s; *p = pm_parser_new(a, (const uint8_t *)"", 0, o); return pm_parse(*p); }
      size_t pm_source_length(const pm_source_t *s) { return s->len; }
      void pm_source_free(pm_source_t *s) { free(s); }
      void pm_visit_node(const pm_node_t *n, #{visit_cb_type} (*cb)(const pm_node_t *, void *), void *d) { if (n) cb(n, d); }
      void pm_visit_child_nodes(const pm_node_t *n, #{visit_cb_type} (*cb)(const pm_node_t *, void *), void *d) { (void)n; (void)cb; (void)d; }
      const char *pm_node_type(pm_node_type_t t) { (void)t; return "node"; }
      pm_location_t pm_diagnostic_location(const pm_diagnostic_t *d) { (void)d; return (pm_location_t){0, 0}; }
      const char *pm_diagnostic_type(const pm_diagnostic_t *d) { (void)d; return "err"; }
      unsigned pm_diagnostic_error_level(const pm_diagnostic_t *d) { (void)d; return 0; }
      unsigned pm_diagnostic_warning_level(const pm_diagnostic_t *d) { (void)d; return 0; }
      pm_location_t pm_comment_location(const pm_comment_t *c) { (void)c; return (pm_location_t){0, 0}; }
      int pm_comment_type(const pm_comment_t *c) { (void)c; return 0; }
      pm_location_t pm_magic_comment_key(const pm_magic_comment_t *mc) { (void)mc; return (pm_location_t){0, 0}; }
      pm_location_t pm_magic_comment_value(const pm_magic_comment_t *mc) { (void)mc; return (pm_location_t){0, 0}; }
      const pm_diagnostic_t *pm_diagnostic_next(const pm_diagnostic_t *d) { (void)d; return NULL; }
      const pm_comment_t *pm_comment_next(const pm_comment_t *c) { (void)c; return NULL; }
      const pm_magic_comment_t *pm_magic_comment_next(const pm_magic_comment_t *mc) { (void)mc; return NULL; }
      const pm_diagnostic_t *pm_parser_errors_first(const pm_parser_t *p) { (void)p; return NULL; }
      const pm_diagnostic_t *pm_parser_warnings_first(const pm_parser_t *p) { (void)p; return NULL; }
      const pm_comment_t *pm_parser_comments_first(const pm_parser_t *p) { (void)p; return NULL; }
      const pm_magic_comment_t *pm_parser_magic_comments_first(const pm_parser_t *p) { (void)p; return NULL; }
      void pm_parser_errors_each(const pm_parser_t *p, void (*cb)(const pm_diagnostic_t *, void *), void *d) { (void)p; (void)cb; (void)d; }
      void pm_parser_warnings_each(const pm_parser_t *p, void (*cb)(const pm_diagnostic_t *, void *), void *d) { (void)p; (void)cb; (void)d; }
      void pm_parser_comments_each(const pm_parser_t *p, void (*cb)(const pm_comment_t *, void *), void *d) { (void)p; (void)cb; (void)d; }
      void pm_parser_magic_comments_each(const pm_parser_t *p, void (*cb)(const pm_magic_comment_t *, void *), void *d) { (void)p; (void)cb; (void)d; }
    C
  end

  def commit_mock_prism!(repo_dir, mode:, crash_on:, message:)
    write_mock_prism_files(repo_dir, mode: mode, crash_on: crash_on)
    assert_cmd("git", "-C", repo_dir, "add", "include", "src")
    assert_cmd("git", "-C", repo_dir, "commit", "-q", "--allow-empty", "-m", message)
    sha_out, = assert_cmd("git", "-C", repo_dir, "rev-parse", "HEAD")
    sha_out.strip
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

  def build_cluster_triage_fixture(dir)
    tok_dir = File.join(dir, "ABRT/tok_bug")
    tok2_dir = File.join(dir, "ABRT/tok2_bug")
    FileUtils.mkdir_p([tok_dir, tok2_dir])

    hdr = "\x80\x80\xff\x01".b
    File.binwrite(File.join(tok_dir, "input.min"), seed_bytes("CRASH_TOK_INPUT", header: hdr))
    write_tar_gz(File.join(tok_dir, "inputs.tar.gz"), [["bc1", seed_bytes("CRASH_BC1_INPUT", header: hdr)]])

    File.binwrite(File.join(tok2_dir, "input.min"), seed_bytes("CRASH_TOK2_INPUT", header: hdr))
    write_tar_gz(File.join(tok2_dir, "inputs.tar.gz"), [["arch_extra", seed_bytes("CRASH_ARCH_INPUT", header: hdr)]])

    meta = {
      "schema_version" => 1,
      "buckets" => [
        { "bucket_id" => "ABRT/tok_bug", "reason" => "ABRT", "signature" => "tok_bug", "reproducible" => true, "occurrences" => { "count" => 5 } },
        { "bucket_id" => "ABRT/tok2_bug", "reason" => "ABRT", "signature" => "tok2_bug", "reproducible" => true, "occurrences" => { "count" => 3 } }
      ]
    }
    clusters = {
      "schema_version" => 1,
      "clusters" => [
        {
          "cluster_id" => "cluster-01",
          "bucket_count" => 2,
          "occurrences" => 8,
          "reasons" => { "ABRT" => 8 },
          "representative" => { "bucket_id" => "ABRT/tok_bug" },
          "buckets" => [{ "bucket_id" => "ABRT/tok_bug" }, { "bucket_id" => "ABRT/tok2_bug" }]
        }
      ]
    }
    File.write(File.join(dir, "metadata.json"), JSON.pretty_generate(meta))
    File.write(File.join(dir, "clusters.json"), JSON.pretty_generate(clusters))
  end

  def run_bisect!(bisect_rb, *args, label:)
    out, st = Open3.capture2e(RbConfig.ruby, bisect_rb, *args.map(&:to_s), chdir: root_dir)
    assert st.success?, "#{label} failed (exit=#{st.exitstatus}):\n#{out}"
    out
  end
end
