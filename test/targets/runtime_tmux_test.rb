# frozen_string_literal: true

require_relative "../lib/autorun"
require_relative "../lib/fixtures"

require "fileutils"
require "json"
require "open3"
require "rbconfig"
require "shellwords"

require_relative "../../runtime/campaign"

# Migrated integration tests covering sections [10/10] and [12/12]..[15/15] of
# test/test_targets.sh: runtime/run.sh trap & signal handling, multi-generator
# live seed capture & isolated coverage attribution, real tmux pipe-pane log
# streaming, runtime/kill.sh remain-on-exit/timeout handling, and paths --shell
# escaping with nested sync_group.dir.
class TargetsRuntimeTmuxTest < Minitest::Test
  READY_STAMP = "/tmp/.fuzzer.tmux.ready"
  DEFAULT_SESSION = "fuzzer"

  def test_run_sh_cleanup_trap_exit_codes_and_sigterm
    with_tmpdir("targets-run-sh-") do |dir|
      sandbox = setup_run_sh_sandbox(
        dir,
        kill_sh: <<~'SH',
          #!/usr/bin/env bash
          set -euo pipefail
          : > "${RUN_SANDBOX:?}/kill.called"
          rm -f "${MOCK_TMUX_STATE:?}"
        SH
        topology_rb: <<~'RB',
          require "json"
          cmd = ARGV.shift
          case cmd
          when "paths"
            puts <<~ENV
              WORKSPACE_DIR=./ws
              WORKSPACE_BUILD_DIR=./ws/build
              WORKSPACE_AFL_DIR=./ws/afl
              WORKSPACE_CORPUS_DIR=./ws/corpus
              WORKSPACE_LOGS_DIR=./ws/logs
            ENV
          when "plan-launch"
            mode = ENV.fetch("MOCK_PLAN_MODE", "ok")
            if mode == "fail_nonzero"
              puts '{"partial":true}'
              exit Integer(ENV.fetch("MOCK_PLAN_EXIT", "1"))
            elsif mode == "zero_workers"
              puts JSON.generate("primary_afl_dir" => "./ws/afl", "generator_seeds_dirs" => [], "workers" => [])
            else
              puts JSON.generate("primary_afl_dir" => "./ws/afl", "generator_seeds_dirs" => [], "workers" => [{ "id" => "w1", "cmd" => "true" }])
            end
          else
            abort "unexpected stub topology command: #{cmd.inspect}"
          end
        RB
        tmux_sh: <<~'SH'
          #!/usr/bin/env bash
          set -euo pipefail
          while [ "$#" -gt 0 ]; do
            case "$1" in
              -2) shift ;;
              *) break ;;
            esac
          done
          case "${1:-}" in
            new-session) : > "${MOCK_TMUX_STATE:?}" ;;
            has-session) [ -f "${MOCK_TMUX_STATE:?}" ] || exit 1 ;;
            new-window) echo "%1" ;;
            pipe-pane)
              case " $* " in
                *" -t %1 "*) ;;
                *) echo "expected pipe-pane -t %1, got: $*" >&2; exit 1 ;;
              esac
              ;;
            kill-session) rm -f "${MOCK_TMUX_STATE:?}" ;;
            *) ;;
          esac
          exit 0
        SH
      )

      tmux_state = File.join(sandbox[:root], "tmux.alive")
      kill_called = File.join(sandbox[:root], "kill.called")
      base_env = {
        "RUN_SANDBOX" => sandbox[:root],
        "MOCK_TMUX_STATE" => tmux_state
      }
      spawned_pid = nil

      begin
        # 1. plan-launch non-zero exit must propagate cleanly and remove .launch.plan.json
        reset_mock_run_state!(tmux_state, kill_called)
        st = run_run_sh_sync(
          sandbox,
          env: base_env.merge("MOCK_PLAN_MODE" => "fail_nonzero", "MOCK_PLAN_EXIT" => "2"),
          log_path: File.join(sandbox[:root], "case1.out")
        )
        assert_equal 2, st.exitstatus, "expected run.sh to preserve plan-launch exit code 2"
        refute_path_exists File.join(sandbox[:ws], ".launch.plan.json"),
                           "expected failed run.sh launch to clean up .launch.plan.json"

        # 2. Zero active workers must exit 1 without starting tmux
        reset_mock_run_state!(tmux_state, kill_called)
        st = run_run_sh_sync(
          sandbox,
          env: base_env.merge("MOCK_PLAN_MODE" => "zero_workers"),
          log_path: File.join(sandbox[:root], "case2.out")
        )
        assert_equal 1, st.exitstatus, "expected run.sh with zero workers to exit 1"
        refute_path_exists tmux_state, "zero-worker run.sh should not start tmux session"

        # 3. SIGTERM while waiting in loop must tear down via kill.sh and exit 0
        reset_mock_run_state!(tmux_state, kill_called)
        case3_log = File.join(sandbox[:root], "case3.out")
        spawned_pid = spawn_run_sh_until_ready(
          sandbox,
          env: base_env.merge("MOCK_PLAN_MODE" => "ok"),
          log_path: case3_log
        ) { File.file?(READY_STAMP) && File.file?(tmux_state) }

        Process.kill("TERM", spawned_pid)
        st = wait_pid_exit(spawned_pid)
        spawned_pid = nil
        assert_equal 0, st.exitstatus,
                     "expected run.sh SIGTERM cleanup to exit 0 (log:\n#{safe_read(case3_log)})"
        assert_path_exists kill_called, "expected SIGTERM cleanup to invoke kill.sh"
        refute_path_exists READY_STAMP, "expected SIGTERM cleanup to remove #{READY_STAMP}"

        # 4. Normal tmux session exit must terminate cleanly with exit 0
        reset_mock_run_state!(tmux_state, kill_called)
        case4_log = File.join(sandbox[:root], "case4.out")
        spawned_pid = spawn_run_sh_until_ready(
          sandbox,
          env: base_env.merge("MOCK_PLAN_MODE" => "ok"),
          log_path: case4_log
        ) { File.file?(READY_STAMP) && File.file?(tmux_state) }

        FileUtils.rm_f(tmux_state)
        st = wait_pid_exit(spawned_pid)
        spawned_pid = nil
        assert_equal 0, st.exitstatus,
                     "expected normal run.sh exit to return 0 (log:\n#{safe_read(case4_log)})"
        refute_path_exists READY_STAMP, "expected normal exit cleanup to remove #{READY_STAMP}"
      ensure
        reap_child!(spawned_pid) if spawned_pid
        FileUtils.rm_f(READY_STAMP)
      end
    end
  end

  def test_multi_generator_live_seeds_archive_and_capture
    refute_includes File.read(repo_path("Makefile")), "/tmp/afl-tmpdir/grammar/seeds",
                    "Makefile still hardcodes /tmp/afl-tmpdir/grammar/seeds"

    with_tmpdir("targets-live-seeds-") do |dir|
      fake_root = File.join(dir, "live_gen_fake_root")
      FileUtils.mkdir_p(fake_root)
      FileUtils.ln_s(repo_path("topology.schema.json"), File.join(fake_root, "topology.schema.json"))

      hub_dir = File.join(dir, "live_hub_seeds")
      ijon_dir = File.join(dir, "live_ijon_seeds")
      FileUtils.mkdir_p([hub_dir, ijon_dir])
      File.write(File.join(hub_dir, ".keep"), "ignored\n")

      s_a1 = File.join(hub_dir, "seed_a1")
      s_a2 = File.join(hub_dir, "seed_a2")
      s_b1 = File.join(ijon_dir, "seed_b1")
      File.binwrite(s_a1, seed_bytes("def live_a1; 1; end\n", header: "\x00\x00\x00\x00"))
      File.binwrite(s_a2, seed_bytes("def live_a2; 2; end\n", header: "\x00\x00\x00\x00"))
      File.binwrite(s_b1, seed_bytes("def live_b1; 3; end\n", header: "\x00\x00\x00\x00"))
      past = Time.at(1_000_000)
      [s_a1, s_a2, s_b1].each { |p| File.utime(past, past, p) }

      multi_camp = File.join(fake_root, "camp_multi_gen.rb")
      File.write(multi_camp, <<~RB)
        PrismFuzzer.campaign "multi-live-gen" do
          workspace #{File.join(dir, "live_gen_ws").dump}
          prism :prism_a, repo: "https://example.invalid/prism.git", dir: "$WS_ROOT/build/targets/prism_a", patches: "none", templates: "never"
          corpus_generator :corpus, source: :prism_a, fuzzer: "fuzz"
          grammar_generator :grammar_hub, source: :prism_a, fuzzer: "fuzz", sync_group: :afl_a, seeds_dir: #{hub_dir.dump}
          grammar_generator :grammar_ijon, source: :prism_a, fuzzer: "fuzz", sync_group: :afl_b
          fuzzer "fuzz", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
          sync_group :afl_a, dir: "afl-a", primary: true
          sync_group :afl_b, dir: "afl-b"
          worker :gen_hub, kind: :generator, generator: :grammar_hub
          worker :gen_ijon, kind: :generator, generator: :grammar_ijon
          worker :w1, fuzzer: "fuzz", sync_group: :afl_a, afl_role: :main, schedule: "fast" do
            foreign_sync :grammar_hub
          end
          worker :w2, fuzzer: "fuzz", sync_group: :afl_b, afl_role: :main, schedule: "fast" do
            foreign_sync :grammar_ijon
          end
        end
      RB

      no_gen_camp = File.join(fake_root, "camp_no_gen.rb")
      File.write(no_gen_camp, <<~RB)
        PrismFuzzer.campaign "no-gen" do
          workspace #{File.join(dir, "no_gen_ws").dump}
          prism :prism_a, repo: "https://example.invalid/prism.git", dir: "$WS_ROOT/build/targets/prism_a", patches: "none", templates: "never"
          fuzzer "fuzz", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
          sync_group :afl, dir: "afl", primary: true
          worker :w1, fuzzer: "fuzz", sync_group: :afl, afl_role: :main, schedule: "fast"
        end
      RB

      multi_ctx = PrismFuzzer::Campaign.resolve_context(campaign_path: multi_camp, fuzz_root: fake_root)
      no_gen_ctx = PrismFuzzer::Campaign.resolve_context(campaign_path: no_gen_camp, fuzz_root: fake_root)

      expected_dirs = {
        "grammar_hub" => hub_dir,
        "grammar_ijon" => "/tmp/afl-tmpdir/grammar_ijon/seeds"
      }
      assert_equal expected_dirs, PrismFuzzer::Topology.grammar_seeds_dirs(multi_ctx[:plan])
      assert_empty PrismFuzzer::Topology.grammar_seeds_dirs(no_gen_ctx[:plan])

      # Run LIVE_SEEDS_ARCHIVE_SCRIPT against real directories & verify tar paths + atime preservation
      tar_file = File.join(dir, "live_real.tar")
      build_live_seeds_tar(tar_file, "grammar_hub" => hub_dir, "grammar_ijon" => ijon_dir)

      entries_out, = assert_cmd("tar", "-tf", tar_file)
      entries = entries_out.lines.map(&:strip).reject(&:empty?).sort
      assert_equal %w[grammar_hub/seed_a1 grammar_hub/seed_a2 grammar_ijon/seed_b1], entries

      [s_a1, s_a2, s_b1].each do |p|
        assert_equal past.to_i, File.stat(p).atime.to_i,
                     "expected tar archive creation to preserve atime on #{p}"
      end

      # Verify capture_live_seeds_tar & capture_live_seeds_shell_env forward resolved maps and default fallback
      fake_status_ok = Struct.new(:exitstatus) { def success? = exitstatus == 0 }.new(0)
      seen_json_args = []
      orig_capture3 = Open3.method(:capture3)
      captured_files = []

      begin
        with_stubbed_method(PrismFuzzer::Campaign, :container_running?, ->(_name) { true }) do
          stub_capture3 = lambda do |*args, **kw|
            if args[0] == "docker" && args[1] == "exec"
              seen_json_args << JSON.parse(args.last)
              [File.binread(tar_file), "", fake_status_ok]
            elsif kw.empty?
              orig_capture3.call(*args)
            else
              orig_capture3.call(*args, **kw)
            end
          end
          with_stubbed_method(Open3, :capture3, stub_capture3) do
            captured = PrismFuzzer::Campaign.capture_live_seeds_tar(multi_ctx)
            refute_nil captured
            assert_path_exists captured
            captured_files << captured
            FileUtils.rm_f(captured)

            captured_fallback = PrismFuzzer::Campaign.capture_live_seeds_tar(no_gen_ctx)
            refute_nil captured_fallback
            assert_path_exists captured_fallback
            captured_files << captured_fallback
            FileUtils.rm_f(captured_fallback)

            assert_equal 2, seen_json_args.size
            assert_equal expected_dirs, seen_json_args[0]
            assert_equal({ "grammar" => "/tmp/afl-tmpdir/grammar/seeds" }, seen_json_args[1])

            shell_env = PrismFuzzer::Campaign.capture_live_seeds_shell_env(
              campaign_path: multi_camp,
              container_name: "fake-ctr",
              fuzz_dir: multi_ctx[:ws][:fuzz_dir]
            )
            assert_includes shell_env, "LIVE_SEEDS_TAR="
            assert_includes shell_env, "GUEST_LIVE_SEEDS_TAR="
          end
        end
      ensure
        captured_files.each { |p| FileUtils.rm_f(p) }
        FileUtils.rm_f(File.join(multi_ctx[:ws][:fuzz_dir], ".live-seeds.#{Process.pid}.tar"))
      end
    end
  end

  def test_multi_generator_live_seed_coverage_attribution
    skip "clang/llvm-profdata/llvm-cov required" unless find_executable("clang") &&
                                                         find_executable("llvm-profdata") &&
                                                         find_executable("llvm-cov")
    real_prism_a = prism_a_dir
    skip "built prism_a checkout required" unless real_prism_a

    real_prism_a_gen = prism_a_gen_dir

    with_tmpdir("targets-live-cov-") do |dir|
      live_cov_topo = File.join(dir, "live_cov_campaign.rb")
      live_cov_ws = File.join(dir, "live_cov_ws")
      FileUtils.mkdir_p([File.join(live_cov_ws, "build/targets/gen"), File.join(live_cov_ws, "afl")])
      if real_prism_a_gen
        FileUtils.ln_s(real_prism_a_gen, File.join(live_cov_ws, "build/targets/gen/prism_a"))
        FileUtils.ln_s(real_prism_a_gen, File.join(live_cov_ws, "build/targets/gen/prism_b"))
      end

      unused_gen_a = "/tmp/afl-tmpdir/custom_gen_a_#{$$}_#{object_id}/seeds"
      unused_gen_b = "/tmp/afl-tmpdir/custom_gen_b_#{$$}_#{object_id}/seeds"

      File.write(live_cov_topo, <<~RB)
        PrismFuzzer.campaign "live-cov-isolation" do
          workspace #{live_cov_ws.dump}
          prism :prism_a, repo: "https://example.invalid/prism.git", dir: #{real_prism_a.dump}, patches: "none", templates: "never"
          prism :prism_b, repo: "https://example.invalid/prism.git", dir: #{real_prism_a.dump}, patches: "none", templates: "never"
          coverage source: :prism_a, fuzzer: "fuzz_a"

          grammar_generator :grammar_a, source: :prism_a, fuzzer: "fuzz_a", sync_group: :afl_a, seeds_dir: #{unused_gen_a.dump}
          grammar_generator :grammar_b, source: :prism_b, fuzzer: "fuzz_b", sync_group: :afl_b, seeds_dir: #{unused_gen_b.dump}

          fuzzer "fuzz_a", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
          fuzzer "fuzz_b", shape: :prism_parse, source: :prism_b, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto

          sync_group :afl_a, dir: "afl-a", primary: true
          sync_group :afl_b, dir: "afl-b"
          worker :gen_a, kind: :generator, generator: :grammar_a
          worker :gen_b, kind: :generator, generator: :grammar_b
          worker :w_a, fuzzer: "fuzz_a", sync_group: :afl_a, afl_role: :main, schedule: "fast" do
            foreign_sync :grammar_a
          end
          worker :w_b, fuzzer: "fuzz_b", sync_group: :afl_b, afl_role: :main, schedule: "fast" do
            foreign_sync :grammar_b
          end
        end
      RB

      # 1. Structured multi-generator tar isolates grammar_a (2 seeds) vs grammar_b (1 seed)
      ga = File.join(dir, "ga_seeds")
      gb = File.join(dir, "gb_seeds")
      FileUtils.mkdir_p([ga, gb])
      File.binwrite(File.join(ga, "a1"), seed_bytes("def ga_one; 1; end\n", header: "\x00\x00\x00\x00"))
      File.binwrite(File.join(ga, "a2"), seed_bytes("def ga_two; 2; end\n", header: "\x00\x00\x00\x00"))
      File.binwrite(File.join(gb, "b1"), seed_bytes("def gb_one; 3; end\n", header: "\x00\x00\x00\x00"))

      live_tar = File.join(live_cov_ws, ".live-seeds.multi.tar")
      build_live_seeds_tar(live_tar, "grammar_a" => ga, "grammar_b" => gb)

      assert_cmd("./report/coverage.sh", env: coverage_env(live_cov_topo, live_cov_ws, live_tar), chdir: root_dir)
      refute_path_exists live_tar, "coverage.sh did not delete FUZZ_LIVE_SEEDS_TAR"

      cov_doc = JSON.parse(File.read(File.join(live_cov_ws, "report/coverage/coverage.json")))
      by_id = cov_doc.fetch("pairs").each_with_object({}) { |p, h| h[p["id"]] = p }
      assert_equal 2, by_id.fetch("prism_a__native").fetch("input_count")
      assert_equal 1, by_id.fetch("prism_b__native").fetch("input_count")

      # 2. Legacy flat tar fallback (seeds directly at tar root without <gid>/ subdirectory)
      flat_dir = File.join(dir, "flat_live_seeds")
      flat_tar = File.join(live_cov_ws, ".live-seeds.flat.tar")
      FileUtils.mkdir_p(flat_dir)
      File.binwrite(File.join(flat_dir, "flat_1"), seed_bytes("def flat_one; 42; end\n", header: "\x00\x00\x00\x00"))
      assert_cmd("tar", "-C", flat_dir, "-cf", flat_tar, "flat_1")

      assert_cmd("./report/coverage.sh", env: coverage_env(live_cov_topo, live_cov_ws, flat_tar), chdir: root_dir)
      refute_path_exists flat_tar, "coverage.sh did not delete legacy flat FUZZ_LIVE_SEEDS_TAR"

      flat_cov = JSON.parse(File.read(File.join(live_cov_ws, "report/coverage/coverage.json")))
      pa_flat = flat_cov.fetch("pairs").find { |p| p["id"] == "prism_a__native" }
      assert pa_flat && pa_flat["input_count"] == 1,
             "expected legacy flat tar fallback input_count==1, got #{pa_flat.inspect}"

      # 3. Regression (Bug #37): g["seeds_dir"] takes precedence over flat live_seeds_dir, empty
      # generators do not steal shared /tmp/afl-tmpdir/grammar/seeds or flat seeds, and pipefail
      # catches failing llvm-cov report in pipelines.
      iso_ws = File.join(dir, "iso_cov_ws")
      iso_topo = File.join(dir, "iso_cov_campaign.rb")
      iso_seeds_a = File.join(iso_ws, "seeds_a")
      iso_seeds_b = File.join(iso_ws, "seeds_b")
      FileUtils.mkdir_p([File.join(iso_ws, "afl-a"), File.join(iso_ws, "afl-b"), iso_seeds_a, iso_seeds_b])
      File.binwrite(File.join(iso_seeds_a, "a1"), seed_bytes("def iso_a1; 1; end\n", header: "\x00\x00\x00\x00"))
      File.binwrite(File.join(iso_seeds_a, "a2"), seed_bytes("def iso_a2; 2; end\n", header: "\x00\x00\x00\x00"))

      File.write(iso_topo, <<~RB)
        PrismFuzzer.campaign "iso-cov-seeds" do
          workspace #{iso_ws.dump}
          prism :prism_a, repo: "https://example.invalid/prism.git", dir: #{real_prism_a.dump}, patches: "none", templates: "never"
          prism :prism_b, repo: "https://example.invalid/prism.git", dir: #{real_prism_a.dump}, patches: "none", templates: "never"
          coverage source: :prism_a, fuzzer: "fuzz_a"
          grammar_generator :grammar_a, source: :prism_a, fuzzer: "fuzz_a", sync_group: :afl_a, seeds_dir: #{iso_seeds_a.dump}
          grammar_generator :grammar_b, source: :prism_b, fuzzer: "fuzz_b", sync_group: :afl_b, seeds_dir: #{iso_seeds_b.dump}
          fuzzer "fuzz_a", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
          fuzzer "fuzz_b", shape: :prism_parse, source: :prism_b, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
          sync_group :afl_a, dir: "afl-a", primary: true
          sync_group :afl_b, dir: "afl-b"
          worker :gen_a, kind: :generator, generator: :grammar_a
          worker :gen_b, kind: :generator, generator: :grammar_b
          worker :w_a, fuzzer: "fuzz_a", sync_group: :afl_a, afl_role: :main, schedule: "fast" do
            foreign_sync :grammar_a
          end
          worker :w_b, fuzzer: "fuzz_b", sync_group: :afl_b, afl_role: :main, schedule: "fast" do
            foreign_sync :grammar_b
          end
        end
      RB

      iso_flat_dir = File.join(dir, "iso_flat_dir")
      iso_flat_tar = File.join(iso_ws, ".live-seeds.flat.tar")
      FileUtils.mkdir_p(iso_flat_dir)
      %w[1 2 3].each do |n|
        File.binwrite(File.join(iso_flat_dir, "f#{n}"), seed_bytes("def flat_s#{n}; 1#{n}; end\n", header: "\x00\x00\x00\x00"))
      end
      assert_cmd("tar", "-C", iso_flat_dir, "-cf", iso_flat_tar, "f1", "f2", "f3")

      shared_grammar_dir = "/tmp/afl-tmpdir/grammar/seeds"
      created_shared_grammar = false
      begin
        unless File.exist?(shared_grammar_dir)
          FileUtils.mkdir_p(shared_grammar_dir)
          File.binwrite(File.join(shared_grammar_dir, "shared_1"), seed_bytes("def shared_g; 99; end\n", header: "\x00\x00\x00\x00"))
          created_shared_grammar = true
        end

        assert_cmd(
          "./report/coverage.sh",
          env: coverage_env(iso_topo, iso_ws, iso_flat_tar, build_dir: File.join(live_cov_ws, "build")),
          chdir: root_dir
        )
      ensure
        if created_shared_grammar
          FileUtils.rm_rf(shared_grammar_dir)
          FileUtils.rmdir("/tmp/afl-tmpdir/grammar") if Dir.exist?("/tmp/afl-tmpdir/grammar") && Dir.empty?("/tmp/afl-tmpdir/grammar")
        end
      end

      iso_cov = JSON.parse(File.read(File.join(iso_ws, "report/coverage/coverage.json")))
      iso_by_id = iso_cov.fetch("pairs").each_with_object({}) { |p, h| h[p["id"]] = p }
      assert_equal 2, iso_by_id.fetch("prism_a__native").fetch("input_count"),
                   "expected prism_a__native input_count==2 from own seeds_dir (not 3 flat seeds)"
      assert_equal 0, iso_by_id.fetch("prism_b__native").fetch("input_count"),
                   "expected prism_b__native input_count==0 (empty seeds_dir must not fall back to flat or shared grammar seeds)"

      # 4. Pipeline failure propagation: failing llvm-cov report must not be masked by | tee
      fail_llvm_bin = File.join(dir, "fail_llvm_bin")
      real_llvm_cov = find_executable("llvm-cov")
      write_executable(
        File.join(fail_llvm_bin, "llvm-cov"),
        <<~SH
          #!/usr/bin/env bash
          if [ "${1:-}" = "report" ]; then
            echo "simulated llvm-cov report failure" >&2
            exit 42
          fi
          exec #{Shellwords.escape(real_llvm_cov)} "$@"
        SH
      )

      pipefail_tar = File.join(live_cov_ws, ".live-seeds.pipefail.tar")
      assert_cmd("tar", "-C", flat_dir, "-cf", pipefail_tar, "flat_1")

      _out, _err, st = run_cmd(
        "./report/coverage.sh",
        env: coverage_env(live_cov_topo, live_cov_ws, pipefail_tar).merge(
          "LLVM_VERSION" => "",
          "PATH" => "#{fail_llvm_bin}:#{ENV.fetch('PATH', '')}"
        ),
        chdir: root_dir
      )
      assert_equal 42, st.exitstatus,
                   "coverage.sh masked llvm-cov report failure in | tee pipeline (expected rc 42, got #{st.exitstatus})"
    end
  end

  def test_real_tmux_pipe_pane_dotted_worker_logs_and_sigterm
    skip "tmux not found in PATH" unless find_executable("tmux")

    with_tmpdir("targets-real-tmux-") do |dir|
      sandbox = setup_run_sh_sandbox(
        dir,
        status_rb: "sleep 30\n",
        kill_sh: <<~'SH',
          #!/usr/bin/env bash
          set -euo pipefail
          tmux kill-session -t "${1:-fuzzer}" 2>/dev/null || true
        SH
        topology_rb: <<~'RB'
          require "json"
          cmd = ARGV.shift
          case cmd
          when "paths"
            puts <<~ENV
              WORKSPACE_DIR=./ws
              WORKSPACE_BUILD_DIR=./ws/build
              WORKSPACE_AFL_DIR=./ws/afl
              WORKSPACE_CORPUS_DIR=./ws/corpus
              WORKSPACE_LOGS_DIR=./ws/logs
            ENV
          when "plan-launch"
            puts JSON.generate(
              "primary_afl_dir" => "./ws/afl",
              "generator_seeds_dirs" => [],
              "workers" => [
                { "id" => "cand.asan", "cmd" => "sh -c 'while true; do printf \"WORKER_CAND_OK\\n\"; sleep 0.1; done'" },
                { "id" => "diff.1",    "cmd" => "sh -c 'while true; do printf \"WORKER_DIFF1_OK\\n\"; sleep 0.1; done'" }
              ]
            )
          else
            abort "unexpected stub topology command: #{cmd.inspect}"
          end
        RB
      )

      cleanup_tmux_session(DEFAULT_SESSION)
      FileUtils.rm_f(READY_STAMP)

      cand_log = File.join(sandbox[:ws], "logs/workers/cand.asan.log")
      diff_log = File.join(sandbox[:ws], "logs/workers/diff.1.log")
      run_out = File.join(sandbox[:root], "run.out")
      pid = nil

      begin
        pid = spawn_run_sh_until_ready(sandbox, log_path: run_out, timeout: 8.0) do
          File.file?(READY_STAMP) &&
            File.file?(cand_log) && File.read(cand_log).include?("WORKER_CAND_OK") &&
            File.file?(diff_log) && File.read(diff_log).include?("WORKER_DIFF1_OK")
        end

        Process.kill("TERM", pid)
        st = wait_pid_exit(pid)
        pid = nil
        assert_equal 0, st.exitstatus,
                     "expected real tmux run.sh SIGTERM exit 0 (log:\n#{safe_read(run_out)})"

        _o, _e, has_st = run_cmd("tmux", "has-session", "-t", DEFAULT_SESSION, env: clean_tmux_env)
        refute has_st.success?, "expected tmux session '#{DEFAULT_SESSION}' to be cleaned up on SIGTERM"
      ensure
        reap_child!(pid) if pid
        cleanup_tmux_session(DEFAULT_SESSION)
        FileUtils.rm_f(READY_STAMP)
      end
    end
  end

  def test_kill_sh_dead_remain_on_exit_panes_and_full_timeout
    skip "tmux not found in PATH" unless find_executable("tmux")

    ks_session = "kill_test_#{$$}"
    kill_sh = repo_path("runtime/kill.sh")
    cleanup_tmux_session(ks_session)

    begin
      # 1. Direct non-shell process exiting on C-c with remain-on-exit on must NOT stall until timeout
      assert_cmd(
        "tmux", "new-session", "-d", "-s", ks_session, "-n", "dash",
        "ruby -e '$stdout.sync = true; trap(\"INT\") { exit 0 }; puts \"LIVE\"; sleep 30'",
        env: clean_tmux_env
      )
      assert_cmd("tmux", "set-option", "-t", ks_session, "remain-on-exit", "on", env: clean_tmux_env)
      assert_cmd(
        "tmux", "new-window", "-d", "-t", ks_session, "-n", "worker",
        "sh -c 'trap \"exit 0\" INT; sleep 30'",
        env: clean_tmux_env
      )
      assert wait_for(timeout: 3.0) { pane_contains?(ks_session, "0", "LIVE") },
             "timed out waiting for dash pane to become live"
      sleep 0.2

      ks_start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      ks_out, = assert_cmd("bash", kill_sh, ks_session, env: clean_tmux_env.merge("KILL_TIMEOUT" => "5"))
      elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - ks_start

      assert_operator elapsed, :<, 3.0,
                      "expected dead remain-on-exit panes to finish quickly (<3s), took #{elapsed.round(2)}s"
      assert_includes ks_out, "All panes are idle. Killing session."
      _o, _e, has_st = run_cmd("tmux", "has-session", "-t", ks_session, env: clean_tmux_env)
      refute has_st.success?, "expected kill.sh to destroy session '#{ks_session}'"

      # 2. Live process ignoring SIGINT must wait full KILL_TIMEOUT seconds (not halved) before force killing
      assert_cmd(
        "tmux", "new-session", "-d", "-s", ks_session, "-n", "stubborn",
        "ruby -e '$stdout.sync = true; trap(\"INT\", \"IGNORE\"); puts \"STUBBORN\"; sleep 30'",
        env: clean_tmux_env
      )
      assert_cmd("tmux", "set-option", "-t", ks_session, "remain-on-exit", "on", env: clean_tmux_env)
      assert wait_for(timeout: 3.0) { pane_contains?(ks_session, "0", "STUBBORN") },
             "timed out waiting for stubborn pane to install INT IGNORE trap"

      ks_start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      ks_out, = assert_cmd("bash", kill_sh, ks_session, env: clean_tmux_env.merge("KILL_TIMEOUT" => "2"))
      elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - ks_start

      assert_operator elapsed, :>=, 1.9,
                      "expected KILL_TIMEOUT=2 to wait >=1.9s (not halved to 1s), took #{elapsed.round(2)}s"
      assert_includes ks_out, "Timeout reached. Force killing session."
      _o, _e, has_st = run_cmd("tmux", "has-session", "-t", ks_session, env: clean_tmux_env)
      refute has_st.success?, "expected kill.sh to force-kill session '#{ks_session}'"
    ensure
      cleanup_tmux_session(ks_session)
    end
  end

  def test_topology_paths_shell_escaping_and_run_sh_nested_sync_group
    with_tmpdir("targets-paths-nested-") do |dir|
      up = PrismFuzzerTest::Fixtures.build_synthetic_upstream_prism(File.join(dir, "upstream"))
      topo_cli = repo_path("bin/topology.rb")

      space_ws = File.join(dir, "ws with spaces", "dir$literal")
      space_camp = File.join(dir, "space_nested_campaign.rb")
      File.write(space_camp, <<~RB)
        PrismFuzzer.campaign "space-nested-test" do
          workspace #{space_ws.dump}
          prism :prism_a, repo: #{up[:repo].dump}, ref: #{up[:v1].dump}, patches: "none", templates: "never"
          fuzzer "fuzz", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
          sync_group :afl, dir: "sync/afl", primary: true
          worker :w1, fuzzer: "fuzz", sync_group: :afl, afl_role: :main, schedule: "fast"
        end
      RB

      # 1. Real bin/topology.rb paths --relative --shell preserves spaces & $ literals across eval
      paths_sh, = assert_ruby_cmd(topo_cli, "paths", "--topology", space_camp, "--relative", "--shell")
      eval_script = <<~'SH'
        eval "$1"
        printf '%s\0%s\0%s\0%s\0%s\0%s\0' \
          "$WORKSPACE_DIR" \
          "$WORKSPACE_AFL_DIR" \
          "$WORKSPACE_LOGS_DIR" \
          "$WORKSPACE_BIN_DIR" \
          "$WORKSPACE_SNAPSHOT_DIR" \
          "$WORKSPACE_SEEDS_DIR"
      SH
      eval_out, = assert_cmd("bash", "-c", eval_script, "_", paths_sh)
      eval_vals = eval_out.split("\0", -1)[0, 6]
      assert_equal [
        space_ws,
        "#{space_ws}/sync/afl",
        "#{space_ws}/logs",
        "#{space_ws}/bin",
        "#{space_ws}/snapshot",
        "#{space_ws}/seeds"
      ], eval_vals, "bin/topology.rb paths --shell eval round-trip failed"

      # Default (non-shell) paths output stays unquoted for Makefile consumption
      plain_out, = assert_ruby_cmd(topo_cli, "paths", "--topology", space_camp, "--relative")
      plain_ws_line = plain_out.lines.map(&:chomp).find { |ln| ln.start_with?("WORKSPACE_DIR=") }
      assert_equal "WORKSPACE_DIR=#{space_ws}", plain_ws_line

      # 2. runtime/run.sh handles paths failing, spaces/$ in WORKSPACE_DIR, and nested sync_group.dir
      nested_ws_rel = "./ws with spaces/item$x"
      nested_sandbox_dir = File.join(dir, "run_sh_nested")
      FileUtils.mkdir_p(nested_sandbox_dir)
      nested_tmux_state = File.join(nested_sandbox_dir, "tmux.alive")
      args_log = File.join(nested_sandbox_dir, "plan_args.json")

      sandbox = setup_run_sh_sandbox(
        nested_sandbox_dir,
        ws_subdir: "ws with spaces/item$x",
        extra_ws_dirs: %w[sync/afl],
        kill_sh: <<~'SH',
          #!/usr/bin/env bash
          set -euo pipefail
          rm -f "${NESTED_TMUX_STATE:?}"
        SH
        topology_rb: <<~'RB',
          require "json"
          require "shellwords"

          cmd = ARGV.shift
          case cmd
          when "paths"
            exit 3 if ENV["MOCK_PATHS_FAIL"] == "1"

            ws = "./ws with spaces/item$x"
            m = {
              "WORKSPACE_DIR" => ws,
              "WORKSPACE_BUILD_DIR" => "#{ws}/build",
              "WORKSPACE_AFL_DIR" => "#{ws}/sync/afl",
              "WORKSPACE_BIN_DIR" => "#{ws}/bin",
              "WORKSPACE_SNAPSHOT_DIR" => "#{ws}/snapshot",
              "WORKSPACE_CORPUS_DIR" => "#{ws}/corpus",
              "WORKSPACE_SEEDS_DIR" => "#{ws}/seeds",
              "WORKSPACE_LOGS_DIR" => "#{ws}/logs"
            }
            use_shell = ARGV.include?("--shell")
            m.each { |k, v| puts "#{k}=#{use_shell ? Shellwords.escape(v) : v}" }
          when "plan-launch"
            args_log = ENV.fetch("MOCK_PLAN_ARGS_LOG")
            File.write(args_log, JSON.pretty_generate(ARGV))
            ws = "./ws with spaces/item$x"
            puts JSON.generate("primary_afl_dir" => "#{ws}/sync/afl", "generator_seeds_dirs" => [], "workers" => [{ "id" => "w1", "cmd" => "true" }])
          else
            abort "unexpected stub topology command: #{cmd.inspect}"
          end
        RB
        tmux_sh: <<~'SH'
          #!/usr/bin/env bash
          set -euo pipefail
          while [ "$#" -gt 0 ]; do
            case "$1" in
              -2) shift ;;
              *) break ;;
            esac
          done
          case "${1:-}" in
            new-session) : > "${NESTED_TMUX_STATE:?}" ;;
            has-session) [ -f "${NESTED_TMUX_STATE:?}" ] || exit 1 ;;
            new-window) echo "%1" ;;
            kill-session) rm -f "${NESTED_TMUX_STATE:?}" ;;
            *) ;;
          esac
          exit 0
        SH
      )

      nested_pid = nil
      begin
        # 2a. Failure in bin/topology.rb paths must propagate out of run.sh
        st_fail = run_run_sh_sync(
          sandbox,
          env: { "MOCK_PATHS_FAIL" => "1" },
          log_path: File.join(sandbox[:root], "fail.out")
        )
        assert_equal 3, st_fail.exitstatus,
                     "expected topology paths exit code 3 to propagate from run.sh"

        # 2b. Successful nested sync_group + spaced WORKSPACE_DIR passes true workspace paths (not .../sync)
        reset_mock_run_state!(nested_tmux_state)
        ok_log = File.join(sandbox[:root], "ok.out")
        nested_pid = spawn_run_sh_until_ready(
          sandbox,
          env: {
            "NESTED_TMUX_STATE" => nested_tmux_state,
            "MOCK_PLAN_ARGS_LOG" => args_log
          },
          log_path: ok_log
        ) { File.file?(READY_STAMP) && File.file?(nested_tmux_state) }

        Process.kill("TERM", nested_pid)
        st_ok = wait_pid_exit(nested_pid)
        nested_pid = nil
        assert_equal 0, st_ok.exitstatus,
                     "expected nested spaced run.sh SIGTERM exit 0 (log:\n#{safe_read(ok_log)})"

        nested_ws = sandbox[:ws]
        assert_path_exists File.join(nested_ws, "logs/run.log"),
                           "expected run.log under true workspace logs dir (#{nested_ws}/logs)"
        refute_path_exists File.join(nested_ws, "sync/logs"),
                           "run.sh unexpectedly created logs under nested sync/ subdir"
        refute_path_exists File.join(nested_ws, "sync/bin"),
                           "run.sh unexpectedly created bin under nested sync/ subdir"

        plan_args = JSON.parse(File.read(args_log))
        fidx = plan_args.index("--fuzz-dir")
        refute_nil fidx, "missing --fuzz-dir in #{plan_args.inspect}"
        assert_equal nested_ws_rel, plan_args[fidx + 1]

        bidx = plan_args.index("--bin-dir")
        refute_nil bidx, "missing --bin-dir in #{plan_args.inspect}"
        assert_equal "#{nested_ws_rel}/bin", plan_args[bidx + 1]
      ensure
        reap_child!(nested_pid) if nested_pid
        FileUtils.rm_f(READY_STAMP)
      end
    end
  end

  private

  def with_stubbed_method(target, method_name, impl)
    sc = target.singleton_class
    had_orig = sc.method_defined?(method_name) || sc.private_method_defined?(method_name)
    orig = target.method(method_name) if had_orig
    sc.define_method(method_name, &impl)
    yield
  ensure
    if had_orig
      sc.define_method(method_name, orig)
    elsif sc.method_defined?(method_name) || sc.private_method_defined?(method_name)
      sc.remove_method(method_name)
    end
  end

  def clean_tmux_env
    { "TMUX" => nil, "TMUX_PANE" => nil }
  end

  def setup_run_sh_sandbox(base_dir, topology_rb:, kill_sh:, tmux_sh: nil, status_rb: nil, ws_subdir: "ws", extra_ws_dirs: %w[afl])
    root = File.join(base_dir, "sandbox")
    ws = File.join(root, ws_subdir)
    mock_bin = tmux_sh ? File.join(root, "mock_bin") : nil

    dirs = [
      File.join(root, "runtime"),
      File.join(root, "bin"),
      File.join(ws, "build"),
      File.join(ws, "corpus"),
      *extra_ws_dirs.map { |sub| File.join(ws, sub) }
    ]
    dirs << mock_bin if mock_bin
    FileUtils.mkdir_p(dirs)

    run_sh = File.join(root, "runtime/run.sh")
    FileUtils.cp(repo_path("runtime/run.sh"), run_sh)
    File.chmod(0o755, run_sh)

    File.write(File.join(root, "runtime/provenance.rb"), "exit 0\n")
    File.write(File.join(root, "runtime/status.rb"), status_rb) if status_rb
    File.write(File.join(root, "bin/topology.rb"), topology_rb)
    write_executable(File.join(root, "runtime/kill.sh"), kill_sh)
    write_executable(File.join(mock_bin, "tmux"), tmux_sh) if mock_bin

    { root: root, ws: ws, mock_bin: mock_bin }
  end

  def run_sh_env(sandbox, extra = {})
    path_val = ENV.fetch("PATH", "")
    path_val = "#{sandbox[:mock_bin]}:#{path_val}" if sandbox[:mock_bin]
    clean_tmux_env.merge(
      "FUZZ_DAEMON" => "1",
      "PATH" => path_val
    ).merge(extra)
  end

  def reset_mock_run_state!(*paths)
    FileUtils.rm_f([READY_STAMP, *paths])
  end

  def run_run_sh_sync(sandbox, env: {}, log_path:)
    pid = Process.spawn(
      run_sh_env(sandbox, env),
      "bash", "./runtime/run.sh",
      chdir: sandbox[:root],
      in: File::NULL,
      out: log_path,
      err: [:child, :out]
    )
    wait_pid_exit(pid, timeout: 10.0)
  end

  def spawn_run_sh_until_ready(sandbox, env: {}, log_path:, timeout: 6.0, &ready_check)
    pid = Process.spawn(
      run_sh_env(sandbox, env),
      "bash", "./runtime/run.sh",
      chdir: sandbox[:root],
      in: File::NULL,
      out: log_path,
      err: [:child, :out]
    )

    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    loop do
      return pid if ready_check.call

      if (reaped = Process.waitpid2(pid, Process::WNOHANG))
        flunk "run.sh exited early (status=#{reaped[1].exitstatus || reaped[1].termsig}) " \
              "before becoming ready:\n#{safe_read(log_path)}"
      end

      if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
        reap_child!(pid)
        flunk "timed out waiting for run.sh to reach ready state:\n#{safe_read(log_path)}"
      end

      sleep 0.05
    end
  end

  def wait_pid_exit(pid, timeout: 6.0)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    loop do
      reaped = Process.waitpid2(pid, Process::WNOHANG)
      return reaped[1] if reaped

      if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
        reap_child!(pid)
        flunk "timed out waiting for pid #{pid} to exit"
      end

      sleep 0.05
    end
  end

  def reap_child!(pid)
    return unless pid

    return if Process.waitpid2(pid, Process::WNOHANG)

    Process.kill("KILL", pid)
    Process.waitpid2(pid)
  rescue Errno::ESRCH, Errno::ECHILD
    nil
  end

  def cleanup_tmux_session(session)
    return unless find_executable("tmux")

    run_cmd("tmux", "kill-session", "-t", session, env: clean_tmux_env)
  end

  def pane_contains?(session, target_window, needle)
    out, _err, st = run_cmd("tmux", "capture-pane", "-p", "-t", "#{session}:#{target_window}", env: clean_tmux_env)
    st.success? && out.include?(needle)
  end

  def wait_for(timeout: 5.0, interval: 0.05)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    loop do
      return true if yield
      return false if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

      sleep interval
    end
  end

  def safe_read(path)
    File.file?(path) ? File.read(path) : "(missing #{path})"
  end

  def build_live_seeds_tar(out_tar, dirs_map)
    bytes, = assert_ruby_cmd("-e", PrismFuzzer::Campaign::LIVE_SEEDS_ARCHIVE_SCRIPT, JSON.generate(dirs_map))
    refute_empty bytes, "LIVE_SEEDS_ARCHIVE_SCRIPT produced empty archive"
    File.binwrite(out_tar, bytes)
  end

  def coverage_env(topo_path, ws_dir, live_tar, build_dir: nil)
    {
      "TOPOLOGY" => topo_path,
      "CAMPAIGN" => topo_path,
      "WORKSPACE_DIR" => ws_dir,
      "WORKSPACE_BUILD_DIR" => build_dir || File.join(ws_dir, "build"),
      "WORKSPACE_AFL_DIR" => File.join(ws_dir, "afl"),
      "WORKSPACE_REPORT_DIR" => File.join(ws_dir, "report"),
      "WORKSPACE_COVERAGE_DIR" => File.join(ws_dir, "report/coverage"),
      "WORKSPACE_CORPUS_DIR" => File.join(ws_dir, "corpus"),
      "FUZZ_LIVE_SEEDS_TAR" => live_tar
    }
  end
end
