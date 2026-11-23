# frozen_string_literal: true

require_relative "../lib/autorun"
require_relative "../lib/fixtures"

require "fileutils"
require "json"
require "open3"
require "rbconfig"
require "shellwords"
require "stringio"

require_relative "../../runtime/topology"
require_relative "../../runtime/campaign"
require_relative "../../runtime/status"

# Integration tests for launch planning/staging, seed backup/restore,
# status dashboard I/O and contribution attribution, Campaign::CLI dispatch,
# startup timeout diagnostics, and ASan+UBSan CRuby diff self_pass screening.
class LaunchAndStatusTest < Minitest::Test
  def test_peer_imports_relative_symlinks_and_safe_stale_cleanup
    worker_ids = %w[t5_peer_real_foo_peer t5_peer_ijon_scout]

    with_afl_tmpdirs(worker_ids) do
      with_tmpdir("t5-peer-nested-") do |tmpdir|
        upstream = PrismFuzzerTest::Fixtures.build_synthetic_upstream_prism(File.join(tmpdir, "upstream"))
        ws = File.join(tmpdir, "peer_nested_ws")
        camp = File.join(tmpdir, "peer_nested_campaign.rb")

        FileUtils.mkdir_p([
          File.join(ws, "build"),
          File.join(ws, "bin"),
          File.join(ws, "corpus"),
          File.join(ws, "sync/hub/stale_feed"),
          File.join(ws, "sync/hub/old_peer"),
          File.join(ws, "sync/hub/t5_peer_real_foo_peer/queue"),
          File.join(ws, "islands/deep/ijon")
        ])

        write_executable(File.join(ws, "bin/fuzz"), "#!/bin/sh\nexit 0\n")
        File.binwrite(File.join(ws, "corpus/seed_1"), seed_bytes("x = 1\n", header: "\x00\x00\x00\x00"))

        # Pre-create stale shadow peer dirs (both non-_peer and *_peer) and a legitimate worker ending in _peer.
        File.symlink("../../nonexistent/queue", File.join(ws, "sync/hub/stale_feed/queue"))
        File.symlink("../../nonexistent/queue", File.join(ws, "sync/hub/old_peer/queue"))
        File.write(File.join(ws, "sync/hub/t5_peer_real_foo_peer/fuzzer_stats"), "execs_done : 10\n")
        File.binwrite(
          File.join(ws, "sync/hub/t5_peer_real_foo_peer/queue/id:000000"),
          seed_bytes("kept = 1\n", header: "\x00\x00\x00\x00")
        )

        File.write(camp, <<~RUBY)
          PrismFuzzer.campaign "peer-nested-test" do
            workspace #{ws.inspect}
            prism :prism_a, repo: #{upstream[:repo].inspect}, ref: #{upstream[:v1].inspect}, patches: "none", templates: "never"
            fuzzer "fuzz", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
            sync_group :hub, dir: "sync/hub", primary: true
            sync_group :ijon_island, dir: "islands/deep/ijon"
            worker :t5_peer_real_foo_peer, fuzzer: "fuzz", sync_group: :hub, afl_role: :main, schedule: "fast" do
              peer_import group: :ijon_island, worker: :t5_peer_ijon_scout, alias: "ijon_feed"
            end
            worker :t5_peer_ijon_scout, fuzzer: "fuzz", sync_group: :ijon_island, afl_role: :main, schedule: "explore"
          end
        RUBY

        ir, = PrismFuzzer::Topology.load_ir(camp, fuzz_root: root_dir)
        plan = PrismFuzzer::Topology.compile_plan(ir, fuzz_root: root_dir, build_dir: File.join(ws, "build"))
        PrismFuzzer::Topology.plan_launch!(
          plan,
          fuzz_root: root_dir,
          fuzz_dir: ws,
          corpus_dir: File.join(ws, "corpus"),
          bin_dir: File.join(ws, "bin")
        )

        refute File.exist?(File.join(ws, "sync/hub/stale_feed")),
               "expected stale non-_peer shadow dir stale_feed to be deleted"
        refute File.exist?(File.join(ws, "sync/hub/old_peer")),
               "expected stale *_peer shadow dir old_peer to be deleted"
        assert File.file?(File.join(ws, "sync/hub/t5_peer_real_foo_peer/fuzzer_stats")),
               "real worker t5_peer_real_foo_peer/fuzzer_stats was wrongly deleted"
        assert File.file?(File.join(ws, "sync/hub/t5_peer_real_foo_peer/queue/id:000000")),
               "real worker t5_peer_real_foo_peer/queue/id:000000 was wrongly deleted"

        peer_q = File.join(ws, "sync/hub/ijon_feed/queue")
        assert File.symlink?(peer_q), "expected symlink at #{peer_q}"
        assert_equal "../../../islands/deep/ijon/t5_peer_ijon_scout/queue", File.readlink(peer_q)
        assert_equal(
          File.realpath(File.join(ws, "islands/deep/ijon/t5_peer_ijon_scout/queue")),
          File.realpath(peer_q)
        )
      end
    end
  end

  def test_per_generator_seed_backup_in_run_sh_and_restore_in_plan_launch
    worker_ids = %w[t5_seed_ga t5_seed_gb t5_seed_gc t5_seed_wa t5_seed_wb t5_seed_wc]
    ready_file = "/tmp/.fuzzer.tmux.ready"

    with_afl_tmpdirs(worker_ids) do
      with_tmpdir("t5-seed-restore-") do |tmpdir|
        upstream = PrismFuzzerTest::Fixtures.build_synthetic_upstream_prism(File.join(tmpdir, "upstream"))
        sandbox = File.join(tmpdir, "seed_restore_sandbox")
        mock_bin = File.join(sandbox, "mock_bin")
        ws = File.join(sandbox, "ws")
        sdir_a = File.join(sandbox, "gen_a_seeds")
        sdir_b = File.join(sandbox, "gen_b_seeds")
        sdir_c = File.join(sandbox, "gen_c_seeds")
        tmux_state = File.join(sandbox, "tmux.alive")
        camp = File.join(sandbox, "seed_restore_campaign.rb")

        FileUtils.mkdir_p([
          File.join(sandbox, "runtime"),
          File.join(sandbox, "bin"),
          mock_bin,
          File.join(ws, "build"),
          File.join(ws, "bin"),
          File.join(ws, "corpus"),
          sdir_a,
          sdir_b,
          sdir_c
        ])

        write_executable(File.join(ws, "bin/fuzz"), "#!/bin/sh\nexit 0\n")
        File.binwrite(File.join(ws, "corpus/seed_1"), seed_bytes("seed_ok = 1\n", header: "\x00\x00\x00\x00"))
        FileUtils.cp(repo_path("runtime/run.sh"), File.join(sandbox, "runtime/run.sh"))
        File.chmod(0o755, File.join(sandbox, "runtime/run.sh"))

        File.write(camp, <<~RUBY)
          PrismFuzzer.campaign "seed-restore-test" do
            workspace #{ws.inspect}
            prism :prism_a, repo: #{upstream[:repo].inspect}, dir: #{upstream[:repo].inspect}, patches: "none", templates: "never"
            grammar_generator :gen_a, source: :prism_a, fuzzer: "fuzz", sync_group: :g_a, seeds_dir: #{sdir_a.inspect}
            grammar_generator :gen_b, source: :prism_a, fuzzer: "fuzz", sync_group: :g_b, seeds_dir: #{sdir_b.inspect}
            grammar_generator :gen_c, source: :prism_a, fuzzer: "fuzz", sync_group: :g_c, seeds_dir: #{sdir_c.inspect}
            fuzzer "fuzz", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
            sync_group :g_a, dir: "afl-a", primary: true
            sync_group :g_b, dir: "afl-b"
            sync_group :g_c, dir: "afl-c"
            worker :t5_seed_ga, kind: :generator, generator: :gen_a
            worker :t5_seed_gb, kind: :generator, generator: :gen_b
            worker :t5_seed_gc, kind: :generator, generator: :gen_c
            worker :t5_seed_wa, fuzzer: "fuzz", sync_group: :g_a, afl_role: :main, schedule: "fast" do
              foreign_sync :gen_a
            end
            worker :t5_seed_wb, fuzzer: "fuzz", sync_group: :g_b, afl_role: :main, schedule: "fast" do
              foreign_sync :gen_b
            end
            worker :t5_seed_wc, fuzzer: "fuzz", sync_group: :g_c, afl_role: :main, schedule: "fast" do
              foreign_sync :gen_c
            end
          end
        RUBY

        File.write(File.join(sandbox, "runtime/provenance.rb"), "exit 0\n")
        write_executable(File.join(sandbox, "runtime/kill.sh"), <<~SH)
          #!/usr/bin/env bash
          set -euo pipefail
          rm -f "${SEED_TMUX_STATE:?}"
        SH

        File.write(File.join(sandbox, "bin/topology.rb"), <<~RUBY)
          require "json"
          require "shellwords"
          cmd = ARGV.shift
          case cmd
          when "paths"
            m = {
              "WORKSPACE_DIR" => #{ws.inspect},
              "WORKSPACE_BUILD_DIR" => #{File.join(ws, "build").inspect},
              "WORKSPACE_AFL_DIR" => #{File.join(ws, "afl-a").inspect},
              "WORKSPACE_BIN_DIR" => #{File.join(ws, "bin").inspect},
              "WORKSPACE_SNAPSHOT_DIR" => #{File.join(ws, "snapshot").inspect},
              "WORKSPACE_CORPUS_DIR" => #{File.join(ws, "corpus").inspect},
              "WORKSPACE_SEEDS_DIR" => #{File.join(ws, "seeds").inspect},
              "WORKSPACE_LOGS_DIR" => #{File.join(ws, "logs").inspect}
            }
            use_shell = ARGV.include?("--shell")
            m.each { |k, v| puts "\#{k}=\#{use_shell ? Shellwords.escape(v) : v}" }
          when "plan-launch"
            puts JSON.generate(
              "primary_afl_dir" => #{File.join(ws, "afl-a").inspect},
              "generator_seeds_dirs" => [#{sdir_a.inspect}, #{sdir_b.inspect}, #{sdir_c.inspect}],
              "generator_seeds_map" => {
                "gen_a" => #{sdir_a.inspect},
                "gen_b" => #{sdir_b.inspect},
                "gen_c" => #{sdir_c.inspect}
              },
              "workers" => [{ "id" => "t5_seed_wa", "cmd" => "true" }]
            )
          end
        RUBY

        write_executable(File.join(mock_bin, "tmux"), <<~'SH')
          #!/usr/bin/env bash
          set -euo pipefail
          while [ "$#" -gt 0 ]; do
            case "$1" in
              -2) shift ;;
              *) break ;;
            esac
          done
          case "${1:-}" in
            new-session) : > "${SEED_TMUX_STATE:?}" ;;
            has-session) [ -f "${SEED_TMUX_STATE:?}" ] || exit 1 ;;
            new-window) echo "%1" ;;
            kill-session) rm -f "${SEED_TMUX_STATE:?}" ;;
            *) ;;
          esac
          exit 0
        SH

        t0 = Time.at(1_000_000)
        t1 = Time.at(1_000_500)
        ua = File.join(sdir_a, "unread_from_a")
        ra = File.join(sdir_a, "already_read_a")
        ub = File.join(sdir_b, "unread_from_b")
        File.write(ua, "SEED_A")
        File.write(ra, "READ_A")
        File.write(ub, "SEED_B")
        File.utime(t0, t0, ua)
        File.utime(t1, t0, ra) # atime > mtime => already read
        File.utime(t0, t0, ub)

        FileUtils.rm_f([ready_file, tmux_state])
        run_log = File.join(sandbox, "run.out")
        run_pid = nil
        begin
          run_pid = Process.spawn(
            {
              "PATH" => "#{mock_bin}:#{ENV.fetch('PATH', '')}",
              "SEED_TMUX_STATE" => tmux_state,
              "FUZZ_DAEMON" => "1"
            },
            "bash", "./runtime/run.sh",
            chdir: sandbox,
            out: run_log,
            err: [:child, :out]
          )

          ready = false
          50.times do
            if File.file?(ready_file) && File.file?(tmux_state)
              ready = true
              break
            end
            sleep 0.1
          end
          assert ready, "timed out waiting for seed_restore_sandbox:\n#{File.file?(run_log) ? File.read(run_log) : ''}"

          Process.kill("TERM", run_pid)
          _, seed_st = Process.wait2(run_pid)
          run_pid = nil
          assert seed_st.success?, "expected SIGTERM exit 0 in seed backup test, got #{seed_st.inspect}\n#{File.read(run_log)}"
        ensure
          if run_pid
            begin
              Process.kill("KILL", run_pid)
              Process.wait2(run_pid)
            rescue Errno::ESRCH, Errno::ECHILD
              nil
            end
          end
          FileUtils.rm_f(ready_file)
        end

        backup = File.join(ws, "seeds")
        assert File.file?(File.join(backup, "gen_a", "0_unread_from_a"))
        assert_empty Dir.glob(File.join(backup, "**", "*already_read*"))
        assert File.file?(File.join(backup, "gen_b", "0_unread_from_b"))
        refute File.exist?(File.join(backup, "gen_c"))

        # Add a legacy flat file alongside an obsolete removed-generator subdir before restore.
        File.write(File.join(backup, "legacy_flat"), "LEGACY_A")
        FileUtils.mkdir_p(File.join(backup, "removed_gen"))
        File.write(File.join(backup, "removed_gen", "stale"), "STALE")

        FileUtils.rm_rf(Dir.glob(File.join(sdir_a, "*")))
        FileUtils.rm_rf(Dir.glob(File.join(sdir_b, "*")))

        ir, = PrismFuzzer::Topology.load_ir(camp, fuzz_root: root_dir)
        plan = PrismFuzzer::Topology.compile_plan(ir, fuzz_root: root_dir, build_dir: File.join(ws, "build"))
        plan["sources"]["prism_a"]["path"] = ws
        lp = PrismFuzzer::Topology.plan_launch!(
          plan,
          fuzz_root: root_dir,
          fuzz_dir: ws,
          corpus_dir: File.join(ws, "corpus"),
          bin_dir: File.join(ws, "bin")
        )

        assert_equal({ "gen_a" => sdir_a, "gen_b" => sdir_b, "gen_c" => sdir_c }, lp["generator_seeds_map"])
        refute File.exist?(backup), "expected backup dir removed after restore"
        assert_equal %w[0_unread_from_a legacy_flat], Dir.children(sdir_a).sort
        assert_equal %w[0_unread_from_b], Dir.children(sdir_b).sort
        assert_empty Dir.children(sdir_c)
      end
    end
  end

  def test_status_rb_sleeps_on_closed_or_piped_eof_stdin
    with_tmpdir("t5-status-eof-") do |tmpdir|
      afl_dir = File.join(tmpdir, "status_eof_afl")
      FileUtils.mkdir_p(File.join(afl_dir, "w1/queue"))
      status_rb = repo_path("runtime/status.rb")

      # 1. /dev/null stdin must not spin (renders <= 4 frames in 1.2s).
      out_r, out_w = IO.pipe
      pid = nil
      begin
        pid = Process.spawn(RbConfig.ruby, status_rb, afl_dir, "w1", in: File::NULL, out: out_w, err: out_w)
        out_w.close
        out_w = nil
        sleep 1.2
        Process.kill("TERM", pid)
        _, st = Process.wait2(pid)
        pid = nil
        out = out_r.read

        assert st.success?, "status.rb exited unexpectedly on TERM: #{st.inspect}"
        frames = out.scan("Prism AFL++ Fleet Dashboard").size
        assert frames.between?(1, 4), "expected 1..4 rendered frames over 1.2s with /dev/null stdin, got #{frames}"
      ensure
        out_w&.close
        out_r&.close
        if pid
          begin
            Process.kill("KILL", pid)
            Process.wait2(pid)
          rescue Errno::ESRCH, Errno::ECHILD
            nil
          end
        end
      end

      # 2. Piped command before EOF toggles page and still does not spin after EOF.
      in_r, in_w = IO.pipe
      out_r2, out_w2 = IO.pipe
      pid2 = nil
      begin
        pid2 = Process.spawn(RbConfig.ruby, status_rb, afl_dir, "w1", in: in_r, out: out_w2, err: out_w2)
        in_r.close
        in_r = nil
        out_w2.close
        out_w2 = nil
        in_w.write("2")
        in_w.close
        in_w = nil
        sleep 1.2
        Process.kill("TERM", pid2)
        _, st2 = Process.wait2(pid2)
        pid2 = nil
        out2 = out_r2.read

        assert st2.success?, "status.rb (piped) exited unexpectedly on TERM: #{st2.inspect}"
        assert_includes out2, "[2: Queue & Sync]"
        frames2 = out2.scan("Prism AFL++ Fleet Dashboard").size
        assert frames2.between?(2, 5), "expected 2..5 rendered frames over 1.2s after pipe EOF, got #{frames2}"
      ensure
        in_r&.close
        in_w&.close
        out_w2&.close
        out_r2&.close
        if pid2
          begin
            Process.kill("KILL", pid2)
            Process.wait2(pid2)
          rescue Errno::ESRCH, Errno::ECHILD
            nil
          end
        end
      end
    end
  end

  def test_status_classifies_custom_grammar_workers_and_contributions_without_object_leak
    refute Object.const_defined?(:STATUS_TOPOLOGY, false), "Object leaked STATUS_TOPOLOGY"
    refute Object.const_defined?(:BOLD, false), "Object leaked BOLD"
    refute(
      Object.private_method_defined?(:collect_fuzzer_rows) || Object.method_defined?(:collect_fuzzer_rows),
      "Object leaked collect_fuzzer_rows"
    )
    refute(
      Object.private_method_defined?(:compute_contributions) || Object.method_defined?(:compute_contributions),
      "Object leaked compute_contributions"
    )

    with_tmpdir("t5-status-custom-gen-") do |tmpdir|
      upstream = PrismFuzzerTest::Fixtures.build_synthetic_upstream_prism(File.join(tmpdir, "upstream"))
      ws = File.join(tmpdir, "status_custom_gen_ws")
      camp = File.join(tmpdir, "status_custom_gen_camp.rb")
      seeds_hub = File.join(tmpdir, "custom_seeds_hub")
      seeds_ijon = File.join(tmpdir, "custom_seeds_ijon")

      FileUtils.mkdir_p([
        File.join(ws, "afl-hub/hub_main/queue"),
        File.join(ws, "afl-ijon/ijon_scout/queue"),
        seeds_hub,
        seeds_ijon
      ])
      File.write(File.join(seeds_hub, "seed_h1"), "s1\n")
      File.write(File.join(seeds_hub, "seed_h2"), "s2\n")
      File.write(File.join(seeds_ijon, "seed_i1"), "s3\n")

      # Hub consumer synced 2 seeds from grammar_hub; mutated 1 descendant + synced ijon's seed via peer_import;
      # ijon consumer synced 1 seed from grammar_ijon + mutated 2 descendants.
      FileUtils.touch([
        File.join(ws, "afl-hub/hub_main/queue/id:000000,sync:seeds,src:seed_h1"),
        File.join(ws, "afl-hub/hub_main/queue/id:000001,sync:seeds,src:seed_h2"),
        File.join(ws, "afl-hub/hub_main/queue/id:000002,src:000000"),
        File.join(ws, "afl-hub/hub_main/queue/id:000003,sync:ijon_feed,src:000000"),
        File.join(ws, "afl-ijon/ijon_scout/queue/id:000000,sync:seeds,src:seed_i1"),
        File.join(ws, "afl-ijon/ijon_scout/queue/id:000001,src:000000"),
        File.join(ws, "afl-ijon/ijon_scout/queue/id:000002,src:000001")
      ])

      File.write(camp, <<~RUBY)
        PrismFuzzer.campaign "status-custom-gen-test" do
          workspace #{ws.inspect}
          prism :prism_a, repo: #{upstream[:repo].inspect}, ref: #{upstream[:v1].inspect}, patches: "none", templates: "never"
          grammar_generator :grammar_hub, source: :prism_a, fuzzer: "fuzz", sync_group: :san_hub, seeds_dir: #{seeds_hub.inspect}, schedule: "lrama"
          grammar_generator :grammar_ijon, source: :prism_a, fuzzer: "fuzz", sync_group: :ijon_island, seeds_dir: #{seeds_ijon.inspect}, schedule: "lrama"
          fuzzer "fuzz", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
          sync_group :san_hub, dir: "afl-hub", primary: true
          sync_group :ijon_island, dir: "afl-ijon"
          worker :gen_hub, kind: :generator, generator: :grammar_hub
          worker :gen_ijon, kind: :generator, generator: :grammar_ijon
          worker :ijon_scout, fuzzer: "fuzz", sync_group: :ijon_island, afl_role: :main, schedule: "explore" do
            foreign_sync :grammar_ijon
          end
          worker :hub_main, fuzzer: "fuzz", sync_group: :san_hub, afl_role: :main, schedule: "exploit" do
            foreign_sync :grammar_hub
            peer_import group: :ijon_island, worker: :ijon_scout, alias: "ijon_feed"
          end
        end
      RUBY

      afl_hub = File.join(ws, "afl-hub")
      PrismFuzzer::Status.instance_variable_set(:@queue_entry_cache, {})
      begin
        with_env("CAMPAIGN" => camp, "TOPOLOGY" => camp) do
          now = Time.now.to_i
          rows = PrismFuzzer::Status.collect_fuzzer_rows(afl_hub, %w[gen_hub gen_ijon ijon_scout hub_main], now - 10, now)
          by_name = rows.each_with_object({}) { |r, h| h[r[:name]] = r }

          assert_equal :generator, by_name["gen_hub"][:role]
          assert_equal 2, by_name["gen_hub"][:pending_files]
          assert_equal :alive, by_name["gen_hub"][:state]
          assert_equal :generator, by_name["gen_ijon"][:role]
          assert_equal 1, by_name["gen_ijon"][:pending_files]
          assert_equal :fuzzer, by_name["ijon_scout"][:role]
          assert_equal :fuzzer, by_name["hub_main"][:role]

          contribs = PrismFuzzer::Status.compute_contributions(afl_hub)
          assert_equal 2, contribs[:shared]["gen_hub"]
          assert_equal 1, contribs[:descendants]["gen_hub"]
          assert_equal 1, contribs[:shared]["gen_ijon"]
          assert_equal 2, contribs[:descendants]["gen_ijon"]
          assert_equal 0, contribs[:shared]["grammar"], "did not expect leaked 'grammar' shared bucket: #{contribs.inspect}"
          assert_equal 0, contribs[:descendants]["grammar"], "did not expect leaked 'grammar' descendants bucket: #{contribs.inspect}"
        end
      ensure
        PrismFuzzer::Status.instance_variable_set(:@queue_entry_cache, {})
      end
    end
  end

  def test_pure_plan_launch_json_roundtrip_stage_launch_and_campaign_cli_dispatch
    worker_ids = %w[t5_pure_g1 t5_pure_w_main t5_pure_w_diff t5_pure_w_shard1 t5_pure_w_shard2 t5_pure_w_arm]

    with_afl_tmpdirs(worker_ids) do
      with_tmpdir("t5-pure-launch-") do |tmpdir|
        upstream = PrismFuzzerTest::Fixtures.build_synthetic_upstream_prism(File.join(tmpdir, "upstream"))
        ws = File.join(tmpdir, "pure_launch_ws")
        bin_dir = File.join(ws, "bin")
        corpus_dir = File.join(ws, "corpus")
        build_dir = File.join(ws, "build")
        gram_seeds = File.join(tmpdir, "pure_grammar_seeds")
        canary = File.join(tmpdir, "pure_binary_executed")
        camp = File.join(tmpdir, "pure_launch_campaign.rb")

        FileUtils.mkdir_p([bin_dir, build_dir])
        write_executable(File.join(bin_dir, "p_fast"), <<~SH)
          #!/bin/sh
          : > #{Shellwords.escape(canary)}
          exit 99
        SH
        write_executable(File.join(bin_dir, "p_diff"), <<~SH)
          #!/bin/sh
          : > #{Shellwords.escape(canary)}
          case ":${ASAN_OPTIONS:-}:" in *":detect_leaks=0:"*) ;; *) exit 23 ;; esac
          case ":${UBSAN_OPTIONS:-}:" in *":abort_on_error=1:"*) ;; *) exit 24 ;; esac
          grep -q "KEEP_SEED" "$1"
        SH
        write_executable(File.join(bin_dir, "p_arm"), <<~SH)
          #!/bin/sh
          : > #{Shellwords.escape(canary)}
          exit 99
        SH

        File.write(camp, <<~RUBY)
          PrismFuzzer.campaign "pure-launch-test" do
            workspace #{ws.inspect}
            prism :prism_a, repo: #{upstream[:repo].inspect}, ref: #{upstream[:v1].inspect}, dir: #{upstream[:repo].inspect}, patches: "none", templates: "never"
            corpus_generator :corpus, source: :prism_a, fuzzer: "p_fast"
            grammar_generator :gram_a, source: :prism_a, fuzzer: "p_fast", sync_group: :main_sg, seeds_dir: #{gram_seeds.inspect}
            fuzzer "p_fast", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
            fuzzer "p_diff", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :pcguard
            fuzzer "p_arm",  shape: :prism_cross_oracle, source: :prism_a, arch: :arm32, sanitizers: %i[asan ubsan], afl: :pcguard
            sync_group :main_sg, dir: "afl-main", primary: true
            sync_group :alt_sg,  dir: "afl-alt"
            worker :t5_pure_g1, kind: :generator, generator: :gram_a
            worker :t5_pure_w_main, fuzzer: "p_fast", sync_group: :main_sg, afl_role: :main, schedule: "exploit" do
              foreign_sync :gram_a
              peer_import group: :alt_sg, worker: :t5_pure_w_diff, alias: "diff_peer"
            end
            worker :t5_pure_w_diff, fuzzer: "p_diff", sync_group: :alt_sg, afl_role: :main, schedule: "explore" do
              seeds from: :corpus, filter: "self_pass", cache_key: "pdiff"
            end
            worker :t5_pure_w_shard1, fuzzer: "p_fast", sync_group: :main_sg, afl_role: :secondary, schedule: "fast" do
              seeds from: :corpus, shard_group: "pure_sg"
            end
            worker :t5_pure_w_shard2, fuzzer: "p_fast", sync_group: :main_sg, afl_role: :secondary, schedule: "fast" do
              seeds from: :corpus, shard_group: "pure_sg"
            end
            worker :t5_pure_w_arm, fuzzer: "p_arm", sync_group: :main_sg, afl_role: :secondary, schedule: "fast"
          end
        RUBY

        topo_cli = repo_path("bin/topology.rb")
        campaign_cli = repo_path("bin/campaign.rb")

        %w[--no-stage --pure --dry-run].each do |cli_flag|
          pure_out, = assert_ruby_cmd(topo_cli, "plan-launch", cli_flag, "--topology", camp)
          lp = JSON.parse(pure_out)
          assert_equal false, lp["staged"], "expected staged=false for pure plan-launch (#{cli_flag})"
          assert_equal worker_ids, lp["worker_names"]
          diff_w = lp["workers"].find { |w| w["id"] == "t5_pure_w_diff" }
          assert_equal "/tmp/afl-tmpdir/t5_pure_w_diff/seeds", diff_w["input_dir"]
          assert_equal false, diff_w["staged"]
        end

        camp_pure_out, = assert_ruby_cmd(campaign_cli, "plan-launch", "--no-stage", "--campaign", camp)
        camp_lp = JSON.parse(camp_pure_out)
        assert_equal false, camp_lp["staged"]
        assert_equal 6, camp_lp["worker_names"].size

        refute File.exist?(canary), "pure plan-launch unexpectedly executed a target binary"
        refute File.exist?(corpus_dir), "pure plan-launch unexpectedly created/populated corpus dir"
        refute File.exist?(gram_seeds), "pure plan-launch unexpectedly created grammar seeds dir"
        refute File.exist?(File.join(ws, "afl-main")), "pure plan-launch unexpectedly created afl-main sync dir"
        refute File.exist?(File.join(ws, "afl-alt")), "pure plan-launch unexpectedly created afl-alt sync dir"
        worker_ids.each do |wid|
          refute File.exist?("/tmp/afl-tmpdir/#{wid}"), "pure plan-launch unexpectedly touched /tmp/afl-tmpdir/#{wid}"
        end

        # Prepare staging preconditions for in-memory Campaign::CLI dispatch and stage_launch!.
        FileUtils.mkdir_p([corpus_dir, File.join(ws, "seeds/gram_a"), File.join(ws, "afl-main/stale_peer")])
        File.symlink("../../gone/queue", File.join(ws, "afl-main/stale_peer/queue"))
        File.write(File.join(ws, "seeds/gram_a/0_backup"), "BACKUP_SEED=1\n")
        File.binwrite(File.join(corpus_dir, "seed_keep"), seed_bytes("KEEP_SEED\n"))
        File.binwrite(File.join(corpus_dir, "seed_drop"), seed_bytes("DROP_SEED\n"))
        File.binwrite(File.join(corpus_dir, "seed_third"), seed_bytes("THIRD_SEED\n"))

        ir, = PrismFuzzer::Topology.load_ir(camp, fuzz_root: root_dir)
        plan = PrismFuzzer::Topology.compile_plan(ir, fuzz_root: root_dir, build_dir: build_dir)

        # 1. Verify in-memory Campaign::Instance with non-existent source_path dispatches TopologyCLI without Kernel.load.
        in_mem = PrismFuzzer::Campaign::Instance.new(
          ir,
          source_path: File.join(ws, "nonexistent_in_memory_only.rb"),
          fuzz_root: root_dir
        )
        no_load = ->(*args) { raise "unexpected Kernel.load(#{args.inspect}) during Campaign::CLI dispatch" }
        with_stubbed_singleton_method(Kernel, :load, no_load) do
          rc_paths, paths_out = capture_stdout { in_mem.cli!(["paths", "--relative", "--shell"]) }
          assert_equal 0, rc_paths
          assert_includes paths_out, "WORKSPACE_DIR="

          rc_pure, pure_json = capture_stdout { in_mem.cli!(["plan-launch", "--no-stage"]) }
          assert_equal 0, rc_pure
          lp_mem = JSON.parse(pure_json)
          assert_equal false, lp_mem["staged"]
        end

        refute File.exist?(canary), "pure plan_launch executed target binary"
        refute File.exist?("/tmp/afl-tmpdir/t5_pure_w_main"), "pure plan_launch touched /tmp/afl-tmpdir/t5_pure_w_main"
        assert File.file?(File.join(ws, "seeds/gram_a/0_backup")), "pure plan_launch removed seeds backup"

        # 2. Verify plan_launch embeds self_pass_env sanitizer options for self_pass workers.
        pure_lp = PrismFuzzer::Topology.plan_launch(
          plan,
          fuzz_root: root_dir,
          fuzz_dir: ws,
          corpus_dir: corpus_dir,
          bin_dir: bin_dir
        )
        diff_sp_env = pure_lp["workers"].find { |w| w["id"] == "t5_pure_w_diff" }&.dig("seeds", "self_pass_env")
        assert_kind_of Hash, diff_sp_env
        assert_includes diff_sp_env["ASAN_OPTIONS"].to_s, "detect_leaks=0"
        refute_includes diff_sp_env["ASAN_OPTIONS"].to_s, "detect_stack_use_after_return=0"
        assert_includes diff_sp_env["UBSAN_OPTIONS"].to_s, "abort_on_error=1"

        # 3. JSON round-trip into stage_launch! executes all staging side effects (both with self_pass_env and fallback).
        roundtripped = JSON.parse(JSON.generate(pure_lp))
        orig_cap = Open3.method(:capture2)
        qemu_cap = lambda do |*args|
          if args.any? { |a| a.to_s.include?("qemu-arm") }
            ["32768\n", Struct.new(:success?).new(true)]
          else
            orig_cap.call(*args)
          end
        end
        with_stubbed_singleton_method(Open3, :capture2, qemu_cap) do
          staged = PrismFuzzer::Topology.stage_launch!(roundtripped, fuzz_root: root_dir)

          assert_equal true, staged["staged"]
          refute File.exist?(File.join(ws, "afl-main/stale_peer"))
          assert File.symlink?(File.join(ws, "afl-main/diff_peer/queue"))
          assert File.file?(File.join(gram_seeds, "0_backup"))
          refute File.exist?(File.join(ws, "seeds"))
          assert File.file?("/tmp/afl-tmpdir/t5_pure_w_diff/seeds/seed_keep")
          refute File.exist?("/tmp/afl-tmpdir/t5_pure_w_diff/seeds/seed_drop")
          refute_empty Dir.children("/tmp/afl-tmpdir/t5_pure_w_shard1/seeds")
          refute_empty Dir.children("/tmp/afl-tmpdir/t5_pure_w_shard2/seeds")

          arm_w = staged["workers"].find { |w| w["id"] == "t5_pure_w_arm" }
          assert_includes arm_w["cmd"], "AFL_MAP_SIZE\\=32768"

          # Also verify legacy serialized plans without seeds.self_pass_env fall back to afl_launch env_prefix.
          fallback_rt = JSON.parse(JSON.generate(pure_lp))
          fallback_rt["workers"].each { |w| w["seeds"]&.delete("self_pass_env") }
          FileUtils.rm_rf("/tmp/afl-tmpdir/t5_pure_w_diff")
          PrismFuzzer::Topology.stage_launch!(fallback_rt, fuzz_root: root_dir)

          assert File.file?("/tmp/afl-tmpdir/t5_pure_w_diff/seeds/seed_keep")
          refute File.exist?("/tmp/afl-tmpdir/t5_pure_w_diff/seeds/seed_drop")
        end
      end
    end
  end

  def test_campaign_start_timeout_and_ensure_tmux_session_errors
    with_tmpdir("t5-start-timeout-") do |tmpdir|
      logs_dir = File.join(tmpdir, "startup_timeout_logs")
      FileUtils.mkdir_p(logs_dir)
      File.write(File.join(logs_dir, "run.log"), "# starting...\n")

      with_env("FUZZ_START_TIMEOUT" => nil) do
        assert_equal 180, PrismFuzzer::Campaign.start_timeout_seconds
      end

      with_env("FUZZ_START_TIMEOUT" => "240") do
        assert_equal 240, PrismFuzzer::Campaign.start_timeout_seconds

        ctx = { container_name: "test-timeout-ctr", ws: { logs_dir: logs_dir } }
        running_state = true

        with_stubbed_singleton_method(PrismFuzzer::Campaign, :wait_for_tmux_session!, ->(*_a, **_kw) { false }) do
          with_stubbed_singleton_method(PrismFuzzer::Campaign, :container_running?, ->(_cname) { running_state }) do
            err_running = assert_raises(PrismFuzzer::Campaign::CampaignError) do
              capture_stdout { PrismFuzzer::Campaign.ensure_tmux_session!(ctx) }
            end
            assert_includes err_running.message, "Timed out after 240s"
            assert_includes err_running.message, "still running"

            running_state = false
            err_exited = assert_raises(PrismFuzzer::Campaign::CampaignError) do
              capture_stdout { PrismFuzzer::Campaign.ensure_tmux_session!(ctx) }
            end
            assert_includes err_exited.message, "exited before starting tmux session 'fuzzer'"
          end
        end
      end
    end
  end

  def test_real_asan_cruby_fuzz_diff_self_pass_screening
    pa = prism_a_dir
    skip "missing Prism A target (run 'make targets-sync' first)" unless pa && File.file?(File.join(pa, "include/prism.h"))
    skip "missing /opt/ruby/libruby-static.a" unless File.file?("/opt/ruby/libruby-static.a")
    skip "AFL++ PCGUARD not available in environment" unless afl_pcguard_ready?

    with_afl_tmpdirs(["t5_real_w_diff"]) do
      with_tmpdir("t5-real-diff-") do |tmpdir|
        upstream = PrismFuzzerTest::Fixtures.build_synthetic_upstream_prism(File.join(tmpdir, "upstream"))
        ws = File.join(tmpdir, "real_diff_self_pass_ws")
        camp = File.join(tmpdir, "real_diff_self_pass_camp.rb")

        FileUtils.mkdir_p([
          File.join(ws, "corpus"),
          File.join(ws, "build"),
          File.join(ws, "bin")
        ])
        seed_valid = File.join(ws, "corpus/seed_valid")
        File.binwrite(seed_valid, seed_bytes("1 + 2\n"))

        ruby_ref = File.read(repo_path("docker/Dockerfile"))[/^ARG RUBY_GIT_REF=([0-9a-f]+)/, 1] || "495f3778a4020ecc828083239e945e60c51245ae"

        File.write(camp, <<~RUBY)
          PrismFuzzer.campaign "real-diff-self-pass-test" do
            workspace #{ws.inspect}
            prism :prism_a, repo: #{upstream[:repo].inspect}, ref: #{upstream[:v1].inspect}, dir: #{pa.inspect}, patches: "none", templates: "never"
            ruby  :ruby,    repo: "https://example.invalid/ruby.git", ref: #{ruby_ref.inspect}
            corpus_generator :corpus, source: :prism_a, fuzzer: "fuzz.diff"
            fuzzer "fuzz.diff", shape: :prism_diff_ruby, prism: :prism_a, ruby: :ruby, sanitizers: %i[asan ubsan], afl: :pcguard
            sync_group :afl, dir: "afl", primary: true
            worker :t5_real_w_diff, fuzzer: "fuzz.diff", sync_group: :afl, afl_role: :main do
              seeds from: :corpus, filter: :self_pass, cache_key: "real_diff"
            end
          end
        RUBY

        ir, = PrismFuzzer::Topology.load_ir(camp, fuzz_root: root_dir)
        plan = PrismFuzzer::Topology.compile_plan(ir, fuzz_root: root_dir, build_dir: File.join(ws, "build"))

        afl_path = afl_build_dir || "/usr/local/lib/afl"
        diff_bin = File.join(ws, "build/fuzz.diff")
        build_env = {
          "AFL_USE_ASAN" => "1",
          "AFL_USE_UBSAN" => "1",
          "AFL_UBSAN_VERBOSE" => "1",
          "FUZZ_GIT_COMMIT" => "",
          "FUZZ_GIT_DIRTY" => ""
        }
        assert_cmd(
          repo_path("harnesses/prism/build_diff.sh"),
          "--mode", "fuzz",
          "--prism-root", pa,
          "--fuzz-root", root_dir,
          "--oracle-dir", File.join(ws, "build/diff-oracle"),
          "--afl-path", afl_path,
          "--max-input-size", "1024",
          "--output", diff_bin,
          env: build_env,
          msg: "build_diff.sh --mode fuzz failed"
        )
        assert File.executable?(diff_bin), "expected executable diff binary at #{diff_bin}"

        # Bare ASan+CRuby fuzz.diff embeds detect_leaks=0 via __asan_default_options
        # because CRuby intentionally retains VM allocations through process exit.
        # Forcing detect_leaks=1 triggers LeakSanitizer, while stage_launch! self_pass enforces detect_leaks=0.
        lsan_def_out, lsan_def_err, lsan_def_st = run_cmd(
          diff_bin,
          seed_valid,
          env: { "FUZZ_DIFF_BACKTRACE" => "0", "ASAN_OPTIONS" => nil }
        )
        assert lsan_def_st.success?,
               "expected bare ASan fuzz.diff to disable LSan via __asan_default_options, got #{lsan_def_st.inspect}\n" \
               "#{lsan_def_out}\n#{lsan_def_err}"

        lsan_force_out, lsan_force_err, lsan_force_st = run_cmd(
          diff_bin,
          seed_valid,
          env: { "FUZZ_DIFF_BACKTRACE" => "0", "ASAN_OPTIONS" => "detect_leaks=1:symbolize=0" }
        )
        refute lsan_force_st.success?,
               "expected ASAN_OPTIONS=detect_leaks=1 on ASan+CRuby fuzz.diff to fail LeakSanitizer, got #{lsan_force_st.inspect}\n" \
               "#{lsan_force_out}\n#{lsan_force_err}"

        # stage_launch! self_pass and worker env must pass the compiled ASan+UBSan CRuby diff binary cleanly
        # and disable both detect_leaks and detect_stack_use_after_return for embedded CRuby GC safety.
        lp = PrismFuzzer::Topology.plan_launch(
          plan,
          fuzz_root: root_dir,
          fuzz_dir: ws,
          corpus_dir: File.join(ws, "corpus"),
          bin_dir: File.join(ws, "build")
        )
        diff_w = lp["workers"].first
        assert_includes diff_w["cmd"].to_s.delete("\\"), "detect_stack_use_after_return=0"
        assert_includes diff_w.dig("seeds", "self_pass_env", "ASAN_OPTIONS").to_s, "detect_stack_use_after_return=0"

        # Aggressive CRuby GC during parsing must survive both default ASAN_OPTIONS and explicit
        # detect_leaks=0 without stack-UAR FakeStack hiding C stack VALUE roots.
        gc_seed = File.join(tmpdir, "gc_stress_seed")
        File.binwrite(gc_seed, seed_bytes("def f(a = 1); [1, 2].map { |x| { k: x.to_s } }; end\n"))
        [nil, "detect_leaks=0:symbolize=0"].each do |asan_env|
          gc_out, gc_err, gc_st = run_cmd(
            diff_bin,
            gc_seed,
            env: {
              "FUZZ_DIFF_BACKTRACE" => "0",
              "ASAN_OPTIONS" => asan_env,
              "RUBY_GC_MALLOC_LIMIT" => "1024",
              "RUBY_GC_MALLOC_LIMIT_MAX" => "2048",
              "RUBY_GC_OLDMALLOC_LIMIT" => "1024",
              "RUBY_GC_OLDMALLOC_LIMIT_MAX" => "2048"
            }
          )
          assert gc_st.success?,
                 "expected fuzz.diff under CRuby GC stress (ASAN_OPTIONS=#{asan_env.inspect}) to pass, got #{gc_st.inspect}\n#{gc_out}\n#{gc_err}"
        end

        staged = PrismFuzzer::Topology.stage_launch!(lp, fuzz_root: root_dir)

        assert File.file?("/tmp/afl-tmpdir/t5_real_w_diff/seeds/seed_valid")
        assert_equal true, staged["staged"]
      end
    end
  end

  private

  def with_afl_tmpdirs(worker_ids)
    paths = worker_ids.map { |wid| "/tmp/afl-tmpdir/#{wid}" }
    paths.each { |p| FileUtils.rm_rf(p) }
    yield
  ensure
    paths.each { |p| FileUtils.rm_rf(p) }
  end

  def with_stubbed_singleton_method(target, method_name, impl)
    sc = target.singleton_class
    had_orig = sc.method_defined?(method_name) || sc.private_method_defined?(method_name)
    orig = target.method(method_name) if had_orig
    sc.define_method(method_name, impl)
    yield
  ensure
    if had_orig
      sc.define_method(method_name, orig)
    elsif sc.method_defined?(method_name) || sc.private_method_defined?(method_name)
      sc.remove_method(method_name)
    end
  end

  def capture_stdout
    io = StringIO.new
    prev = $stdout
    $stdout = io
    res = yield
    [res, io.string]
  ensure
    $stdout = prev
  end
end
