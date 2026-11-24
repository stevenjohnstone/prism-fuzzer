# frozen_string_literal: true

require_relative "../lib/autorun"
require_relative "../lib/fixtures"

require "cgi/escape"
require "fileutils"
require "json"
require "open3"
require "pty"
require "shellwords"
require "stringio"

require_relative "../../bin/publish"
require_relative "../../runtime/campaign"
require_relative "../../runtime/progress"
require_relative "../../runtime/provenance"
require_relative "../../runtime/topology"
require_relative "../../triage/explain"
require_relative "../../triage/match"

class WorkspaceAndCoverageTest < Minitest::Test
  CLEAN_WS_ENV = {
    "CAMPAIGN" => nil,
    "TOPOLOGY" => nil,
    "TOPOLOGY_FILE" => nil,
    "TOPOLOGY_RESOLVED" => nil,
    "FUZZ_DIR" => nil,
    "FUZZ_BUILD_DIR" => nil,
    "FUZZ_LOGS_DIR" => nil,
    "FUZZ_CONTAINER_NAME" => nil,
    "FUZZ_SKIP_COVERAGE" => nil,
    "FUZZ_COVERAGE_NO_CACHE" => nil,
    "FUZZ_COVERAGE_FINAL" => nil,
    "FUZZ_COVERAGE_LIVE" => nil,
    "FUZZ_COVERAGE_CACHE_DIR" => nil,
    "TRIAGE_DIR" => nil,
    "TRIAGE_CORPUS_DIR" => nil,
    "REPORTS_DIR" => nil,
    "PRISM_DIR" => nil,
    "PRISM_A_DIR" => nil,
    "PRISM_A_GEN_DIR" => nil,
    "PRISM_A_REF" => nil,
    "PRISM_A_REPO" => nil,
    "PRISM_A_PATCHES" => nil,
    "PRISM_A_TEMPLATES" => nil,
    "PRISM_B_DIR" => nil,
    "PRISM_B_GEN_DIR" => nil,
    "PRISM_B_REF" => nil,
    "PRISM_B_REPO" => nil,
    "PRISM_B_PATCHES" => nil,
    "PRISM_B_TEMPLATES" => nil,
    "RUBY_DIR" => nil,
    "TARGETS_OFFLINE" => nil
  }.freeze

  def topo_cli
    repo_path("bin", "topology.rb")
  end

  def campaign_cli
    repo_path("bin", "campaign.rb")
  end

  def with_clean_ws_env(extra = {}, &block)
    with_env(CLEAN_WS_ENV.merge(extra), &block)
  end

  def with_singleton_stubs(stubs)
    saved = []
    stubs.each do |target, method_name, impl|
      sc = target.singleton_class
      had_orig = sc.method_defined?(method_name) || sc.private_method_defined?(method_name)
      orig = target.method(method_name) if had_orig
      sc.define_method(method_name, &impl)
      saved << [sc, method_name, had_orig, orig]
    end
    yield
  ensure
    saved&.reverse_each do |sc, method_name, had_orig, orig|
      if had_orig
        sc.define_method(method_name, orig)
      elsif sc.method_defined?(method_name) || sc.private_method_defined?(method_name)
        sc.remove_method(method_name)
      end
    end
  end

  def write_ws_campaign(path, ws_root:, upstream:, prism_ref:, ruby_dir:, worker_id: :w1)
    write_executable(path, <<~RB)
      #!/usr/bin/env ruby
      # frozen_string_literal: true

      require #{File.join(root_dir, "lib", "prism_fuzzer").dump}

      PrismFuzzer.campaign "isolated-ws-test" do
        workspace #{ws_root.dump}
        duration "45m"
        after_run do
          report threads: 2, top: 10
          publish run_id: "iso-01", title: "Isolated WS"
        end

        prism :prism_a, repo: #{upstream.dump}, ref: #{prism_ref.dump}, patches: "auto", templates: "auto"
        ruby :ruby, repo: "https://example.invalid/ruby.git", dir: #{ruby_dir.dump}
        fuzzer "ws_fuzz", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
        fuzzer "ws_diff", shape: :prism_diff_ruby, prism: :prism_a, ruby: :ruby, afl: :pcguard
        sync_group :afl, dir: "afl-ws", primary: true
        worker #{worker_id.to_sym.inspect}, fuzzer: "ws_fuzz", sync_group: :afl, afl_role: :main, schedule: "fast"
      end
    RB
  end

  def write_cov_pairs_campaign(path, ws_root:, prism_a_dir:, prism_b_dir:, name: "cov-pairs-test")
    File.write(path, <<~RB)
      PrismFuzzer.campaign #{name.dump} do
        workspace #{ws_root.dump}
        prism :prism_a, repo: "https://example.invalid/prism.git", dir: #{prism_a_dir.dump}, patches: "none", templates: "never"
        prism :prism_b, repo: "https://example.invalid/prism.git", dir: #{prism_b_dir.dump}, patches: "none", templates: "never"
        coverage source: :prism_a, fuzzer: "fuzz"

        fuzzer "fuzz",       shape: :prism_parse,        source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
        fuzzer "fuzz_slow",  shape: :prism_parse,        source: :prism_a, sanitizers: [:msan],        mode: :slow, afl: :lto, ijon: true
        fuzzer "fuzz_swar",  shape: :prism_parse,        source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto, defines: { PRISM_ACCEL_SWAR: true }
        fuzzer "fuzz_arm32", shape: :prism_cross_oracle, source: :prism_a, arch: :arm32, sanitizers: %i[asan ubsan], afl: :pcguard
        fuzzer "fuzz_ab",    shape: :prism_diff_prism,   prism_a: :prism_a, prism_b: :prism_b, sanitizers: %i[asan ubsan], afl: :pcguard

        sync_group :afl, dir: "afl", primary: true
        worker :main,  fuzzer: "fuzz",       sync_group: :afl, afl_role: :main,      schedule: "exploit"
        worker :slow,  fuzzer: "fuzz_slow",  sync_group: :afl, afl_role: :secondary, schedule: "fast"
        worker :swar,  fuzzer: "fuzz_swar",  sync_group: :afl, afl_role: :secondary, schedule: "fast"
        worker :arm32, fuzzer: "fuzz_arm32", sync_group: :afl, afl_role: :secondary, schedule: "explore"
        worker :pdiff, fuzzer: "fuzz_ab",    sync_group: :afl, afl_role: :secondary, schedule: "explore"
      end
    RB
  end

  def populate_afl_cov_worker_dirs(afl_dir)
    stats_body = <<~STATS
      start_time        : 1700000000
      last_update       : 1700000010
      run_time          : 10
      execs_done        : 100
      execs_per_sec     : 10.00
      corpus_count      : 1
      pending_total     : 0
      pending_favs      : 0
      cycles_done       : 0
      max_depth         : 1
      bitmap_cvg        : 12.50%
      edges_found       : 25
      total_edges       : 200
      saved_crashes     : 0
      saved_hangs       : 0
      afl_banner        : fuzz
      command_line      : fuzz
    STATS

    %w[main slow swar arm32 pdiff].each do |w|
      FileUtils.mkdir_p([File.join(afl_dir, w, "queue"), File.join(afl_dir, w, "crashes")])
      File.write(File.join(afl_dir, w, "fuzzer_stats"), stats_body)
    end

    File.binwrite(File.join(afl_dir, "main/queue/id:000000,time:0,execs:0,orig:seed_1"), "\x00\x00\x00\x00x = 1 + 2\n".b)
    File.binwrite(File.join(afl_dir, "swar/queue/id:000000,time:0,execs:0,orig:swar_1"), "\x00\x00\x00\x00def foo; 42; end\n".b)
    File.binwrite(File.join(afl_dir, "pdiff/queue/id:000000,time:0,execs:0,orig:pdiff_1"), "\x00\x00\x00\x00class Bar; end\n".b)

    raw = "\x00\x00\x00\x00puts :oracle32\n".b
    oracle = "PRISM\x00\x00\x00\x00payload".b
    pm64_env = [0x504D3634, oracle.bytesize].pack("V2") + oracle + raw
    File.binwrite(File.join(afl_dir, "arm32/queue/id:000000,time:0,execs:0,orig:arm32_1"), pm64_env)
  end

  def build_triage_fixture!(triage_dir)
    FileUtils.mkdir_p([File.join(triage_dir, "ABRT", "b_rel"), File.join(triage_dir, "ABRT", "b_main")])
    meta = {
      "schema_version" => 1,
      "versions" => {
        "fuzz" => {
          "prism" => { "version" => "1.9.0", "git_short" => "abc123456" },
          "ruby_parse_y" => { "version" => "4.1.0dev", "revision" => "72d4cf2e9a1234567890" }
        }
      },
      "buckets" => [
        {
          "bucket_id" => "ABRT/b_rel",
          "reason" => "ABRT",
          "signature" => "b_rel",
          "reproducible" => true,
          "timed_out" => false,
          "reproduced_by" => "vs_release",
          "verify_profile" => "diff_prism",
          "target" => { "id" => "vs_release", "shape" => "prism_diff_prism", "sources" => { "prism_a" => "release", "prism_b" => "pr" } },
          "occurrences" => { "count" => 2, "first_seen" => "2026-11-21T10:00:00Z", "last_seen" => "2026-11-21T10:01:00Z", "by_worker" => { "rel-diff" => 2 } },
          "input" => { "min_path" => "input.min", "min_size_bytes" => 10, "source_preview" => "1 + 2" },
          "options" => { "header_hex" => "00000301", "ruby_version" => "4.1" },
          "symptom" => { "headline" => "INVARIANT[diff_prism]: kind=error_mismatch sub=count a=0 b=1", "invariant" => { "namespace" => "diff_prism", "fields" => { "kind" => "error_mismatch", "sub" => "count" } } },
          "frames" => [{ "depth" => 0, "scope" => "harness", "func" => "prism_diff_fail", "file" => "harnesses/prism/prism_diff.c", "line" => 25 }]
        },
        {
          "bucket_id" => "ABRT/b_main",
          "reason" => "ABRT",
          "signature" => "b_main",
          "reproducible" => true,
          "timed_out" => false,
          "reproduced_by" => "vs_main",
          "verify_profile" => "diff_prism",
          "target" => { "id" => "vs_main", "shape" => "prism_diff_prism", "sources" => { "prism_a" => "main", "prism_b" => "pr" } },
          "occurrences" => { "count" => 2, "first_seen" => "2026-11-21T10:00:00Z", "last_seen" => "2026-11-21T10:01:00Z", "by_worker" => { "cur-diff" => 2 } },
          "input" => { "min_path" => "input.min", "min_size_bytes" => 10, "source_preview" => "1 + 2" },
          "options" => { "header_hex" => "00000301", "ruby_version" => "4.1" },
          "symptom" => { "headline" => "INVARIANT[diff_prism]: kind=error_mismatch sub=count a=0 b=1", "invariant" => { "namespace" => "diff_prism", "fields" => { "kind" => "error_mismatch", "sub" => "count" } } },
          "frames" => [{ "depth" => 0, "scope" => "harness", "func" => "prism_diff_fail", "file" => "harnesses/prism/prism_diff.c", "line" => 25 }]
        }
      ]
    }
    meta_path = File.join(triage_dir, "metadata.json")
    clusters_path = File.join(triage_dir, "clusters.json")
    File.write(meta_path, JSON.pretty_generate(meta))
    assert_ruby_cmd(repo_path("triage", "cluster.rb"), "--metadata", meta_path, "--output", clusters_path, "--quiet")
  end

  def read_pty_during
    master, slave = PTY.open
    buf = +""
    reader = Thread.new do
      loop { buf << master.readpartial(4096) }
    rescue EOFError, Errno::EIO
      nil
    end
    begin
      yield slave
    ensure
      slave.close unless slave.closed?
      reader.join(5)
      master.close unless master.closed?
    end
    buf
  end

  # [8/8] isolated workspace paths, sync/plan/dry-run routing, explain/worktree, docker mounts, ps/stats
  def test_isolated_workspace_paths_sync_plan_and_routing
    with_tmpdir("ws-isolated-") do |workdir|
      with_clean_ws_env do
        upstream = PrismFuzzerTest::Fixtures.build_synthetic_upstream_prism(File.join(workdir, "upstream"))
        good_ruby = PrismFuzzerTest::Fixtures.build_good_ruby_dir(File.join(workdir, "good_ruby"))
        cache_dir = File.join(workdir, "cache")
        ws_root = File.join(workdir, "ws_isolated")
        ws_topo = File.join(workdir, "ws_campaign.rb")
        w1_id = :"ws_w1_#{Process.pid}"

        write_ws_campaign(ws_topo, ws_root: ws_root, upstream: upstream[:repo], prism_ref: upstream[:v1], ruby_dir: good_ruby, worker_id: w1_id)

        assert_cmd(ws_topo, "validate", env: CLEAN_WS_ENV)

        ws_paths_out, = assert_ruby_cmd(topo_cli, "paths", "--topology", ws_topo, "--json", env: CLEAN_WS_ENV)
        paths = JSON.parse(ws_paths_out)
        ws = File.expand_path(ws_root)
        assert_equal ws, paths["WORKSPACE_DIR"]
        assert_equal File.join(ws, "build"), paths["WORKSPACE_BUILD_DIR"]
        assert_equal File.join(ws, "afl-ws"), paths["WORKSPACE_AFL_DIR"]
        assert_equal File.join(ws, "report"), paths["WORKSPACE_REPORT_DIR"]
        assert_equal File.join(ws, "report", "triage"), paths["WORKSPACE_TRIAGE_DIR"]
        assert_equal File.join(ws, "report", "coverage"), paths["WORKSPACE_COVERAGE_DIR"]
        assert_equal File.join(ws, "logs"), paths["WORKSPACE_LOGS_DIR"]
        assert_equal File.join(ws, "corpus"), paths["WORKSPACE_CORPUS_DIR"]

        # First sync populates cache mirror from local upstream repo; second sync verifies TARGETS_OFFLINE=1.
        assert_ruby_cmd(topo_cli, "sync", "--topology", ws_topo, "--cache-dir", cache_dir, "--json", env: CLEAN_WS_ENV)
        assert_ruby_cmd(topo_cli, "sync", "--topology", ws_topo, "--cache-dir", cache_dir, "--json", env: CLEAN_WS_ENV.merge("TARGETS_OFFLINE" => "1"))
        assert_path_exists File.join(ws_root, "build", "topology.resolved.json")
        assert_path_exists File.join(ws_root, "build", "targets", "prism_a", "include", "prism.h")

        dry_out, = assert_ruby_cmd(topo_cli, "build", "--topology", ws_topo, "--dry-run", env: CLEAN_WS_ENV)
        assert_includes dry_out, "-o #{ws_root}/build/ws_fuzz "
        assert_includes dry_out, "--oracle-dir #{ws_root}/build/diff-oracle"

        with_env("TOPOLOGY" => ws_topo) do
          opts, = FuzzExplain.parse_options(["-e", "1"])
          assert_equal File.join(ws, "build", "fuzz.explain"), opts[:explain_bin]
        end

        wt_out, = assert_cmd(repo_path("triage", "target_worktree.sh"), upstream[:v1], env: CLEAN_WS_ENV.merge("TOPOLOGY" => ws_topo))
        assert_equal File.join(ws, "build", ".fuzz-target-worktree"), wt_out.chomp

        ws_d_args, = assert_ruby_cmd(topo_cli, "docker-args", "--topology", ws_topo, env: CLEAN_WS_ENV)
        assert_includes ws_d_args, "/external/ws_dir"
        assert_includes ws_d_args, "/external/ws_build_dir"

        FileUtils.mkdir_p([File.join(ws_root, "bin"), File.join(ws_root, "corpus")])
        File.binwrite(File.join(ws_root, "corpus", "seed1"), seed_bytes("1 + 1\n"))
        write_executable(File.join(ws_root, "bin", "ws_fuzz"), "#!/bin/sh\nexit 0\n")

        g_id = :"g_custom_#{Process.pid}"
        m_id = :"custom_master_#{Process.pid}"
        begin
          ws_launch_out, = assert_ruby_cmd(topo_cli, "plan-launch", "--topology", ws_topo, env: CLEAN_WS_ENV)
          lp = JSON.parse(ws_launch_out)
          assert_equal File.join(ws, "afl-ws"), lp["primary_afl_dir"]
          assert_includes lp.dig("workers", 0, "cmd"), File.join(ws, "afl-ws")

          ws_gram_root = File.join(workdir, "ws_gram")
          FileUtils.mkdir_p([File.join(ws_gram_root, "bin"), File.join(ws_gram_root, "corpus")])
          FileUtils.cp(File.join(ws_root, "corpus", "seed1"), File.join(ws_gram_root, "corpus", "seed1"))
          FileUtils.cp(File.join(ws_root, "bin", "ws_fuzz"), File.join(ws_gram_root, "bin", "ws_fuzz"))
          File.chmod(0o755, File.join(ws_gram_root, "bin", "ws_fuzz"))

          ws_gram_topo = File.join(workdir, "ws_grammar_campaign.rb")
          gram_seeds = File.join(workdir, "gram_seeds")
          File.write(ws_gram_topo, <<~RB)
            #!/usr/bin/env ruby
            require #{File.join(root_dir, "lib", "prism_fuzzer").dump}

            PrismFuzzer.campaign "isolated-ws-grammar-test" do
              workspace #{ws_gram_root.dump}
              prism :prism_a, repo: #{upstream[:repo].dump}, dir: #{File.join(ws_root, "build", "targets", "prism_a").dump}, patches: "none", templates: "never"
              fuzzer "ws_fuzz", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
              grammar_generator :gram_custom, source: :prism_a, fuzzer: "ws_fuzz", sync_group: :afl, seeds_dir: #{gram_seeds.dump}
              sync_group :afl, dir: "afl-ws", primary: true
              sync_group :intake_sg, dir: "afl-intake"
              worker #{g_id.inspect}, kind: :generator, generator: :gram_custom
              worker #{m_id.inspect}, fuzzer: "ws_fuzz", sync_group: :intake_sg, afl_role: :main, foreign_sync: [:gram_custom], schedule: "fast"
            end
          RB

          assert_ruby_cmd(topo_cli, "sync", "--topology", ws_gram_topo, "--cache-dir", cache_dir, env: CLEAN_WS_ENV.merge("TARGETS_OFFLINE" => "1"))
          gram_launch_out, = assert_ruby_cmd(topo_cli, "plan-launch", "--topology", ws_gram_topo, env: CLEAN_WS_ENV)
          gram_lp = JSON.parse(gram_launch_out)
          by_id = gram_lp.fetch("workers").each_with_object({}) { |w, h| h[w.fetch("id")] = w }
          expected_stats = File.join(File.expand_path(ws_gram_root), "afl-intake", m_id.to_s, "fuzzer_stats")

          g_inner = Shellwords.split(by_id.fetch(g_id.to_s).fetch("cmd")).last
          assert_includes g_inner, "FUZZ_GRAMMAR_WORKER_ID=#{g_id}"
          assert_includes g_inner, "FUZZ_GRAMMAR_BIN=ws_fuzz"
          assert_includes g_inner, "FUZZ_INTAKE_STATS_PATH=#{expected_stats}"

          m_inner = Shellwords.split(by_id.fetch(m_id.to_s).fetch("cmd")).last
          assert_includes m_inner, "-M #{m_id}"
          assert_includes m_inner, "-F #{gram_seeds}"
        ensure
          [w1_id, g_id, m_id].each { |wid| FileUtils.rm_rf(File.join("/tmp/afl-tmpdir", wid.to_s)) }
        end

        ps_out, = assert_cmd(ws_topo, "ps", "--json", env: CLEAN_WS_ENV)
        assert_kind_of Array, JSON.parse(ps_out)

        stats_out, = assert_cmd(ws_topo, "stats", "--json", env: CLEAN_WS_ENV)
        st = JSON.parse(stats_out)
        assert_equal "isolated-ws-test", st["campaign"]
        assert_equal ws, st.dig("workspace", "fuzz_dir")
        assert_kind_of Hash, st["fleet"]
      end
    end
  end

  def test_attach_command_and_run_stop_dry_runs
    with_tmpdir("ws-dry-run-") do |workdir|
      upstream = PrismFuzzerTest::Fixtures.build_synthetic_upstream_prism(File.join(workdir, "upstream"))
      good_ruby = PrismFuzzerTest::Fixtures.build_good_ruby_dir(File.join(workdir, "good_ruby"))
      ws_root = File.join(workdir, "ws_isolated")
      ws_topo = File.join(workdir, "ws_campaign.rb")
      write_ws_campaign(ws_topo, ws_root: ws_root, upstream: upstream[:repo], prism_ref: upstream[:v1], ruby_dir: good_ruby)

      attach_out, = assert_cmd(ws_topo, "attach", "--dry-run", env: CLEAN_WS_ENV)
      attach_cmd = attach_out.chomp
      assert_match(/\Adocker exec -it prism-fuzzer-isolated-ws-test-[0-9a-f]{6} tmux -2 attach-session -t fuzzer\z/, attach_cmd)

      attach_override, = assert_cmd(ws_topo, "attach", "--dry-run", "--fuzz-dir", File.join(workdir, "ws_other"), env: CLEAN_WS_ENV)
      refute_equal attach_cmd, attach_override.chomp

      dry_campaign, = assert_cmd(ws_topo, "run", "--dry-run", "--skip-build", env: CLEAN_WS_ENV)
      assert_match(/triage\.rb/, dry_campaign)
      assert_match(/coverage\.sh/, dry_campaign)
      assert_match(/report\.rb/, dry_campaign)
      assert_includes dry_campaign, "--sankey-top 10"
      assert_match(/publish\.rb/, dry_campaign)
      assert_includes dry_campaign, "--run-id iso-01"

      dry_stop, = assert_cmd(ws_topo, "stop", "--dry-run", env: CLEAN_WS_ENV)
      assert_includes dry_stop, "docker stop -t 30 "
      assert_match(/triage\.rb/, dry_stop)
      assert_match(/coverage\.sh/, dry_stop)
      assert_match(/report\.rb/, dry_stop)
      assert_match(/publish\.rb/, dry_stop)

      dry_stop_nopost, = assert_cmd(ws_topo, "stop", "--no-post", "--dry-run", env: CLEAN_WS_ENV)
      assert_includes dry_stop_nopost, "docker stop -t 30 "
      refute_match(/triage\.rb|coverage\.sh|report\.rb|publish\.rb/, dry_stop_nopost)
    end
  end

  def test_stop_lifecycle_flock_imperative_and_timed_tty
    with_tmpdir("ws-lifecycle-") do |workdir|
      with_clean_ws_env do
        camp = File.join(workdir, "stop_lifecycle_camp.rb")
        ws_dir = File.join(workdir, "stop_lifecycle_ws")
        File.write(camp, <<~RB)
          require #{File.join(root_dir, "lib", "prism_fuzzer").dump}
          c = PrismFuzzer.campaign "stop-lifecycle-test" do
            workspace #{ws_dir.dump}
            after_run { report threads: 2 }
            prism :prism_a, repo: "https://example.invalid/prism.git", ref: "deadbeef", patches: "none", templates: "never"
            fuzzer "ws_fuzz", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
            sync_group :afl, dir: "afl", primary: true
            worker :w1, fuzzer: "ws_fuzz", sync_group: :afl, afl_role: :main, schedule: "fast"
          end
          c
        RB

        # 1. Detached launch with CLI overrides (--publish --run-id) persists lifecycle for `stop`
        ctx_det = PrismFuzzer::Campaign.resolve_context(
          campaign_path: camp,
          cli: { post: true, publish: true, publish_run_id: "det-01" },
          fuzz_root: root_dir
        )
        PrismFuzzer::Campaign.write_run_state!(ctx_det, lifecycle: ctx_det[:lifecycle], post_handled: false)
        stop_ctx = PrismFuzzer::Campaign.resolve_stop_context(PrismFuzzer::Campaign.resolve_context(campaign_path: camp, fuzz_root: root_dir), {})
        assert_equal "det-01", stop_ctx[:lifecycle].dig("publish", "run_id")

        nopost_stop_ctx = PrismFuzzer::Campaign.resolve_stop_context(stop_ctx, { no_post: true })
        refute PrismFuzzer::Campaign.any_post_steps?(nopost_stop_ctx[:lifecycle])

        # 2. Stub container stop & post pipeline to verify stop_campaign! runs post once and avoids duplicate runs
        post_calls = []
        run_calls = []
        running = true
        with_singleton_stubs([
          [PrismFuzzer::Campaign, :stop_container!, ->(_name, timeout: 30) { running ? (running = false; true) : false }],
          [PrismFuzzer::Campaign, :run_post_pipeline!, ->(c, dry_run: false) { post_calls << [c[:lifecycle].dup, dry_run] }],
          [PrismFuzzer::Campaign, :print_stats_summary, ->(_c, _s = nil) { nil }],
          [PrismFuzzer::Campaign, :run_campaign!, ->(c, detach: false, dry_run: false, skip_sync: false, skip_build: false, run_post: true) {
            run_calls << [run_post, PrismFuzzer::Campaign.any_post_steps?(c[:lifecycle])]
            PrismFuzzer::Campaign.write_run_state!(c, lifecycle: c[:lifecycle], post_handled: false)
            0
          }]
        ]) do
          base_ctx = PrismFuzzer::Campaign.resolve_context(campaign_path: camp, fuzz_root: root_dir)
          capture_io do
            assert_equal true, PrismFuzzer::Campaign.stop_campaign!(base_ctx)
          end
          assert_equal 1, post_calls.size
          assert_equal "det-01", post_calls[0][0].dig("publish", "run_id")

          # Repeated stop when container is already stopped must not re-run post steps
          capture_io do
            assert_equal false, PrismFuzzer::Campaign.stop_campaign!(base_ctx)
          end
          assert_equal 1, post_calls.size

          # Active foreground watcher holding flock suppresses duplicate post execution in stop_campaign!
          running = true
          PrismFuzzer::Campaign.write_run_state!(base_ctx, lifecycle: base_ctx[:lifecycle], post_handled: false)
          lock_ready_r, lock_ready_w = IO.pipe
          lock_done_r, lock_done_w = IO.pipe
          pid = Process.fork do
            lock_ready_r.close
            lock_done_w.close
            PrismFuzzer::Campaign.with_watcher_lock(base_ctx, blocking: true) do
              lock_ready_w.write("1")
              lock_ready_w.close
              lock_done_r.read
            end
            exit!(0)
          end
          lock_ready_w.close
          lock_done_r.close
          lock_ready_r.read(1)
          lock_ready_r.close
          begin
            capture_io { PrismFuzzer::Campaign.stop_campaign!(base_ctx) }
          ensure
            lock_done_w.close unless lock_done_w.closed?
            Process.wait(pid)
          end
          assert_equal 1, post_calls.size, "expected active watcher lock to prevent duplicate post call"

          # Imperative start! preserves after_run (run_post: false) and stop! invokes it when stopped
          inst = PrismFuzzer::Campaign::Instance.new(
            PrismFuzzer::CampaignDSL.compile_file(camp, fuzz_root: root_dir),
            source_path: camp
          )
          inst.start!(detach: true, skip_sync: true, skip_build: true)
          assert_equal [[false, true]], run_calls
          running = true
          capture_io { assert_equal true, inst.stop! }
          assert_equal 2, post_calls.size
        end

        # 3. Timed interactive TTY campaigns must attach to tmux and honor both expiry and Ctrl-B d detach
        attach_calls = []
        timed_post_calls = []
        tmux_alive = false
        timed_ctx = PrismFuzzer::Campaign.resolve_context(
          campaign_path: camp,
          cli: { duration_seconds: 60 },
          fuzz_root: root_dir
        )
        with_singleton_stubs([
          [PrismFuzzer::Campaign, :in_docker?, -> { false }],
          [PrismFuzzer::Campaign, :interactive_tty?, ->(**) { true }],
          [PrismFuzzer::Campaign, :build!, ->(*_a, **_kw) { nil }],
          [PrismFuzzer::Campaign, :start_detached_container!, ->(c) { ["deadbeef0001", PrismFuzzer::Campaign.write_run_state!(c, lifecycle: c[:lifecycle], post_handled: false)] }],
          [PrismFuzzer::Campaign, :attach_tmux_session!, ->(_c, duration_seconds: nil) {
            attach_calls << duration_seconds
            { expired: !tmux_alive, interrupted: false }
          }],
          [PrismFuzzer::Campaign, :tmux_session_alive?, ->(_n) { tmux_alive }],
          [PrismFuzzer::Campaign, :wait_for_container_exit, ->(_n, **_kw) { nil }],
          [PrismFuzzer::Campaign, :run_post_pipeline!, ->(c, dry_run: false) { timed_post_calls << [c[:lifecycle].dup, dry_run] }],
          [PrismFuzzer::Campaign, :print_stats_summary, ->(_c, _s = nil) { nil }]
        ]) do
          # Case A: Timer expires while attached -> triggers post pipeline
          tmux_alive = false
          capture_io { PrismFuzzer::Campaign.run_campaign!(timed_ctx, skip_sync: true, skip_build: true) }
          assert_equal [60], attach_calls
          assert_equal 1, timed_post_calls.size

          # Case B: User detaches with Ctrl-B d while timed -> returns to shell leaving post_handled=false
          tmux_alive = true
          capture_io { PrismFuzzer::Campaign.run_campaign!(timed_ctx, skip_sync: true, skip_build: true) }
          assert_equal [60, 60], attach_calls
          assert_equal 1, timed_post_calls.size
          st_after_det = PrismFuzzer::Campaign.read_run_state(timed_ctx)
          assert_equal false, st_after_det["post_handled"]
        end

        # 4. Direct SIGINT in untimed attach_tmux_session! / ensure_tmux_session! / in_docker? triggers container stop + post pipeline
        sig_ctx = PrismFuzzer::Campaign.resolve_context(campaign_path: camp, fuzz_root: root_dir)
        stop_calls = []
        sig_post_calls = []
        running_ctr = true
        with_singleton_stubs([
          [PrismFuzzer::Campaign, :in_docker?, -> { false }],
          [PrismFuzzer::Campaign, :interactive_tty?, ->(**) { true }],
          [PrismFuzzer::Campaign, :build!, ->(*_a, **_kw) { nil }],
          [PrismFuzzer::Campaign, :start_detached_container!, ->(c) { ["deadbeef0002", PrismFuzzer::Campaign.write_run_state!(c, lifecycle: c[:lifecycle], post_handled: false)] }],
          [PrismFuzzer::Campaign, :wait_for_tmux_session!, ->(_n, **_kw) { true }],
          [PrismFuzzer::Campaign, :container_running?, ->(_n) { running_ctr }],
          [PrismFuzzer::Campaign, :stop_container!, ->(n, **_kw) { stop_calls << n; running_ctr = false; true }],
          [PrismFuzzer::Campaign, :wait_for_container_exit, ->(_n, **_kw) { nil }],
          [PrismFuzzer::Campaign, :system, ->(*_cmd, **_kw) { Process.kill("INT", Process.pid); sleep 0.35; true }],
          [PrismFuzzer::Campaign, :run_post_pipeline!, ->(c, dry_run: false) { sig_post_calls << [c[:lifecycle].dup, dry_run] }],
          [PrismFuzzer::Campaign, :print_stats_summary, ->(_c, _s = nil) { nil }]
        ]) do
          out_int, = capture_io { PrismFuzzer::Campaign.run_campaign!(sig_ctx, skip_sync: true, skip_build: true) }
          assert_includes out_int, "Signal received; stopped campaign"
          assert_equal [sig_ctx[:container_name]], stop_calls
          assert_equal 1, sig_post_calls.size

          # Interrupting while waiting for tmux session startup aborts cleanly instead of raising CampaignError
          running_ctr = true
          abort_calls = []
          with_singleton_stubs([
            [PrismFuzzer::Campaign, :wait_for_tmux_session!, ->(_n, abort_if: nil, **_kw) { Process.kill("INT", Process.pid); sleep 0.05 until abort_if&.call; false }],
            [PrismFuzzer::Campaign, :stop_container!, ->(n, **_kw) { abort_calls << n; running_ctr = false; true }]
          ]) do
            attach_outcome = nil
            out_abort, = capture_io { attach_outcome = PrismFuzzer::Campaign.attach_tmux_session!(sig_ctx) }
            assert_equal [sig_ctx[:container_name]], abort_calls
            assert_equal({ expired: false, interrupted: true }, attach_outcome)
            refute_includes out_abort, "ready."
          end
        end

        in_docker_post_calls = []
        with_singleton_stubs([
          [PrismFuzzer::Campaign, :in_docker?, -> { true }],
          [PrismFuzzer::Campaign, :build!, ->(*_a, **_kw) { nil }],
          [PrismFuzzer::Campaign, :system, ->(*_args, **_kw) { Process.kill("INT", Process.pid); true }],
          [PrismFuzzer::Campaign, :run_post_pipeline!, ->(c, dry_run: false) { in_docker_post_calls << [c[:lifecycle].dup, dry_run] }],
          [PrismFuzzer::Campaign, :print_stats_summary, ->(_c, _s = nil) { nil }]
        ]) do
          PrismFuzzer::Campaign.run_campaign!(sig_ctx, skip_sync: true, skip_build: true)
          assert_equal 1, in_docker_post_calls.size
        end
      end
    end
  end

  def test_external_host_require_and_imperative_campaign
    with_tmpdir("ws-imperative-") do |workdir|
      upstream = PrismFuzzerTest::Fixtures.build_synthetic_upstream_prism(File.join(workdir, "upstream"))
      ws_root = File.join(workdir, "ws_isolated")

      ext_host_req = File.join(workdir, "external_host_req.rb")
      File.write(ext_host_req, <<~RB)
        #!/usr/bin/env ruby
        require "/nonexistent/host/prism-fuzzer/lib/prism_fuzzer"

        PrismFuzzer.campaign "external-host-req" do
          workspace #{ws_root.dump}
          prism :prism_a, repo: #{upstream[:repo].dump}, ref: #{upstream[:v1].dump}, patches: "auto", templates: "auto"
          fuzzer "ws_fuzz", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
          sync_group :afl, dir: "afl-ws", primary: true
          worker :w1, fuzzer: "ws_fuzz", sync_group: :afl, afl_role: :main, schedule: "fast"
        end
      RB
      assert_ruby_cmd(campaign_cli, "validate", ext_host_req, env: CLEAN_WS_ENV)

      ws_imp = File.join(workdir, "ws_imperative")
      imp_campaign = write_executable(File.join(workdir, "imperative_campaign.rb"), <<~RB)
        #!/usr/bin/env ruby
        require #{File.join(root_dir, "lib", "prism_fuzzer").dump}

        c = PrismFuzzer.campaign "imperative-test" do
          workspace #{ws_imp.dump}
          duration "15m"
          after_run { report threads: 2 }
          prism :prism_a, repo: #{upstream[:repo].dump}, ref: #{upstream[:v1].dump}, patches: "auto", templates: "auto"
          fuzzer "ws_fuzz", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
          sync_group :afl, dir: "afl", primary: true
          worker :w1, fuzzer: "ws_fuzz", sync_group: :afl, afl_role: :main, schedule: "fast"
        end

        c.validate!
        raise "expected distinct container_name" unless c.container_name.start_with?("prism-fuzzer-imperative-test-")
        puts JSON.generate("campaign" => c.stats["campaign"], "ws" => c.workspace[:fuzz_dir])
      RB

      imp_out, = assert_cmd(imp_campaign, env: CLEAN_WS_ENV)
      parsed = JSON.parse(imp_out)
      assert_equal "imperative-test", parsed["campaign"]
      assert_equal File.expand_path(ws_imp), parsed["ws"]
    end
  end

  def test_progress_ui_and_workspace_logs_cli
    with_tmpdir("ws-progress-logs-") do |workdir|
      ws_root = File.join(workdir, "ws_isolated")
      ws_topo = File.join(workdir, "ws_campaign.rb")
      write_ws_campaign(
        ws_topo,
        ws_root: ws_root,
        upstream: "https://example.invalid/prism.git",
        prism_ref: "deadbeef",
        ruby_dir: workdir
      )

      ok_log = File.join(ws_root, "logs", "sync.log")
      fail_log = File.join(ws_root, "logs", "build.log")

      tty_out = with_env("FUZZ_PROGRESS" => "tty", "CI" => nil) do
        read_pty_during do |slave|
          PrismFuzzer::Progress.stage("Sync targets", log_path: ok_log, display_log: "logs/sync.log", done_message: "Targets synced", io: slave) do |st|
            st.exec_stream("sh", "-c", "echo line-alpha; echo line-beta")
          end
        end
      end

      assert_includes tty_out, "\e[2K"
      assert_includes tty_out, "\e[?25l"
      assert tty_out.end_with?("\e[?25h\e[?2026l"), "expected cursor restore at end of TTY progress: #{tty_out.inspect}"
      assert_includes tty_out, "\e[?2026h"
      assert_includes tty_out, "\e[?2026l"
      assert_includes tty_out, "line-alpha"
      assert_includes tty_out, "Targets synced"

      int_buf = with_env("FUZZ_PROGRESS" => "tty", "CI" => nil) do
        read_pty_during do |int_slave|
          assert_raises(Interrupt) do
            PrismFuzzer::Progress.stage("Interrupted stage", io: int_slave) do |_st|
              raise Interrupt, "SIGINT"
            end
          end
        end
      end

      assert_includes int_buf, "\e[?25l"
      assert int_buf.end_with?("\e[?25h\e[?2026l"), "expected Interrupted TTY stage to restore cursor: #{int_buf.inspect}"

      ok_body = File.read(ok_log)
      assert_includes ok_body, "line-alpha"
      assert_includes ok_body, "DONE"

      err_io = StringIO.new
      with_env("FUZZ_PROGRESS" => "plain") do
        assert_raises(PrismFuzzer::Progress::StageCommandError) do
          PrismFuzzer::Progress.stage("Build fuzzers", log_path: fail_log, io: err_io) do |st|
            st.exec_stream("sh", "-c", "echo compiler-diagnostic-line >&2; exit 2")
          end
        end
      end

      err_text = err_io.string
      assert_includes err_text, "FAILED"
      assert_includes err_text, "compiler-diagnostic-line"
      assert_includes err_text, "Full log: #{fail_log}"
      assert_includes File.read(fail_log), "compiler-diagnostic-line"

      FileUtils.mkdir_p(File.join(ws_root, "logs", "workers"))
      File.write(File.join(ws_root, "logs", "workers", "main.log"), "\e[32mfuzzer running cleanly\e[0m\n")

      logs_json_out, = assert_cmd(ws_topo, "logs", "--json", env: CLEAN_WS_ENV)
      names = JSON.parse(logs_json_out).map { |x| x["name"] }
      assert_empty(%w[sync build workers/main] - names)

      build_log_out, = assert_cmd(ws_topo, "logs", "build", env: CLEAN_WS_ENV)
      assert_includes build_log_out, "compiler-diagnostic-line"

      worker_log_out, = assert_cmd(ws_topo, "logs", "worker", "main", env: CLEAN_WS_ENV)
      assert_match(/^fuzzer running cleanly$/, worker_log_out)
    end
  end

  def test_default_paths_multi_campaign_isolation_and_host_ir_split
    with_tmpdir("ws-iso-ir-") do |workdir|
      with_clean_ws_env do
        default_camp = repo_path("campaigns", "default.rb")
        def_paths_out, = assert_cmd(default_camp, "paths", "--json", env: CLEAN_WS_ENV)
        def_paths = JSON.parse(def_paths_out)
        expected_ws = File.join(root_dir, "tmp", "fuzz")
        assert_equal expected_ws, def_paths["WORKSPACE_DIR"]
        assert_equal File.join(expected_ws, "build"), def_paths["WORKSPACE_BUILD_DIR"]

        ovr_dir = File.join(workdir, "def_override")
        ovr_paths_out, = assert_cmd(default_camp, "paths", "--fuzz-dir", ovr_dir, "--json", env: CLEAN_WS_ENV)
        ovr_paths = JSON.parse(ovr_paths_out)
        assert_equal File.join(File.expand_path(ovr_dir), "build"), ovr_paths["WORKSPACE_BUILD_DIR"]

        upstream = PrismFuzzerTest::Fixtures.build_synthetic_upstream_prism(File.join(workdir, "upstream"))
        cache_dir = File.join(workdir, "cache")
        iso_a = File.join(workdir, "iso_a")
        iso_b = File.join(workdir, "iso_b")
        camp_a = File.join(workdir, "iso_a_campaign.rb")
        camp_b = File.join(workdir, "iso_b_campaign.rb")

        [[camp_a, "iso-a", iso_a, upstream[:v1]], [camp_b, "iso-b", iso_b, upstream[:v2]]].each do |path, cname, ws, sha|
          File.write(path, <<~RB)
            PrismFuzzer.campaign #{cname.dump} do
              workspace #{ws.dump}
              prism :prism_a, repo: #{upstream[:repo].dump}, ref: #{sha.dump}, patches: "auto", templates: "auto"
              fuzzer "iso_fuzz", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
              sync_group :afl, dir: "afl", primary: true
              worker :w1, fuzzer: "iso_fuzz", sync_group: :afl, afl_role: :main, schedule: "fast"
            end
          RB
        end

        assert_ruby_cmd(campaign_cli, "sync", camp_a, "--cache-dir", cache_dir, env: CLEAN_WS_ENV)
        assert_ruby_cmd(campaign_cli, "sync", camp_b, "--cache-dir", cache_dir, env: CLEAN_WS_ENV.merge("TARGETS_OFFLINE" => "1"))

        FileUtils.mkdir_p([File.join(iso_a, "triage"), File.join(iso_b, "triage"), File.join(iso_b, "bin")])

        topo_b = PrismFuzzer::Topology.discover(triage_dir: File.join(iso_b, "triage"), start_dir: root_dir)
        assert_equal upstream[:v2], topo_b&.dig("sources", "prism_a", "commit")

        bin_b = write_executable(File.join(iso_b, "build", "iso_fuzz"), "#!/bin/sh\nexit 0\n")
        resolved_fuzzers = FuzzMatcher.resolve_fuzzers(bins: [], triage_dir: File.join(iso_b, "triage"))
        assert resolved_fuzzers.any? { |f| f[:path] == File.expand_path(bin_b) }

        FuzzProvenance.write_build_manifest(File.join(iso_b, "build"), repo_root: root_dir)
        prov_b = FuzzProvenance.resolve_dir_provenance(File.join(iso_b, "build"), repo_root: root_dir, use_manifest: false)
        assert_equal upstream[:v2], prov_b.dig("prism", "git_commit")

        vers_b = PrismFuzzerPublish.resolve_versions(fuzz_root: root_dir, bin_dir: File.join(iso_b, "bin"), triage_dir: File.join(iso_b, "triage"))
        assert_equal upstream[:v2], vers_b.dig("prism_a", "commit")

        ctx_b = PrismFuzzer::Campaign.resolve_context(campaign_path: camp_b, fuzz_root: root_dir)
        obs_io = StringIO.new
        prev_stdout = $stdout
        $stdout = obs_io
        begin
          PrismFuzzer::Campaign.print_observe_commands(ctx_b)
        ensure
          $stdout = prev_stdout
        end
        obs_out = obs_io.string
        assert_includes obs_out, "Container : #{ctx_b[:container_name]}"
        %w[attach status logs stop].each { |sub| assert_includes obs_out, sub }
        refute_includes obs_out, "docker exec"
        refute_includes obs_out, "docker logs"

        # Host-runs-Ruby / container-sees-IR split
        count_log = File.join(workdir, "eval_once.count")
        camp_rb = File.join(workdir, "eval_once_campaign.rb")
        eval_ws = File.join(workdir, "eval_once_ws")
        File.write(camp_rb, <<~RB)
          File.open(#{count_log.dump}, "a") { |f| f.puts("eval") }
          ws_suffix = File.readlines(#{count_log.dump}).size
          PrismFuzzer.campaign "host-ir-split" do
            workspace "#{eval_ws}/run-\#{ws_suffix}"
            prism :prism_a, repo: "https://example.invalid/prism.git", dir: #{File.join(iso_a, "build", "targets", "prism_a").dump}, patches: "none", templates: "never"
            fuzzer "split_fuzz", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
            sync_group :afl, dir: "afl", primary: true
            worker :w1, fuzzer: "split_fuzz", sync_group: :afl, afl_role: :main, schedule: "fast"
          end
        RB

        ctx = PrismFuzzer::Campaign.resolve_context(campaign_path: camp_rb, fuzz_root: root_dir)
        assert_equal 1, File.readlines(count_log).size
        assert_equal "run-1", File.basename(ctx[:ws][:fuzz_dir])

        dcmd = PrismFuzzer::Campaign.docker_cmd_for(ctx, ["/bin/bash", "-c", "exec ./runtime/run.sh"], detach: true, name: ctx[:container_name])
        assert_includes dcmd, "prism_fuzzer.campaign_file=#{File.expand_path(camp_rb)}"
        refute dcmd.any? { |t| t.include?("/external/campaign.rb") }
        assert_includes dcmd, "CAMPAIGN=/external/ws_build_dir/topology.ir.json"
        assert_includes dcmd, "TOPOLOGY=/external/ws_build_dir/topology.ir.json"

        dry_ir = PrismFuzzer::Campaign.ir_snapshot_host_path(ctx)
        PrismFuzzer::Campaign.write_container_ir!(ctx, dry_run: true)
        refute_path_exists dry_ir

        ir_host = PrismFuzzer::Campaign.write_container_ir!(ctx, dry_run: false)
        assert_path_exists ir_host

        ir_loaded, = PrismFuzzer::Topology.load_ir(ir_host, fuzz_root: root_dir)
        assert_equal ctx[:ws][:fuzz_dir], File.expand_path(ir_loaded.dig("workspace", "dir"), root_dir)

        assert_ruby_cmd(topo_cli, "paths", "--json", env: CLEAN_WS_ENV.merge("CAMPAIGN" => ir_host, "TOPOLOGY" => ir_host))

        disc_plan = PrismFuzzer::Topology.discover(topology_path: ir_host, start_dir: root_dir)
        assert disc_plan&.dig("fuzzers", "split_fuzz", "verify_profile")

        synced = PrismFuzzer::Topology.sync_plan!(ctx[:plan], fuzz_root: root_dir, build_dir: ctx[:ws][:build_dir], cache_dir: cache_dir)
        disc_resolved = PrismFuzzer::Topology.discover(topology_path: ir_host, start_dir: root_dir)
        assert_equal synced.dig("sources", "prism_a", "commit"), disc_resolved&.dig("sources", "prism_a", "commit")

        assert_ruby_cmd(campaign_cli, "build", "--in-container-step", "--skip-sync", "--campaign", ir_host, "--dry-run", env: CLEAN_WS_ENV)
        assert_equal 1, File.readlines(count_log).size, "campaign.rb must not be re-evaluated by IR consumers"

        ovr_ws = File.join(workdir, "cli_ws_override")
        ctx_ovr = PrismFuzzer::Campaign.resolve_context(campaign_path: default_camp, cli: { fuzz_dir: ovr_ws }, fuzz_root: root_dir)
        dcmd_ovr = PrismFuzzer::Campaign.docker_cmd_for(ctx_ovr, ["./runtime/run.sh"], detach: true, name: ctx_ovr[:container_name])
        assert_includes dcmd_ovr, "#{ovr_ws}:/external/ws_dir"
        assert_includes dcmd_ovr, "#{File.join(ovr_ws, "build")}:/external/ws_build_dir"
        assert_includes dcmd_ovr, "CAMPAIGN=/external/ws_build_dir/topology.ir.json"

        ir_ovr_host = PrismFuzzer::Campaign.write_container_ir!(ctx_ovr, dry_run: false)
        ir_ovr = JSON.parse(File.read(ir_ovr_host))
        assert_equal ovr_ws, ir_ovr.dig("workspace", "dir")

        clean_msg, = assert_cmd(default_camp, "clean", "--dry-run", env: CLEAN_WS_ENV)
        assert_includes clean_msg, "preserving report/triage/, build/"
      end
    end
  end

  # [9/9] (source, target) coverage pair resolution, cross-oracle PM64 unwrap, real coverage replay, report & publish
  def test_coverage_pair_resolution
    with_tmpdir("cov-pairs-") do |workdir|
      with_clean_ws_env do
        cov_ws = File.join(workdir, "cov_pairs_ws")
        cov_topo = File.join(workdir, "cov_pairs_campaign.rb")
        write_cov_pairs_campaign(
          cov_topo,
          ws_root: cov_ws,
          prism_a_dir: File.join(workdir, "prism_a"),
          prism_b_dir: File.join(workdir, "prism_b")
        )

        ir, = PrismFuzzer::Topology.load_ir(cov_topo, fuzz_root: root_dir)
        plan = PrismFuzzer::Topology.compile_plan(ir, fuzz_root: root_dir)
        pairs = PrismFuzzer::Topology.coverage_pairs(plan, fuzz_root: root_dir)
        assert_equal %w[prism_a__native prism_a__swar prism_b__native], pairs.map { |p| p["id"] }

        a_native = pairs.find { |p| p["id"] == "prism_a__native" }
        assert_equal %w[arm32 main pdiff slow], a_native["workers"].sort
        assert_equal ["arm32"], a_native["cross_oracle_workers"]

        a_swar = pairs.find { |p| p["id"] == "prism_a__swar" }
        assert_equal ["swar"], a_swar["workers"]
        assert_equal ["-DPRISM_ACCEL_SWAR"], a_swar["cflags"]

        b_native = pairs.find { |p| p["id"] == "prism_b__native" }
        assert_equal ["pdiff"], b_native["workers"]

        wp = PrismFuzzer::Topology.worker_coverage_pairs(plan, fuzz_root: root_dir)
        assert_equal ["prism_a__native"], wp["main"]
        assert_equal ["prism_a__native"], wp["slow"]
        assert_equal ["prism_a__native"], wp["arm32"]
        assert_equal ["prism_a__swar"], wp["swar"]
        assert_equal %w[prism_a__native prism_b__native], wp["pdiff"]
      end
    end
  end

  def test_multi_sync_group_report_attributes_secondaries_to_group_masters
    require_relative "../../report/report"

    with_tmpdir("report-multi-master-") do |workdir|
      ws_dir = File.join(workdir, "ws")
      afl_ijon_dir = File.join(ws_dir, "afl-ijon")
      afl_cfg_dir = File.join(ws_dir, "afl")
      camp = File.join(workdir, "ijon_multi.rb")

      File.write(camp, <<~RB)
        PrismFuzzer.campaign "multi-master-report-test" do
          workspace #{ws_dir.dump}
          prism :prism_a, repo: "https://example.invalid/prism.git", dir: #{workdir.dump}, patches: "none", templates: "never"
          grammar_generator :grammar, source: :prism_a, fuzzer: "fuzz.ijon", sync_group: "afl-ijon", seeds_dir: #{File.join(workdir, "gseeds").dump}
          fuzzer "fuzz.ijon",      shape: :prism_parse, source: :prism_a, sanitizers: [],             mode: :fast, afl: :lto, ijon: true
          fuzzer "fuzz.ijon.asan", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto, ijon: true
          fuzzer "fuzz",           shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
          sync_group "afl-ijon", dir: "afl-ijon", primary: true
          sync_group :afl,       dir: "afl"

          worker :grammar, kind: :generator, generator: :grammar
          worker :"ijon-scout", fuzzer: "fuzz.ijon", sync_group: "afl-ijon", afl_role: :main, schedule: "explore" do
            foreign_sync :grammar
            peer_import group: :afl, worker: :main, alias: "cfg_peer"
          end
          worker :"ijon-asan", fuzzer: "fuzz.ijon.asan", sync_group: "afl-ijon", afl_role: :secondary, schedule: "exploit"
          worker :main, fuzzer: "fuzz", sync_group: :afl, afl_role: :main, schedule: "exploit" do
            peer_import group: "afl-ijon", worker: :"ijon-scout", alias: "ijon_scout_peer"
            peer_import group: "afl-ijon", worker: :"ijon-asan",  alias: "ijon_asan_peer"
          end
          worker :cfg_sec, fuzzer: "fuzz", sync_group: :afl, afl_role: :secondary, schedule: "fast"
        end
      RB

      ir, = PrismFuzzer::Topology.load_ir(camp, fuzz_root: root_dir)
      topo = PrismFuzzer::Topology.compile_plan(ir, fuzz_root: root_dir)

      write_worker = lambda do |root, name, count:, cmd:, queue_files:, cursors: {}|
        wdir = File.join(root, name)
        FileUtils.mkdir_p([File.join(wdir, "queue"), File.join(wdir, ".synced")])
        File.write(File.join(wdir, "fuzzer_stats"), <<~STATS)
          start_time    : 1700000000
          run_time      : 30
          execs_done    : 5000
          execs_per_sec : 166.0
          corpus_count  : #{count}
          bitmap_cvg    : 22.50%
          edges_found   : 45
          total_edges   : 200
          afl_banner    : #{name}
          command_line  : #{cmd}
        STATS
        queue_files.each { |fn| File.binwrite(File.join(wdir, "queue", fn), "\x00\x00\x03\x01x\n".b) }
        cursors.each { |k, v| File.binwrite(File.join(wdir, ".synced", k), [v].pack("V")) }
      end

      FileUtils.mkdir_p(File.join(afl_ijon_dir, "grammar"))
      File.write(File.join(afl_ijon_dir, "grammar/fuzzer_stats"), "fuzzer_role : generator\nfiles_created : 20\npending_files : 5\nrun_time : 30\n")

      # ijon-scout (-M of afl-ijon): imported 2 from ijon-asan, 1 from grammar, 1 from main via cfg_peer
      write_worker.call(
        afl_ijon_dir, "ijon-scout",
        count: 5,
        cmd: "afl-fuzz -M ijon-scout -- fuzz.ijon",
        queue_files: [
          "id:000000,orig:seed",
          "id:000001,sync:grammar,src:000001",
          "id:000002,sync:ijon-asan,src:000001",
          "id:000003,sync:ijon-asan,src:000002",
          "id:000004,sync:cfg_peer,src:000001"
        ],
        cursors: { "ijon-asan" => 4, "cfg_peer" => 3 }
      )

      # ijon-asan (-S of afl-ijon): 4 items (1 echoed from ijon-scout, 3 local); ijon-scout scanned all 4 (3 tested, 2 imported)
      write_worker.call(
        afl_ijon_dir, "ijon-asan",
        count: 4,
        cmd: "afl-fuzz -S ijon-asan -- fuzz.ijon.asan",
        queue_files: [
          "id:000000,sync:ijon-scout,src:000000",
          "id:000001,src:000000,op:havoc",
          "id:000002,src:000000,op:havoc",
          "id:000003,src:000000,op:havoc"
        ],
        cursors: { "ijon-scout" => 5 }
      )

      # main (-M of afl): imported 2 from cfg_sec, 1 from ijon-scout, 0 from ijon-asan (tested only 2 via ijon_asan_peer!)
      write_worker.call(
        afl_cfg_dir, "main",
        count: 4,
        cmd: "afl-fuzz -M main -- fuzz",
        queue_files: [
          "id:000000,orig:seed",
          "id:000001,sync:cfg_sec,src:000000",
          "id:000002,sync:cfg_sec,src:000001",
          "id:000003,sync:ijon_scout_peer,src:000002"
        ],
        cursors: { "cfg_sec" => 3, "ijon_scout_peer" => 5, "ijon_asan_peer" => 2 }
      )

      # cfg_sec (-S of afl): 3 items, synced against main (not ijon-scout!)
      write_worker.call(
        afl_cfg_dir, "cfg_sec",
        count: 3,
        cmd: "afl-fuzz -S cfg_sec -- fuzz",
        queue_files: [
          "id:000000,orig:seed",
          "id:000001,src:000000,op:havoc",
          "id:000002,src:000000,op:havoc"
        ],
        cursors: { "main" => 4 }
      )

      topo_ctx = PrismFuzzerReport::Helpers.topology_context(topo)
      fleet = PrismFuzzerReport::StatsIngest.ingest_fuzzers(afl_ijon_dir, topo_ctx: topo_ctx)

      assert_equal "ijon-scout", fleet[:main_name]
      assert_nil fleet[:peer_sync_by_name]["ijon-scout"]

      # ijon-asan is secondary to ijon-scout (NOT main!)
      ps_ijon_asan = fleet[:peer_sync_by_name]["ijon-asan"]
      assert_equal "ijon-scout", ps_ijon_asan[:consumer_name]
      assert_equal :peer, ps_ijon_asan[:sync_mode]
      assert_equal 4, ps_ijon_asan[:cursor]
      assert_equal 1, ps_ijon_asan[:skipped_from_main]
      assert_equal 3, ps_ijon_asan[:tested_by_main]
      assert_equal 2, ps_ijon_asan[:imported_by_main]

      # cfg_sec is secondary to main (NOT ijon-scout!)
      ps_cfg_sec = fleet[:peer_sync_by_name]["cfg_sec"]
      assert_equal "main", ps_cfg_sec[:consumer_name]
      assert_equal :peer, ps_cfg_sec[:sync_mode]
      assert_equal 3, ps_cfg_sec[:tested_by_main]
      assert_equal 2, ps_cfg_sec[:imported_by_main]

      # main bridges into ijon-scout via cfg_peer, and cross-group peer_import_stats tracks ijon-scout -> main & ijon-asan -> main
      ps_main = fleet[:peer_sync_by_name]["main"]
      assert_equal "ijon-scout", ps_main[:consumer_name]
      assert_equal :shadow_peer, ps_main[:sync_mode]
      assert_equal 3, ps_main[:cursor]
      assert_equal 1, ps_main[:imported_by_main]

      bridge_scout_main = fleet[:peer_import_stats][["ijon-scout", "main"]]
      assert_equal 5, bridge_scout_main[:tested_by_main]
      assert_equal 1, bridge_scout_main[:imported_by_main]

      bridge_asan_main = fleet[:peer_import_stats][["ijon-asan", "main"]]
      assert_equal 2, bridge_asan_main[:tested_by_main]
      assert_equal 0, bridge_asan_main[:imported_by_main]

      out_html = File.join(ws_dir, "report", "index.html")
      PrismFuzzerReport.generate(afl_dir: afl_ijon_dir, out_path: out_html, triage_dir: File.join(ws_dir, "report", "triage"), topo: topo)
      html = File.read(out_html)
      sync_sec = html[%r{<div class="chart-card sync-overview-card">.*?</div>\s*<div class="table-card">}m].to_s

      assert_includes html, "Hub Coverage (ijon-scout)"
      assert_includes html, "Master Sync"
      assert_match(%r{<strong>ijon-asan</strong>\s*<span[^>]*>&rarr; ijon-scout</span>}, sync_sec)
      assert_match(%r{<strong>cfg_sec</strong>\s*<span[^>]*>&rarr; main</span>}, sync_sec)
      assert_match(%r{<strong>ijon-scout</strong>\s*<span[^>]*>&rarr; main \(peer\)</span>}, sync_sec)
      assert_match(%r{<strong>main</strong>\s*<span[^>]*>&rarr; ijon-scout \(peer\)</span>}, sync_sec)

      asan_tab = html[%r{<section id="tab-ijon-asan" class="tab-panel">.*?</section>}m]
      assert_includes asan_tab, "Sync to ijon-scout"
      assert_includes asan_tab, "Sync from ijon-scout"

      cfg_tab = html[%r{<section id="tab-cfg_sec" class="tab-panel">.*?</section>}m]
      assert_includes cfg_tab, "Sync to main"
      assert_includes cfg_tab, "Sync from main"
    end
  end

  def test_real_multi_pair_coverage_replay_report_publish_and_signal_safety
    skip "clang/llvm-profdata/llvm-cov unavailable" unless find_executable("clang") && find_executable("llvm-profdata") && find_executable("llvm-cov")

    real_prism_a = prism_a_dir
    skip "synced prism_a directory unavailable" unless real_prism_a

    with_tmpdir("cov-real-") do |workdir|
      with_clean_ws_env do
        real_ws = File.join(workdir, "cov_real_ws")
        real_topo = File.join(workdir, "cov_real_campaign.rb")
        FileUtils.mkdir_p([File.join(real_ws, "build", "targets", "gen"), File.join(real_ws, "afl")])
        populate_afl_cov_worker_dirs(File.join(real_ws, "afl"))

        write_cov_pairs_campaign(
          real_topo,
          ws_root: real_ws,
          prism_a_dir: real_prism_a,
          prism_b_dir: real_prism_a,
          name: "cov-real-test"
        )

        if (gen_a = prism_a_gen_dir)
          FileUtils.ln_s(gen_a, File.join(real_ws, "build", "targets", "gen", "prism_a"))
          FileUtils.ln_s(gen_a, File.join(real_ws, "build", "targets", "gen", "prism_b"))
        end

        ccache_test_dir = File.join(workdir, "cov_ccache")
        cov_env = CLEAN_WS_ENV.merge(
          "TOPOLOGY" => real_topo,
          "CAMPAIGN" => real_topo,
          "WORKSPACE_DIR" => real_ws,
          "WORKSPACE_BUILD_DIR" => File.join(real_ws, "build"),
          "WORKSPACE_AFL_DIR" => File.join(real_ws, "afl"),
          "WORKSPACE_REPORT_DIR" => File.join(real_ws, "report"),
          "WORKSPACE_COVERAGE_DIR" => File.join(real_ws, "report", "coverage"),
          "WORKSPACE_CORPUS_DIR" => File.join(real_ws, "corpus"),
          "CCACHE_DIR" => ccache_test_dir
        )
        assert_cmd(repo_path("report", "coverage.sh"), env: cov_env, chdir: root_dir)
        if find_executable("ccache")
          ccache_stats, = assert_cmd("ccache", "-s", env: { "CCACHE_DIR" => ccache_test_dir })
          assert_match(/Hits:\s+[1-9]\d*/, ccache_stats, "expected ccache hits across shared prism_a/prism_b coverage pairs:\n#{ccache_stats}")
          refute_match(/Uncacheable calls:\s+[1-9]/, ccache_stats, "expected zero uncacheable calls during coverage.sh:\n#{ccache_stats}")
        end

        cov_dir = File.join(real_ws, "report", "coverage")
        cov = JSON.parse(File.read(File.join(cov_dir, "coverage.json")))
        refute cov.key?("origins") || cov.key?("combined"), "unexpected legacy origins/combined key in coverage.json"
        assert_equal %w[prism_a__native prism_a__swar prism_b__native], cov.fetch("pairs").map { |p| p["id"] }

        cov["pairs"].each do |p|
          assert_equal true, p["has_coverage"], "pair #{p["id"]} missing coverage"
          assert_path_exists File.join(cov_dir, "pairs", p["id"], "report", "index.html")
          refute_empty p["files"], "pair #{p["id"]} has no files"
          p["files"].first(3).each do |fe|
            rel = fe["report_rel_path"].to_s.sub(%r{\Acoverage/}, "")
            assert_path_exists File.join(cov_dir, rel), "pair #{p["id"]} missing file report #{rel}"
            refute fe["filename"].start_with?("/"), "file entry has raw absolute path prefix: #{fe["filename"]}"
          end
          refute p["files"].any? { |f| f.key?("vs_corpus") || f.key?("exclusive") }
        end

        an = cov["pairs"].find { |p| p["id"] == "prism_a__native" }
        assert_equal 3, an["input_count"]
        assert_equal %w[prism_a__native prism_b__native], cov.dig("worker_pairs", "pdiff")

        # Regression check for harnesses/prism/coverage.c async-signal safety
        sig_stub = File.join(workdir, "cov_sig_stub.c")
        sig_bin = File.join(workdir, "cov_sig_bin")
        File.write(sig_stub, <<~C)
          #define _POSIX_C_SOURCE 200809L
          #include <signal.h>
          #include <stdint.h>
          #include <stdio.h>
          #include <string.h>
          #include <unistd.h>

          void harness(const uint8_t *input, size_t size) {
              if (size >= 5 && memcmp(input, "CRASH", 5) == 0) {
                  flockfile(stderr);
                  raise(SIGSEGV);
              } else if (size >= 4 && memcmp(input, "TERM", 4) == 0) {
                  raise(SIGTERM);
              }
          }
        C
        assert_cmd(
          "clang", "-O1", "-DPROFILE", "-fprofile-instr-generate", "-fcoverage-mapping", "-Wall", "-Werror",
          repo_path("harnesses", "prism", "coverage.c"), sig_stub, "-o", sig_bin
        )

        crash_in = File.join(workdir, "cov_crash.in")
        term_in = File.join(workdir, "cov_term.in")
        ok_in = File.join(workdir, "cov_ok.in")
        File.binwrite(crash_in, "CRASH")
        File.binwrite(term_in, "TERM")
        File.binwrite(ok_in, "OK")

        crash_profraw = File.join(workdir, "cov_crash.profraw")
        if find_executable("timeout")
          _out, _err, crash_st = run_cmd("timeout", "3s", sig_bin, crash_in, env: { "LLVM_PROFILE_FILE" => crash_profraw })
          assert_equal 139, crash_st.exitstatus, "expected coverage.c crash exit 139 without deadlock"
        else
          _out, _err, crash_st = run_cmd(sig_bin, crash_in, env: { "LLVM_PROFILE_FILE" => crash_profraw })
          assert crash_st.signaled? && crash_st.termsig == Signal.list["SEGV"], "expected SIGSEGV exit without deadlock"
        end

        term_profraw = File.join(workdir, "cov_term.profraw")
        FileUtils.rm_f(term_profraw)
        assert_cmd(sig_bin, term_in, ok_in, env: { "LLVM_PROFILE_FILE" => term_profraw })
        assert_path_exists term_profraw
        assert_operator File.size(term_profraw), :>, 0

        # Unified report output
        triage_fixture = File.join(workdir, "triage_fixture")
        build_triage_fixture!(triage_fixture)
        report_html_path = File.join(real_ws, "report", "index.html")
        assert_ruby_cmd(
          repo_path("report", "report.rb"),
          File.join(real_ws, "afl"),
          report_html_path,
          File.join(cov_dir, "coverage.json"),
          "--triage-dir", triage_fixture,
          env: CLEAN_WS_ENV.merge("TOPOLOGY" => real_topo, "CAMPAIGN" => real_topo)
        )

        html = File.read(report_html_path)
        %w[prism_a__native prism_a__swar prism_b__native].each do |pid|
          assert_includes html, "coverage/pairs/#{pid}/report/index.html"
        end
        refute_includes html, "Exclusive Worker Coverage"
        refute_includes html, "Gain vs. Corpus"
        refute_includes html, "Coverage by Origin"

        pdiff_sec = html[%r{<section id="tab-pdiff" class="tab-panel">.*?</section>}m]
        refute_nil pdiff_sec, "missing tab-pdiff section"
        assert_includes pdiff_sec, "coverage/pairs/prism_a__native/report/index.html"
        assert_includes pdiff_sec, "prism_a (native)"
        assert_includes pdiff_sec, "coverage/pairs/prism_b__native/report/index.html"
        assert_includes pdiff_sec, "prism_b (native)"
        refute_includes pdiff_sec, "Coverage: prism_a"
        refute_includes pdiff_sec, "Source Coverage ("

        nav_sec = html[%r{<nav class="tabs-bar">.*?</nav>}m]
        refute_nil nav_sec, "missing tabs-bar"
        assert_includes nav_sec, 'id="worker-tab-select"'
        assert_includes nav_sec, 'value="pdiff"'
        refute_includes nav_sec, 'data-tab="pdiff"'

        ov_sec = html[%r{<section id="tab-overview" class="tab-panel active">.*?</section>}m]
        refute_nil ov_sec, "missing tab-overview"
        assert_includes ov_sec, 'class="topo-svg"'
        assert_includes ov_sec, 'selectTab(&quot;pdiff&quot;)'
        assert_includes ov_sec, 'class="topo-context-strip"'
        assert_includes ov_sec, "queue sync"
        assert_includes ov_sec, "MASTER -M"

        g_pos = ov_sec.index('class="topo-groups"')
        e_pos = ov_sec.index('class="topo-edges"')
        n_pos = ov_sec.index('class="topo-nodes"')
        l_pos = ov_sec.index('class="topo-edge-labels"')
        assert g_pos && e_pos && n_pos && l_pos
        assert g_pos < e_pos && e_pos < n_pos && n_pos < l_pos

        %w[cov-pair-prism_a__native cov-pair-prism_a__swar cov-pair-prism_b__native].each do |cdom|
          assert_includes ov_sec, "jumpToCoveragePair('#{cdom}')"
        end
        refute_includes ov_sec, "3 Pairs)"

        topo_sec = html[%r{<section id="tab-topology" class="tab-panel">.*?</section>}m]
        refute_nil topo_sec, "missing tab-topology"
        raw_topo_json = topo_sec[%r{<pre id="topology-json-pre"[^>]*><code>(.*?)</code></pre>}m, 1]
        refute_nil raw_topo_json, "missing topology-json-pre"
        parsed_topo = JSON.parse(CGI.unescapeHTML(raw_topo_json))
        assert_equal "cov-real-test", parsed_topo["name"]
        assert parsed_topo.dig("fuzzers", "fuzz_ab")

        assert_includes html, 'id="tab-triage"'
        assert_includes html, 'id="tab-sankey"'
        assert_includes html, "sankey-root"

        # Publish manifest + all artifacts (including llvm-cov HTML and triage buckets)
        bucket_dir = File.join(real_ws, "report", "triage", "ABRT", "deadbeef")
        FileUtils.mkdir_p([bucket_dir, File.join(real_ws, "bin")])
        File.write(File.join(real_ws, "report", "triage", "metadata.json"), "{\"buckets\":[]}\n")
        File.write(File.join(real_ws, "report", "triage", "clusters.json"), "{\"clusters\":[]}\n")
        File.write(File.join(bucket_dir, "meta.json"), "{\"bucket_id\":\"ABRT/deadbeef\"}\n")
        File.write(File.join(bucket_dir, "input.min"), "x\n")
        File.write(File.join(bucket_dir, "verify.sh"), "#!/bin/sh\nexit 0\n")

        assert_ruby_cmd(
          repo_path("bin", "publish.rb"),
          "--run-id", "cov-pairs-01",
          "--report-dir", File.join(real_ws, "report"),
          "--triage-dir", File.join(real_ws, "report", "triage"),
          "--coverage-dir", cov_dir,
          "--bin-dir", File.join(real_ws, "bin"),
          "--out-dir", File.join(real_ws, "reports"),
          env: CLEAN_WS_ENV
        )

        manifest_path = File.join(real_ws, "reports", "runs", "cov-pairs-01", "manifest.json")
        manifest = JSON.parse(File.read(manifest_path))
        cov_pairs = manifest.dig("coverage", "pairs")
        refute_nil cov_pairs, "missing coverage.pairs in manifest.json"
        assert_equal %w[prism_a__native prism_a__swar prism_b__native], cov_pairs.keys.sort
        assert_equal "report/index.html", manifest.dig("artifacts", "report")
        assert_equal "report/triage/clusters.json", manifest.dig("artifacts", "clusters")
        assert_equal "report/coverage/pairs/prism_a__native/report/index.html", manifest.dig("artifacts", "coverage_html")

        pub_dir = File.dirname(manifest_path)
        assert_path_exists File.join(pub_dir, "report", "index.html")
        assert_path_exists File.join(pub_dir, "report", "triage", "clusters.json")
        assert_path_exists File.join(pub_dir, "report", "triage", "ABRT", "deadbeef", "meta.json")
        assert_path_exists File.join(pub_dir, "report", "triage", "ABRT", "deadbeef", "input.min")
        assert_path_exists File.join(pub_dir, "report", "triage", "ABRT", "deadbeef", "verify.sh")
        assert_path_exists File.join(pub_dir, "report", "coverage", "pairs", "prism_a__native", "summary.txt")
        assert_path_exists File.join(pub_dir, "report", "coverage", "pairs", "prism_a__native", "report", "index.html")
      end
    end
  end

  # [11/11] Campaign.run_coverage! cleans up .live-seeds.<pid>.tar across standard/custom layouts and failures
  def test_run_coverage_live_seeds_tar_cleanup
    with_tmpdir("cov-live-tar-") do |workdir|
      with_clean_ws_env do
        fake_root = File.join(workdir, "cov_fake_root")
        FileUtils.mkdir_p(fake_root)
        FileUtils.ln_s(repo_path("topology.schema.json"), File.join(fake_root, "topology.schema.json"))

        in_repo_camp = File.join(fake_root, "camp_in_repo.rb")
        File.write(in_repo_camp, <<~RB)
          PrismFuzzer.campaign "live-seeds-in-repo" do
            workspace "tmp/fuzz"
            prism :prism_a, repo: "https://example.invalid/prism.git", dir: "$WS_ROOT/build/targets/prism_a", patches: "none", templates: "never"
            fuzzer "fuzz", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
            sync_group :afl, dir: "afl", primary: true
            worker :w1, fuzzer: "fuzz", sync_group: :afl, afl_role: :main, schedule: "fast"
          end
        RB

        ext_ws = File.join(workdir, "cov_external_ws")
        ext_camp = File.join(fake_root, "camp_ext.rb")
        File.write(ext_camp, <<~RB)
          PrismFuzzer.campaign "live-seeds-ext" do
            workspace #{ext_ws.dump}
            prism :prism_a, repo: "https://example.invalid/prism.git", dir: "$WS_ROOT/build/targets/prism_a", patches: "none", templates: "never"
            fuzzer "fuzz", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
            sync_group :afl, dir: "afl", primary: true
            worker :w1, fuzzer: "fuzz", sync_group: :afl, afl_role: :main, schedule: "fast"
          end
        RB

        in_repo_ctx = PrismFuzzer::Campaign.resolve_context(campaign_path: in_repo_camp, fuzz_root: fake_root)
        ext_ctx = PrismFuzzer::Campaign.resolve_context(campaign_path: ext_camp, fuzz_root: fake_root)

        fake_status = Struct.new(:exitstatus) do
          def success?
            exitstatus == 0
          end
        end

        fake_in_docker = false
        raise_in_container = false
        seen_tar_envs = []
        seen_cov_modes = []
        seen_tar_existed = []
        fake_running = true
        orig_capture3 = Open3.method(:capture3)

        with_singleton_stubs([
          [PrismFuzzer::Campaign, :in_docker?, -> { fake_in_docker }],
          [PrismFuzzer::Campaign, :ensure_docker_image!, ->(**_kw) { "img-ok" }],
          [PrismFuzzer::Campaign, :container_running?, ->(_name) { fake_running }],
          [Open3, :capture3, ->(*args, **kw) {
            if args[0] == "docker" && args[1] == "exec"
              ["FAKE_TAR_BYTES", "", fake_status.new(0)]
            else
              orig_capture3.call(*args, **kw)
            end
          }],
          [PrismFuzzer::Campaign, :run_in_container!, ->(ctx, _cmd, extra_env: {}, **_kw) {
            tar_host = File.join(ctx[:ws][:fuzz_dir], ".live-seeds.#{Process.pid}.tar")
            seen_tar_existed << File.file?(tar_host)
            seen_tar_envs << extra_env["FUZZ_LIVE_SEEDS_TAR"]
            seen_cov_modes << [extra_env["FUZZ_COVERAGE_LIVE"], extra_env["FUZZ_COVERAGE_FINAL"]]
            raise PrismFuzzer::Campaign::CampaignError, "simulated coverage failure" if raise_in_container

            true
          }]
        ]) do
          with_env("FUZZ_PROGRESS" => "plain") do
            # 1. Host mode with workspace inside fuzz_root (live container -> FUZZ_COVERAGE_LIVE=1)
            fake_in_docker = false
            capture_io { PrismFuzzer::Campaign.run_coverage!(in_repo_ctx) }
            tar_in_repo = File.join(in_repo_ctx[:ws][:fuzz_dir], ".live-seeds.#{Process.pid}.tar")
            assert_equal [true], seen_tar_existed
            refute_path_exists tar_in_repo
            assert_equal "/prism-fuzzer/tmp/fuzz/.live-seeds.#{Process.pid}.tar", seen_tar_envs.last
            assert_equal ["1", nil], seen_cov_modes.last

            # 2. Host mode with workspace outside fuzz_root (/external/ws_dir)
            capture_io { PrismFuzzer::Campaign.run_coverage!(ext_ctx) }
            tar_ext = File.join(ext_ctx[:ws][:fuzz_dir], ".live-seeds.#{Process.pid}.tar")
            assert_equal [true, true], seen_tar_existed
            refute_path_exists tar_ext
            assert_equal "/external/ws_dir/.live-seeds.#{Process.pid}.tar", seen_tar_envs.last
            assert_equal ["1", nil], seen_cov_modes.last

            # 3. Ensure block cleans up host tar even when run_in_container! raises
            raise_in_container = true
            capture_io do
              assert_raises(PrismFuzzer::Campaign::CampaignError) do
                PrismFuzzer::Campaign.run_coverage!(in_repo_ctx)
              end
            end
            assert_equal [true, true, true], seen_tar_existed
            refute_path_exists tar_in_repo

            # 4. In-container mode preserves direct local tar path and cleans up
            raise_in_container = false
            fake_in_docker = true
            capture_io { PrismFuzzer::Campaign.run_coverage!(in_repo_ctx) }
            assert_equal [true, true, true, true], seen_tar_existed
            refute_path_exists tar_in_repo
            assert_equal tar_in_repo, seen_tar_envs.last
            assert_equal ["1", nil], seen_cov_modes.last

            # 5. Stopped container marks coverage run as final (FUZZ_COVERAGE_FINAL=1) and skips live tar capture
            fake_running = false
            fake_in_docker = false
            capture_io { PrismFuzzer::Campaign.run_coverage!(in_repo_ctx) }
            assert_equal [true, true, true, true, false], seen_tar_existed
            assert_nil seen_tar_envs.last
            assert_equal [nil, "1"], seen_cov_modes.last
          end
        end
      end
    end
  end

  def test_multi_grammar_funnel_report_attributes_imports_and_lineage_per_generator
    require_relative "../../report/report"

    with_tmpdir("report-multi-grammar-") do |workdir|
      ws_dir = File.join(workdir, "funnel_ws")
      afl_small_dir = File.join(ws_dir, "afl-small")
      afl_8k_dir = File.join(ws_dir, "afl-8k")
      seeds_256 = File.join(workdir, "seeds_256/seeds")
      seeds_8k = File.join(workdir, "seeds_8k/seeds")
      camp = File.join(workdir, "funnel.rb")

      FileUtils.mkdir_p([seeds_256, seeds_8k])
      File.binwrite(File.join(seeds_256, "aaa11111111111111111"), "\x00\x00\x03\x01small_1 = 1\n".b)
      File.binwrite(File.join(seeds_256, "bbb22222222222222222"), "\x00\x00\x03\x01small_2 = 2\n".b)
      File.binwrite(File.join(seeds_8k, "ccc33333333333333333"), "\x00\x00\x03\x01big_1 = 999999\n".b)

      File.write(camp, <<~RB)
        PrismFuzzer.campaign "multi-grammar-funnel-test" do
          workspace #{ws_dir.dump}
          prism :prism_a, repo: "https://example.invalid/prism.git", dir: #{workdir.dump}, patches: "none", templates: "never"
          grammar_generator :grammar_small, source: :prism_a, fuzzer: "fuzz", sync_group: "afl-small", seeds_dir: #{seeds_256.dump}
          grammar_generator :grammar_8k,    source: :prism_a, fuzzer: "fuzz", sync_group: "afl-8k",    seeds_dir: #{seeds_8k.dump}
          fuzzer "fuzz", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
          sync_group "afl-8k",    dir: "afl-8k",    primary: true
          sync_group "afl-small", dir: "afl-small"

          worker :"grammar-256", kind: :generator, generator: :grammar_small, color: "#34d399"
          worker :"grammar-8k",  kind: :generator, generator: :grammar_8k,    color: "#10b981"

          worker :"small-scout", fuzzer: "fuzz", sync_group: "afl-small", afl_role: :main, schedule: "explore" do
            foreign_sync :grammar_small
          end
          worker :"8k-main", fuzzer: "fuzz", sync_group: "afl-8k", afl_role: :main, schedule: "explore" do
            foreign_sync :grammar_8k
            peer_import group: "afl-small", worker: :"small-scout", alias: "small_scout_feed"
          end
          worker :"8k-slow", fuzzer: "fuzz", sync_group: "afl-8k", afl_role: :secondary, schedule: "exploit"
        end
      RB

      ir, = PrismFuzzer::Topology.load_ir(camp, fuzz_root: root_dir)
      topo = PrismFuzzer::Topology.compile_plan(ir, fuzz_root: root_dir)

      FileUtils.mkdir_p([
        File.join(afl_small_dir, "grammar-256"),
        File.join(afl_small_dir, "small-scout/queue"),
        File.join(afl_8k_dir, "grammar-8k"),
        File.join(afl_8k_dir, "8k-main/queue"),
        File.join(afl_8k_dir, "8k-slow/queue"),
        File.join(afl_8k_dir, "8k-slow/crashes")
      ])

      File.write(File.join(afl_small_dir, "grammar-256/fuzzer_stats"), "fuzzer_role : generator\nfiles_created : 100\npending_files : 10\nrun_time : 30\n")
      File.write(File.join(afl_8k_dir, "grammar-8k/fuzzer_stats"), "fuzzer_role : generator\nfiles_created : 80\npending_files : 5\nrun_time : 30\n")
      File.write(File.join(afl_small_dir, "small-scout/fuzzer_stats"), "start_time : 1700000000\nrun_time : 30\nexecs_done : 5000\ncorpus_count : 3\ncommand_line : afl-fuzz -M small-scout -- fuzz\n")
      File.write(File.join(afl_8k_dir, "8k-main/fuzzer_stats"), "start_time : 1700000000\nrun_time : 30\nexecs_done : 4000\ncorpus_count : 3\ncommand_line : afl-fuzz -M 8k-main -- fuzz\n")
      File.write(File.join(afl_8k_dir, "8k-slow/fuzzer_stats"), "start_time : 1700000000\nrun_time : 30\nexecs_done : 3000\ncorpus_count : 2\nsaved_crashes : 1\ncommand_line : afl-fuzz -S 8k-slow -- fuzz\n")

      # Both small-scout and 8k-main use AFL++'s basename-derived `sync:seeds_0` tag!
      File.binwrite(File.join(afl_small_dir, "small-scout/queue/id:000000,orig:seed"), "\x00\x00\x03\x01x\n".b)
      File.binwrite(File.join(afl_small_dir, "small-scout/queue/id:000001,sync:seeds_0,src:aaa11111111111111111,+cov"), "\x00\x00\x03\x01small_1 = 1\n".b)
      File.binwrite(File.join(afl_small_dir, "small-scout/queue/id:000002,sync:seeds_0,src:bbb22222222222222222,+cov"), "\x00\x00\x03\x01small_2 = 2\n".b)

      File.binwrite(File.join(afl_8k_dir, "8k-main/queue/id:000000,orig:seed"), "\x00\x00\x03\x01y\n".b)
      File.binwrite(File.join(afl_8k_dir, "8k-main/queue/id:000001,sync:seeds_0,src:ccc33333333333333333,+cov"), "\x00\x00\x03\x01big_1 = 999999\n".b)
      File.binwrite(File.join(afl_8k_dir, "8k-main/queue/id:000002,sync:small_scout_feed,src:000001,+cov"), "\x00\x00\x03\x01small_1 = 1\n".b)

      File.binwrite(File.join(afl_8k_dir, "8k-slow/queue/id:000000,sync:8k-main,src:000002"), "\x00\x00\x03\x01small_1 = 1\n".b)
      File.binwrite(File.join(afl_8k_dir, "8k-slow/queue/id:000001,sync:8k-main,src:000001"), "\x00\x00\x03\x01big_1 = 999999\n".b)
      File.binwrite(File.join(afl_8k_dir, "8k-slow/crashes/id:000000,sig:06,src:000000,op:havoc"), "\x00\x00\x03\x01small_1 = boom\n".b)

      out_html = File.join(ws_dir, "report/index.html")
      PrismFuzzerReport.generate(afl_dir: afl_8k_dir, out_path: out_html, triage_dir: File.join(ws_dir, "report/triage"), topo: topo)
      html = File.read(out_html)

      topo_ctx = PrismFuzzerReport::Helpers.topology_context(topo)
      fleet = PrismFuzzerReport::StatsIngest.ingest_fuzzers(afl_8k_dir, topo_ctx: topo_ctx)
      assert_equal 2, fleet[:peer_sync_by_name]["grammar-256"][:imported_by_main]
      assert_equal "small-scout", fleet[:peer_sync_by_name]["grammar-256"][:consumer_name]
      assert_equal 1, fleet[:peer_sync_by_name]["grammar-8k"][:imported_by_main]
      assert_equal "8k-main", fleet[:peer_sync_by_name]["grammar-8k"][:consumer_name]

      tab_256 = html[%r{<section id="tab-grammar-256" class="tab-panel">.*?</section>}m]
      tab_8k = html[%r{<section id="tab-grammar-8k" class="tab-panel">.*?</section>}m]
      refute_nil tab_256
      refute_nil tab_8k

      # grammar-256 tab shows +2 imported into small-scout, 4 fleet queue items (2 in small-scout + 1 in 8k-main + 1 in 8k-slow), and 1 crash!
      assert_includes tab_256, "Imported by small-scout"
      assert_includes tab_256, "+2 <span"
      assert_includes tab_256, "4 fleet queue items &bull; 1 crashes (1 seeds)"
      assert_includes tab_256, "aaa11111111111111111"
      refute_includes tab_256, "ccc33333333333333333"

      # grammar-8k tab shows +1 imported into 8k-main, 2 fleet queue items (1 in 8k-main + 1 in 8k-slow), and 0 crashes!
      assert_includes tab_8k, "Imported by 8k-main"
      assert_includes tab_8k, "+1 <span"
      assert_includes tab_8k, "2 fleet queue items &bull; 0 crashes (0 seeds)"
      refute_includes tab_8k, "aaa11111111111111111"
    end
  end

  def test_incremental_coverage_windowing_swar_isolation_and_final_cleanup
    skip "clang/llvm-profdata/llvm-cov unavailable" unless find_executable("clang") && find_executable("llvm-profdata") && find_executable("llvm-cov")

    real_prism_a = prism_a_dir
    skip "synced prism_a directory unavailable" unless real_prism_a

    with_tmpdir("cov-incremental-") do |workdir|
      with_clean_ws_env do
        inc_ws = File.join(workdir, "inc_ws")
        inc_topo = File.join(workdir, "inc_campaign.rb")
        afl_dir = File.join(inc_ws, "afl")
        cov_dir = File.join(inc_ws, "report", "coverage")
        cache_dir = File.join(inc_ws, ".coverage-cache")
        ccache_dir = File.join(workdir, "inc_ccache")

        FileUtils.mkdir_p([File.join(inc_ws, "build", "targets", "gen"), afl_dir])
        if (gen_a = prism_a_gen_dir)
          FileUtils.ln_s(gen_a, File.join(inc_ws, "build", "targets", "gen", "prism_a"))
        end

        File.write(inc_topo, <<~RB)
          PrismFuzzer.campaign "cov-incremental-test" do
            workspace #{inc_ws.dump}
            prism :prism_a, repo: "https://example.invalid/prism.git", dir: #{real_prism_a.dump}, patches: "none", templates: "never"
            coverage source: :prism_a, fuzzer: "fuzz"

            fuzzer "fuzz",      shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
            fuzzer "fuzz_slow", shape: :prism_parse, source: :prism_a, sanitizers: [:msan],        mode: :slow, afl: :lto
            fuzzer "fuzz_swar", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto, defines: { PRISM_ACCEL_SWAR: true }

            sync_group :afl, dir: "afl", primary: true
            worker :main, fuzzer: "fuzz",      sync_group: :afl, afl_role: :main,      schedule: "exploit"
            worker :slow, fuzzer: "fuzz_slow", sync_group: :afl, afl_role: :secondary, schedule: "fast"
            worker :swar, fuzzer: "fuzz_swar", sync_group: :afl, afl_role: :secondary, schedule: "fast"
          end
        RB

        %w[main slow swar].each do |w|
          FileUtils.mkdir_p([File.join(afl_dir, w, "queue"), File.join(afl_dir, w, "crashes")])
          File.write(File.join(afl_dir, w, "fuzzer_stats"), "start_time : 1700000000\nrun_time : 10\nexecs_done : 100\ncorpus_count : 1\n")
        end

        # Window 1 seed in main exercises long comment + string scanning; swar starts with a tiny integer literal.
        shared_scan_seed = "\x00\x00\x00\x00# #{'a' * 64}\n\"#{'b' * 64}\"\n".b
        swar_init_seed = "\x00\x00\x00\x001\n".b
        future_seed = "\x00\x00\x00\x00class Foo\n  def bar(x = /abc/i)\n    <<~HEREDOC\n      \#{x rescue :fallback}\n    HEREDOC\n  end\nend\n".b

        main_q0 = File.join(afl_dir, "main/queue/id:000000,orig:scan_seed")
        swar_q0 = File.join(afl_dir, "swar/queue/id:000000,orig:swar_init")
        main_q1_future = File.join(afl_dir, "main/queue/id:000001,src:000000,op:havoc")

        File.binwrite(main_q0, shared_scan_seed)
        File.binwrite(swar_q0, swar_init_seed)
        File.binwrite(main_q1_future, future_seed)
        future_t = Time.now + 120
        File.utime(future_t, future_t, main_q1_future)

        base_env = CLEAN_WS_ENV.merge(
          "TOPOLOGY" => inc_topo,
          "CAMPAIGN" => inc_topo,
          "WORKSPACE_DIR" => inc_ws,
          "WORKSPACE_BUILD_DIR" => File.join(inc_ws, "build"),
          "WORKSPACE_AFL_DIR" => afl_dir,
          "WORKSPACE_REPORT_DIR" => File.join(inc_ws, "report"),
          "WORKSPACE_COVERAGE_DIR" => cov_dir,
          "WORKSPACE_CORPUS_DIR" => File.join(inc_ws, "corpus"),
          "CCACHE_DIR" => ccache_dir
        )

        # 1. Run 1 (mid-run incremental): ignores main_q1_future (mtime > cutoff) and creates per-pair caches
        out1, = assert_cmd(repo_path("report", "coverage.sh"), env: base_env, chdir: root_dir)
        assert_includes out1, "prism_a (native)=1 inputs"
        assert_includes out1, "prism_a (swar)=1 inputs"
        assert_path_exists File.join(cache_dir, "prism_a__native", "cached.profdata")
        assert_path_exists File.join(cache_dir, "prism_a__native", "seen.sha256")
        assert_path_exists File.join(cache_dir, "prism_a__swar", "cached.profdata")
        assert_path_exists File.join(cache_dir, "prism_a__swar", "seen.sha256")

        cov1 = JSON.parse(File.read(File.join(cov_dir, "coverage.json")))
        p1_native = cov1.fetch("pairs").find { |p| p["id"] == "prism_a__native" }
        p1_swar = cov1.fetch("pairs").find { |p| p["id"] == "prism_a__swar" }
        assert_equal 1, p1_native["input_count"], "future queue file (mtime > cutoff) must be deferred to next window"
        assert_equal 1, p1_swar["input_count"]
        native_lines_1 = p1_native.dig("totals", "lines", "covered").to_i
        swar_lines_1 = p1_swar.dig("totals", "lines", "covered").to_i

        # 2. Run 2 with zero new inputs in (last_cutoff, cutoff] hits fast reuse without target replay
        sleep 0.05
        out2, = assert_cmd(repo_path("report", "coverage.sh"), env: base_env, chdir: root_dir)
        assert_includes out2, "Reusing cached coverage for prism_a (native) (0 new inputs, 1 cached)"
        assert_includes out2, "Reusing cached coverage for prism_a (swar) (0 new inputs, 1 cached)"

        # 3. Window 2:
        #    - main_q1_future lands in (cutoff_2, cutoff_3]
        #    - slow imports shared_scan_seed (same pair prism_a__native -> deduplicated via seen.sha256!)
        #    - swar imports shared_scan_seed (different pair prism_a__swar -> MUST NOT be robbed of SWAR coverage!)
        sleep 0.05
        now_w2 = Time.now
        File.utime(now_w2, now_w2, main_q1_future)
        File.binwrite(File.join(afl_dir, "slow/queue/id:000000,sync:main,src:000000"), shared_scan_seed)
        File.binwrite(File.join(afl_dir, "swar/queue/id:000001,sync:main,src:000000"), shared_scan_seed)

        out3, = assert_cmd(repo_path("report", "coverage.sh"), env: base_env, chdir: root_dir)
        assert_includes out3, "prism_a (native)=2 inputs (1 new, 1 cached)"
        assert_includes out3, "prism_a (swar)=2 inputs (1 new, 1 cached)"
        assert_includes out3, "Replaying 1 new inputs for prism_a (native) (+1 cached"
        assert_includes out3, "Replaying 1 new inputs for prism_a (swar) (+1 cached"

        cov3 = JSON.parse(File.read(File.join(cov_dir, "coverage.json")))
        p3_native = cov3.fetch("pairs").find { |p| p["id"] == "prism_a__native" }
        p3_swar = cov3.fetch("pairs").find { |p| p["id"] == "prism_a__swar" }
        assert_equal 2, p3_native["input_count"]
        assert_equal 2, p3_swar["input_count"]
        assert_operator p3_native.dig("totals", "lines", "covered").to_i, :>, native_lines_1
        assert_operator p3_swar.dig("totals", "lines", "covered").to_i, :>, swar_lines_1,
                        "prism_a__swar must replay inputs synced from native queues against its own SWAR binary"

        # 4. Final run (FUZZ_COVERAGE_FINAL=1): sweeps any remaining tail items (even without upper cutoff),
        #    merges into cached.profdata, removes .coverage-cache, and matches an uncached full replay exactly.
        tail_seed = "\x00\x00\x00\x00case [1, 2, 3]\nin [a, *rest] if a > 0\n  rest.map { _1 ** 2 }\nend\n".b
        tail_path = File.join(afl_dir, "main/queue/id:000002,src:000001,op:havoc")
        File.binwrite(tail_path, tail_seed)
        tail_future = Time.now + 30
        File.utime(tail_future, tail_future, tail_path)

        out_final, = assert_cmd(repo_path("report", "coverage.sh"), env: base_env.merge("FUZZ_COVERAGE_FINAL" => "1"), chdir: root_dir)
        assert_includes out_final, "prism_a (native)=3 inputs (1 new, 2 cached)"
        assert_includes out_final, "Cleaned up incremental coverage cache"
        refute_path_exists cache_dir

        cov_final = JSON.parse(File.read(File.join(cov_dir, "coverage.json")))

        # Compare against a fresh uncached full replay (FUZZ_COVERAGE_NO_CACHE=1)
        assert_cmd(repo_path("report", "coverage.sh"), env: base_env.merge("FUZZ_COVERAGE_NO_CACHE" => "1"), chdir: root_dir)
        refute_path_exists cache_dir
        cov_uncached = JSON.parse(File.read(File.join(cov_dir, "coverage.json")))

        %w[prism_a__native prism_a__swar].each do |pid|
          inc_p = cov_final.fetch("pairs").find { |p| p["id"] == pid }
          raw_p = cov_uncached.fetch("pairs").find { |p| p["id"] == pid }
          assert_equal raw_p["input_count"], inc_p["input_count"], "input_count mismatch on #{pid}"
          assert_equal raw_p["queue_count"], inc_p["queue_count"], "queue_count mismatch on #{pid}"
          assert_equal raw_p["totals"], inc_p["totals"], "LLVM totals mismatch between incremental and full replay on #{pid}"
        end

        # 5. Campaign restart (changed fuzzer_stats start_time) automatically invalidates that pair's cache
        #    while preserving unaffected pairs' caches.
        now_w5 = Time.now
        File.utime(now_w5, now_w5, tail_path)
        assert_cmd(repo_path("report", "coverage.sh"), env: base_env, chdir: root_dir)
        assert_path_exists File.join(cache_dir, "prism_a__native", "state.json")
        File.write(File.join(afl_dir, "main/fuzzer_stats"), "start_time : 1700099999\nrun_time : 5\nexecs_done : 50\ncorpus_count : 3\n")
        out_restart, = assert_cmd(repo_path("report", "coverage.sh"), env: base_env, chdir: root_dir)
        assert_includes out_restart, "prism_a (native)=3 inputs,"
        assert_includes out_restart, "prism_a (swar)=2 inputs (0 new, 2 cached)"
      end
    end
  end
end
