# frozen_string_literal: true

require_relative "lib/autorun"

require "digest"
require "fileutils"
require "json"
require "rbconfig"
require_relative "../runtime/grammar"

class GrammarTest < Minitest::Test
  def test_library_require_safety_and_no_object_pollution
    with_tmpdir("grammar-require-") do |dir|
      script = <<~'RUBY'
        require "json"
        root_dir = ARGV.fetch(0)
        workdir = ARGV.fetch(1)

        require File.join(root_dir, "runtime/topology")
        seen_afl_dirs = []
        sc = PrismFuzzer::Topology.singleton_class
        orig_discover = PrismFuzzer::Topology.method(:discover)
        sc.define_method(:discover) { |**kw| seen_afl_dirs << kw[:afl_dir]; orig_discover.call(**kw) }
        begin
          ARGV.replace(["--json", File.join(workdir, "out.json")])
          require File.join(root_dir, "runtime/grammar")
        ensure
          sc.define_method(:discover, orig_discover)
        end

        result = {
          "seen_afl_dirs" => seen_afl_dirs,
          "tmp_exists" => Dir.exist?("tmp"),
          "default_header_defined" => defined?(PrismFuzzer::Grammar::DEFAULT_HEADER) ? true : false,
          "default_header_bytesize" => PrismFuzzer::Grammar::DEFAULT_HEADER.bytesize,
          "prism_composer_defined" => defined?(PrismFuzzer::Grammar::PrismComposer) ? true : false,
          "leaked_prism_composer" => Object.const_defined?(:PrismComposer, false),
          "leaked_evolver" => Object.const_defined?(:GuidedGrammarEvolver, false),
          "leaked_default_header" => Object.const_defined?(:DEFAULT_HEADER, false),
          "leaked_write_atomic_seed" => Object.private_method_defined?(:write_atomic_seed) || Object.method_defined?(:write_atomic_seed),
          "leaked_run_worker" => Object.private_method_defined?(:run_worker) || Object.method_defined?(:run_worker)
        }
        File.write(File.join(workdir, "result.json"), JSON.generate(result))
      RUBY

      out, _err = assert_ruby_cmd("-I#{repo_path("runtime")}", "-e", script, root_dir, dir, chdir: dir)
      assert_equal "", out

      res = JSON.parse(File.read(File.join(dir, "result.json")))
      assert_equal [nil], res["seen_afl_dirs"]
      refute res["tmp_exists"], "unexpected tmp directory created on require"
      assert res["default_header_defined"], "PrismFuzzer::Grammar::DEFAULT_HEADER missing"
      assert_equal 4, res["default_header_bytesize"]
      assert res["prism_composer_defined"], "PrismFuzzer::Grammar::PrismComposer missing"
      refute res["leaked_prism_composer"], "Object leaked PrismComposer"
      refute res["leaked_evolver"], "Object leaked GuidedGrammarEvolver"
      refute res["leaked_default_header"], "Object leaked DEFAULT_HEADER"
      refute res["leaked_write_atomic_seed"], "Object leaked write_atomic_seed"
      refute res["leaked_run_worker"], "Object leaked run_worker"
    end
  end

  def test_write_atomic_seed_atomicity_dedup_and_eviction
    with_tmpdir("grammar-write-seed-") do |dir|
      q = File.join(dir, "q")
      s = File.join(dir, "s")
      FileUtils.mkdir_p([q, s])
      seen = {}

      assert PrismFuzzer::Grammar.write_atomic_seed(q, s, PrismFuzzer::Grammar::DEFAULT_HEADER, "x = 1\n", seen, max_seen_digests: 5)
      refute PrismFuzzer::Grammar.write_atomic_seed(q, s, PrismFuzzer::Grammar::DEFAULT_HEADER, "x = 1\n", seen, max_seen_digests: 5)
      assert PrismFuzzer::Grammar.write_atomic_seed(q, s, PrismFuzzer::Grammar::ATTACH_COMMENTS_HEADER, "x = 1\n", seen, max_seen_digests: 5)

      expected_bytes = PrismFuzzer::Grammar::DEFAULT_HEADER + "x = 1\n".b
      expected_path = File.join(q, Digest::SHA1.hexdigest(expected_bytes))
      assert_path_exists expected_path
      assert_equal expected_bytes, File.binread(expected_path)

      alt_bytes = PrismFuzzer::Grammar::ATTACH_COMMENTS_HEADER + "x = 1\n".b
      alt_path = File.join(q, Digest::SHA1.hexdigest(alt_bytes))
      assert_path_exists alt_path
      assert_equal alt_bytes, File.binread(alt_path)

      assert_empty Dir.children(s)

      10.times do |i|
        PrismFuzzer::Grammar.write_atomic_seed(q, s, PrismFuzzer::Grammar::DEFAULT_HEADER, "y = #{i}\n", seen, max_seen_digests: 5)
      end
      assert_operator seen.size, :<=, 5
      refute PrismFuzzer::Grammar.write_atomic_seed(q, s, PrismFuzzer::Grammar::DEFAULT_HEADER, "x = 1\n", seen, max_seen_digests: 5)
    end
  end

  def test_prune_synced_seeds_lifecycle_and_backpressure
    PrismFuzzer::Grammar.reset_max_synced_mtime!
    with_tmpdir("grammar-prune-") do |dir|
      q = File.join(dir, "prune_q")
      FileUtils.mkdir_p(q)
      now = Time.now

      fresh_unread = File.join(q, "a_fresh_unread")
      recent_read = File.join(q, "b_recent_read")
      old_read = File.join(q, "c_old_read")
      stranded_unread = File.join(q, "d_stranded_unread")
      [fresh_unread, recent_read, old_read, stranded_unread].each { |p| File.binwrite(p, "seed") }

      t_fresh = Time.at(now.to_i)
      File.utime(t_fresh, t_fresh, fresh_unread)
      File.utime(now - 0.2, now - 0.5, recent_read)
      old_read_mtime = Time.at(now.to_i - 5)
      File.utime(Time.at(now.to_i - 3), old_read_mtime, old_read)
      old_stranded_mtime = Time.at(now.to_i - 10)
      File.utime(old_stranded_mtime, old_stranded_mtime, stranded_unread)

      remaining, pruned = PrismFuzzer::Grammar.prune_synced_seeds(q, max_pending: 50)
      assert_equal 1, pruned
      assert_equal 3, remaining
      refute_path_exists old_read
      assert_path_exists fresh_unread
      assert_path_exists recent_read
      assert_path_exists stranded_unread

      st_bumped = File.stat(stranded_unread)
      assert_equal 1, st_bumped.atime.to_i
      assert_operator st_bumped.mtime.to_i, :>, old_read_mtime.to_i

      # Over-cap stranded eviction check
      File.utime(old_stranded_mtime, old_stranded_mtime, stranded_unread)
      s2 = File.join(q, "e_stranded_2")
      File.binwrite(s2, "seed2")
      File.utime(Time.at(now.to_i - 9), Time.at(now.to_i - 9), s2)

      rem2, pruned2 = PrismFuzzer::Grammar.prune_synced_seeds(q, max_pending: 2)
      assert_operator pruned2, :>=, 1
      assert_operator rem2, :<=, 3
      refute_path_exists stranded_unread
      refute_path_exists s2
      assert_path_exists fresh_unread
      assert_path_exists recent_read
    end
  ensure
    PrismFuzzer::Grammar.reset_max_synced_mtime!
  end

  def test_guarded_evaluators_and_in_flight_reset
    with_tmpdir("grammar-eval-") do |dir|
      in_flight_path = File.join(dir, "unit_in_flight")
      io = File.open(in_flight_path, File::RDWR | File::CREAT | File::BINARY, 0o600)
      begin
        io.sync = true
        fit, val, parse_fn = PrismFuzzer::Grammar.build_guarded_evaluators(io)

        assert_operator fit.call("x = 1 + 2\n"), :>=, 1.0
        assert_operator fit.call("def broken(\n"), :<, 0.5
        assert val.call("x = 1\n")
        refute val.call("class =\n")
        assert parse_fn.call("x = 1\n")&.success?
        assert_equal 0, File.size(io.path)
      ensure
        io.close unless io.closed?
      end
    end
  end

  def test_supervisor_crash_recovery_and_custom_worker_id
    with_tmpdir("grammar-sup-") do |dir|
      run_supervisor_crash_check(File.join(dir, "default"))
      run_supervisor_crash_check(
        File.join(dir, "custom"),
        worker_id: "g_custom",
        bin_name: "fuzz.custom"
      )
    end
  end

  def test_run_worker_signal_trap_safety
    with_tmpdir("grammar-trap-safety-") do |dir|
      afl = File.join(dir, "afl")
      wdir = File.join(afl, "grammar")
      qdir = File.join(dir, "seeds")
      sdir = File.join(dir, "staging")
      FileUtils.mkdir_p([wdir, qdir, sdir])
      plot_path = File.join(wdir, "plot_data")
      stats_path = File.join(wdir, "fuzzer_stats")
      stats_tmp = File.join(wdir, ".fuzzer_stats.tmp")
      in_flight = File.join(dir, "in_flight")
      File.write(plot_path, "# relative_time, files_created\n")

      script = <<~'RUBY'
        require "fileutils"
        require "timeout"
        require ARGV.fetch(0)

        dir = ARGV.fetch(1)
        afl = File.join(dir, "afl")
        wdir = File.join(afl, "grammar")
        qdir = File.join(dir, "seeds")
        sdir = File.join(dir, "staging")
        plot_path = File.join(wdir, "plot_data")
        stats_path = File.join(wdir, "fuzzer_stats")
        stats_tmp = File.join(wdir, ".fuzzer_stats.tmp")
        in_flight = File.join(dir, "in_flight")

        ruby_src = ENV.fetch("RUBY_SRC_DIR") { ENV.fetch("RUBY_ORACLE_DIR", "/opt/ruby") }
        grammar = Lrama::Fuzz.parse_ruby(
          parse_y_path: File.join(ruby_src, "parse.y"),
          id_def_path: File.join(ruby_src, "defs", "id.def")
        )

        mtx = Mutex.new
        orig_evolve = Lrama::Fuzz::Evolver.instance_method(:evolve)
        Lrama::Fuzz::Evolver.class_eval do
          define_method(:evolve) do
            mtx.synchronize do
              Process.kill("INT", Process.pid)
              [["x = 1 + 2\n", 1.0]]
            end
          end
        end
        begin
          Timeout.timeout(10) do
            PrismFuzzer::Grammar.run_worker(
              grammar: grammar,
              supervisor_pid: Process.pid,
              start_time: Time.now.to_f,
              prior_elapsed: 0,
              saved_crashes: 0,
              afl_dir: afl,
              queue_dir: qdir,
              staging_dir: sdir,
              in_flight_path: in_flight,
              stats_path: stats_path,
              stats_tmp_path: stats_tmp,
              plot_path: plot_path
            )
          end
        ensure
          Lrama::Fuzz::Evolver.class_eval { define_method(:evolve, orig_evolve) }
        end
      RUBY

      assert_ruby_cmd(
        "-e", script, repo_path("runtime/grammar"), dir,
        env: { "FUZZ_GRAMMAR_TEST_CRASH_SIG" => nil }
      )
      assert File.size?(stats_path), "expected fuzzer_stats flushed after trap-safe shutdown"
      assert_operator File.readlines(plot_path).size, :>=, 2
    end
  end

  def test_notify_intake_sync_sigusr2_targeting
    with_tmpdir("grammar-notify-") do |dir|
      afl_dir = File.join(dir, "sig_afl")
      decoy_dir = File.join(afl_dir, "main")
      target_dir = File.join(dir, "sig_custom", "intake_master")
      FileUtils.mkdir_p([decoy_dir, target_dir])
      decoy_flag = File.join(dir, "decoy.usr2")
      target_flag = File.join(dir, "target.usr2")

      decoy_pid = nil
      target_pid = nil
      begin
        decoy_pid = spawn_usr2_waiter(decoy_flag)
        target_pid = spawn_usr2_waiter(target_flag)

        File.write(File.join(decoy_dir, "fuzzer_stats"), "fuzzer_pid : #{decoy_pid}\n")
        target_stats = File.join(target_dir, "fuzzer_stats")
        File.write(target_stats, "fuzzer_pid : #{target_pid}\n")

        with_env("FUZZ_INTAKE_STATS_PATH" => target_stats) do
          PrismFuzzer::Grammar.notify_intake_sync(afl_dir)
        end
        assert wait_for_file(target_flag), "expected SIGUSR2 on explicit target"
        sleep 0.1
        refute_path_exists decoy_flag, "decoy main received unexpected SIGUSR2"

        FileUtils.rm_f([target_flag, decoy_flag])
        with_env("FUZZ_INTAKE_STATS_PATH" => "") do
          PrismFuzzer::Grammar.notify_intake_sync(afl_dir)
        end
        sleep 0.15
        refute_path_exists target_flag, "empty FUZZ_INTAKE_STATS_PATH should not signal target"
        refute_path_exists decoy_flag, "empty FUZZ_INTAKE_STATS_PATH should not signal decoy"

        with_env("FUZZ_INTAKE_STATS_PATH" => nil) do
          PrismFuzzer::Grammar.notify_intake_sync(afl_dir)
        end
        assert wait_for_file(decoy_flag), "expected fallback SIGUSR2 on main/fuzzer_stats"
        sleep 0.1
        refute_path_exists target_flag, "explicit target received unexpected fallback SIGUSR2"
      ensure
        [decoy_pid, target_pid].compact.each do |pid|
          terminate_child(pid)
        end
      end
    end
  end

  def test_grammar_bench_require_safety_smoke_and_compare
    with_tmpdir("grammar-bench-") do |dir|
      req_script = <<~'RUBY'
        require "json"
        require ARGV.fetch(0)
        result = {
          "grammar_bench_defined" => defined?(GrammarBench) ? true : false,
          "leaked_prism_composer" => Object.const_defined?(:PrismComposer, false),
          "leaked_default_header" => Object.const_defined?(:DEFAULT_HEADER, false),
          "leaked_write_atomic_seed" => Object.private_method_defined?(:write_atomic_seed) || Object.method_defined?(:write_atomic_seed)
        }
        puts JSON.generate(result)
      RUBY

      req_out, _err = assert_ruby_cmd("-e", req_script, repo_path("runtime/grammar_bench"), chdir: dir)
      req_res = JSON.parse(req_out)
      assert req_res["grammar_bench_defined"], "GrammarBench missing after require"
      refute req_res["leaked_prism_composer"], "Object leaked PrismComposer"
      refute req_res["leaked_default_header"], "Object leaked DEFAULT_HEADER"
      refute req_res["leaked_write_atomic_seed"], "Object leaked write_atomic_seed"

      bench_json = File.join(dir, "bench.json")
      bench_args = [
        repo_path("runtime/grammar_bench.rb"),
        "--epochs", "1",
        "--gens", "5",
        "--variant-trials", "20",
        "--seed", "42",
        "--max-seconds", "20",
        "--json", bench_json
      ]
      bench_args << "--strict" if ENV["GRAMMAR_TEST_STRICT"] == "1"
      assert_ruby_cmd(*bench_args)

      data = JSON.parse(File.read(bench_json))
      %w[schema_version env regexp_audit literals_and_terminals heredoc_audit variants_audit simulation].each do |key|
        assert data.key?(key), "missing key #{key} in grammar_bench JSON"
      end

      sim = data.fetch("simulation")
      assert_equal 5, sim["generations_completed"]
      assert_operator sim.dig("throughput", "attempts_per_sec").to_f, :>, 0
      assert_operator sim.dig("coverage", "peak_combined_used").to_i, :>, 0

      cmp_out, _cmp_err = assert_ruby_cmd(
        repo_path("runtime/grammar_bench.rb"),
        "--epochs", "1",
        "--gens", "2",
        "--variant-trials", "10",
        "--seed", "42",
        "--max-seconds", "20",
        "--json", bench_json,
        "--compare", bench_json
      )
      assert_includes cmp_out, "=== Baseline Comparison ==="
    end
  end

  private

  def run_supervisor_crash_check(base_dir, worker_id: nil, bin_name: nil)
    afl_dir = File.join(base_dir, "afl")
    seeds_dir = File.join(base_dir, "work", "seeds")
    out_log = File.join(base_dir, "sup.out")
    err_log = File.join(base_dir, "sup.err")
    FileUtils.mkdir_p(base_dir)

    effective_worker = worker_id || "grammar"
    effective_bin = bin_name || "fuzz.native"
    worker_dir = File.join(afl_dir, effective_worker)
    crashes_dir = File.join(worker_dir, "crashes")
    stats_path = File.join(worker_dir, "fuzzer_stats")
    plot_path = File.join(worker_dir, "plot_data")
    cmdline_path = File.join(worker_dir, "cmdline")

    spawn_env = {
      "FUZZ_GRAMMAR_TEST_CRASH_SIG" => "ABRT",
      "FUZZ_GRAMMAR_WORKER_ID" => worker_id,
      "FUZZ_GRAMMAR_BIN" => bin_name,
      "FUZZ_BIN_DIR" => nil
    }

    pid = Process.spawn(
      spawn_env,
      RbConfig.ruby,
      repo_path("runtime/grammar.rb"),
      afl_dir,
      seeds_dir,
      out: out_log,
      err: err_log
    )

    sig_num = Signal.list.fetch("ABRT")
    crash_glob = File.join(crashes_dir, format("id:000000,sig:%02d,*", sig_num))
    crash_file = nil
    reaped_status = nil

    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 15.0
    while Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
      if (res = Process.wait2(pid, Process::WNOHANG))
        reaped_status = res[1]
        pid = nil
        break
      end

      crash_file = Dir.glob(crash_glob).first
      if crash_file && File.size?(stats_path) &&
         File.read(stats_path).match?(/^saved_crashes\s*:\s*1$/)
        break
      end

      sleep 0.1
    end

    if pid
      Process.kill("INT", pid)
      stop_deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 8.0
      while Process.clock_gettime(Process::CLOCK_MONOTONIC) < stop_deadline
        if (res = Process.wait2(pid, Process::WNOHANG))
          reaped_status = res[1]
          pid = nil
          break
        end
        sleep 0.05
      end
    end

    err_text = File.exist?(err_log) ? File.read(err_log) : ""
    out_text = File.exist?(out_log) ? File.read(out_log) : ""
    diag = "worker=#{effective_worker} status=#{reaped_status.inspect}\n--- stdout ---\n#{out_text}\n--- stderr ---\n#{err_text}"

    refute_nil reaped_status, "supervisor did not exit after SIGINT\n#{diag}"
    refute_nil crash_file, "supervisor did not save FUZZ_GRAMMAR_TEST_CRASH_SIG crash\n#{diag}"
    assert_path_exists crash_file, diag
    assert File.size?(stats_path), "missing or empty fuzzer_stats after supervisor shutdown\n#{diag}"
    assert File.size?(plot_path), "missing or empty plot_data after supervisor shutdown\n#{diag}"
    assert_equal "./tmp/fuzz/build/#{effective_bin}", File.read(cmdline_path).strip, diag
    assert_match(/^files_created\b/, File.read(stats_path), diag)

    raw = File.binread(crash_file)
    expected = "\x00\x00\x03\x01".b + "def crash_test; end\n".b
    assert_equal expected, raw, "unexpected crash payload\n#{diag}"

    forwarded_seed = File.join(seeds_dir, Digest::SHA1.hexdigest(raw))
    assert_path_exists forwarded_seed, "crash seed not forwarded to queue_dir (#{forwarded_seed})\n#{diag}"
  ensure
    terminate_child(pid, sig: "KILL") if pid
  end

  def spawn_usr2_waiter(flag_path)
    r, w = IO.pipe
    pid = Process.fork do
      begin
        r.close
        Signal.trap("USR2") { File.write(flag_path, "1") }
        Signal.trap("TERM") { exit!(0) }
        Signal.trap("INT") { exit!(0) }
        w.write("ready\n")
        w.flush
        w.close
        loop { sleep 0.2 }
      ensure
        exit!(0)
      end
    end
    w.close
    ready = r.gets
    r.close
    if ready != "ready\n"
      terminate_child(pid, sig: "KILL")
      flunk "SIGUSR2 waiter failed to start"
    end
    pid
  ensure
    r.close unless r.nil? || r.closed?
    w.close unless w.nil? || w.closed?
  end

  def wait_for_file(path, timeout: 2.0)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    until File.exist?(path)
      return false if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

      sleep 0.02
    end
    true
  end

  def terminate_child(pid, sig: "TERM")
    return unless pid

    begin
      Process.kill(sig, pid)
    rescue Errno::ESRCH
      return
    end
    Process.waitpid(pid)
  rescue Errno::ECHILD
    nil
  end
end
