# frozen_string_literal: true

module PrismFuzzer
  module Campaign
    module_function

    def stage_log_paths(ctx, step_key)
      logs_dir = ctx&.dig(:ws, :logs_dir)
      return [nil, nil] unless logs_dir && !logs_dir.to_s.empty?

      abs = File.join(logs_dir, "#{step_key}.log")
      rel = Topology.path_relative_or_abs(abs, ctx[:fuzz_root])
      display = rel.start_with?("/") ? rel : "./#{rel}"
      [abs, display]
    end

    def sync_sources!(ctx, skip_sync: false, dry_run: false, build_ruby: false, cache_dir: nil)
      plan = ctx[:plan]
      return plan if skip_sync || dry_run

      sync_log, sync_disp = stage_log_paths(ctx, "sync")
      Progress.stage("Sync targets", log_path: sync_log, display_log: sync_disp) do |stage|
        plan = Topology.sync_plan!(
          plan,
          fuzz_root: ctx[:fuzz_root],
          build_dir: ctx[:ws][:build_dir],
          cache_dir: cache_dir || Topology.default_cache_dir(ctx[:fuzz_root]),
          allow_ruby_build: build_ruby
        )
        summary = plan.fetch("sources", {}).map do |id, s|
          ref = s["commit"] ? s["commit"][0, 7] : (s["requested_ref"] || s["path"] || "local")
          "#{id}@#{ref}"
        end.join(", ")
        stage.custom_done = summary.empty? ? "Targets synced" : "Targets synced (#{summary})"
      end
      plan
    end

    def build!(ctx, skip_sync: false, dry_run: false, build_ruby: false)
      logs_dir = ctx.dig(:ws, :logs_dir)
      ensure_docker_image!(fuzz_root: ctx[:fuzz_root], build_dir: ctx.dig(:ws, :build_dir), dry_run: dry_run, logs_dir: logs_dir, emit_cached: true) unless in_docker?

      plan = sync_sources!(ctx, skip_sync: skip_sync, dry_run: dry_run, build_ruby: build_ruby)

      fcount = plan.fetch("fuzzers", {}).size
      write_container_ir!(ctx, dry_run: dry_run)
      if in_docker?
        if dry_run
          ensure_afl_passes!(fuzz_root: ctx[:fuzz_root], dry_run: true)
          Topology.build_plan!(plan, fuzz_root: ctx[:fuzz_root], build_dir: ctx[:ws][:build_dir], dry_run: true)
          return plan
        end
        build_log, build_disp = stage_log_paths(ctx, "build")
        Progress.stage("Build fuzzers (#{fcount} targets)", log_path: build_log, display_log: build_disp, done_message: "Fuzzers ready (#{fcount} targets)") do |_stage|
          ensure_afl_passes!(fuzz_root: ctx[:fuzz_root], dry_run: false)
          Topology.build_plan!(plan, fuzz_root: ctx[:fuzz_root], build_dir: ctx[:ws][:build_dir], dry_run: false)
          FuzzProvenance.write_build_manifest(ctx[:ws][:build_dir], repo_root: ctx[:fuzz_root])
        end
        return plan
      end

      cmd = ["ruby", "./bin/campaign.rb", "build", "--in-container-step", "--skip-sync", "--campaign", container_ir_guest_path(ctx)]
      cmd.push("--fuzz-dir", guest_path_for(ctx[:ws][:fuzz_dir], ctx, ws_key: "dir")) if ctx[:ws_custom_dir]
      cmd.push("--build-dir", guest_path_for(ctx[:ws][:build_dir], ctx, ws_key: "build_dir")) if ctx[:ws_custom_build] || ctx[:ws_custom_dir]
      if dry_run
        cmd << "--dry-run"
        run_in_container!(ctx, cmd, dry_run: true)
        return plan
      end

      build_log, build_disp = stage_log_paths(ctx, "build")
      Progress.stage("Build fuzzers (#{fcount} targets)", log_path: build_log, display_log: build_disp, done_message: "Fuzzers ready (#{fcount} targets)") do |stage|
        run_in_container!(ctx, cmd, dry_run: false, stage: stage)
      end
      plan
    end

    def attach_command_string(ctx)
      "docker exec -it #{Shellwords.escape(ctx[:container_name])} tmux -2 attach-session -t fuzzer"
    end

    def status_command_string(ctx)
      guest_afl = guest_path_for(ctx[:ws][:afl_dir], ctx, ws_key: "dir")
      "docker exec -i #{Shellwords.escape(ctx[:container_name])} ruby /prism-fuzzer/runtime/status.rb #{Shellwords.escape(guest_afl)}"
    end

    def script_cli_command(ctx, subcmd)
      path = ctx[:campaign_path].to_s
      rel = ctx[:campaign_rel].to_s
      display = rel.start_with?("/") ? rel : "./#{rel}"
      base = if !path.empty? && File.extname(path) != ".rb"
               "./bin/campaign.rb #{subcmd} #{Shellwords.escape(display)}"
             elsif !path.empty? && File.file?(path) && File.executable?(path)
               "#{Shellwords.escape(display)} #{subcmd}"
             else
               "ruby #{Shellwords.escape(display)} #{subcmd}"
             end
      flags = []
      flags.push("--fuzz-dir", Shellwords.escape(ctx[:ws][:fuzz_dir])) if ctx[:ws_custom_dir]
      flags.push("--build-dir", Shellwords.escape(ctx[:ws][:build_dir])) if ctx[:ws_custom_build] && !ctx[:ws_custom_dir]
      flags.empty? ? base : "#{base} #{flags.join(' ')}"
    end

    def script_cli_prefix(ctx)
      path = ctx[:campaign_path].to_s
      rel = ctx[:campaign_rel].to_s
      display = rel.start_with?("/") ? rel : "./#{rel}"
      return "./bin/campaign.rb" if !path.empty? && File.extname(path) != ".rb"
      return Shellwords.escape(display) if !path.empty? && File.file?(path) && File.executable?(path)

      "ruby #{Shellwords.escape(display)}"
    end

    def print_observe_commands(ctx, duration_seconds: nil)
      puts "== Campaign '#{ctx[:plan]['name']}' running =="
      puts "Container : #{ctx[:container_name]}"
      puts "Workspace : #{ctx[:ws][:fuzz_dir]} (build: #{ctx[:ws][:build_dir]})"
      puts "Timer     : #{duration_seconds}s" if duration_seconds && duration_seconds > 0
      puts "Attach    : #{script_cli_command(ctx, 'attach')}"
      puts "Status    : #{script_cli_command(ctx, 'status')}"
      puts "Logs      : #{script_cli_command(ctx, 'logs -f')}"
      puts "Stop      : #{script_cli_command(ctx, 'stop')}"
    end

    def interactive_tty?(input: $stdin, output: $stdout)
      input.tty? && output.tty?
    end

    def ensure_tmux_session!(ctx, abort_if: nil)
      cname = ctx[:container_name]
      print "Starting fuzzing fleet tmux session in '#{cname}'... "
      $stdout.flush
      ready = if abort_if
                wait_for_tmux_session!(cname, abort_if: abort_if)
              else
                wait_for_tmux_session!(cname)
              end
      return true if ready
      return false if abort_if&.call

      puts "failed."
      still_running = container_running?(cname)
      run_log = File.join(ctx[:ws][:logs_dir], "run.log")
      tail_msg = ""
      if File.file?(run_log)
        tail = File.readlines(run_log, encoding: "UTF-8", invalid: :replace).last(20).map(&:rstrip).join("\n")
        tail_msg = "\n#{tail}\nFull log: #{run_log}" unless tail.empty?
      end
      msg = if still_running
              "Timed out after #{start_timeout_seconds}s waiting for container '#{cname}' to start tmux session 'fuzzer' (container is still running)#{tail_msg}"
            else
              "Container '#{cname}' exited before starting tmux session 'fuzzer'#{tail_msg}"
            end
      raise CampaignError, msg
    end

    def attach_tmux_session!(ctx, duration_seconds: nil)
      cname = ctx[:container_name]
      timed = !duration_seconds.nil? && duration_seconds > 0
      deadline = timed ? (Time.now + duration_seconds) : nil

      expired = false
      interrupted = false
      mutex = Mutex.new
      cv = ConditionVariable.new
      done = false
      stop_handled = false

      # Signal traps only flip a flag (no mutex/IO in trap context); monitor_thread tears down cleanly.
      prev_int = Signal.trap("INT") { interrupted = true }
      prev_term = Signal.trap("TERM") { interrupted = true }

      monitor_thread = Thread.new do
        loop do
          break if done || interrupted || (deadline && Time.now >= deadline)

          step = deadline ? [deadline - Time.now, 0.25].min : 0.25
          mutex.synchronize { cv.wait(mutex, step) if !done && step > 0 }
        end
        expired = !done && !interrupted && !deadline.nil? && Time.now >= deadline
        if (expired || interrupted) && !stop_handled && container_running?(cname)
          stop_handled = true
          stop_container!(cname, quiet: true)
        end
      end

      begin
        ready = ensure_tmux_session!(ctx, abort_if: -> { interrupted })
        if ready && !interrupted
          puts "ready."
          system("docker", "exec", "-it", cname, "tmux", "-2", "attach-session", "-t", "fuzzer")
        end
      ensure
        Signal.trap("INT", prev_int || "DEFAULT")
        Signal.trap("TERM", prev_term || "DEFAULT")
        mutex.synchronize do
          done = true
          cv.broadcast
        end
        monitor_thread.join
      end

      stop_container!(cname, quiet: true) if interrupted && !stop_handled && container_running?(cname)

      { expired: expired, interrupted: interrupted }
    end

    def wait_with_timer(ctx, duration_seconds)
      name = ctx[:container_name]
      deadline = Time.now + duration_seconds
      interrupted = false

      prev_int = Signal.trap("INT") { interrupted = true }
      prev_term = Signal.trap("TERM") { interrupted = true }

      begin
        loop do
          break if interrupted || !container_running?(name) || Time.now >= deadline

          sleep 1
        end
      ensure
        Signal.trap("INT", prev_int || "DEFAULT")
        Signal.trap("TERM", prev_term || "DEFAULT")
      end

      if interrupted
        puts "\nSignal received; stopping campaign early..."
        stop_container!(name)
      elsif container_running?(name)
        puts "Timer expired (#{duration_seconds}s); stopping campaign..."
        stop_container!(name)
      else
        puts "Campaign container '#{name}' exited before timer expiry."
      end
      !interrupted
    end

    def capture_live_seeds_tar(ctx)
      name = ctx[:container_name]
      return nil unless container_running?(name)

      seeds_dirs = Topology.grammar_seeds_dirs(ctx[:plan])
      seeds_dirs = { "grammar" => "/tmp/afl-tmpdir/grammar/seeds" } if seeds_dirs.empty?

      ws = ctx[:ws]
      FileUtils.mkdir_p(ws[:fuzz_dir])
      tar_path = File.join(ws[:fuzz_dir], ".live-seeds.#{Process.pid}.tar")
      out, _err, st = Open3.capture3("docker", "exec", name, "ruby", "-e", LIVE_SEEDS_ARCHIVE_SCRIPT, JSON.generate(seeds_dirs))
      if st.success? && !out.empty?
        File.binwrite(tar_path, out)
        return tar_path
      end
      nil
    rescue SystemCallError, IOError => e
      warn "PrismFuzzer::Campaign: failed to capture live seeds from container '#{name}': #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
      nil
    end

    def capture_live_seeds_shell_env(campaign_path: nil, container_name: ENV["FUZZ_CONTAINER_NAME"], fuzz_dir: ENV["FUZZ_DIR"])
      camp = campaign_path || (ENV["CAMPAIGN"].to_s.empty? ? ENV["TOPOLOGY"] : ENV["CAMPAIGN"])
      cli = {}
      cli[:container_name] = container_name unless container_name.to_s.empty?
      cli[:fuzz_dir] = fuzz_dir unless fuzz_dir.to_s.empty?
      ctx = resolve_context(campaign_path: camp, cli: cli)
      host = capture_live_seeds_tar(ctx)
      return "" unless host

      guest = in_docker? ? host : guest_path_for(host, ctx, ws_key: "dir")
      "LIVE_SEEDS_TAR=#{Shellwords.escape(host)}; GUEST_LIVE_SEEDS_TAR=#{Shellwords.escape(guest)}"
    end

    def run_host_script_stage!(ctx, step_key, title, cmd, fail_message:, done_message: nil, dry_run: false)
      if dry_run
        puts "[dry-run] #{cmd.map { |t| Shellwords.escape(t) }.join(' ')}"
        return true
      end
      ir_host = write_container_ir!(ctx, dry_run: false)
      log_abs, log_disp = stage_log_paths(ctx, step_key)
      Progress.stage(title, log_path: log_abs, display_log: log_disp, done_message: done_message) do |stage|
        stage.exec_stream(*cmd, env: { "CAMPAIGN" => ir_host, "TOPOLOGY" => ir_host }, chdir: ctx[:fuzz_root], fail_message: fail_message)
      end
      true
    end

    def run_triage!(ctx, dry_run: false)
      ensure_docker_image!(fuzz_root: ctx[:fuzz_root], build_dir: ctx.dig(:ws, :build_dir), dry_run: dry_run, logs_dir: ctx.dig(:ws, :logs_dir)) unless in_docker?
      ws = ctx[:ws]
      rep_opts = step_opts(ctx[:lifecycle], "report")
      env = {}
      env["TRIAGE_THREADS"] = rep_opts["threads"].to_s if rep_opts["threads"]
      env["TRIAGE_MINIMIZE"] = (rep_opts["minimize"] ? "1" : "0") if rep_opts.key?("minimize")
      env["TRIAGE_RECOUNT"] = (rep_opts["recount"] ? "1" : "0") if rep_opts.key?("recount")
      env["TRIAGE_LIVE_SCRIPTS"] = (rep_opts["live_scripts"] ? "1" : "0") if rep_opts.key?("live_scripts")
      env["TRIAGE_DIR"] = guest_path_for(ws[:triage_dir], ctx, ws_key: "triage_dir")
      env["TRIAGE_CORPUS_DIR"] = guest_path_for(ws[:corpus_dir], ctx, ws_key: "corpus_dir")

      snap_triage = File.join(ws[:snapshot_dir], "triage", "triage.rb")
      live_scripts = env["TRIAGE_LIVE_SCRIPTS"] == "1"
      script = if !live_scripts && File.file?(snap_triage)
                 guest_path_for(snap_triage, ctx, ws_key: "dir")
               else
                 "triage/triage.rb"
               end
      if dry_run
        puts "== Running triage (#{ws[:triage_dir]}) =="
        return run_in_container!(ctx, ["ruby", script], interactive: false, extra_env: env, dry_run: true)
      end
      log_abs, log_disp = stage_log_paths(ctx, "triage")
      Progress.stage("Triage crashes (#{Topology.path_relative_or_abs(ws[:triage_dir], ctx[:fuzz_root])})", log_path: log_abs, display_log: log_disp, done_message: "Triage complete") do |stage|
        run_in_container!(ctx, ["ruby", script], interactive: false, extra_env: env, dry_run: false, stage: stage)
      end
    end

    def run_coverage!(ctx, dry_run: false, coverage_flags: nil)
      ensure_docker_image!(fuzz_root: ctx[:fuzz_root], build_dir: ctx.dig(:ws, :build_dir), dry_run: dry_run, logs_dir: ctx.dig(:ws, :logs_dir)) unless in_docker?
      ws = ctx[:ws]
      rep_opts = step_opts(ctx[:lifecycle], "report")
      flags = coverage_flags || rep_opts["coverage_flags"] || rep_opts["flags"]
      env = {
        "WORKSPACE_REPORT_DIR" => guest_path_for(ws[:report_dir], ctx, ws_key: "report_dir"),
        "WORKSPACE_COVERAGE_DIR" => guest_path_for(ws[:coverage_dir], ctx, ws_key: "coverage_dir")
      }
      env["JOBS"] = ctx[:cli][:jobs].to_s if ctx.dig(:cli, :jobs)
      env["FUZZ_FLAGS"] = flags.to_s if flags && !flags.to_s.empty?
      tar_host = dry_run ? nil : capture_live_seeds_tar(ctx)
      env["FUZZ_LIVE_SEEDS_TAR"] = in_docker? ? tar_host : guest_path_for(tar_host, ctx, ws_key: "dir") if tar_host
      if dry_run
        puts "== Collecting LLVM coverage (#{ws[:coverage_dir]}) =="
        return run_in_container!(ctx, ["./report/coverage.sh"], extra_env: env, dry_run: true)
      end
      log_abs, log_disp = stage_log_paths(ctx, "coverage")
      Progress.stage("Collect LLVM coverage", log_path: log_abs, display_log: log_disp, done_message: "LLVM coverage collected") do |stage|
        run_in_container!(ctx, ["./report/coverage.sh"], extra_env: env, dry_run: false, stage: stage)
      end
    ensure
      FileUtils.rm_f(tar_host) if tar_host
    end

    def render_coverage_and_report!(ctx, dry_run: false)
      ws = ctx[:ws]
      rep_opts = step_opts(ctx[:lifecycle], "report")
      if ENV["FUZZ_SKIP_COVERAGE"].to_s.empty? && (dry_run || Dir.exist?(ws[:afl_dir]))
        run_coverage!(ctx, dry_run: dry_run, coverage_flags: rep_opts["coverage_flags"] || rep_opts["flags"])
      end

      report_rb = File.join(ctx[:fuzz_root], "report", "report.rb")
      out_html = File.join(ws[:report_dir], "index.html")
      cov_json = File.join(ws[:coverage_dir], "coverage.json")
      cmd = [RbConfig.ruby, report_rb, ws[:afl_dir], out_html, cov_json, "--triage-dir", ws[:triage_dir]]
      cmd.push("--sankey-top", rep_opts["top"].to_s) if rep_opts["top"]
      FileUtils.mkdir_p(ws[:report_dir]) unless dry_run
      run_host_script_stage!(ctx, "report", "Generate campaign report", cmd, fail_message: "report.rb failed", done_message: "Report written to #{Topology.path_relative_or_abs(out_html, ctx[:fuzz_root])}", dry_run: dry_run)
    end

    def run_report!(ctx, dry_run: false)
      ws = ctx[:ws]
      sync_dirs = Topology.sync_group_dirs(ctx[:plan], base_dir: ws[:fuzz_dir])
      sync_dirs = [ws[:afl_dir]] if sync_dirs.empty?

      if dry_run || sync_dirs.any? { |d| Dir.exist?(d) }
        run_triage!(ctx, dry_run: dry_run)
      end
      render_coverage_and_report!(ctx, dry_run: dry_run)
    end

    def run_retriage!(ctx, extra_args: [], skip_sync: false, skip_build: false, run_report: false, run_publish: false, build_ruby: false, cache_dir: nil, dry_run: false)
      ws = ctx[:ws]
      ensure_docker_image!(fuzz_root: ctx[:fuzz_root], build_dir: ws[:build_dir], dry_run: dry_run, logs_dir: ws[:logs_dir]) unless in_docker?
      sync_sources!(ctx, skip_sync: skip_sync, dry_run: dry_run, build_ruby: build_ruby, cache_dir: cache_dir)

      fwd_args = Array(extra_args).dup
      run_report = true if fwd_args.delete("--report")
      effective_report_dry = dry_run || fwd_args.include?("--dry-run")
      if skip_build && !fwd_args.include?("--skip-fuzzer-build") && !fwd_args.include?("--no-build")
        fwd_args << "--skip-fuzzer-build"
      end

      triage_guest = guest_path_for(ws[:triage_dir], ctx, ws_key: "triage_dir")
      run_in_container!(ctx, ["ruby", "./triage/retriage.rb", "--triage-dir", triage_guest, *fwd_args], interactive: true, dry_run: dry_run)
      render_coverage_and_report!(ctx, dry_run: effective_report_dry) if run_report
      run_publish!(ctx, dry_run: effective_report_dry) if run_publish
      true
    end

    def run_verify!(ctx, extra_args: [], skip_sync: false, build_ruby: false, cache_dir: nil, dry_run: false)
      ws = ctx[:ws]
      ensure_docker_image!(fuzz_root: ctx[:fuzz_root], build_dir: ws[:build_dir], dry_run: dry_run, logs_dir: ws[:logs_dir]) unless in_docker?
      sync_sources!(ctx, skip_sync: skip_sync, dry_run: dry_run, build_ruby: build_ruby, cache_dir: cache_dir)

      triage_guest = guest_path_for(ws[:triage_dir], ctx, ws_key: "triage_dir")
      run_in_container!(ctx, ["ruby", "./triage/verify.rb", "--triage-dir", triage_guest, *Array(extra_args)], interactive: true, dry_run: dry_run)
      true
    end

    def run_publish!(ctx, extra_args: [], dry_run: false)
      ws = ctx[:ws]
      pub_opts = step_opts(ctx[:lifecycle], "publish")
      slug = ctx[:plan].fetch("name", "campaign").to_s.downcase.gsub(/[^a-z0-9_.-]+/, "-")
      run_id = pub_opts["run_id"] || "#{slug}-#{Time.now.utc.strftime('%Y%m%d-%H%M%S')}"
      out_dir = pub_opts["out_dir"] ? Topology.expand_workspace_path(pub_opts["out_dir"], fuzz_root: ctx[:fuzz_root]) : ws[:reports_dir]

      pub_rb = File.join(ctx[:fuzz_root], "bin", "publish.rb")
      cmd = [
        RbConfig.ruby, pub_rb,
        "--run-id", run_id,
        "--report-dir", ws[:report_dir],
        "--triage-dir", ws[:triage_dir],
        "--coverage-dir", ws[:coverage_dir],
        "--bin-dir", ws[:bin_dir],
        "--out-dir", out_dir
      ]
      cmd.push("--title", pub_opts["title"]) if pub_opts["title"]
      cmd.push(pub_opts["gh_pages"] ? "--gh-pages" : "--no-gh-pages") if pub_opts.key?("gh_pages")
      cmd.push("--branch", pub_opts["branch"]) if pub_opts["branch"]
      cmd.push("--remote", pub_opts["remote"]) if pub_opts["remote"]
      cmd << "--commit" if pub_opts["commit"]
      cmd << "--push" if pub_opts["push"]
      cmd.concat(Array(extra_args))
      run_host_script_stage!(ctx, "publish", "Publish report '#{run_id}'", cmd, fail_message: "publish.rb failed", done_message: "Published '#{run_id}' to #{Topology.path_relative_or_abs(out_dir, ctx[:fuzz_root])}", dry_run: dry_run)
    end

    def run_post_pipeline!(ctx, dry_run: false)
      lc = ctx[:lifecycle]
      run_report!(ctx, dry_run: dry_run) if step_enabled?(lc, "report")
      run_publish!(ctx, dry_run: dry_run) if step_enabled?(lc, "publish")
    end

    def clean_preserving_paths(root_dir, preserved_dirs)
      return unless Dir.exist?(root_dir)

      normalized_keep = Array(preserved_dirs).map { |p| File.expand_path(p) }.uniq
      Dir.children(root_dir).each do |entry|
        path = File.join(root_dir, entry)
        abs = File.expand_path(path)
        next if normalized_keep.include?(abs)

        if File.directory?(path) && normalized_keep.any? { |p| p.start_with?("#{abs}/") }
          clean_preserving_paths(path, normalized_keep)
        else
          FileUtils.rm_rf(path)
        end
      end
    end

    def collect_stats(ctx)
      ws = ctx[:ws]
      sync_dirs = Topology.sync_group_dirs(ctx[:plan], base_dir: ws[:fuzz_dir])
      sync_dirs = [ws[:afl_dir]] if sync_dirs.empty?

      workers = []
      sync_dirs.uniq.each do |sdir|
        next unless File.directory?(sdir)

        Dir.glob(File.join(sdir, "*", "fuzzer_stats")).sort.each do |st_file|
          kv = {}
          File.foreach(st_file, encoding: "UTF-8", invalid: :replace) do |ln|
            k, v = ln.split(":", 2)
            kv[k.strip] = v.strip if k && v
          end
          workers << {
            "id" => File.basename(File.dirname(st_file)),
            "execs_done" => kv["execs_done"].to_i,
            "execs_per_sec" => kv["execs_per_sec"].to_f,
            "corpus_count" => kv["corpus_count"].to_i,
            "saved_crashes" => kv["saved_crashes"].to_i,
            "saved_hangs" => kv["saved_hangs"].to_i,
            "run_time_sec" => kv["run_time"].to_i
          }
        end
      end

      triage_meta = Topology.read_json(File.join(ws[:triage_dir], "metadata.json"))
      clusters_meta = Topology.read_json(File.join(ws[:triage_dir], "clusters.json"))
      cov_meta = Topology.read_json(File.join(ws[:coverage_dir], "coverage.json"))
      totals = cov_meta&.dig("pairs", 0, "totals") || cov_meta&.dig("data", 0, "totals") || cov_meta&.dig("totals")

      {
        "campaign" => ctx[:plan]["name"],
        "campaign_file" => ctx[:campaign_path],
        "container" => ctx[:container_name],
        "container_running" => container_running?(ctx[:container_name]),
        "workspace" => ws.transform_keys(&:to_s),
        "fleet" => {
          "worker_stats_found" => workers.size,
          "total_execs" => workers.sum { |w| w["execs_done"] },
          "total_execs_per_sec" => workers.sum { |w| w["execs_per_sec"] }.round(2),
          "max_run_time_sec" => workers.map { |w| w["run_time_sec"] }.max || 0,
          "max_corpus_count" => workers.map { |w| w["corpus_count"] }.max || 0,
          "saved_crashes" => workers.sum { |w| w["saved_crashes"] },
          "saved_hangs" => workers.sum { |w| w["saved_hangs"] }
        },
        "triage" => triage_meta ? {
          "bucket_count" => triage_meta.dig("summary", "bucket_count"),
          "total_occurrences" => triage_meta.dig("summary", "total_occurrences"),
          "cluster_count" => clusters_meta&.dig("summary", "cluster_count") || clusters_meta&.dig("clusters")&.size
        }.compact : nil,
        "coverage" => totals.is_a?(Hash) ? {
          "regions_percent" => totals.dig("regions", "percent")&.round(2),
          "lines_percent" => totals.dig("lines", "percent")&.round(2),
          "functions_percent" => totals.dig("functions", "percent")&.round(2)
        }.compact : nil
      }.compact
    end

    def show_workspace_logs(ctx, args, json: false)
      logs_dir = ctx.dig(:ws, :logs_dir)
      cname = ctx[:container_name]

      follow = false
      raw = false
      tail_lines = nil
      positional = []
      i = 0
      while i < args.size
        tok = args[i]
        case tok
        when "-f", "--follow"
          follow = true
        when "--raw"
          raw = true
        when "-n", "--tail"
          tail_lines = Integer(args[i + 1]) if i + 1 < args.size
          i += 1
        when /\A--tail=(\d+)\z/
          tail_lines = Integer(Regexp.last_match(1))
        else
          positional << tok unless tok.start_with?("-")
        end
        i += 1
      end

      if positional.empty? && args.all? { |a| a.start_with?("-") } && container_running?(cname) && !json
        exec("docker", "logs", *args, cname)
      end

      files = logs_dir && File.directory?(logs_dir) ? Dir.glob(File.join(logs_dir, "**", "*.log")).sort : []
      if json
        payload = files.map do |p|
          {
            "name" => p.delete_prefix("#{logs_dir}/").delete_suffix(".log"),
            "path" => p,
            "bytes" => File.size(p),
            "mtime" => File.mtime(p).utc.iso8601
          }
        end
        puts JSON.pretty_generate(payload)
        return 0
      end

      target = if positional.size >= 2 && positional[0] == "worker"
                 File.join(logs_dir.to_s, "workers", "#{positional[1].delete_suffix('.log')}.log")
               elsif positional.size == 1
                 name = positional[0].delete_suffix(".log")
                 cand1 = File.join(logs_dir.to_s, "#{name}.log")
                 cand2 = File.join(logs_dir.to_s, "workers", "#{name}.log")
                 File.file?(cand1) ? cand1 : cand2
               else
                 files.max_by { |p| File.mtime(p) }
               end

      if positional.empty? && files.any?
        puts "== Workspace logs (#{logs_dir}) =="
        files.each do |p|
          rel = p.delete_prefix("#{logs_dir}/")
          puts "  #{rel.ljust(24)} #{File.size(p).to_s.rjust(8)}B  (#{File.mtime(p).utc.strftime('%Y-%m-%d %H:%M:%S UTC')})"
        end
        puts ""
      end

      unless target && File.file?(target)
        hint = files.any? ? " (available: #{files.map { |p| p.delete_prefix("#{logs_dir}/").delete_suffix('.log') }.join(', ')})" : ""
        raise CampaignError, "No log file found under #{logs_dir}#{hint}"
      end

      if follow
        exec("tail", "-n", (tail_lines || 100).to_s, "-f", target)
      end

      puts "== #{target} =="
      lines = File.readlines(target, encoding: "UTF-8", invalid: :replace)
      total = lines.size
      limit = tail_lines || (lines.size > 150 ? 120 : lines.size)
      shown = lines.last(limit)
      puts "... (#{total - shown.size} earlier lines omitted; use --tail #{total} or open #{target}) ..." if total > shown.size
      shown.each do |ln|
        out_ln = raw ? ln : Progress.strip_ansi(ln).delete("\r")
        print out_ln
      end
      0
    end

    def print_stats_summary(ctx, stats = collect_stats(ctx))
      fl = stats["fleet"]
      puts "== Campaign Stats: #{stats['campaign']} =="
      puts "Workspace   : #{ctx[:ws][:fuzz_dir]}"
      puts "Container   : #{stats['container']} (#{stats['container_running'] ? 'running' : 'stopped'})"
      if fl["worker_stats_found"] > 0
        puts "Fuzzing     : #{fl['worker_stats_found']} workers | #{fl['total_execs']} execs (#{fl['total_execs_per_sec']}/s) | max corpus #{fl['max_corpus_count']} | crashes #{fl['saved_crashes']} | hangs #{fl['saved_hangs']} | max runtime #{fl['max_run_time_sec']}s"
      else
        puts "Fuzzing     : no fuzzer_stats found yet"
      end
      if (tr = stats["triage"])
        puts "Triage      : #{tr['bucket_count'] || 0} buckets, #{tr['cluster_count'] || 0} clusters (#{tr['total_occurrences'] || 0} occurrences)"
      end
      if (cov = stats["coverage"])
        puts "Coverage    : regions=#{cov['regions_percent']}% lines=#{cov['lines_percent']}% functions=#{cov['functions_percent']}%"
      end
      report_idx = File.join(ctx[:ws][:report_dir], "index.html")
      puts "Report      : #{report_idx}" if File.file?(report_idx)
    end
  end
end
