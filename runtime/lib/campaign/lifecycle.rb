# frozen_string_literal: true

module PrismFuzzer
  module Campaign
    module_function

    def merge_lifecycle(base_lifecycle, cli = {})
      lc = base_lifecycle.is_a?(Hash) ? Topology.deep_dup(base_lifecycle) : {}

      if cli.key?(:duration_seconds)
        if cli[:duration_seconds].nil? || cli[:duration_seconds] <= 0
          lc.delete("duration_seconds")
        else
          lc["duration_seconds"] = cli[:duration_seconds]
        end
      end

      if cli[:no_post]
        %w[report publish].each { |k| lc.delete(k) }
        return lc
      end

      if cli[:post]
        lc["report"] = true unless lc.key?("report")
      end

      %w[report publish].each do |step|
        sym = step.to_sym
        next unless cli.key?(sym) && !cli[sym].nil?

        if cli[sym] == false
          lc[step] = false
        elsif cli[sym].is_a?(Hash)
          merged = lc[step].is_a?(Hash) ? lc[step].dup : {}
          cli[sym].each { |k, v| merged[k.to_s] = v }
          merged["enabled"] = true unless merged.key?("enabled")
          lc[step] = merged
        elsif lc[step].is_a?(Hash)
          lc[step]["enabled"] = true
        else
          lc[step] = true
        end
      end

      if cli[:publish_run_id] || cli[:publish_title] || cli[:publish_out_dir]
        pub = lc["publish"].is_a?(Hash) ? lc["publish"] : {}
        pub["enabled"] = true unless pub.key?("enabled") && pub["enabled"] == false
        pub["run_id"] = cli[:publish_run_id] if cli[:publish_run_id]
        pub["title"] = cli[:publish_title] if cli[:publish_title]
        pub["out_dir"] = cli[:publish_out_dir] if cli[:publish_out_dir]
        lc["publish"] = pub
      end

      lc
    end

    def step_enabled?(lifecycle, key)
      val = lifecycle[key.to_s]
      return true if val == true
      return val["enabled"] != false if val.is_a?(Hash)

      false
    end

    def step_opts(lifecycle, key)
      val = lifecycle[key.to_s]
      val.is_a?(Hash) ? val : {}
    end

    def any_post_steps?(lifecycle)
      %w[report publish].any? { |k| step_enabled?(lifecycle, k) }
    end

    def resolve_context(ir: nil, campaign_path: nil, cli: {}, fuzz_root: Topology.locate_fuzz_root)
      if ir
        ir = Topology.deep_dup(ir)
        ir_path = File.expand_path(campaign_path || Topology.default_topology_path(fuzz_root), fuzz_root)
        Topology.validate_ir!(ir, fuzz_root: fuzz_root, source_label: ir_path)
      else
        ir, ir_path = Topology.load_ir(campaign_path, fuzz_root: fuzz_root)
      end
      ws = Topology.workspace_paths(
        ir,
        fuzz_root: fuzz_root,
        build_dir: cli[:build_dir],
        fuzz_dir: cli[:fuzz_dir],
        corpus_dir: cli[:corpus_dir],
        bin_dir: cli[:bin_dir]
      )
      plan = Topology.compile_plan(ir, fuzz_root: fuzz_root, build_dir: ws[:build_dir])
      ws = Topology.workspace_paths(
        plan,
        fuzz_root: fuzz_root,
        build_dir: ws[:build_dir],
        fuzz_dir: cli[:fuzz_dir],
        corpus_dir: cli[:corpus_dir],
        bin_dir: cli[:bin_dir]
      )
      lifecycle = merge_lifecycle(plan["lifecycle"], cli)
      cname = container_name_for(plan, ws: ws, override: cli[:container_name], fuzz_root: fuzz_root)
      ws_custom_dir = !cli[:fuzz_dir].nil? || !Topology.blank?(ENV["FUZZ_DIR"])
      ws_custom_build = !cli[:build_dir].nil? || !Topology.blank?(ENV["FUZZ_BUILD_DIR"])
      ws_custom_corpus = !cli[:corpus_dir].nil? || !Topology.blank?(ENV["TRIAGE_CORPUS_DIR"])
      ws_overridden = ws_custom_dir || ws_custom_build || ws_custom_corpus ||
                      !Topology.blank?(ENV["TRIAGE_DIR"]) ||
                      !Topology.blank?(ENV["FUZZ_LOGS_DIR"]) ||
                      !Topology.blank?(ENV["REPORTS_DIR"])

      {
        fuzz_root: fuzz_root,
        ir: ir,
        campaign_path: ir_path,
        campaign_rel: Topology.path_relative_or_abs(ir_path, fuzz_root),
        plan: plan,
        ws: ws,
        ws_custom_dir: ws_custom_dir,
        ws_custom_build: ws_custom_build,
        ws_custom_corpus: ws_custom_corpus,
        ws_overridden: ws_overridden,
        lifecycle: lifecycle,
        container_name: cname
      }
    end

    def watcher_lock_path(ctx)
      File.join(ctx[:ws][:fuzz_dir], ".run-watcher.lock")
    end

    def run_state_path(ctx)
      File.join(ctx[:ws][:fuzz_dir], ".run-state.json")
    end

    def read_run_state(ctx)
      Topology.read_json(run_state_path(ctx))
    end

    def write_run_state!(ctx, lifecycle: ctx[:lifecycle], run_token: SecureRandom.hex(8), post_handled: false)
      FileUtils.mkdir_p(ctx[:ws][:fuzz_dir])
      Topology.write_json_atomic(
        run_state_path(ctx),
        {
          "container" => ctx[:container_name],
          "run_token" => run_token,
          "lifecycle" => lifecycle || {},
          "post_handled" => post_handled
        }
      )
      run_token
    end

    def with_watcher_lock(ctx, blocking: true)
      path = watcher_lock_path(ctx)
      FileUtils.mkdir_p(File.dirname(path))
      File.open(path, File::CREAT | File::RDWR, 0o644) do |f|
        mode = blocking ? File::LOCK_EX : (File::LOCK_EX | File::LOCK_NB)
        return nil unless f.flock(mode)

        begin
          yield
        ensure
          begin
            f.flock(File::LOCK_UN)
          rescue SystemCallError, IOError => e
            warn "PrismFuzzer::Campaign: failed to unlock watcher lock #{path}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
            nil
          end
        end
      end
    end

    def resolve_stop_context(ctx, cli_opts = {})
      state = read_run_state(ctx)
      return ctx unless state.is_a?(Hash) && state["container"] == ctx[:container_name] && state["lifecycle"].is_a?(Hash)

      ctx.merge(lifecycle: merge_lifecycle(state["lifecycle"], cli_opts || {}))
    end

    def finalize_campaign_run!(ctx, run_post: true, print_stats: true, expected_run_token: nil)
      state = read_run_state(ctx)
      if expected_run_token && state.is_a?(Hash) && state["run_token"] && state["run_token"] != expected_run_token
        return :superseded
      end
      if state.is_a?(Hash) && state["post_handled"] && state["container"] == ctx[:container_name]
        return :already_handled
      end

      token = state.is_a?(Hash) && state["run_token"] ? state["run_token"] : SecureRandom.hex(8)
      write_run_state!(ctx, lifecycle: ctx[:lifecycle], run_token: token, post_handled: true)

      if run_post
        run_post_pipeline!(ctx, dry_run: false) if any_post_steps?(ctx[:lifecycle])
        print_stats_summary(ctx) if print_stats
      end
      :ran
    end

    def stop_campaign!(ctx, timeout: 30, cli_opts: {}, dry_run: false)
      cname = ctx[:container_name]
      post_ctx = resolve_stop_context(ctx, cli_opts)
      has_post = any_post_steps?(post_ctx[:lifecycle])

      if dry_run
        puts "docker stop -t #{timeout} #{Shellwords.escape(cname)}"
        run_post_pipeline!(post_ctx, dry_run: true) if has_post
        return true
      end

      stopped = stop_container!(cname, timeout: timeout)
      unless stopped
        puts "Container '#{cname}' is not running."
        return false
      end

      puts "Stopped '#{cname}'."
      if has_post
        acquired = with_watcher_lock(post_ctx, blocking: false) do
          finalize_campaign_run!(post_ctx, run_post: true, print_stats: true)
        end
        puts "Active foreground runner will complete post-run steps for '#{cname}'." if acquired.nil?
      end
      true
    end

    def run_campaign!(ctx, detach: false, dry_run: false, skip_sync: false, skip_build: false, run_post: true)
      lc = ctx[:lifecycle]
      duration = lc["duration_seconds"]
      ws = ctx[:ws]

      unless dry_run
        build!(ctx, skip_sync: skip_sync, dry_run: false) unless skip_build
        FileUtils.mkdir_p([ws[:afl_dir], ws[:bin_dir]])
      else
        build!(ctx, skip_sync: skip_sync, dry_run: true) unless skip_build
      end

      if in_docker?
        run_cmd = ["/bin/bash", "-c", "exec ./runtime/run.sh"]
        if dry_run
          puts "[dry-run] duration=#{duration.inspect} after_run=#{lc.keys.join(',')}"
          run_post_pipeline!(ctx, dry_run: true) if run_post && any_post_steps?(lc)
          return 0
        end
        ir_host = write_container_ir!(ctx, dry_run: false)
        child_env = { "CAMPAIGN" => ir_host, "TOPOLOGY" => ir_host }
        interrupted = false
        prev_int = Signal.trap("INT") { interrupted = true }
        prev_term = Signal.trap("TERM") { interrupted = true }
        begin
          if duration && duration > 0
            ok = system(child_env.merge("FUZZ_DAEMON" => "1"), "timeout", "-s", "TERM", "-k", "30", duration.to_s, *run_cmd, chdir: ctx[:fuzz_root])
            raise CampaignError, "Campaign run failed" unless ok || $?.exitstatus == 124 || $?.exitstatus == 143 || (interrupted && ($?.exitstatus == 130 || $?.exitstatus == 143))
          else
            ok = system(child_env, *run_cmd, chdir: ctx[:fuzz_root])
            raise CampaignError, "Campaign run failed" unless ok || (interrupted && ($?.exitstatus == 130 || $?.exitstatus == 143))
          end
        ensure
          Signal.trap("INT", prev_int || "DEFAULT")
          Signal.trap("TERM", prev_term || "DEFAULT")
        end
        if run_post
          run_post_pipeline!(ctx, dry_run: false) if any_post_steps?(lc)
          print_stats_summary(ctx)
        end
        return 0
      end

      if dry_run
        cmd = docker_cmd_for(ctx, ["/bin/bash", "-c", "exec ./runtime/run.sh"], detach: true, name: ctx[:container_name], extra_env: { "FUZZ_DAEMON" => "1" })
        puts "[dry-run] #{cmd.map { |t| Shellwords.escape(t) }.join(' ')}"
        if detach
          puts "[dry-run] detach attach: #{attach_command_string(ctx)}"
        elsif duration && duration > 0
          puts "[dry-run] wait timer: #{duration}s (attach: #{attach_command_string(ctx)})"
        else
          puts "[dry-run] #{attach_command_string(ctx)}"
        end
        run_post_pipeline!(ctx, dry_run: true) if !detach && run_post && any_post_steps?(lc)
        return 0
      end

      cid, run_token = start_detached_container!(ctx)
      puts "Container ID  : #{cid}"

      if detach
        print_observe_commands(ctx, duration_seconds: duration)
      else
        cname = ctx[:container_name]
        timed = !duration.nil? && duration > 0
        with_watcher_lock(ctx, blocking: true) do
          if interactive_tty?
            outcome = attach_tmux_session!(ctx, duration_seconds: timed ? duration : nil)
            if outcome[:expired]
              puts "\nTimer expired (#{duration}s); stopped campaign '#{ctx[:plan]['name']}'."
              wait_for_container_exit(cname)
              finalize_campaign_run!(ctx, run_post: run_post, print_stats: true, expected_run_token: run_token)
            elsif outcome[:interrupted]
              puts "\nSignal received; stopped campaign '#{ctx[:plan]['name']}'."
              wait_for_container_exit(cname)
              finalize_campaign_run!(ctx, run_post: run_post, print_stats: timed || any_post_steps?(lc), expected_run_token: run_token)
            elsif tmux_session_alive?(cname)
              puts "\nDetached from campaign '#{ctx[:plan]['name']}' (still running in background)."
              print_observe_commands(ctx, duration_seconds: nil)
            else
              wait_for_container_exit(cname)
              finalize_campaign_run!(ctx, run_post: run_post, print_stats: timed || any_post_steps?(lc), expected_run_token: run_token)
            end
          elsif timed
            ensure_tmux_session!(ctx)
            puts "ready."
            print_observe_commands(ctx, duration_seconds: duration)
            wait_with_timer(ctx, duration)
            finalize_campaign_run!(ctx, run_post: run_post, print_stats: true, expected_run_token: run_token)
          else
            ensure_tmux_session!(ctx)
            puts "ready."
            puts "Non-interactive terminal; leaving campaign '#{ctx[:plan]['name']}' running in background."
            print_observe_commands(ctx, duration_seconds: nil)
          end
        end
      end
      0
    end

    def maybe_register_autorun!(instance, caller_path:)
      return if Thread.current[:prism_fuzzer_compiling_dsl]
      return unless caller_path && File.file?(caller_path) && File.file?($PROGRAM_NAME)
      return unless File.realpath(caller_path) == File.realpath($PROGRAM_NAME)

      @autorun_lock.synchronize do
        @autorun_candidates << instance
        unless @autorun_hook_installed
          @autorun_hook_installed = true
          at_exit do
            next unless $!.nil?

            PrismFuzzer::Campaign.autorun_dispatch!
          end
        end
      end
    rescue Errno::ENOENT
      nil
    end

    def autorun_dispatch!
      candidates = @autorun_lock.synchronize { @autorun_candidates.dup }
      return if candidates.empty? || candidates.any?(&:invoked?)

      if candidates.size > 1
        warn "Error: Multiple PrismFuzzer.campaign blocks defined in #{$PROGRAM_NAME}; invoke .run! or .cli! explicitly."
        exit(1)
      end

      rc = run_cli(ARGV, instance: candidates.first)
      exit(rc) unless rc == 0
    end

    def run_cli(argv = ARGV, instance: nil)
      CLI.run(argv, instance: instance)
    end
  end
end
