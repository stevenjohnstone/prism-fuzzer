# frozen_string_literal: true

module PrismFuzzer
  module Campaign
    # Shared CLI dispatcher used by both executable campaign scripts and `bin/campaign.rb`.
    module CLI
      module_function

      KNOWN_SUBCOMMANDS = %w[
        run validate compile plan paths sync sync-ruby build docker-build
        ensure-afl-passes invalidate-docker-caches
        attach stop logs ps status stats clean shell
        report retriage verify bisect match explain inspect publish bench accel
        env docker-args plan-launch
      ].freeze

      def run(argv = ARGV, instance: nil)
        argv = argv.dup
        subcmd = if argv.first && !argv.first.start_with?("-")
                   if KNOWN_SUBCOMMANDS.include?(argv.first)
                     argv.shift
                   elsif instance.nil? && (File.extname(argv.first) == ".rb" || File.extname(argv.first) == ".json")
                     "run"
                   else
                     argv.shift
                   end
                 else
                   "run"
                 end

        fuzz_root = instance ? instance.fuzz_root : PrismFuzzer::Topology.locate_fuzz_root
        opts = {
          campaign: nil,
          build_dir: nil,
          cache_dir: ENV.fetch("TARGETS_CACHE_DIR", PrismFuzzer::Topology.default_cache_dir(fuzz_root)),
          fuzz_dir: nil,
          corpus_dir: nil,
          bin_dir: nil,
          container_name: nil,
          build_ruby: false,
          dry_run: false,
          no_stage: false,
          detach: false,
          skip_sync: false,
          skip_build: false,
          in_container_step: false,
          force: false,
          live: false,
          relative: false,
          shell: false,
          json: false
        }

        passthrough = []
        if (sep = argv.index("--"))
          passthrough = argv[(sep + 1)..]
          argv = argv[0...sep]
        end

        prog_name = if instance
                      ($0 && !$0.empty? ? $0 : instance.source_path)
                    else
                      "campaign.rb"
                    end

        parser = OptionParser.new do |op|
          usage_target = instance ? "#{prog_name} <subcommand> [options]" : "campaign.rb <subcommand> [campaign.rb] [options]"
          op.banner = <<~BANNER
            Usage: #{usage_target} [-- passthrough-args]

            Subcommands:
              run            Sync, build, start fuzzers, wait on duration timer (if set), and run after_run steps
              attach         Attach to the running tmux session in the campaign container
              stop / logs    Stop container (and run after_run steps) or show logs
              ps             List running prism-fuzzer campaign containers with attach commands
              status / stats Show live container status (--live) or workspace campaign statistics
              report         Triage crashes, collect LLVM coverage, and generate HTML report (<ws>/report/)
              retriage       Re-triage failing inputs in the campaign workspace
              verify         Verify fixed inputs across triage buckets
              bisect         Bisect regression/fix commit across Prism history
              match / inspect / explain / publish
              bench / accel / shell / clean
              validate / compile / plan / paths / sync / sync-ruby / build / docker-build
          BANNER
          op.on("-c", "--campaign PATH", "--topology PATH", "Campaign DSL (.rb) or topology IR (.json) (default: campaigns/default.rb)") { |v| opts[:campaign] = v }
          op.on("--build-dir PATH", "Override workspace build_dir") { |v| opts[:build_dir] = File.expand_path(v) }
          op.on("--cache-dir PATH", "Git mirror cache directory") { |v| opts[:cache_dir] = File.expand_path(v) }
          op.on("--fuzz-dir PATH", "Override workspace runtime dir") { |v| opts[:fuzz_dir] = File.expand_path(v) }
          op.on("--corpus-dir PATH", "Override workspace corpus dir") { |v| opts[:corpus_dir] = File.expand_path(v) }
          op.on("--bin-dir PATH", "Override snapshot bin dir") { |v| opts[:bin_dir] = File.expand_path(v) }
          op.on("--container-name NAME", "Override Docker container name") { |v| opts[:container_name] = v }
          op.on("--duration SPEC", "Override campaign timer duration (e.g. 30m, 2h, 300; 0 clears)") do |v|
            opts[:duration_seconds] = v.to_s.strip == "0" ? nil : PrismFuzzer::CampaignDSL.parse_duration(v)
          end
          op.on("-d", "--detach", "Run fuzzers detached and print Docker attach commands") { opts[:detach] = true }
          op.on("--post", "Run report (triage, coverage, HTML report) after fuzzing stops") { opts[:post] = true }
          op.on("--no-post", "Skip all after_run post-processing steps") { opts[:no_post] = true }
          op.on("--report", "Enable post-run report (triage + coverage + unified HTML)") { opts[:report] = true }
          op.on("--publish", "Enable post-run report publishing") { opts[:publish] = true }
          op.on("--run-id ID", "Run ID for publish step") { |v| opts[:publish_run_id] = v }
          op.on("--title TEXT", "Title for publish step") { |v| opts[:publish_title] = v }
          op.on("--out-dir DIR", "Output directory for publish step") { |v| opts[:publish_out_dir] = v }
          op.on("--skip-sync", "Skip source sync") { opts[:skip_sync] = true }
          op.on("--skip-build", "Skip binary build") { opts[:skip_build] = true }
          op.on("--in-container-step", "Internal flag for container build dispatch") { opts[:in_container_step] = true }
          op.on("--build-ruby", "Build custom ruby source ref if different from /opt/ruby") { opts[:build_ruby] = true }
          op.on("--dry-run", "Print planned actions without executing") { opts[:dry_run] = true }
          op.on("--no-stage", "--pure", "Compute plan-launch output without staging (for plan-launch)") { opts[:no_stage] = true }
          op.on("--force", "Force Docker rebuild (for docker-build)") { opts[:force] = true }
          op.on("--live", "Attach/query live running status inside container") { opts[:live] = true }
          op.on("-f", "--follow", "Follow log output (for logs subcommand)") { opts[:follow] = true }
          op.on("-n", "--tail LINES", Integer, "Number of trailing log lines to show") { |v| opts[:tail] = v }
          op.on("--raw", "Preserve ANSI escapes when printing worker logs") { opts[:raw] = true }
          op.on("--progress MODE", "Progress UI mode: auto, tty, plain") { |v| ENV["FUZZ_PROGRESS"] = v }
          op.on("--relative", "Output relative paths (for paths subcommand)") { opts[:relative] = true }
          op.on("--shell", "Shell-escape values for eval (for paths subcommand)") { opts[:shell] = true }
          op.on("--json", "Output JSON") { opts[:json] = true }
          op.on("-h", "--help", "Show help") { puts op; return 0 }
        end

        if instance.nil? && opts[:campaign].nil? && argv.first && !argv.first.start_with?("-") && (File.extname(argv.first) == ".rb" || File.extname(argv.first) == ".json")
          opts[:campaign] = argv.shift
        end
        parser.order!(argv)
        if instance.nil? && opts[:campaign].nil? && argv.first && (File.extname(argv.first) == ".rb" || File.extname(argv.first) == ".json")
          opts[:campaign] = argv.shift
        end
        extra_args = argv + passthrough

        case subcmd
        when "ps"
          containers = PrismFuzzer::Campaign.list_containers
          if opts[:json]
            puts JSON.pretty_generate(containers)
          elsif containers.empty?
            puts "No running prism-fuzzer campaign containers."
          else
            containers.each do |c|
              meta = []
              meta << "campaign=#{c['campaign_file']}" if c["campaign_file"]
              meta << "ws=#{c['workspace']}" if c["workspace"]
              suffix = meta.empty? ? "" : " [#{meta.join(' ')}]"
              puts "#{c['name']} (#{c['status']})#{suffix} -> docker exec -it #{Shellwords.escape(c['name'])} tmux -2 attach-session -t fuzzer"
            end
          end
          return 0
        when "docker-build"
          PrismFuzzer::Campaign.ensure_docker_image!(fuzz_root: fuzz_root, build_dir: opts[:build_dir], force: opts[:force], dry_run: opts[:dry_run])
          return 0
        when "ensure-afl-passes"
          PrismFuzzer::Campaign.ensure_afl_passes!(fuzz_root: fuzz_root, dry_run: opts[:dry_run])
          return 0
        when "invalidate-docker-caches"
          PrismFuzzer::Campaign.invalidate_docker_dependent_caches!(fuzz_root: fuzz_root, build_dir: opts[:build_dir]) unless opts[:dry_run]
          return 0
        end

        ctx = if instance && opts[:campaign].nil?
                PrismFuzzer::Campaign.resolve_context(ir: instance.ir, campaign_path: instance.source_path, cli: opts, fuzz_root: fuzz_root)
              else
                PrismFuzzer::Campaign.resolve_context(campaign_path: opts[:campaign], cli: opts, fuzz_root: fuzz_root)
              end
        ws = ctx[:ws]
        plan = ctx[:plan]

        case subcmd
        when "run"
          return PrismFuzzer::Campaign.run_campaign!(ctx, detach: opts[:detach], dry_run: opts[:dry_run], skip_sync: opts[:skip_sync], skip_build: opts[:skip_build])
        when "validate"
          sp = PrismFuzzer::Topology.schema_path(fuzz_root)
          if opts[:json]
            puts JSON.pretty_generate(
              "valid" => true,
              "schema" => sp,
              "campaign" => ctx[:campaign_path],
              "schema_version" => plan["schema_version"],
              "name" => plan["name"],
              "workspace" => plan["workspace"],
              "lifecycle" => ctx[:lifecycle],
              "sources" => plan["sources"].keys,
              "fuzzers" => plan["fuzzers"].keys,
              "workers" => plan["workers"].map { |w| w["id"] }
            )
          else
            puts "OK: #{ctx[:campaign_path]} valid against #{sp} (schema_version=#{plan['schema_version']}, #{plan['fuzzers'].size} fuzzers, #{plan['workers'].size} workers)"
          end
          0
        when "compile"
          puts JSON.pretty_generate(ctx[:ir])
          0
        when "plan"
          puts JSON.pretty_generate(plan)
          0
        when "paths", "env", "docker-args", "plan-launch", "sync", "sync-ruby"
          delegated = [subcmd]
          delegated.push("--build-dir", ws[:build_dir]) if opts[:build_dir]
          delegated.push("--cache-dir", opts[:cache_dir]) if opts[:cache_dir]
          delegated.push("--fuzz-dir", ws[:fuzz_dir]) if opts[:fuzz_dir]
          delegated.push("--corpus-dir", ws[:corpus_dir]) if opts[:corpus_dir]
          delegated.push("--bin-dir", ws[:bin_dir]) if opts[:bin_dir]
          delegated << "--build-ruby" if opts[:build_ruby]
          delegated << "--dry-run" if opts[:dry_run]
          delegated << "--no-stage" if opts[:no_stage]
          delegated << "--relative" if opts[:relative]
          delegated << "--shell" if opts[:shell]
          delegated << "--json" if opts[:json]
          PrismFuzzer::TopologyCLI.run(
            delegated,
            preloaded_ir: ctx[:ir],
            preloaded_plan: plan,
            preloaded_path: ctx[:campaign_path]
          )
        when "build"
          if opts[:in_container_step]
            PrismFuzzer::Campaign.ensure_afl_passes!(fuzz_root: fuzz_root, dry_run: opts[:dry_run])
            resolved = PrismFuzzer::Topology.read_json(File.join(ws[:build_dir], "topology.resolved.json"))
            PrismFuzzer::Topology.normalize_runtime_paths!(resolved, fuzz_root: fuzz_root) if resolved
            resolved ||= plan
            plan["sources"].each do |id, s|
              s.merge!(resolved["sources"][id].slice("resolved", "path", "gen_dir", "commit", "oracle_dir", "ruby_bin").compact) if resolved["sources"][id]
            end
            PrismFuzzer::Topology.build_plan!(plan, fuzz_root: fuzz_root, build_dir: ws[:build_dir], dry_run: opts[:dry_run])
            unless opts[:dry_run]
              puts FuzzProvenance.write_build_manifest(ws[:build_dir], repo_root: fuzz_root)
              puts "Fuzzers up to date"
            end
          else
            PrismFuzzer::Campaign.build!(ctx, skip_sync: opts[:skip_sync], dry_run: opts[:dry_run], build_ruby: opts[:build_ruby])
          end
          0
        when "attach"
          cname = ctx[:container_name]
          if opts[:dry_run]
            puts PrismFuzzer::Campaign.attach_command_string(ctx)
            return 0
          end
          unless PrismFuzzer::Campaign.container_running?(cname)
            raise PrismFuzzer::Campaign::CampaignError, "Container '#{cname}' is not running (check '#{PrismFuzzer::Campaign.script_cli_prefix(ctx)} ps')"
          end

          exec("docker", "exec", "-it", cname, "tmux", "-2", "attach-session", "-t", "fuzzer")
        when "stop"
          PrismFuzzer::Campaign.stop_campaign!(ctx, cli_opts: opts, dry_run: opts[:dry_run])
          0
        when "logs"
          log_args = extra_args.dup
          log_args << "-f" if opts[:follow]
          log_args << "--raw" if opts[:raw]
          log_args.push("--tail", opts[:tail].to_s) if opts[:tail]
          return PrismFuzzer::Campaign.show_workspace_logs(ctx, log_args, json: opts[:json])
        when "status", "stats"
          cname = ctx[:container_name]
          if (subcmd == "status" || opts[:live]) && PrismFuzzer::Campaign.container_running?(cname) && !opts[:json]
            guest_afl = PrismFuzzer::Campaign.guest_path_for(ws[:afl_dir], ctx, ws_key: "dir")
            tty_flags = ($stdin.tty? && $stdout.tty?) ? ["-it"] : ($stdin.tty? ? ["-i"] : ($stdout.tty? ? ["-t"] : []))
            exec("docker", "exec", *tty_flags, cname, "ruby", "/prism-fuzzer/runtime/status.rb", guest_afl)
          end
          stats = PrismFuzzer::Campaign.collect_stats(ctx)
          if opts[:json]
            puts JSON.pretty_generate(stats)
          else
            PrismFuzzer::Campaign.print_stats_summary(ctx, stats)
          end
          0
        when "report"
          PrismFuzzer::Campaign.run_report!(ctx, dry_run: opts[:dry_run])
          0
        when "publish"
          PrismFuzzer::Campaign.run_publish!(ctx, dry_run: opts[:dry_run])
          0
        when "retriage"
          PrismFuzzer::Campaign.ensure_docker_image!(fuzz_root: fuzz_root, dry_run: opts[:dry_run])
          PrismFuzzer::Campaign.run_in_container!(ctx, ["ruby", "./triage/retriage.rb", "--triage-dir", PrismFuzzer::Campaign.guest_path_for(ws[:triage_dir], ctx, ws_key: "triage_dir"), *extra_args], interactive: true, dry_run: opts[:dry_run])
          0
        when "verify"
          PrismFuzzer::Campaign.ensure_docker_image!(fuzz_root: fuzz_root, dry_run: opts[:dry_run])
          PrismFuzzer::Campaign.run_in_container!(ctx, ["ruby", "./triage/verify.rb", "--triage-dir", PrismFuzzer::Campaign.guest_path_for(ws[:triage_dir], ctx, ws_key: "triage_dir"), *extra_args], interactive: true, dry_run: opts[:dry_run])
          0
        when "bisect"
          PrismFuzzer::Campaign.ensure_docker_image!(fuzz_root: fuzz_root, dry_run: opts[:dry_run])
          ir_host = PrismFuzzer::Campaign.write_container_ir!(ctx, dry_run: opts[:dry_run])
          camp_env = File.file?(ir_host) ? ir_host : ctx[:campaign_path]
          ok = system({ "CAMPAIGN" => camp_env, "TOPOLOGY" => camp_env }, RbConfig.ruby, File.join(fuzz_root, "triage", "bisect.rb"), "--triage-dir", ws[:triage_dir], *extra_args, chdir: fuzz_root)
          ok ? 0 : 1
        when "match"
          PrismFuzzer::Campaign.ensure_docker_image!(fuzz_root: fuzz_root, dry_run: opts[:dry_run])
          PrismFuzzer::Campaign.run_in_container!(ctx, ["ruby", "./triage/match.rb", "--triage-dir", PrismFuzzer::Campaign.guest_path_for(ws[:triage_dir], ctx, ws_key: "triage_dir"), *extra_args], interactive: true, dry_run: opts[:dry_run])
          0
        when "explain"
          PrismFuzzer::Campaign.build!(ctx, dry_run: opts[:dry_run])
          ir_host = PrismFuzzer::Campaign.write_container_ir!(ctx, dry_run: opts[:dry_run])
          camp_env = File.file?(ir_host) ? ir_host : ctx[:campaign_path]
          ok = system({ "CAMPAIGN" => camp_env, "TOPOLOGY" => camp_env }, RbConfig.ruby, File.join(fuzz_root, "triage", "explain.rb"), "--triage-dir", ws[:triage_dir], *extra_args, chdir: fuzz_root)
          ok ? 0 : 1
        when "inspect"
          ir_host = PrismFuzzer::Campaign.write_container_ir!(ctx, dry_run: opts[:dry_run])
          camp_env = File.file?(ir_host) ? ir_host : ctx[:campaign_path]
          ok = system({ "CAMPAIGN" => camp_env, "TOPOLOGY" => camp_env }, RbConfig.ruby, File.join(fuzz_root, "triage", "inspect.rb"), "--triage-dir", ws[:triage_dir], *extra_args, chdir: fuzz_root)
          ok ? 0 : 1
        when "bench"
          PrismFuzzer::Campaign.ensure_docker_image!(fuzz_root: fuzz_root, dry_run: opts[:dry_run])
          json_out = File.join(PrismFuzzer::Campaign.guest_path_for(ws[:fuzz_dir], ctx, ws_key: "dir"), "grammar-bench.json")
          PrismFuzzer::Campaign.run_in_container!(ctx, ["ruby", "./runtime/grammar_bench.rb", "--json", json_out, *extra_args], dry_run: opts[:dry_run])
          0
        when "accel"
          PrismFuzzer::Campaign.ensure_docker_image!(fuzz_root: fuzz_root, dry_run: opts[:dry_run])
          PrismFuzzer::Campaign.run_in_container!(ctx, ["./test/test_accel.sh", *extra_args], dry_run: opts[:dry_run])
          0
        when "shell"
          PrismFuzzer::Campaign.ensure_docker_image!(fuzz_root: fuzz_root, dry_run: opts[:dry_run])
          PrismFuzzer::Campaign.run_in_container!(ctx, ["/bin/bash", *extra_args], interactive: true, dry_run: opts[:dry_run])
          0
        when "clean"
          ws_abs = File.expand_path(ws[:fuzz_dir])
          preserved_dirs = [ws[:triage_dir], ws[:build_dir]].map { |p| File.expand_path(p) }.uniq
          kept_labels = preserved_dirs.map do |p|
            p.start_with?("#{ws_abs}/") ? "#{p.delete_prefix("#{ws_abs}/")}/" : p
          end
          puts "Removing runtime files under #{ws[:fuzz_dir]}/ (preserving #{kept_labels.join(', ')})"
          PrismFuzzer::Campaign.clean_preserving_paths(ws[:fuzz_dir], preserved_dirs) unless opts[:dry_run]
          0
        else
          raise PrismFuzzer::Campaign::CampaignError, "Unknown subcommand '#{subcmd}' (run --help)"
        end
      rescue PrismFuzzer::Topology::TopologyError, PrismFuzzer::Campaign::CampaignError, PrismFuzzer::CampaignDSL::Error, PrismFuzzer::Progress::StageCommandError, OptionParser::ParseError => e
        warn "Error: #{e.message}" unless e.instance_variable_defined?(:@logged_by_progress)
        1
      end
    end
  end
end
