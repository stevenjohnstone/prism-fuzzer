# frozen_string_literal: true

module PrismFuzzer
  module Campaign
    # Object-oriented handle returned by `PrismFuzzer.campaign(...)`, supporting
    # both imperative Ruby orchestration (`c.build!`, `c.start!`, `c.wait!`,
    # `c.triage!`, `c.stats`) and automatic CLI dispatch when a campaign script
    # is executed directly from the shell.
    class Instance
      attr_reader :ir, :source_path, :fuzz_root

      def initialize(ir, source_path: nil, fuzz_root: Topology.locate_fuzz_root)
        @ir = Topology.deep_dup(ir)
        @source_path = source_path ? File.expand_path(source_path) : nil
        @fuzz_root = fuzz_root
        @invoked = false
      end

      def invoked?
        @invoked
      end

      def validate!
        mark_invoked!
        Topology.validate_ir!(@ir, fuzz_root: @fuzz_root, source_label: @source_path || @ir["name"].to_s)
        self
      end

      def context(**cli_opts)
        cli = normalize_cli_opts(cli_opts)
        Campaign.resolve_context(ir: @ir, campaign_path: @source_path, cli: cli, fuzz_root: @fuzz_root)
      end

      def workspace(**ws_opts)
        mark_invoked!
        context(**ws_opts)[:ws]
      end

      def plan(**ws_opts)
        mark_invoked!
        context(**ws_opts)[:plan]
      end

      def container_name(**ws_opts)
        mark_invoked!
        context(**ws_opts)[:container_name]
      end

      def attach_command(**ws_opts)
        mark_invoked!
        Campaign.attach_command_string(context(**ws_opts))
      end

      def running?(**ws_opts)
        mark_invoked!
        Campaign.container_running?(context(**ws_opts)[:container_name])
      end

      def sync!(build_ruby: false, cache_dir: nil, **ws_opts)
        mark_invoked!
        return context(**ws_opts)[:plan] if Thread.current[:prism_fuzzer_compiling_dsl]

        ctx = context(**ws_opts)
        Topology.sync_plan!(
          ctx[:plan],
          fuzz_root: @fuzz_root,
          build_dir: ctx[:ws][:build_dir],
          cache_dir: cache_dir || Topology.default_cache_dir(@fuzz_root),
          allow_ruby_build: build_ruby
        )
      end

      def build!(skip_sync: false, dry_run: false, build_ruby: false, **ws_opts)
        mark_invoked!
        return context(**ws_opts)[:plan] if Thread.current[:prism_fuzzer_compiling_dsl]

        Campaign.build!(context(**ws_opts), skip_sync: skip_sync, dry_run: dry_run, build_ruby: build_ruby)
      end

      def start!(detach: true, duration: nil, skip_sync: false, skip_build: false, dry_run: false, **opts)
        mark_invoked!
        return self if Thread.current[:prism_fuzzer_compiling_dsl]

        merged = duration.nil? ? opts : opts.merge(duration: duration)
        Campaign.run_campaign!(context(**merged), detach: detach, dry_run: dry_run, skip_sync: skip_sync, skip_build: skip_build, run_post: false)
        self
      end

      def run!(duration: nil, detach: false, dry_run: false, skip_sync: false, skip_build: false, **opts)
        mark_invoked!
        return 0 if Thread.current[:prism_fuzzer_compiling_dsl]

        merged = duration.nil? ? opts : opts.merge(duration: duration)
        Campaign.run_campaign!(context(**merged), detach: detach, dry_run: dry_run, skip_sync: skip_sync, skip_build: skip_build)
      end

      def wait!(duration = nil, **opts)
        mark_invoked!
        return self if Thread.current[:prism_fuzzer_compiling_dsl]

        merged = duration.nil? ? opts : opts.merge(duration: duration)
        ctx = context(**merged)
        sec = ctx[:lifecycle]["duration_seconds"]
        raise CampaignError, "Campaign timer duration required (pass duration or set `duration` in campaign DSL)" unless sec && sec > 0

        Campaign.wait_with_timer(ctx, sec)
        self
      end

      def stop!(timeout: 30, dry_run: false, **opts)
        mark_invoked!
        return false if Thread.current[:prism_fuzzer_compiling_dsl]

        cli = normalize_cli_opts(opts)
        ctx = Campaign.resolve_context(ir: @ir, campaign_path: @source_path, cli: cli, fuzz_root: @fuzz_root)
        Campaign.stop_campaign!(ctx, timeout: timeout, cli_opts: cli, dry_run: dry_run)
      end

      def attach!(**ws_opts)
        mark_invoked!
        return nil if Thread.current[:prism_fuzzer_compiling_dsl]

        cname = context(**ws_opts)[:container_name]
        raise CampaignError, "Container '#{cname}' is not running" unless Campaign.container_running?(cname)

        exec("docker", "exec", "-it", cname, "tmux", "-2", "attach-session", "-t", "fuzzer")
      end

      def report!(dry_run: false, **opts)
        mark_invoked!
        return true if Thread.current[:prism_fuzzer_compiling_dsl]

        rep_cli = if opts.empty?
                    {}
                  elsif opts.key?(:enabled) && opts.size == 1
                    { report: opts[:enabled] }
                  else
                    { report: opts.transform_keys(&:to_s) }
                  end
        ctx = rep_cli.empty? ? context : context(**rep_cli)
        Campaign.run_report!(ctx, dry_run: dry_run)
      end

      def publish!(dry_run: false, **opts)
        mark_invoked!
        return true if Thread.current[:prism_fuzzer_compiling_dsl]

        cli_opts = {
          publish_run_id: opts[:run_id],
          publish_title: opts[:title],
          publish_out_dir: opts[:out_dir]
        }
        cli_opts[:publish_gh_pages] = opts[:gh_pages] if opts.key?(:gh_pages)
        cli_opts[:publish_branch] = opts[:branch] if opts.key?(:branch)
        cli_opts[:publish_remote] = opts[:remote] if opts.key?(:remote)
        cli_opts[:publish_commit] = opts[:commit] if opts.key?(:commit)
        cli_opts[:publish_push] = opts[:push] if opts.key?(:push)
        ctx = opts.empty? ? context : context(**cli_opts)
        Campaign.run_publish!(ctx, dry_run: dry_run)
      end

      def post_pipeline!(dry_run: false, **opts)
        mark_invoked!
        return self if Thread.current[:prism_fuzzer_compiling_dsl]

        Campaign.run_post_pipeline!(context(**opts), dry_run: dry_run)
      end

      def stats(**ws_opts)
        mark_invoked!
        return {} if Thread.current[:prism_fuzzer_compiling_dsl]

        Campaign.collect_stats(context(**ws_opts))
      end

      def print_stats(**ws_opts)
        mark_invoked!
        return nil if Thread.current[:prism_fuzzer_compiling_dsl]

        ctx = context(**ws_opts)
        Campaign.print_stats_summary(ctx, Campaign.collect_stats(ctx))
      end

      def cli!(argv = ARGV)
        mark_invoked!
        return 0 if Thread.current[:prism_fuzzer_compiling_dsl]

        Campaign.run_cli(argv, instance: self)
      end

      private

      def mark_invoked!
        @invoked = true
      end

      def normalize_cli_opts(opts)
        cli = opts.dup
        if cli.key?(:duration)
          d = cli.delete(:duration)
          cli[:duration_seconds] = (d.nil? || d.to_s.strip == "0") ? nil : CampaignDSL.parse_duration(d)
        end
        cli[:publish_run_id] ||= cli.delete(:run_id) if cli.key?(:run_id)
        cli[:publish_title] ||= cli.delete(:title) if cli.key?(:title)
        cli[:publish_out_dir] ||= cli.delete(:out_dir) if cli.key?(:out_dir)
        cli
      end
    end
  end
end
