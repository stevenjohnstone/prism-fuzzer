# frozen_string_literal: true

module PrismFuzzer
  Object.const_set(:RubyFuzz, self) unless Object.const_defined?(:RubyFuzz, false)

  # Ergonomic Ruby Campaign DSL (`campaigns/*.rb`) compiled into Topology IR v2
  # (`topology.schema.json`) without injecting hidden defaults or scaling pools.
  module CampaignDSL
    PRISM_DEFAULT_REPO = "https://github.com/ruby/prism.git"
    RUBY_DEFAULT_REPO = "https://github.com/ruby/ruby.git"

    DURATION_UNITS = {
      "s" => 1,
      "sec" => 1,
      "secs" => 1,
      "m" => 60,
      "min" => 60,
      "mins" => 60,
      "h" => 3600,
      "hr" => 3600,
      "hrs" => 3600,
      "d" => 86_400,
      "day" => 86_400,
      "days" => 86_400
    }.freeze

    class Error < StandardError; end

    module_function

    def normalize_value(val)
      case val
      when Symbol
        val.to_s
      when Hash
        val.each_with_object({}) do |(k, v), acc|
          next if v.nil?

          acc[k.to_s] = normalize_value(v)
        end
      when Array
        val.map { |v| normalize_value(v) }
      else
        val
      end
    end

    def parse_duration(val)
      return nil if val.nil?
      return Integer(val) if val.is_a?(Integer) || val.is_a?(Float)

      str = val.to_s.strip.downcase
      raise Error, "Duration cannot be empty" if str.empty?
      return Integer(str, 10) if str.match?(/\A\d+\z/)

      total = 0
      pos = 0
      str.scan(/(\d+(?:\.\d+)?)\s*([a-z]+)/) do |num_s, unit|
        match_start = Regexp.last_match.begin(0)
        raise Error, "Invalid duration '#{val}'" unless match_start == pos

        mult = DURATION_UNITS[unit]
        raise Error, "Unknown duration unit '#{unit}' in '#{val}'" unless mult

        total += (num_s.to_f * mult).round
        pos = Regexp.last_match.end(0)
        pos += 1 while pos < str.length && str[pos] =~ /\s/
      end
      raise Error, "Invalid duration '#{val}'" unless pos == str.length && total > 0

      total
    end

    def compile_file(path, fuzz_root: nil)
      expanded = File.expand_path(path)
      raise Error, "Campaign DSL file not found: #{expanded}" unless File.file?(expanded)

      compile_source(File.read(expanded, encoding: "UTF-8"), path: expanded, fuzz_root: fuzz_root)
    end

    def compile_source(source, path: "(dsl)", fuzz_root: nil)
      prev_compiling = Thread.current[:prism_fuzzer_compiling_dsl]
      Thread.current[:prism_fuzzer_compiling_dsl] = true
      Thread.current[:prism_fuzzer_last_dsl_campaign] = nil

      sandbox = Module.new
      dsl_self_feature = %r{\A(?:prism_fuzzer|ruby_fuzz|campaign|campaign_dsl|topology|topology_dsl)(?:\.rb)?\z|/(?:lib/(?:prism_fuzzer|ruby_fuzz)|runtime/(?:campaign|campaign_dsl|topology|topology_dsl))(?:\.rb)?\z}
      sandbox.define_singleton_method(:require) do |feature|
        return false if dsl_self_feature.match?(feature.to_s)

        Kernel.instance_method(:require).bind_call(self, feature)
      end
      sandbox.define_singleton_method(:require_relative) do |rel|
        base_dir = File.file?(path) ? File.dirname(File.expand_path(path)) : Dir.pwd
        resolved = File.expand_path(rel.to_s, base_dir)
        return false if dsl_self_feature.match?(resolved) || dsl_self_feature.match?(rel.to_s)

        Kernel.instance_method(:require).bind_call(self, resolved)
      end

      result = sandbox.module_eval(source, path, 1)
      result = result.ir if result.respond_to?(:ir)
      captured = Thread.current[:prism_fuzzer_last_dsl_campaign]
      ir = result.is_a?(Hash) && result.key?("schema_version") ? result : captured
      unless ir.is_a?(Hash) && ir.key?("schema_version")
        raise Error, "DSL file '#{path}' did not produce a campaign via PrismFuzzer.campaign"
      end

      if fuzz_root && PrismFuzzer::Topology.respond_to?(:validate_ir!)
        PrismFuzzer::Topology.validate_ir!(ir, fuzz_root: fuzz_root, source_label: path)
      end
      ir
    ensure
      Thread.current[:prism_fuzzer_last_dsl_campaign] = nil
      Thread.current[:prism_fuzzer_compiling_dsl] = prev_compiling
    end

    def build(name, fuzz_root: nil, &block)
      raise ArgumentError, "Campaign block required for '#{name}'" unless block

      builder = CampaignBuilder.new(name)
      builder.instance_eval(&block)
      ir = builder.to_h
      if fuzz_root && PrismFuzzer::Topology.respond_to?(:validate_ir!)
        PrismFuzzer::Topology.validate_ir!(ir, fuzz_root: fuzz_root, source_label: name.to_s)
      end
      Thread.current[:prism_fuzzer_last_dsl_campaign] = ir
      ir
    end

    # Declarative builder for a single fuzzer definition.
    class FuzzerBuilder
      def initialize(id, shape, initial = {})
        @spec = CampaignDSL.normalize_value(initial)
        @spec["shape"] = shape.to_s
        @id = id.to_s
      end

      def source(id) = (@spec["source"] = id.to_s)
      def prism(id) = (@spec["prism"] = id.to_s)
      def ruby(id) = (@spec["ruby"] = id.to_s)
      def prism_a(id) = (@spec["prism_a"] = id.to_s)
      def prism_b(id) = (@spec["prism_b"] = id.to_s)
      def arch(val) = (@spec["arch"] = val.to_s)
      def sanitizers(*vals) = (@spec["sanitizers"] = vals.flatten.map(&:to_s))
      def mode(val) = (@spec["mode"] = val.to_s)
      def afl(val) = (@spec["afl"] = val.to_s)
      def ijon(flag = true) = (@spec["ijon"] = !!flag)
      def xallocator(flag = true) = (@spec["xallocator"] = !!flag)
      def document_ids(flag = true) = (@spec["document_ids"] = !!flag)
      def binary(path) = (@spec["binary"] = path.to_s)
      def verify_profile(name) = (@spec["verify_profile"] = name.to_s)
      def cflags(*vals) = (@spec["cflags"] = vals.flatten.map(&:to_s))
      def mutator(name) = (@spec["mutator"] = name.to_s)
      def repro(name) = (@spec["repro"] = name.to_s)

      def defines(map = {}, **kw)
        merged = CampaignDSL.normalize_value(map.merge(kw))
        @spec["defines"] = (@spec["defines"] || {}).merge(merged)
      end

      def to_h
        @spec
      end
    end

    # Declarative builder for an individual worker definition.
    class WorkerBuilder
      def initialize(initial = {})
        @spec = CampaignDSL.normalize_value(initial)
        if @spec.key?("no_mem_limit")
          nml = @spec.delete("no_mem_limit")
          @spec["mem_limit"] = "none" if nml
        end
        @spec["max_input_size"] = Integer(@spec["max_input_size"]) if @spec["max_input_size"]
      end

      def id(val) = (@spec["id"] = val.to_s)
      def kind(val) = (@spec["kind"] = val.to_s)
      def fuzzer(val) = (@spec["fuzzer"] = val.to_s)
      def aux_fuzzer(val) = (@spec["aux_fuzzer"] = val.to_s)
      def sync_group(val) = (@spec["sync_group"] = val.to_s)
      def afl_role(val) = (@spec["afl_role"] = val.to_s)
      def schedule(val) = (@spec["schedule"] = val.to_s)
      def afl_flags(*vals) = (@spec["afl_flags"] = vals.flatten.map(&:to_s))
      def cmplog(val) = (@spec["cmplog"] = val.to_s)
      def mutator(val) = (@spec["mutator"] = val.to_s)
      def loopcount(val) = (@spec["loopcount"] = Integer(val))
      def max_input_size(val) = (@spec["max_input_size"] = Integer(val))
      def no_trim(flag = true) = (@spec["no_trim"] = !!flag)
      def ulimit_v_kb(val) = (@spec["ulimit_v_kb"] = Integer(val))
      def keep_open_on_exit(flag = true) = (@spec["keep_open_on_exit"] = !!flag)
      def color(val) = (@spec["color"] = val.to_s)
      def generator(val) = (@spec["generator"] = val.to_s)

      def mem_limit(val)
        @spec["mem_limit"] = (val.to_s == "none" ? "none" : Integer(val))
      end

      def no_mem_limit(flag = true)
        @spec["mem_limit"] = "none" if flag
      end

      def seeds(from:, filter: nil, cache_key: nil, shard_group: nil)
        s = { "from" => from.to_s }
        s["filter"] = filter.to_s if filter
        s["cache_key"] = cache_key.to_s if cache_key
        s["shard_group"] = shard_group.to_s if shard_group
        @spec["seeds"] = s
      end

      def foreign_sync(*vals)
        @spec["foreign_sync"] = vals.flatten.map(&:to_s)
      end

      def peer_import(group:, worker:, alias:)
        @spec["peer_imports"] ||= []
        @spec["peer_imports"] << {
          "group" => group.to_s,
          "worker" => worker.to_s,
          "alias" => binding.local_variable_get(:alias).to_s
        }
      end

      def peer_imports(list)
        @spec["peer_imports"] = CampaignDSL.normalize_value(Array(list))
      end

      def env(map = {}, **kw)
        merged = CampaignDSL.normalize_value(map.merge(kw))
        @spec["env"] = (@spec["env"] || {}).merge(merged)
      end

      def to_h
        @spec["kind"] ||= (@spec.key?("generator") ? "generator" : "afl")
        @spec
      end
    end

    # Scoped block context when calling `workers(shared) { worker ... }`.
    class WorkersScope
      def initialize(campaign_builder, shared)
        @campaign_builder = campaign_builder
        @shared = CampaignDSL.normalize_value(shared)
      end

      def worker(id = nil, **opts, &block)
        merged = @shared.merge(CampaignDSL.normalize_value(opts))
        @campaign_builder.send(:add_worker, id, merged, &block)
      end

      def afl(id, **opts, &block)
        merged = @shared.merge(CampaignDSL.normalize_value(opts)).merge("kind" => "afl")
        @campaign_builder.send(:add_worker, id, merged, &block)
      end

      def generator(id, **opts, &block)
        merged = @shared.merge(CampaignDSL.normalize_value(opts)).merge("kind" => "generator")
        @campaign_builder.send(:add_worker, id, merged, &block)
      end
    end

    # Scoped block context for `after_run { report ...; publish ... }`.
    class AfterRunBuilder
      def initialize(lifecycle)
        @lifecycle = lifecycle
      end

      def report(enabled_or_opts = true, **opts)
        @lifecycle["report"] = normalize_step(enabled_or_opts, opts, int_keys: %w[threads top])
      end

      def publish(enabled_or_opts = true, **opts)
        @lifecycle["publish"] = normalize_step(enabled_or_opts, opts)
      end

      private

      def normalize_step(enabled_or_opts, opts, int_keys: [])
        merged = {}
        case enabled_or_opts
        when true, false
          return enabled_or_opts if opts.empty?

          merged["enabled"] = enabled_or_opts
        when Hash
          merged.merge!(CampaignDSL.normalize_value(enabled_or_opts))
        else
          raise Error, "Expected boolean or options Hash for after_run step, got #{enabled_or_opts.class}"
        end
        merged.merge!(CampaignDSL.normalize_value(opts))
        merged["enabled"] = true unless merged.key?("enabled")
        int_keys.each do |k|
          merged[k] = Integer(merged[k]) if merged.key?(k)
        end
        merged
      end
    end

    # Root builder backing `PrismFuzzer.campaign(name) { ... }`.
    class CampaignBuilder
      def initialize(name)
        @name = name.to_s
        raise Error, "Campaign name cannot be empty" if @name.strip.empty?

        @defaults = nil
        @workspace = nil
        @coverage = nil
        @lifecycle = {}
        @sources = {}
        @generators = {}
        @fuzzers = {}
        @sync_groups = {}
        @workers = []
      end

      def duration(val)
        secs = CampaignDSL.parse_duration(val)
        raise Error, "Campaign duration must be positive" unless secs && secs > 0

        @lifecycle["duration_seconds"] = secs
      end

      def after_run(&block)
        raise Error, "after_run requires a block" unless block

        AfterRunBuilder.new(@lifecycle).instance_eval(&block)
      end

      def report(enabled_or_opts = true, **opts)
        AfterRunBuilder.new(@lifecycle).report(enabled_or_opts, **opts)
      end

      def publish(enabled_or_opts = true, **opts)
        AfterRunBuilder.new(@lifecycle).publish(enabled_or_opts, **opts)
      end

      def workspace(dir_or_opts = nil, **opts)
        h = case dir_or_opts
            when Hash then CampaignDSL.normalize_value(dir_or_opts).merge(CampaignDSL.normalize_value(opts))
            when String, Symbol then CampaignDSL.normalize_value(opts).merge("dir" => dir_or_opts.to_s)
            when nil then CampaignDSL.normalize_value(opts)
            else raise Error, "Expected workspace directory path or options Hash, got #{dir_or_opts.class}"
            end
        dir = h["dir"].to_s
        raise Error, "Workspace requires a non-empty 'dir'" if dir.strip.empty?

        h["build_dir"] ||= File.join(dir, "build")
        @workspace = h
      end

      def defaults(max_input_size: nil, max_allocated_mb: nil)
        d = {}
        d["max_input_size"] = Integer(max_input_size) if max_input_size
        d["max_allocated_mb"] = Integer(max_allocated_mb) if max_allocated_mb
        @defaults = d unless d.empty?
      end

      def source(id, kind:, **opts)
        sid = id.to_s
        raise Error, "Duplicate source '#{sid}'" if @sources.key?(sid)

        k = kind.to_s
        s = CampaignDSL.normalize_value(opts)
        s["kind"] = k
        has_local = s.key?("dir") || s.key?("local_path")
        unless has_local
          s["repo"] ||= (k == "prism" ? PRISM_DEFAULT_REPO : RUBY_DEFAULT_REPO)
        end
        if k == "prism"
          s["patches"] ||= (has_local ? "none" : "auto")
          s["templates"] ||= "auto"
        end
        @sources[sid] = s
      end

      def prism(id, **opts)
        source(id, kind: :prism, **opts)
      end

      def ruby(id, **opts)
        source(id, kind: :ruby, **opts)
      end

      def coverage(source:, fuzzer: nil, diff_fuzzer: nil)
        cov = { "source" => source.to_s }
        cov["fuzzer"] = fuzzer.to_s if fuzzer
        cov["diff_fuzzer"] = diff_fuzzer.to_s if diff_fuzzer
        @coverage = cov
      end

      def generator(id, kind:, **opts)
        gid = id.to_s
        raise Error, "Duplicate generator '#{gid}'" if @generators.key?(gid)

        g = CampaignDSL.normalize_value(opts)
        g["kind"] = kind.to_s
        g["max_input_size"] = Integer(g["max_input_size"]) if g["max_input_size"]
        @generators[gid] = g
      end

      def corpus_generator(id, **opts)
        generator(id, kind: :corpus, **opts)
      end

      def grammar_generator(id, **opts)
        generator(id, kind: :grammar, **opts)
      end

      def fuzzer(id, shape:, **opts, &block)
        fid = id.to_s
        raise Error, "Duplicate fuzzer '#{fid}'" if @fuzzers.key?(fid)

        fb = FuzzerBuilder.new(fid, shape, opts)
        fb.instance_eval(&block) if block
        @fuzzers[fid] = fb.to_h
      end

      def sync_group(id, dir: nil, primary: nil)
        gid = id.to_s
        raise Error, "Duplicate sync_group '#{gid}'" if @sync_groups.key?(gid)

        sg = { "dir" => (dir || gid).to_s }
        sg["primary"] = !!primary unless primary.nil?
        @sync_groups[gid] = sg
      end

      def worker(id = nil, **opts, &block)
        add_worker(id, opts, &block)
      end

      def workers(items = nil, **shared, &block)
        shared_norm = CampaignDSL.normalize_value(shared)
        if items.is_a?(Array)
          items.each_with_index do |item, idx|
            raw = case item
                  when Hash then CampaignDSL.normalize_value(item)
                  when String, Symbol then { "id" => item.to_s }
                  else raise Error, "Expected worker Hash/String at index #{idx}, got #{item.class}"
                  end
            merged = shared_norm.merge(raw)
            wid = merged["id"]
            raise Error, "Worker entry at index #{idx} is missing 'id'" if wid.nil? || wid.to_s.strip.empty?

            wb = WorkerBuilder.new(merged)
            if block
              if block.arity == 0
                wb.instance_eval(&block)
              else
                block.call(wb, raw)
              end
            end
            register_worker!(wb.to_h)
          end
        elsif items.nil? && block
          scope = WorkersScope.new(self, shared_norm)
          scope.instance_eval(&block)
        else
          raise Error, "workers expects either an Array of property hashes or a block"
        end
      end

      def to_h
        ir = {
          "schema_version" => 2,
          "name" => @name
        }
        ir["workspace"] = @workspace if @workspace
        ir["lifecycle"] = @lifecycle unless @lifecycle.empty?
        ir["defaults"] = @defaults if @defaults
        ir["sources"] = @sources
        ir["coverage"] = @coverage if @coverage
        ir["generators"] = @generators unless @generators.empty?
        ir["fuzzers"] = @fuzzers
        ir["sync_groups"] = @sync_groups
        ir["workers"] = @workers
        ir
      end

      private

      def add_worker(id, opts, &block)
        merged = CampaignDSL.normalize_value(opts)
        merged["id"] = id.to_s unless id.nil?
        raise Error, "Worker is missing 'id'" if merged["id"].nil? || merged["id"].to_s.strip.empty?

        wb = WorkerBuilder.new(merged)
        if block
          if block.arity == 0
            wb.instance_eval(&block)
          else
            block.call(wb)
          end
        end
        register_worker!(wb.to_h)
      end

      def register_worker!(spec)
        wid = spec["id"].to_s
        raise Error, "Duplicate worker '#{wid}'" if @workers.any? { |w| w["id"] == wid }

        @workers << spec
      end
    end
  end

  def self.campaign(name, autorun: true, &block)
    ir = CampaignDSL.build(name, &block)
    return ir unless defined?(PrismFuzzer::Campaign::Instance)

    loc = caller_locations(1, 1)&.first
    caller_path = loc&.absolute_path || loc&.path
    instance = PrismFuzzer::Campaign::Instance.new(ir, source_path: caller_path)
    PrismFuzzer::Campaign.maybe_register_autorun!(instance, caller_path: caller_path) if autorun
    instance
  end
end
