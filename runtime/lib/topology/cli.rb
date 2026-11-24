# frozen_string_literal: true

require "json"
require "optparse"
require "shellwords"

require_relative "../../topology"

module PrismFuzzer
  # Command-line dispatcher for topology validation, compilation, syncing,
  # building, launch planning, and environment inspection.
  module TopologyCLI
    module_function

    def run(argv = ARGV, preloaded_ir: nil, preloaded_plan: nil, preloaded_path: nil)
      argv = argv.dup
      subcmd = argv.shift || "sync"
      fuzz_root = PrismFuzzer::Topology.locate_fuzz_root
      opts = {
        topology: nil,
        build_dir: nil,
        cache_dir: ENV.fetch("TARGETS_CACHE_DIR", PrismFuzzer::Topology.default_cache_dir(fuzz_root)),
        fuzz_dir: nil,
        corpus_dir: nil,
        bin_dir: nil,
        build_ruby: false,
        dry_run: false,
        no_stage: false,
        relative: false,
        shell: false,
        json: false,
        arch: nil,
        source: nil,
        target: nil,
        prism_dir: nil,
        gen_dir: nil,
        output: nil,
        jobs: nil
      }

      OptionParser.new do |op|
        op.banner = "Usage: topology.rb {validate|compile|plan|paths|sync|sync-ruby|build|build-explain|gen-inc|env|status|docker-args|plan-launch} [options]"
        op.on("--campaign PATH", "--topology PATH", "Path to campaign DSL (.rb) or topology IR (.json) file (default: campaigns/default.rb)") { |v| opts[:topology] = v }
        op.on("--build-dir PATH", "Build directory (default: workspace build_dir or tmp/fuzz/build)") { |v| opts[:build_dir] = File.expand_path(v) }
        op.on("--cache-dir PATH", "Git mirror cache directory") { |v| opts[:cache_dir] = File.expand_path(v) }
        op.on("--fuzz-dir PATH", "Runtime fuzz root directory (default: workspace dir or tmp/fuzz)") { |v| opts[:fuzz_dir] = File.expand_path(v) }
        op.on("--corpus-dir PATH", "Seed corpus directory") { |v| opts[:corpus_dir] = File.expand_path(v) }
        op.on("--bin-dir PATH", "Snapshot bin directory") { |v| opts[:bin_dir] = File.expand_path(v) }
        op.on("--build-ruby", "Build configured ruby source ref if different from /opt/ruby") { opts[:build_ruby] = true }
        op.on("-j", "--jobs N", Integer, "Maximum parallel build jobs (default: JOBS env or min(nproc, 16))") { |v| opts[:jobs] = v }
        op.on("--dry-run", "Print build commands without executing them") { opts[:dry_run] = true }
        op.on("--no-stage", "--pure", "Compute plan-launch output without filesystem or subprocess staging") { opts[:no_stage] = true }
        op.on("--relative", "Output paths relative to repo root where applicable (for paths subcommand)") { opts[:relative] = true }
        op.on("--shell", "Shell-escape values for eval (for paths subcommand)") { opts[:shell] = true }
        op.on("--json", "Output JSON") { opts[:json] = true }
        op.on("--arch ARCH", "Target architecture for build-explain (host|arm32|ppc)") { |v| opts[:arch] = v }
        op.on("--source ID", "Source ID for build-explain/gen-inc (default: prism_a)") { |v| opts[:source] = v }
        op.on("--target TARGET", "Explain target alias (a|b)") { |v| opts[:target] = v }
        op.on("--prism-dir PATH", "Explicit Prism checkout directory for build-explain/gen-inc") { |v| opts[:prism_dir] = File.expand_path(v) }
        op.on("--gen-dir PATH", "Generated include output directory for build-explain/gen-inc") { |v| opts[:gen_dir] = File.expand_path(v) }
        op.on("--output PATH", "Output binary path for build-explain") { |v| opts[:output] = File.expand_path(v) }
        op.on("-h", "--help", "Show help") { puts op; return 0 }
      end.parse!(argv)

      standalone_prism = %w[build-explain gen-inc].include?(subcmd) &&
                         opts[:prism_dir] &&
                         opts[:topology].nil? &&
                         !File.file?(PrismFuzzer::Topology.default_topology_path(fuzz_root))

      use_preloaded = (opts[:topology].nil? || opts[:topology] == preloaded_path) && (!preloaded_plan.nil? || !preloaded_ir.nil?)
      if standalone_prism
        src_id = opts[:source] || (opts[:target] == "b" ? "prism_b" : "prism_a")
        ir_path = nil
        ws = PrismFuzzer::Topology.workspace_paths(nil, fuzz_root: fuzz_root, build_dir: opts[:build_dir], fuzz_dir: opts[:fuzz_dir], corpus_dir: opts[:corpus_dir], bin_dir: opts[:bin_dir])
        build_dir = ws[:build_dir]
        gen_dir = opts[:gen_dir] || File.join(build_dir, "targets", "gen", src_id)
        ir = {}
        plan = {
          "schema_version" => PrismFuzzer::Topology::TOPOLOGY_SCHEMA_VERSION,
          "name" => "standalone-explain",
          "defaults" => { "max_input_size" => 1024, "max_allocated_mb" => 128 },
          "sources" => {
            src_id => { "id" => src_id, "kind" => "prism", "path" => opts[:prism_dir], "gen_dir" => gen_dir }
          },
          "fuzzers" => {},
          "sync_groups" => {},
          "workers" => []
        }
      elsif use_preloaded
        ir = preloaded_ir || preloaded_plan
        ir_path = preloaded_path || opts[:topology] || PrismFuzzer::Topology.default_topology_path(fuzz_root)
        plan = preloaded_plan || PrismFuzzer::Topology.compile_plan(ir, fuzz_root: fuzz_root, build_dir: opts[:build_dir])
        ws = PrismFuzzer::Topology.workspace_paths(plan, fuzz_root: fuzz_root, build_dir: opts[:build_dir], fuzz_dir: opts[:fuzz_dir], corpus_dir: opts[:corpus_dir], bin_dir: opts[:bin_dir])
        build_dir = ws[:build_dir]
      else
        ir, ir_path = PrismFuzzer::Topology.load_ir(opts[:topology], fuzz_root: fuzz_root)
        ws = PrismFuzzer::Topology.workspace_paths(ir, fuzz_root: fuzz_root, build_dir: opts[:build_dir], fuzz_dir: opts[:fuzz_dir], corpus_dir: opts[:corpus_dir], bin_dir: opts[:bin_dir])
        build_dir = ws[:build_dir]
        plan = PrismFuzzer::Topology.compile_plan(ir, fuzz_root: fuzz_root, build_dir: build_dir)
        ws = PrismFuzzer::Topology.workspace_paths(plan, fuzz_root: fuzz_root, build_dir: build_dir, fuzz_dir: opts[:fuzz_dir], corpus_dir: opts[:corpus_dir], bin_dir: opts[:bin_dir])
      end

      case subcmd
      when "validate"
        sp = PrismFuzzer::Topology.schema_path(fuzz_root)
        if opts[:json]
          puts JSON.pretty_generate(
            "valid" => true,
            "schema" => sp,
            "topology" => ir_path,
            "schema_version" => plan["schema_version"],
            "name" => plan["name"],
            "workspace" => plan["workspace"],
            "lifecycle" => plan["lifecycle"],
            "sources" => plan["sources"].keys,
            "fuzzers" => plan["fuzzers"].keys,
            "workers" => plan["workers"].map { |w| w["id"] }
          )
        else
          puts "OK: #{ir_path} valid against #{sp} (schema_version=#{plan['schema_version']}, #{plan['fuzzers'].size} fuzzers, #{plan['workers'].size} workers)"
        end
        0
      when "compile"
        puts JSON.pretty_generate(ir)
        0
      when "plan"
        puts JSON.pretty_generate(plan)
        0
      when "paths"
        fmt_path = ->(p) { opts[:relative] ? PrismFuzzer::Topology.path_relative_or_abs(p, fuzz_root) : p }
        out_map = {
          "WORKSPACE_DIR" => fmt_path.call(ws[:fuzz_dir]),
          "WORKSPACE_BUILD_DIR" => fmt_path.call(ws[:build_dir]),
          "WORKSPACE_AFL_SUBDIR" => ws[:afl_subdir],
          "WORKSPACE_AFL_DIR" => fmt_path.call(ws[:afl_dir]),
          "WORKSPACE_BIN_DIR" => fmt_path.call(ws[:bin_dir]),
          "WORKSPACE_SNAPSHOT_DIR" => fmt_path.call(ws[:snapshot_dir]),
          "WORKSPACE_CORPUS_DIR" => fmt_path.call(ws[:corpus_dir]),
          "WORKSPACE_SEEDS_DIR" => fmt_path.call(ws[:seeds_dir]),
          "WORKSPACE_TRIAGE_DIR" => fmt_path.call(ws[:triage_dir]),
          "WORKSPACE_REPORT_DIR" => fmt_path.call(ws[:report_dir]),
          "WORKSPACE_COVERAGE_DIR" => fmt_path.call(ws[:coverage_dir]),
          "WORKSPACE_LOGS_DIR" => fmt_path.call(ws[:logs_dir]),
          "WORKSPACE_REPORTS_DIR" => fmt_path.call(ws[:reports_dir])
        }
        if opts[:json]
          puts JSON.pretty_generate(out_map)
        elsif opts[:shell]
          out_map.each { |k, v| puts "#{k}=#{Shellwords.escape(v)}" }
        else
          out_map.each { |k, v| puts "#{k}=#{v}" }
        end
        0
      when "sync"
        resolved = PrismFuzzer::Topology.sync_plan!(plan, fuzz_root: fuzz_root, build_dir: build_dir, cache_dir: opts[:cache_dir], allow_ruby_build: opts[:build_ruby])
        if opts[:json]
          puts JSON.pretty_generate(resolved)
        else
          resolved["sources"].each do |id, s|
            if s["kind"] == "prism"
              app = Array(s.dig("resolved", "applied_patches")).size
              skip = Array(s.dig("resolved", "skipped_patches")).size
              puts "#{id}: #{s['path']} (#{s['commit'] || 'local'}) patches=+#{app}/skip=#{skip}"
            elsif s["oracle_dir"]
              puts "#{id}: #{s['oracle_dir']} (#{s['commit'] || s['requested_ref'] || 'default'})"
            else
              puts "#{id}: (will resolve inside container /opt/ruby)"
            end
          end
          puts "topology: #{resolved['name']} (#{resolved['workers'].size} workers, #{resolved['fuzzers'].size} fuzzers)"
        end
        0
      when "sync-ruby"
        ruby_src = plan["sources"].values.find { |s| s["kind"] == "ruby" }
        raise PrismFuzzer::Topology::TopologyError, "No ruby source defined in topology" unless ruby_src

        rstate = PrismFuzzer::Topology.sync_ruby_source(ruby_src, build_dir: build_dir, cache_dir: opts[:cache_dir], allow_build: true)
        puts(opts[:json] ? JSON.pretty_generate(rstate) : "ruby: #{rstate['oracle_dir']} (#{rstate['commit'] || rstate['requested_ref']})")
        0
      when "build"
        resolved = PrismFuzzer::Topology.read_json(File.join(build_dir, "topology.resolved.json"))
        PrismFuzzer::Topology.normalize_runtime_paths!(resolved, fuzz_root: fuzz_root) if resolved
        unless resolved && resolved["sources"]&.all? { |id, s| s["path"] && (s["kind"] != "prism" || File.file?(File.join(s["path"], "include/prism.h"))) && plan["sources"].key?(id) } && resolved["sources"].keys.sort == plan["sources"].keys.sort
          resolved = PrismFuzzer::Topology.sync_plan!(plan, fuzz_root: fuzz_root, build_dir: build_dir, cache_dir: opts[:cache_dir], allow_ruby_build: opts[:build_ruby])
        else
          # Merge latest worker/fuzzer topology metadata while retaining synced source paths.
          plan["sources"].each do |id, s|
            s.merge!(resolved["sources"][id].slice("resolved", "path", "gen_dir", "commit", "oracle_dir", "ruby_bin").compact) if resolved["sources"][id]
          end
          resolved = plan
        end
        PrismFuzzer::Topology.build_plan!(resolved, fuzz_root: fuzz_root, build_dir: build_dir, dry_run: opts[:dry_run], jobs: opts[:jobs])
        return 0 if opts[:dry_run]

        prov_rb = File.join(fuzz_root, "runtime", "provenance.rb")
        if File.file?(prov_rb)
          require prov_rb
          puts FuzzProvenance.write_build_manifest(build_dir, repo_root: fuzz_root)
        end
        puts "Fuzzers up to date"
        0
      when "gen-inc"
        src_id = opts[:source] || (opts[:target] == "b" ? "prism_b" : nil) ||
                 (plan["sources"]["prism_a"] ? "prism_a" : plan["sources"].find { |_, s| s["kind"] == "prism" }&.first)
        raise PrismFuzzer::Topology::TopologyError, "No prism source found in topology" unless src_id

        src_dir = opts[:prism_dir] || (src_id == "prism_a" ? PrismFuzzer::Topology.env_override("PRISM_A_DIR") : nil)
        unless src_dir && File.file?(File.join(src_dir, "include", "prism.h"))
          resolved = PrismFuzzer::Topology.read_json(File.join(build_dir, "topology.resolved.json"))
          PrismFuzzer::Topology.normalize_runtime_paths!(resolved, fuzz_root: fuzz_root) if resolved
          src_spec = resolved&.dig("sources", src_id) || plan.dig("sources", src_id)
          raise PrismFuzzer::Topology::TopologyError, "Source '#{src_id}' not found in topology" unless src_spec

          if src_spec["path"] && File.file?(File.join(src_spec["path"], "include", "prism.h"))
            src_dir = src_spec["path"]
          else
            state = PrismFuzzer::Topology.sync_prism_source(src_spec, fuzz_root: fuzz_root, build_dir: build_dir, cache_dir: opts[:cache_dir])
            src_dir = state.fetch("path")
          end
        end
        gen_dir = opts[:gen_dir] || (src_id == "prism_a" ? PrismFuzzer::Topology.env_override("PRISM_A_GEN_DIR") : nil) || File.join(build_dir, "targets", "gen", src_id)
        PrismFuzzer::Topology.ensure_harness_generated_inc!(src_dir, gen_dir, fuzz_root: fuzz_root)
        puts(opts[:json] ? JSON.pretty_generate("source" => src_id, "prism_dir" => src_dir, "gen_dir" => gen_dir) : gen_dir)
        0
      when "build-explain"
        src_id = opts[:source] || (opts[:target] == "b" ? "prism_b" : nil) ||
                 (plan["sources"]["prism_a"] ? "prism_a" : plan["sources"].find { |_, s| s["kind"] == "prism" }&.first)
        raise PrismFuzzer::Topology::TopologyError, "No prism source found in topology" unless src_id

        if opts[:prism_dir]
          src_dir = opts[:prism_dir]
          PrismFuzzer::Topology.validate_prism_root!(src_dir)
          gen_dir = opts[:gen_dir] || File.join(build_dir, "targets", "gen", src_id)
          PrismFuzzer::Topology.ensure_harness_generated_inc!(src_dir, gen_dir, fuzz_root: fuzz_root)
          plan["sources"][src_id] = (plan["sources"][src_id] || {}).merge("id" => src_id, "kind" => "prism", "path" => src_dir, "gen_dir" => gen_dir)
        else
          resolved = PrismFuzzer::Topology.read_json(File.join(build_dir, "topology.resolved.json"))
          PrismFuzzer::Topology.normalize_runtime_paths!(resolved, fuzz_root: fuzz_root) if resolved
          if resolved&.dig("sources", src_id)
            plan["sources"][src_id] ||= {}
            plan["sources"][src_id].merge!(resolved["sources"][src_id].slice("resolved", "path", "gen_dir", "commit", "oracle_dir", "ruby_bin").compact)
          end
          src = plan.dig("sources", src_id)
          raise PrismFuzzer::Topology::TopologyError, "Source '#{src_id}' not found in topology" unless src

          if src["path"].nil? || !File.file?(File.join(src["path"].to_s, "include", "prism.h"))
            if src_id == "prism_a" && (env_p = PrismFuzzer::Topology.env_override("PRISM_A_DIR")) && File.file?(File.join(env_p, "include", "prism.h"))
              src["path"] = File.expand_path(env_p)
              src["gen_dir"] ||= PrismFuzzer::Topology.env_override("PRISM_A_GEN_DIR") ? File.expand_path(PrismFuzzer::Topology.env_override("PRISM_A_GEN_DIR")) : File.join(build_dir, "targets", "gen", src_id)
            else
              state = PrismFuzzer::Topology.sync_prism_source(src, fuzz_root: fuzz_root, build_dir: build_dir, cache_dir: opts[:cache_dir])
              src["resolved"] = state
              src["path"] = state["path"]
              src["gen_dir"] = state["gen_dir"]
              src["commit"] = state["commit"] if state["commit"]
            end
          end
          gen_dir = opts[:gen_dir] || src["gen_dir"] || File.join(build_dir, "targets", "gen", src_id)
          src["gen_dir"] = gen_dir
          PrismFuzzer::Topology.ensure_harness_generated_inc!(src.fetch("path"), gen_dir, fuzz_root: fuzz_root)
        end

        arch = (opts[:arch] || "host").to_s
        built = if arch == "host" || arch.empty?
                  out_rel = if opts[:output]
                              PrismFuzzer::Topology.path_relative_or_abs(opts[:output], fuzz_root)
                            else
                              plan.dig("explain_binaries", src_id) ||
                                PrismFuzzer::Topology.path_relative_or_abs(File.join(build_dir, src_id == "prism_b" ? "fuzz.explain.b" : "fuzz.explain"), fuzz_root)
                            end
                  PrismFuzzer::Topology.build_explain_for_source!(src_id, out_rel, plan: plan, fuzz_root: fuzz_root, build_dir: build_dir)
                else
                  PrismFuzzer::Topology.build_cross_explain!(arch, plan: plan, fuzz_root: fuzz_root, build_dir: build_dir, out_path: opts[:output], src_id: src_id)
                end
        puts(opts[:json] ? JSON.pretty_generate("binary" => built, "arch" => arch, "source" => src_id) : built)
        0
      when "env"
        resolved = PrismFuzzer::Topology.read_json(File.join(build_dir, "topology.resolved.json")) || plan
        a = resolved.dig("sources", "prism_a") || resolved["sources"].values.find { |s| s["kind"] == "prism" }
        b = resolved.dig("sources", "prism_b")
        r = resolved.dig("sources", "ruby") || resolved["sources"].values.find { |s| s["kind"] == "ruby" }
        a_state = PrismFuzzer::Topology.read_json(File.join(build_dir, "targets", "prism_a.json"))
        b_state = PrismFuzzer::Topology.read_json(File.join(build_dir, "targets", "prism_b.json"))
        r_state = PrismFuzzer::Topology.read_json(File.join(build_dir, "targets", "ruby.json"))

        a_path = a&.dig("path") || a_state&.dig("path")
        a_gen = a&.dig("gen_dir") || a_state&.dig("gen_dir")
        b_path = b&.dig("path") || b_state&.dig("path")
        b_gen = b&.dig("gen_dir") || b_state&.dig("gen_dir")
        r_oracle = r&.dig("oracle_dir") || r_state&.dig("oracle_dir")
        r_bin = r&.dig("ruby_bin") || r_state&.dig("ruby_bin")

        puts "WORKSPACE_DIR=#{ws[:fuzz_dir]}"
        puts "WORKSPACE_BUILD_DIR=#{build_dir}"
        puts "TOPOLOGY_RESOLVED=#{File.join(build_dir, 'topology.resolved.json')}"
        puts "PRISM_A_DIR=#{a_path}" if a_path
        puts "PRISM_A_GEN_DIR=#{a_gen}" if a_gen
        puts "PRISM_B_DIR=#{b_path}" if b_path
        puts "PRISM_B_GEN_DIR=#{b_gen}" if b_gen
        puts "RUBY_ORACLE_DIR=#{r_oracle}" if r_oracle
        puts "COMPARE_RUBY=#{r_bin}" if r_bin
        0
      when "docker-args"
        args = PrismFuzzer::Topology.docker_mount_args(plan, topology_path: ir_path, fuzz_root: fuzz_root)
        puts args.map { |t| Shellwords.escape(t) }.join(" ")
        0
      when "status"
        out = {
          "schema_version" => plan["schema_version"],
          "name" => plan["name"],
          "workspace" => plan["workspace"],
          "worker_count" => plan["workers"].size,
          "sources" => plan["sources"],
          "fuzzers" => plan["fuzzers"].keys,
          "sync_groups" => plan["sync_groups"].keys,
          "workers" => plan["workers"].map { |w| { "id" => w["id"], "kind" => w["kind"], "fuzzer" => w["fuzzer"] || w["generator"], "sync_group" => w["sync_group"] }.compact }
        }.compact
        puts JSON.pretty_generate(out)
        0
      when "plan-launch"
        fuzz_dir = ws[:fuzz_dir]
        corpus_dir = ws[:corpus_dir]
        bin_dir = ws[:bin_dir]
        snap_topo = PrismFuzzer::Topology.read_json(File.join(bin_dir, "topology.json")) ||
                    PrismFuzzer::Topology.read_json(File.join(build_dir, "topology.resolved.json")) ||
                    plan
        launch = if opts[:no_stage] || opts[:dry_run]
                   PrismFuzzer::Topology.plan_launch(snap_topo, fuzz_root: fuzz_root, fuzz_dir: fuzz_dir, corpus_dir: corpus_dir, bin_dir: bin_dir)
                 else
                   PrismFuzzer::Topology.plan_launch!(snap_topo, fuzz_root: fuzz_root, fuzz_dir: fuzz_dir, corpus_dir: corpus_dir, bin_dir: bin_dir)
                 end
        puts JSON.pretty_generate(launch)
        0
      else
        raise PrismFuzzer::Topology::TopologyError, "Unknown subcommand '#{subcmd}'"
      end
    rescue PrismFuzzer::Topology::TopologyError, OptionParser::ParseError => e
      warn "Error: #{e.message}"
      1
    end
  end
end
