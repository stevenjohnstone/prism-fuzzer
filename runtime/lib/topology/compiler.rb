# frozen_string_literal: true

module PrismFuzzer
  module Topology
    module_function

    def validate_schema!(ir, fuzz_root: locate_fuzz_root, source_label: "topology")
      schema = load_schema(fuzz_root: fuzz_root)
      PrismFuzzer::JsonSchema.validate!(schema, deep_dup(ir))
      true
    rescue PrismFuzzer::JsonSchema::ValidationError => e
      raise TopologyError, "Topology schema validation failed (#{source_label}): #{e.message}"
    end

    def validate_references!(ir, fuzz_root: locate_fuzz_root)
      raw_sources = ir["sources"].is_a?(Hash) ? ir["sources"] : {}
      raw_fuzzers = ir["fuzzers"].is_a?(Hash) ? ir["fuzzers"] : {}
      raw_gens = ir["generators"].is_a?(Hash) ? ir["generators"] : {}
      raw_sync = ir["sync_groups"].is_a?(Hash) ? ir["sync_groups"] : {}

      raw_sources.each do |sid, src|
        next unless src.is_a?(Hash)

        local = source_local_dir(src, fuzz_root: fuzz_root)
        if local.nil?
          raise TopologyError, "Source '#{sid}' has neither 'ref' nor 'dir'" if blank?(src["ref"])
          raise TopologyError, "Source '#{sid}' with 'ref' must specify 'repo'" if blank?(src["repo"])
        end
      end

      if ir["coverage"].is_a?(Hash)
        cov = ir["coverage"]
        src = raw_sources[cov["source"].to_s]
        raise TopologyError, "coverage.source references unknown source '#{cov['source']}'" unless src
        raise TopologyError, "coverage.source '#{cov['source']}' must have kind=prism (got #{src['kind']})" unless src["kind"].to_s == "prism"
        if cov["fuzzer"] && !raw_fuzzers.key?(cov["fuzzer"].to_s)
          raise TopologyError, "coverage.fuzzer references unknown fuzzer '#{cov['fuzzer']}'"
        end
        if cov["diff_fuzzer"] && !raw_fuzzers.key?(cov["diff_fuzzer"].to_s)
          raise TopologyError, "coverage.diff_fuzzer references unknown fuzzer '#{cov['diff_fuzzer']}'"
        end
      end

      seen_grammar_seeds_dirs = {}
      raw_gens.each do |gid, g|
        next unless g.is_a?(Hash)

        src_id = g["source"].to_s
        src = raw_sources[src_id]
        raise TopologyError, "Generator '#{gid}' references unknown source '#{src_id}'" unless src
        raise TopologyError, "Generator '#{gid}' source '#{src_id}' must have kind=prism (got #{src['kind']})" unless src["kind"].to_s == "prism"
        if g["fuzzer"] && !raw_fuzzers.key?(g["fuzzer"].to_s)
          raise TopologyError, "Generator '#{gid}' references unknown fuzzer '#{g['fuzzer']}'"
        end
        if g["sync_group"] && !raw_sync.key?(g["sync_group"].to_s)
          raise TopologyError, "Generator '#{gid}' references unknown sync_group '#{g['sync_group']}'"
        end
        if g["kind"].to_s == "grammar"
          sdir = File.expand_path(g["seeds_dir"] || "/tmp/afl-tmpdir/#{gid}/seeds")
          if (prev_gid = seen_grammar_seeds_dirs[sdir])
            raise TopologyError, "Grammar generators '#{prev_gid}' and '#{gid}' cannot share seeds_dir '#{sdir}'"
          end
          seen_grammar_seeds_dirs[sdir] = gid
        end
      end

      raw_fuzzers.each do |fid, f|
        next unless f.is_a?(Hash)

        shape_name = f["shape"].to_s
        shape = SHAPES[shape_name]
        raise TopologyError, "Fuzzer '#{fid}' references unknown shape '#{shape_name}'" unless shape

        shape[:source_roles].each do |role_key, expected_kind|
          src_id = f[role_key].to_s
          src = raw_sources[src_id]
          raise TopologyError, "Fuzzer '#{fid}' (#{shape_name}) references unknown #{expected_kind} source '#{src_id}' for '#{role_key}'" unless src
          raise TopologyError, "Fuzzer '#{fid}' role '#{role_key}' expected kind=#{expected_kind}, got #{src['kind']}" unless src["kind"].to_s == expected_kind.to_s
        end

        (shape[:optional_source_roles] || {}).each do |role_key, expected_kind|
          next if f[role_key].nil? || f[role_key].to_s.empty?

          src_id = f[role_key].to_s
          src = raw_sources[src_id]
          raise TopologyError, "Fuzzer '#{fid}' (#{shape_name}) references unknown #{expected_kind} source '#{src_id}' for '#{role_key}'" unless src
          raise TopologyError, "Fuzzer '#{fid}' role '#{role_key}' expected kind=#{expected_kind}, got #{src['kind']}" unless src["kind"].to_s == expected_kind.to_s
        end

        if shape_name == "prism_cross_oracle"
          arch = f["arch"].to_s
          raise TopologyError, "Fuzzer '#{fid}' has unsupported cross-oracle arch '#{arch}'" unless CROSS_ARCH_CONFIGS.key?(arch)
        end

        effective_afl = f["afl"].to_s.empty? ? shape.fetch(:default_afl) : f["afl"].to_s
        unless shape.fetch(:supported_afl_modes).include?(effective_afl)
          raise TopologyError, "Fuzzer '#{fid}' (shape=#{shape_name}) does not support afl='#{effective_afl}' (supported: #{shape.fetch(:supported_afl_modes).join(', ')})"
        end
        if f["ijon"] && !COVERAGE_GUIDED_IJON_MODES.include?(effective_afl)
          raise TopologyError, "Fuzzer '#{fid}' cannot enable ijon with non-coverage-guided afl mode '#{effective_afl}' (supported: #{COVERAGE_GUIDED_IJON_MODES.join(', ')})"
        end
      end

      workers = Array(ir["workers"])
      worker_ids = workers.map { |w| w.is_a?(Hash) ? w["id"].to_s : "" }.reject(&:empty?).to_set
      if worker_ids.size != workers.size
        dups = workers.group_by { |w| w["id"].to_s }.select { |_, list| list.size > 1 }.keys
        raise TopologyError, "Duplicate worker IDs: #{dups.join(', ')}"
      end

      gen_workers_by_id = {}
      foreign_consumers_by_gen = Hash.new { |h, k| h[k] = [] }

      workers.each do |w|
        next unless w.is_a?(Hash)

        wid = w["id"].to_s
        if w["kind"].to_s == "generator"
          gen_id = w["generator"].to_s
          gen = raw_gens[gen_id]
          raise TopologyError, "Worker '#{wid}' references unknown generator '#{gen_id}'" unless gen
          unless gen["kind"].to_s == "grammar"
            raise TopologyError, "Generator worker '#{wid}' must reference a kind=grammar generator (got '#{gen_id}' with kind=#{gen['kind']})"
          end
          if (prev_wid = gen_workers_by_id[gen_id])
            raise TopologyError, "Grammar generator '#{gen_id}' cannot be shared by multiple generator workers ('#{prev_wid}', '#{wid}')"
          end
          gen_workers_by_id[gen_id] = wid
          next
        end

        fuzzer_id = w["fuzzer"].to_s
        fspec = raw_fuzzers[fuzzer_id]
        raise TopologyError, "Worker '#{wid}' references unknown fuzzer '#{fuzzer_id}'" unless fspec
        raise TopologyError, "Worker '#{wid}' references unknown sync_group '#{w['sync_group']}'" unless raw_sync.key?(w["sync_group"].to_s)

        if w["aux_fuzzer"] && !raw_fuzzers.key?(w["aux_fuzzer"].to_s)
          raise TopologyError, "Worker '#{wid}' aux_fuzzer references unknown fuzzer '#{w['aux_fuzzer']}'"
        end
        if w["cmplog"] && !raw_fuzzers.key?(w["cmplog"].to_s)
          raise TopologyError, "Worker '#{wid}' cmplog references unknown fuzzer '#{w['cmplog']}'"
        end
        Array(w["foreign_sync"]).each do |gid|
          gid_s = gid.to_s
          gen = raw_gens[gid_s]
          raise TopologyError, "Worker '#{wid}' foreign_sync references unknown generator '#{gid_s}'" unless gen
          unless gen["kind"].to_s == "grammar"
            raise TopologyError, "Worker '#{wid}' foreign_sync must reference a kind=grammar generator (got '#{gid_s}' with kind=#{gen['kind']})"
          end
          unless w["afl_role"].to_s == "main"
            raise TopologyError, "Worker '#{wid}' uses foreign_sync '#{gid_s}' and must set afl_role=main (AFL++ forbids -F on secondary workers)"
          end
          if fspec["shape"].to_s == "prism_cross_oracle"
            raise TopologyError, "Worker '#{wid}' uses foreign_sync '#{gid_s}', which is not supported on prism_cross_oracle fuzzer '#{fuzzer_id}'"
          end
          if foreign_consumers_by_gen[gid_s].include?(wid)
            raise TopologyError, "Worker '#{wid}' lists duplicate foreign_sync '#{gid_s}'"
          end

          foreign_consumers_by_gen[gid_s] << wid
          if foreign_consumers_by_gen[gid_s].size > 1
            raise TopologyError, "Grammar generator '#{gid_s}' cannot be shared across multiple foreign_sync consumers (#{foreign_consumers_by_gen[gid_s].join(', ')})"
          end
        end
        if (from = w.dig("seeds", "from"))
          from_id = from.to_s
          gen = raw_gens[from_id]
          raise TopologyError, "Worker '#{wid}' seeds.from references unknown generator '#{from_id}'" unless gen
          if gen["kind"].to_s == "grammar"
            raise TopologyError, "Worker '#{wid}' seeds.from cannot reference grammar generator '#{from_id}' (use foreign_sync on an afl_role=main worker instead)"
          end
        end
        Array(w["peer_imports"]).each do |pi|
          next unless pi.is_a?(Hash)

          raise TopologyError, "Worker '#{wid}' peer_imports references unknown sync_group '#{pi['group']}'" unless raw_sync.key?(pi["group"].to_s)
          raise TopologyError, "Worker '#{wid}' peer_imports references unknown worker '#{pi['worker']}'" unless worker_ids.include?(pi["worker"].to_s)
        end
      end

      gen_workers_by_id.each do |gen_id, wid|
        next unless foreign_consumers_by_gen[gen_id].empty?

        raise TopologyError, "Generator worker '#{wid}' (grammar '#{gen_id}') has no foreign_sync consumer; set foreign_sync :#{gen_id} on an afl_role=main worker"
      end
      raw_gens.each do |gen_id, g|
        next unless g.is_a?(Hash) && g["kind"].to_s == "grammar"
        next if workers.empty?

        if gen_workers_by_id[gen_id].nil?
          raise TopologyError, "Grammar generator '#{gen_id}' has no kind=generator worker"
        elsif foreign_consumers_by_gen[gen_id].empty?
          raise TopologyError, "Grammar generator '#{gen_id}' has no foreign_sync consumer"
        end
      end
      true
    end

    def validate_ir!(ir, fuzz_root: locate_fuzz_root, source_label: "topology")
      validate_schema!(ir, fuzz_root: fuzz_root, source_label: source_label)
      validate_references!(ir, fuzz_root: fuzz_root)
      true
    end

    # Loads either a compiled IR `.json` file or compiles a Ruby `.rb` DSL file
    # and validates the resulting IR against `topology.schema.json`.
    def load_ir(path = nil, fuzz_root: locate_fuzz_root)
      target = path || env_override("CAMPAIGN") || env_override("TOPOLOGY_FILE") || env_override("TOPOLOGY") || default_topology_path(fuzz_root)
      expanded = File.expand_path(target, fuzz_root)
      raise TopologyError, "Campaign/topology file not found: #{expanded}" unless File.file?(expanded)

      ir = if File.extname(expanded) == ".rb"
             begin
               CampaignDSL.compile_file(expanded, fuzz_root: fuzz_root)
             rescue CampaignDSL::Error => e
               raise TopologyError, e.message
             end
           else
             raw = JSON.parse(File.read(expanded, encoding: "UTF-8"))
             raise TopologyError, "Invalid topology in #{expanded} (expected JSON object)" unless raw.is_a?(Hash)

             d = deep_dup(raw)
             validate_schema!(d, fuzz_root: fuzz_root, source_label: expanded)
             d
           end

      [ir, expanded]
    rescue Errno::ENOENT, Errno::ENOTDIR, SystemCallError => e
      raise TopologyError, "Campaign/topology file not found: #{expanded} (#{e.message})"
    rescue JSON::ParserError, EncodingError => e
      raise TopologyError, "Invalid JSON in #{expanded}: #{e.message}"
    end

    # Resolves a validated static authoring IR into a concrete build + deployment
    # plan without introducing implicit workers or heuristic defaults.
    def compile_plan(ir, fuzz_root: locate_fuzz_root, build_dir: nil)
      validate_ir!(ir, fuzz_root: fuzz_root)

      ws = workspace_paths(ir, fuzz_root: fuzz_root, build_dir: build_dir)
      effective_build_dir = ws[:build_dir]
      build_rel = path_relative_or_abs(effective_build_dir, fuzz_root)

      active_sources = {}
      ir.fetch("sources").each do |id, spec|
        norm = deep_dup(spec)
        norm["id"] = id.to_s
        local = source_local_dir(spec, fuzz_root: fuzz_root)
        norm["dir"] = local if local
        active_sources[id.to_s] = norm
      end

      defaults = ir["defaults"].is_a?(Hash) ? ir["defaults"] : {}
      max_input_size = Integer(defaults["max_input_size"] || 1024)
      max_alloc_mb = Integer(defaults["max_allocated_mb"] || 128)

      active_fuzzers = {}
      ir.fetch("fuzzers").each do |id, spec|
        shape = SHAPES.fetch(spec["shape"].to_s)
        f = deep_dup(spec)
        f["id"] = id.to_s
        f["binary"] ||= File.join(build_rel, id.to_s)
        f["verify_profile"] ||= shape[:verify_profile].call(f)
        f["ids_file"] = "#{f['binary']}.ids" if f["document_ids"]
        f["coverage_source"] = shape[:coverage_source].call(f)
        f["coverage_sources"] = shape[:coverage_sources].call(f).compact.uniq
        f["explain_sources"] = shape[:explain_sources].call(f).compact.uniq
        f["sources_map"] = shape[:source_roles].keys.each_with_object({}) { |rk, h| h[rk] = f[rk].to_s }
        active_fuzzers[id.to_s] = f
      end

      active_sync_groups = {}
      ir.fetch("sync_groups").each do |gid, spec|
        sg = deep_dup(spec)
        sg["id"] = gid.to_s
        active_sync_groups[gid.to_s] = sg
      end

      active_generators = {}
      ir.fetch("generators", {}).each do |gid, spec|
        g = deep_dup(spec)
        g["id"] = gid.to_s
        active_generators[gid.to_s] = g
      end

      active_workers = ir.fetch("workers").map do |wspec|
        w = deep_dup(wspec)
        w["color"] ||= active_generators.dig(w["generator"].to_s, "color") || default_color_for(w["id"])
        w
      end

      # Assign concrete shard indices and shard totals within each declared shard_group.
      by_shard_group = Hash.new { |h, k| h[k] = [] }
      active_workers.each do |w|
        sg = w.dig("seeds", "shard_group")
        by_shard_group[sg] << w if sg && !sg.to_s.empty?
      end
      by_shard_group.each_value do |list|
        total = [list.size, 1].max
        list.each_with_index do |w, idx|
          w["seeds"]["shard_index"] = idx
          w["seeds"]["shard_total"] = total
        end
      end

      cov = ir["coverage"].is_a?(Hash) ? deep_dup(ir["coverage"]) : nil

      explain_bins = {}
      active_sources.each do |sid, s|
        next unless s["kind"] == "prism"

        explain_bins[sid] = if sid == "prism_a"
                              File.join(build_rel, "fuzz.explain")
                            elsif sid == "prism_b"
                              File.join(build_rel, "fuzz.explain.b")
                            else
                              File.join(build_rel, "fuzz.explain.#{sid}")
                            end
      end

      grammar_ext_sources = active_generators.values.select { |g| g["kind"] == "grammar" }.map { |g| g["source"].to_s }.uniq

      snapshot_bins = Set.new
      snapshot_aux = Set.new
      active_fuzzers.each_value do |f|
        snapshot_bins << File.basename(f["binary"])
        snapshot_bins << File.basename(f["mutator"]) if f["mutator"]
        snapshot_bins << File.basename(f["repro"]) if f["repro"]
        snapshot_aux << File.basename(f["ids_file"]) if f["ids_file"]
        snapshot_aux << File.basename(f["mutator"]) if f["mutator"]
      end
      active_workers.each do |w|
        next unless w["mutator"]

        mbase = File.basename(w["mutator"].to_s)
        snapshot_bins << mbase
        snapshot_aux << mbase
        if mbase == "libgrammarmutator-ruby.so"
          snapshot_bins << "grammar_generator-ruby"
          snapshot_aux << "grammar_generator-ruby"
        end
      end
      explain_bins.each_value { |eb| snapshot_aux << File.basename(eb) }

      # Map generator names, legacy grammar alias, and shadow peer import names
      # back to their canonical origin node for reporting.
      sync_aliases = {}
      active_generators.each_key do |gid|
        sync_aliases[gid] = gid
        sync_aliases["seeds"] = gid if gid == "grammar"
      end
      active_workers.each do |w|
        Array(w["peer_imports"]).each do |pi|
          sync_aliases[pi["alias"].to_s] = pi["worker"].to_s
        end
      end

      {
        "schema_version" => TOPOLOGY_SCHEMA_VERSION,
        "name" => ir.fetch("name").to_s,
        "workspace" => ir["workspace"].is_a?(Hash) ? deep_dup(ir["workspace"]) : nil,
        "lifecycle" => ir["lifecycle"].is_a?(Hash) ? deep_dup(ir["lifecycle"]) : nil,
        "defaults" => {
          "max_input_size" => max_input_size,
          "max_allocated_mb" => max_alloc_mb
        },
        "sources" => active_sources,
        "coverage" => cov,
        "generators" => active_generators,
        "fuzzers" => active_fuzzers,
        "sync_groups" => active_sync_groups,
        "workers" => active_workers,
        "explain_binaries" => explain_bins,
        "grammar_ext_sources" => grammar_ext_sources,
        "sync_aliases" => sync_aliases,
        "snapshot" => {
          "binaries" => snapshot_bins.to_a.sort,
          "aux_files" => snapshot_aux.to_a.sort,
          "grammar_ext_sources" => grammar_ext_sources
        }
      }.compact
    end
  end
end
