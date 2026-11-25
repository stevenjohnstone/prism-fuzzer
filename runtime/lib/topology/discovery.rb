# frozen_string_literal: true

module PrismFuzzer
  module Topology
    module_function

    # Discovery & query helpers for status, triage, clustering, explain, reporting, and publish.
    def discover(start_dir: nil, triage_dir: nil, afl_dir: nil, bin_dir: nil, topology_path: nil)
      fuzz_root = locate_fuzz_root(start_dir)
      candidates = []
      candidates << topology_path if topology_path && !topology_path.to_s.empty?
      candidates << env_override("CAMPAIGN")
      candidates << env_override("TOPOLOGY_RESOLVED")
      candidates << env_override("TOPOLOGY_FILE")
      candidates << env_override("TOPOLOGY")
      if bin_dir && !bin_dir.to_s.empty?
        bin_abs = File.expand_path(bin_dir)
        candidates << File.join(bin_abs, "topology.json")
        candidates << File.join(bin_abs, "topology.resolved.json")
        if File.basename(bin_abs) == "bin"
          candidates << File.join(File.dirname(bin_abs), "build", "topology.resolved.json")
          candidates << File.join(File.dirname(bin_abs), "build", "topology.ir.json")
        end
      end
      triage_workspace_candidates(triage_dir).each do |t_root|
        candidates << File.join(t_root, "bin", "topology.json")
        candidates << File.join(t_root, "build", "topology.resolved.json")
        candidates << File.join(t_root, "build", "topology.ir.json")
        candidates << File.join(t_root, "topology.json")
      end
      if afl_dir && !afl_dir.to_s.empty?
        afl_parent = File.dirname(File.expand_path(afl_dir))
        candidates << File.join(afl_parent, "bin", "topology.json")
        candidates << File.join(afl_parent, "build", "topology.resolved.json")
        candidates << File.join(afl_parent, "build", "topology.ir.json")
        candidates << File.join(afl_parent, "topology.json")
      end
      if fuzz_root
        candidates << default_topology_path(fuzz_root)
        candidates << File.join(fuzz_root, "tmp", "fuzz", "bin", "topology.json")
        candidates << File.join(fuzz_root, "tmp", "fuzz", "build", "topology.resolved.json")
        candidates << File.join(fuzz_root, "tmp", "fuzz", "build", "topology.ir.json")
      end

      root = fuzz_root || locate_fuzz_root
      candidates.compact.uniq.each do |cand|
        expanded = File.expand_path(cand)
        next unless File.file?(expanded)

        data = if File.extname(expanded) == ".rb"
                 begin
                   load_ir(expanded, fuzz_root: root).first
                 rescue TopologyError
                   nil
                 end
               else
                 read_json(expanded)
               end
        next unless data.is_a?(Hash) && data.key?("fuzzers")

        if !resolved?(data) && data.key?("schema_version")
          ws = workspace_paths(data, fuzz_root: root)
          [
            File.join(ws[:bin_dir], "topology.json"),
            File.join(ws[:build_dir], "topology.resolved.json")
          ].each do |rc|
            rdata = read_json(rc)
            next unless rdata && rdata.key?("fuzzers")
            next if data["name"] && rdata["name"] != data["name"]

            return normalize_runtime_paths!(rdata, fuzz_root: root)
          end
          return normalize_runtime_paths!(compile_plan(data, fuzz_root: root), fuzz_root: root)
        end

        return normalize_runtime_paths!(data, fuzz_root: root)
      end
      nil
    end

    def normalize_runtime_paths!(topo, fuzz_root: locate_fuzz_root)
      return topo unless topo.is_a?(Hash) && topo["sources"].is_a?(Hash) && fuzz_root

      ws = workspace_paths(topo, fuzz_root: fuzz_root)
      topo["sources"].each do |id, s|
        next unless s.is_a?(Hash)

        mode = s.dig("resolved", "mode").to_s
        if mode == "managed_worktree" || (s["path"].to_s.include?("/build/targets/#{id}") && !File.exist?(s["path"].to_s))
          wt = File.join(ws[:build_dir], "targets", id)
          gd = File.join(ws[:build_dir], "targets", "gen", id)
          s["path"] = wt if File.directory?(wt)
          s["gen_dir"] = gd if File.directory?(gd)
        elsif mode == "local_dir" && s["dir"] && !File.exist?(s["path"].to_s)
          mapped = remap_external_path(s["dir"].to_s)
          s["path"] = mapped if mapped
        end
      end
      topo
    end

    def resolved?(topo)
      topo.is_a?(Hash) && topo.key?("explain_binaries")
    end

    def ensure_resolved_view(topo, fuzz_root: locate_fuzz_root)
      return nil unless topo.is_a?(Hash)
      return topo if resolved?(topo)

      compile_plan(deep_dup(topo), fuzz_root: fuzz_root)
    rescue TopologyError
      nil
    end

    def sync_group_dirs(topo, base_dir:)
      return [] unless topo.is_a?(Hash) && topo["sync_groups"].is_a?(Hash)

      base = File.expand_path(base_dir)
      topo["sync_groups"].values.filter_map do |sg|
        next unless sg.is_a?(Hash) && sg["dir"]

        File.join(base, sg["dir"])
      end.uniq
    end

    def worker_spec(topo, worker_id)
      return nil unless topo.is_a?(Hash) && topo["workers"].is_a?(Array)

      topo["workers"].find { |w| w["id"].to_s == worker_id.to_s }
    end

    def fuzzer_spec(topo, fuzzer_id_or_path)
      return nil unless topo.is_a?(Hash) && topo["fuzzers"].is_a?(Hash)

      key = File.basename(fuzzer_id_or_path.to_s)
      topo["fuzzers"][fuzzer_id_or_path.to_s] ||
        topo["fuzzers"][key] ||
        topo["fuzzers"].values.find do |f|
          File.basename(f["binary"].to_s) == key ||
            (!f["repro"].to_s.empty? && File.basename(f["repro"].to_s) == key)
        end
    end

    def fuzzer_for_worker(topo, worker_id)
      w = worker_spec(topo, worker_id)
      return nil unless w && w["fuzzer"]

      fuzzer_spec(topo, w["fuzzer"])
    end

    def worker_order(topo)
      return [] unless topo.is_a?(Hash) && topo["workers"].is_a?(Array)

      gen_ids = topo["generators"].is_a?(Hash) ? topo["generators"].keys : []
      worker_ids = topo["workers"].map { |w| w["id"].to_s }
      (gen_ids + ["corpus"] + worker_ids).uniq
    end

    def worker_colors(topo)
      colors = { "corpus" => "#fbbf24" }
      return colors unless topo.is_a?(Hash)

      if topo["generators"].is_a?(Hash)
        topo["generators"].each do |gid, g|
          colors[gid] = g["color"] if g.is_a?(Hash) && g["color"]
        end
      end
      Array(topo["workers"]).each do |w|
        colors[w["id"].to_s] = w["color"] if w.is_a?(Hash) && w["color"]
      end
      colors
    end

    def sync_aliases(topo)
      return { "seeds" => "grammar" } if topo.nil?
      return {} unless topo.is_a?(Hash)

      aliases = {}
      if topo["sync_aliases"].is_a?(Hash)
        topo["sync_aliases"].each { |k, v| aliases[k.to_s] = v.to_s }
      elsif topo["generators"].is_a?(Hash) || topo["workers"].is_a?(Array)
        topo.fetch("generators", {}).each_key do |gid|
          aliases[gid.to_s] = gid.to_s
          aliases["seeds"] = gid.to_s if gid.to_s == "grammar"
        end
        Array(topo["workers"]).each do |w|
          Array(w["peer_imports"]).each do |pi|
            aliases[pi["alias"].to_s] = pi["worker"].to_s if pi.is_a?(Hash) && !blank?(pi["alias"]) && !blank?(pi["worker"])
          end
        end
      end
      aliases
    end

    def normalize_coverage_target_flags(fspec)
      return [] unless fspec.is_a?(Hash)

      define_tokens = []
      other_tokens = []

      if fspec["defines"].is_a?(Hash)
        fspec["defines"].each do |k, v|
          tok = v == true ? "-D#{k}" : "-D#{k}=#{v}"
          next if COVERAGE_ORTHOGONAL_FLAG_PATTERNS.any? { |pat| pat.match?(tok) }

          define_tokens << tok
        end
      end

      Array(fspec["cflags"]).each do |raw|
        tok = raw.to_s.strip
        next if tok.empty?
        next if COVERAGE_ORTHOGONAL_FLAG_PATTERNS.any? { |pat| pat.match?(tok) }

        if tok.start_with?("-D")
          define_tokens << tok
        else
          other_tokens << tok
        end
      end

      (define_tokens.uniq.sort + other_tokens.uniq)
    end

    # Resolves the canonical compilation target for coverage binaries, ignoring
    # orthogonal instrumentation (sanitizers, AFL mode, IJON, xallocator, fast/slow,
    # and 32-bit cross-oracle architectures whose PM64 inputs replay on host).
    def coverage_target_for_fuzzer(fspec)
      flags = normalize_coverage_target_flags(fspec)
      if flags.empty?
        return { "id" => "native", "label" => "native", "cflags" => [] }
      end
      if flags == ["-DPRISM_ACCEL_SWAR"]
        return { "id" => "swar", "label" => "swar", "cflags" => flags }
      end

      digest = Digest::SHA256.hexdigest(JSON.generate(flags))[0, 8]
      id = if flags.size == 1 && flags[0] =~ /\A-D([A-Za-z0-9_]+)\z/
             slug = Regexp.last_match(1).delete_prefix("PRISM_").downcase.gsub(/[^a-z0-9]+/, "_")
             slug = "cfg" if slug.empty?
             "#{slug}_#{digest[0, 6]}"
           else
             "cfg_#{digest}"
           end
      { "id" => id, "label" => flags.join(" "), "cflags" => flags }
    end

    def coverage_sources_for_fuzzer(fspec)
      return [] unless fspec.is_a?(Hash)

      shape = SHAPES[fspec["shape"].to_s]
      if shape && shape[:coverage_sources]
        shape[:coverage_sources].call(fspec).compact.map(&:to_s).reject(&:empty?).uniq
      elsif fspec["coverage_sources"].is_a?(Array)
        fspec["coverage_sources"].compact.map(&:to_s).reject(&:empty?).uniq
      elsif fspec["coverage_source"]
        [fspec["coverage_source"].to_s]
      else
        []
      end
    end

    def default_coverage_define_flags(topo)
      defaults = topo.is_a?(Hash) && topo["defaults"].is_a?(Hash) ? topo["defaults"] : {}
      max_in = effective_compiled_max_input_size(topo.is_a?(Hash) ? topo : {})
      max_alloc = defaults["max_allocated_mb"] || 128
      [
        "-DPRISM_EXCLUDE_JSON",
        "-DPRISM_EXCLUDE_PRETTYPRINT",
        "-DPM_INTEGER_DIVIDE_THRESHOLD=8",
        "-DPRISM_DEPTH_MAXIMUM=128",
        "-DFUZZ_MAX_INPUT_SIZE=#{max_in}",
        "-DFUZZ_MAX_ALLOCATED=#{max_alloc}",
        "-DFUZZ_HARD_RSS_LIMIT=#{max_alloc.to_i * 16}"
      ]
    end

    # Returns ordered (source, target) coverage pairs for a topology/plan along
    # with the fuzzers, workers, generators, and cross-oracle workers associated
    # with each pair.
    def coverage_pairs(topo, fuzz_root: locate_fuzz_root)
      return [] unless topo.is_a?(Hash) && topo["sources"].is_a?(Hash)

      sources = topo["sources"]
      fuzzers = topo["fuzzers"].is_a?(Hash) ? topo["fuzzers"] : {}
      generators = topo["generators"].is_a?(Hash) ? topo["generators"] : {}
      workers = Array(topo["workers"])

      pair_map = {}
      ensure_pair = lambda do |src_id, target|
        src_spec = sources[src_id]
        next nil unless src_spec.is_a?(Hash) && src_spec["kind"].to_s == "prism"

        tid = target["id"].to_s
        pid = "#{src_id}__#{tid}"
        pair_map[pid] ||= begin
          src_path = src_spec["path"] || source_local_dir(src_spec, fuzz_root: fuzz_root)
          {
            "id" => pid,
            "label" => "#{src_id} (#{target['label']})",
            "source" => src_id,
            "source_path" => src_path,
            "gen_dir" => src_spec["gen_dir"],
            "commit" => src_spec["commit"],
            "requested_ref" => src_spec["requested_ref"],
            "target" => tid,
            "target_label" => target["label"].to_s,
            "cflags" => target["cflags"].dup,
            "fuzzers" => [],
            "workers" => [],
            "generators" => [],
            "cross_oracle_workers" => []
          }
        end
      end

      active_fuzzer_ids = Set.new
      workers.each do |w|
        next unless w.is_a?(Hash) && w["kind"].to_s != "generator"

        wid = w["id"].to_s
        fid = w["fuzzer"].to_s
        fspec = fuzzer_spec(topo, fid)
        next unless fspec

        active_fuzzer_ids.add(fid)
        target = coverage_target_for_fuzzer(fspec)
        is_cross = fspec["shape"].to_s == "prism_cross_oracle"
        coverage_sources_for_fuzzer(fspec).each do |src_id|
          pair = ensure_pair.call(src_id, target)
          next unless pair

          pair["fuzzers"] << fid unless pair["fuzzers"].include?(fid)
          pair["workers"] << wid unless pair["workers"].include?(wid)
          pair["cross_oracle_workers"] << wid if is_cross && !pair["cross_oracle_workers"].include?(wid)
        end
      end

      # Include any fuzzers not directly referenced by workers when no worker mapped them,
      # or when coverage-only topologies declare fuzzers without workers.
      if pair_map.empty?
        fuzzers.each do |fid, fspec|
          next unless fspec.is_a?(Hash)

          target = coverage_target_for_fuzzer(fspec)
          coverage_sources_for_fuzzer(fspec).each do |src_id|
            pair = ensure_pair.call(src_id, target)
            pair["fuzzers"] << fid if pair && !pair["fuzzers"].include?(fid)
          end
        end
      end

      # Associate corpus/grammar generators with matching (source, target) pairs.
      generators.each do |gid, gspec|
        next unless gspec.is_a?(Hash)

        src_id = gspec["source"].to_s
        fspec = gspec["fuzzer"] ? fuzzer_spec(topo, gspec["fuzzer"]) : nil
        target = fspec ? coverage_target_for_fuzzer(fspec) : { "id" => "native", "label" => "native", "cflags" => [] }
        gen_pair = ensure_pair.call(src_id, target)

        matching_pairs = pair_map.values.select { |p| p["source"] == src_id }
        matching_pairs = [gen_pair].compact if matching_pairs.empty?
        matching_pairs.each do |p|
          p["generators"] << gid unless p["generators"].include?(gid)
        end
      end

      if pair_map.empty?
        fallback_src = topo.dig("coverage", "source")&.to_s || sources.find { |_, s| s.is_a?(Hash) && s["kind"].to_s == "prism" }&.first
        ensure_pair.call(fallback_src, { "id" => "native", "label" => "native", "cflags" => [] }) if fallback_src
      end

      primary_src = topo.dig("coverage", "source")&.to_s
      source_order = sources.keys
      pair_map.values.sort_by do |p|
        [
          p["source"] == primary_src && p["target"] == "native" ? 0 : (p["source"] == primary_src ? 1 : 2),
          source_order.index(p["source"]) || 9999,
          p["target"] == "native" ? 0 : (p["target"] == "swar" ? 1 : 2),
          p["id"]
        ]
      end
    end

    # Maps each worker/generator id to its ordered list of coverage pair IDs.
    # For A vs B differential fuzzers (prism_diff_prism), preserves [prism_a_pair, prism_b_pair].
    def worker_coverage_pairs(topo, fuzz_root: locate_fuzz_root)
      return {} unless topo.is_a?(Hash)

      pairs_by_key = {}
      coverage_pairs(topo, fuzz_root: fuzz_root).each do |p|
        pairs_by_key[[p["source"], p["target"]]] = p["id"]
      end

      mapping = {}
      Array(topo["workers"]).each do |w|
        next unless w.is_a?(Hash)

        wid = w["id"].to_s
        if w["kind"].to_s == "generator"
          gspec = topo.dig("generators", w["generator"].to_s)
          next unless gspec.is_a?(Hash)

          fspec = gspec["fuzzer"] ? fuzzer_spec(topo, gspec["fuzzer"]) : nil
          target = fspec ? coverage_target_for_fuzzer(fspec) : { "id" => "native" }
          pid = pairs_by_key[[gspec["source"].to_s, target["id"]]]
          mapping[wid] = [pid] if pid
        else
          fspec = fuzzer_spec(topo, w["fuzzer"].to_s)
          next unless fspec

          target = coverage_target_for_fuzzer(fspec)
          ids = coverage_sources_for_fuzzer(fspec).filter_map do |src_id|
            pairs_by_key[[src_id, target["id"]]]
          end
          mapping[wid] = ids unless ids.empty?
        end
      end
      mapping
    end

    def docker_mount_args(plan, topology_path: nil, fuzz_root: locate_fuzz_root)
      mounts = []
      maps = []
      root_abs = File.expand_path(fuzz_root)
      default_rel = begin
        def_path = default_topology_path(fuzz_root)
        def_path.start_with?("#{root_abs}/") ? def_path.delete_prefix("#{root_abs}/") : File.basename(def_path)
      end

      if topology_path && !topology_path.to_s.empty?
        t_abs = File.expand_path(topology_path, fuzz_root)
        ext = File.extname(t_abs) == ".rb" ? ".rb" : ".json"
        base = ext == ".rb" ? "campaign" : "topology"
        unless t_abs == root_abs || t_abs.start_with?("#{root_abs}/")
          guest = "/external/#{base}#{ext}"
          mounts.push("-v", "#{t_abs}:#{guest}:ro", "-e", "CAMPAIGN=#{guest}", "-e", "TOPOLOGY=#{guest}")
        else
          rel = t_abs.delete_prefix("#{root_abs}/")
          mounts.push("-e", "CAMPAIGN=#{rel}", "-e", "TOPOLOGY=#{rel}") unless rel == default_rel
        end
      end

      plan.fetch("sources", {}).each do |id, spec|
        dir = spec["dir"]
        next if blank?(dir)

        abs = File.expand_path(dir)
        next if abs == root_abs || abs.start_with?("#{root_abs}/")

        guest = "/external/src_#{id.gsub(/[^a-zA-Z0-9_-]/, '_')}"
        mounts.push("-v", "#{abs}:#{guest}:ro")
        maps << "#{abs}=#{guest}"
      end

      if plan["workspace"].is_a?(Hash)
        %w[dir build_dir corpus_dir triage_dir report_dir coverage_dir logs_dir reports_dir].each do |wkey|
          raw_dir = plan.dig("workspace", wkey)
          next if blank?(raw_dir)

          abs = File.expand_path(raw_dir, fuzz_root)
          next if abs == root_abs || abs.start_with?("#{root_abs}/") || maps.any? { |m| m.start_with?("#{abs}=") }

          FileUtils.mkdir_p(abs)
          guest = "/external/ws_#{wkey}"
          mounts.push("-v", "#{abs}:#{guest}")
          maps << "#{abs}=#{guest}"
        end
      end

      maps << "#{root_abs}=/prism-fuzzer" if mounts.any? && maps.none? { |m| m.start_with?("#{root_abs}=") }
      mounts.push("-e", "PRISM_FUZZER_PATH_MAPS=#{maps.join(';')}") unless maps.empty?
      mounts
    end
  end
end
