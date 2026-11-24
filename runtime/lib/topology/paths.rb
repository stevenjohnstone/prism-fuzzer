# frozen_string_literal: true

module PrismFuzzer
  module Topology
    module_function

    def locate_fuzz_root(start_dir = nil)
      PrismFuzzer::Common.locate_fuzz_root(start_dir, fallback: File.expand_path("../../..", __dir__))
    end

    def default_topology_path(fuzz_root = locate_fuzz_root)
      camp_default = File.join(fuzz_root, "campaigns", "default.rb")
      return camp_default if File.file?(camp_default)

      legacy_dsl = File.join(fuzz_root, "topologies", "default.rb")
      return legacy_dsl if File.file?(legacy_dsl)

      File.join(fuzz_root, "topology.json")
    end

    def schema_path(fuzz_root = locate_fuzz_root)
      cand = File.join(fuzz_root, SCHEMA_FILENAME)
      return cand if File.file?(cand)

      File.expand_path("../../../#{SCHEMA_FILENAME}", __dir__)
    end

    def load_schema(fuzz_root: locate_fuzz_root)
      sp = schema_path(fuzz_root)
      raise TopologyError, "Topology JSON Schema not found at #{sp}" unless File.file?(sp)

      JSON.parse(File.read(sp, encoding: "UTF-8"))
    rescue JSON::ParserError => e
      raise TopologyError, "Invalid JSON in schema #{sp}: #{e.message}"
    end

    def default_build_dir(fuzz_root = locate_fuzz_root)
      File.join(fuzz_root, "build")
    end

    def default_cache_dir(fuzz_root = locate_fuzz_root)
      File.join(fuzz_root, ".cache", "repos")
    end

    def path_relative_or_abs(path, base_dir)
      abs = File.expand_path(path)
      base = File.expand_path(base_dir)
      return "." if abs == base
      return abs.delete_prefix("#{base}/") if abs.start_with?("#{base}/")

      abs
    end

    def triage_workspace_candidates(triage_dir)
      return [] if blank?(triage_dir)

      abs_t = File.expand_path(triage_dir)
      parent = File.dirname(abs_t)
      grandparent = File.dirname(parent)
      ordered = File.basename(parent) == "report" ? [grandparent, parent] : [parent, grandparent]
      ordered.uniq
    end

    def outer_repo_root(fuzz_root = locate_fuzz_root, fuzz_dir: nil)
      root_abs = File.expand_path(fuzz_root)
      return root_abs unless File.basename(root_abs) == "snapshot"

      ws_candidate = fuzz_dir ? File.expand_path(fuzz_dir) : File.dirname(root_abs)
      parent_start = File.dirname(ws_candidate)
      outer = PrismFuzzer::Common.locate_fuzz_root(parent_start, fallback: nil)
      return outer if outer && outer != root_abs

      cwd_root = PrismFuzzer::Common.locate_fuzz_root(Dir.pwd, fallback: nil)
      (cwd_root && cwd_root != root_abs) ? cwd_root : root_abs
    end

    def resolve_corpus_generator_dir(raw_dir, fuzz_dir:, fuzz_root: locate_fuzz_root, ws_raw_dir: nil, default_corpus_dir: nil)
      return default_corpus_dir || File.join(fuzz_dir, "corpus") if blank?(raw_dir)

      p = raw_dir.to_s
      if !Dir.exist?(p) && (ENV["PRISM_FUZZER_PATH_MAPS"] || ENV["RUBY_FUZZ_PATH_MAPS"])
        mapped = remap_external_path(p)
        return mapped if mapped
      end
      return File.expand_path(p) if p.start_with?("/")
      return File.expand_path(p, fuzz_dir) unless p.include?("/")

      unless blank?(ws_raw_dir)
        clean_ws = ws_raw_dir.to_s.sub(%r{\A\./}, "").chomp("/")
        clean_p = p.sub(%r{\A\./}, "")
        if !clean_ws.empty? && (clean_p == clean_ws || clean_p.start_with?("#{clean_ws}/"))
          rel_sub = clean_p == clean_ws ? "." : clean_p.delete_prefix("#{clean_ws}/")
          return File.expand_path(rel_sub, fuzz_dir)
        end
      end

      File.expand_path(p, outer_repo_root(fuzz_root, fuzz_dir: fuzz_dir))
    end

    def expand_workspace_path(raw, fuzz_root:)
      p = raw.to_s
      if !Dir.exist?(p) && (ENV["PRISM_FUZZER_PATH_MAPS"] || ENV["RUBY_FUZZ_PATH_MAPS"])
        mapped = remap_external_path(p)
        return mapped if mapped
      end
      File.expand_path(p, fuzz_root)
    end

    def workspace_paths(topo = nil, fuzz_root: locate_fuzz_root, build_dir: nil, fuzz_dir: nil, corpus_dir: nil, bin_dir: nil)
      ws = topo.is_a?(Hash) && topo["workspace"].is_a?(Hash) ? topo["workspace"] : {}
      raw_ws_dir = ws["dir"] || "tmp/fuzz"
      repo_root = outer_repo_root(fuzz_root, fuzz_dir: fuzz_dir)
      res_dir = expand_workspace_path(fuzz_dir || env_override("FUZZ_DIR") || raw_ws_dir, fuzz_root: repo_root)
      ws_dir_abs = expand_workspace_path(raw_ws_dir, fuzz_root: repo_root)
      default_ws_build = File.join(res_dir, "build")
      explicit_build = build_dir || env_override("FUZZ_BUILD_DIR")
      raw_build = explicit_build || (res_dir != ws_dir_abs ? default_ws_build : (ws["build_dir"] || default_ws_build))
      res_build = expand_workspace_path(raw_build, fuzz_root: repo_root)

      sgs = topo.is_a?(Hash) && topo["sync_groups"].is_a?(Hash) ? topo["sync_groups"] : {}
      gram_gen = topo.is_a?(Hash) && topo["generators"].is_a?(Hash) ? topo["generators"].values.find { |g| g.is_a?(Hash) && g["kind"] == "grammar" } : nil
      corp_gens = topo.is_a?(Hash) && topo["generators"].is_a?(Hash) ? topo["generators"].select { |_, g| g.is_a?(Hash) && g["kind"] == "corpus" } : {}
      primary_sg_id = sgs.find { |_, g| g.is_a?(Hash) && g["primary"] }&.first || gram_gen&.dig("sync_group") || sgs.keys.first
      primary_afl_sub = (primary_sg_id && sgs.dig(primary_sg_id, "dir")) || "afl"

      primary_main_from = if primary_sg_id && topo.is_a?(Hash) && topo["workers"].is_a?(Array)
                            pm_w = topo["workers"].find { |w| w.is_a?(Hash) && w["sync_group"].to_s == primary_sg_id.to_s && w["afl_role"].to_s == "main" } ||
                                   topo["workers"].find { |w| w.is_a?(Hash) && w["sync_group"].to_s == primary_sg_id.to_s && w["kind"].to_s != "generator" }
                            pm_w&.dig("seeds", "from")&.to_s
                          end
      corp_gen = (primary_main_from && corp_gens[primary_main_from]) || corp_gens.values.first

      explicit_corpus = corpus_dir || env_override("TRIAGE_CORPUS_DIR") || ws["corpus_dir"]
      res_corpus = if explicit_corpus
                     expand_workspace_path(explicit_corpus, fuzz_root: repo_root)
                   elsif corp_gen&.dig("dir")
                     resolve_corpus_generator_dir(corp_gen["dir"], fuzz_dir: res_dir, fuzz_root: fuzz_root, ws_raw_dir: raw_ws_dir)
                   else
                     File.join(res_dir, "corpus")
                   end
      res_bin = bin_dir ? File.expand_path(bin_dir, repo_root) : File.join(res_dir, "bin")

      res_report = expand_workspace_path(ws["report_dir"] || File.join(res_dir, "report"), fuzz_root: repo_root)

      {
        fuzz_dir: res_dir,
        build_dir: res_build,
        build_rel: path_relative_or_abs(res_build, repo_root),
        afl_subdir: primary_afl_sub,
        afl_dir: File.join(res_dir, primary_afl_sub),
        bin_dir: res_bin,
        snapshot_dir: File.join(res_dir, "snapshot"),
        corpus_dir: res_corpus,
        seeds_dir: File.join(res_dir, "seeds"),
        triage_dir: expand_workspace_path(env_override("TRIAGE_DIR") || ws["triage_dir"] || File.join(res_report, "triage"), fuzz_root: repo_root),
        report_dir: res_report,
        coverage_dir: expand_workspace_path(ws["coverage_dir"] || File.join(res_report, "coverage"), fuzz_root: repo_root),
        logs_dir: expand_workspace_path(env_override("FUZZ_LOGS_DIR") || ws["logs_dir"] || File.join(res_dir, "logs"), fuzz_root: repo_root),
        reports_dir: expand_workspace_path(env_override("REPORTS_DIR") || ws["reports_dir"] || "reports", fuzz_root: repo_root)
      }
    end

    def read_json(path)
      return nil unless path && !path.to_s.empty? && File.file?(path)

      retries = 0
      begin
        data = JSON.parse(File.read(path, encoding: "UTF-8"))
        data.is_a?(Hash) ? data : nil
      rescue Errno::ENOENT
        if (retries += 1) <= 1
          sleep(0.005)
          retry
        end
        nil
      end
    rescue Errno::ENOTDIR, SystemCallError, IOError, JSON::ParserError, EncodingError
      nil
    end

    def write_json_atomic(path, data)
      PrismFuzzer::Common.write_json_atomic(path, data)
    end

    def blank?(val)
      val.nil? || val.to_s.strip.empty?
    end

    def grammar_seeds_dirs(plan)
      return {} unless plan.is_a?(Hash)

      out = {}
      plan.fetch("generators", {}).each do |gid, gspec|
        next unless gspec.is_a?(Hash) && gspec["kind"].to_s == "grammar"

        sdir = gspec["seeds_dir"]
        out[gid.to_s] = (sdir && !sdir.to_s.empty?) ? sdir.to_s : "/tmp/afl-tmpdir/#{gid}/seeds"
      end
      out
    end

    def env_override(name)
      return nil unless ENV.key?(name)

      val = ENV[name].to_s.strip
      val.empty? ? nil : val
    end

    def log_progress(msg)
      stage = defined?(PrismFuzzer::Progress) ? PrismFuzzer::Progress.current_stage : nil
      if stage
        stage.note(msg)
      else
        (@log_progress_mutex ||= Mutex.new).synchronize { puts msg }
      end
    end

    def run_cmd(*cmd, chdir: nil, env: nil, allow_fail: false)
      opts = {}
      opts[:chdir] = chdir if chdir
      args = env ? [env, *cmd] : cmd
      stage = defined?(PrismFuzzer::Progress) ? PrismFuzzer::Progress.current_stage : nil
      inner_stream = ENV["FUZZ_PROGRESS"].to_s.strip.downcase == "inner"
      stage&.log_command(cmd)

      out_buf = +""
      err_buf = +""
      status = nil
      Open3.popen3(*args, **opts) do |stdin, stdout, stderr, wait_thr|
        stdin.close
        pump = lambda do |io, buf|
          if defined?(PrismFuzzer::Progress)
            PrismFuzzer::Progress.drain_stream(io, buf: buf) do |line, is_newline|
              if stage
                stage.feed_line(line, persist: is_newline && !allow_fail, preview: !allow_fail)
              elsif inner_stream && !allow_fail && is_newline
                clean = PrismFuzzer::Progress.clean_utf8(line).rstrip
                $stderr.puts(clean) unless clean.empty?
              end
            end
          else
            buf << io.read.to_s
          end
        end
        t_out = Thread.new { pump.call(stdout, out_buf) }
        t_err = Thread.new { pump.call(stderr, err_buf) }
        t_out.join
        t_err.join
        status = wait_thr.value
      end
      return [out_buf, err_buf, status] if status&.success? || allow_fail

      detail = [err_buf.strip, out_buf.strip].reject(&:empty?).join("\n")
      raise TopologyError, "Command failed (#{cmd.join(' ')}): #{detail}"
    end

    def deep_dup(obj)
      case obj
      when Hash
        obj.each_with_object({}) { |(k, v), acc| acc[k.to_s] = deep_dup(v) }
      when Array
        obj.map { |v| deep_dup(v) }
      else
        obj
      end
    end

    def default_color_for(name)
      h = name.to_s.bytes.reduce(0) { |acc, b| (acc * 31 + b) & 0x7fffffff }
      FALLBACK_PALETTE[h % FALLBACK_PALETTE.size]
    end

    def source_local_dir(spec, fuzz_root:)
      raw = spec["dir"] || spec["local_path"]
      return nil if blank?(raw)

      path = raw.to_s
      if !Dir.exist?(path) && (ENV["PRISM_FUZZER_PATH_MAPS"] || ENV["RUBY_FUZZ_PATH_MAPS"])
        mapped = remap_external_path(path)
        return mapped if mapped
      end
      File.expand_path(path, fuzz_root)
    end

    def remap_external_path(path)
      raw = path.to_s
      abs = raw.start_with?("/") ? File.expand_path(raw) : raw
      raw_maps = ENV["PRISM_FUZZER_PATH_MAPS"] || ENV["RUBY_FUZZ_PATH_MAPS"] || ""
      pairs = raw_maps.split(";").filter_map do |pair|
        host_p, guest_p = pair.split("=", 2)
        next if blank?(host_p) || blank?(guest_p)

        [host_p, guest_p]
      end.sort_by { |(hp, _)| -hp.length }

      pairs.each do |host_p, guest_p|
        return guest_p if raw == host_p || abs == host_p
        return File.join(guest_p, abs.delete_prefix("#{host_p}/")) if abs.start_with?("#{host_p}/")
      end
      nil
    end
  end
end
