# frozen_string_literal: true

module FuzzTriage
  # Collects afl-showmap PCGUARD/LTO edge maps, resolves DOCUMENT_IDS function/domain
  # mappings, and caches baseline corpus document frequencies.
  module CoverageMap
    include Config
    extend self

    def showmap_env
      max_mb = env_max_allocated_mb
      hard_mb = env_hard_rss_limit_mb
      env_sanitizer_env.merge(
        "AFL_NO_IJON" => "1",
        "AFL_CMIN_ALLOW_ANY" => "1",
        "FUZZ_DIFF_BACKTRACE" => "0",
        "ASAN_OPTIONS" => "abort_on_error=1:handle_abort=1:symbolize=0:detect_leaks=0:detect_stack_use_after_return=0:max_allocation_size_mb=#{max_mb}:hard_rss_limit_mb=#{hard_mb}",
        "UBSAN_OPTIONS" => "abort_on_error=1:symbolize=0",
        "MSAN_OPTIONS" => "abort_on_error=1:handle_abort=1:symbolize=0:max_allocation_size_mb=#{max_mb}:hard_rss_limit_mb=#{hard_mb}"
      )
    end

    def parse_showmap_file(path)
      edges = {}
      return edges unless File.file?(path)

      File.foreach(path) do |line|
        next unless line =~ /\A\s*(\d+):(\d+)\s*\z/

        edges[Regexp.last_match(1).to_i] = Regexp.last_match(2).to_i
      end
      edges.sort.to_h { |k, v| [k.to_s, v] }
    end

    # Runs afl-showmap in a single persistent forkserver batch across inputs_by_key
    # (mapping caller key -> input file path), using numeric symlink filenames so
    # arbitrary source paths cannot collide or trigger shell/filename issues.
    def collect_showmap_batch(inputs_by_key, bin_path, showmap_path)
      return { ok: true, maps: {} } if inputs_by_key.empty?

      Dir.mktmpdir("showmap-") do |tmpdir|
        in_dir = File.join(tmpdir, "in")
        out_dir = File.join(tmpdir, "out")
        FileUtils.mkdir_p(in_dir)
        FileUtils.mkdir_p(out_dir)

        key_by_id = {}
        inputs_by_key.each_with_index do |(key, input_path), idx|
          sym_name = format("%06d", idx)
          File.symlink(File.expand_path(input_path), File.join(in_dir, sym_name))
          key_by_id[sym_name] = key
        end

        out, status = Open3.capture2e(
          showmap_env,
          showmap_path, "-q", "-t", env_showmap_timeout_ms.to_s,
          "-i", in_dir, "-o", out_dir, "--", bin_path, "@@"
        )

        out_utf8 = utf8_safe(out)
        if out_utf8.include?("Fork server handshake failed") || out_utf8.include?("PROGRAM ABORT")
          return { ok: false, reason: "afl-showmap forkserver handshake failed for #{bin_path}: #{out_utf8.lines.last&.strip}" }
        end

        maps = {}
        key_by_id.each do |sym_name, key|
          map_file = File.join(out_dir, sym_name)
          maps[key] = parse_showmap_file(map_file) if File.file?(map_file)
        end

        if maps.empty? && !status.success?
          return { ok: false, reason: "afl-showmap exited with #{status.exitstatus} and produced no maps" }
        end

        { ok: true, maps: maps }
      end
    end

    def load_coverage_ids(ids_path)
      if ids_path.nil? || ids_path.empty? || !File.file?(ids_path)
        return { available: false, path: nil, sha256: nil, edge_count_total: nil, edge_functions: {}, edge_domains: {} }
      end

      edge_functions = {}
      edge_domains = {}
      File.foreach(ids_path) do |line|
        next unless line =~ /\bFunction=(\S+)\s+edgeID=(\d+)\s*\z/

        eid = Regexp.last_match(2).to_i
        edge_functions[eid] = Regexp.last_match(1)
        edge_domains[eid] = Regexp.last_match(1) if line =~ /\bDomain=(\S+)\b/
      end

      sorted = edge_functions.sort.to_h { |k, v| [k.to_s, v] }
      sorted_domains = edge_domains.sort.to_h { |k, v| [k.to_s, v] }
      {
        available: true,
        path: ids_path,
        sha256: Digest::SHA256.file(ids_path).hexdigest,
        edge_count_total: sorted.size,
        edge_functions: sorted,
        edge_domains: sorted_domains
      }
    end

    def corpus_dir_fingerprint(corpus_dir)
      return nil, [] unless !corpus_dir.nil? && !corpus_dir.empty? && File.directory?(corpus_dir)

      files = Dir.glob(File.join(corpus_dir, "**", "*")).select { |p| File.file?(p) }.sort
      digest = Digest::SHA256.new
      files.each do |path|
        st = File.stat(path)
        rel = path.delete_prefix("#{corpus_dir}/")
        digest.update("#{rel}\0#{st.size}\0#{st.mtime.to_i}:#{st.mtime.nsec}\n")
      end
      [digest.hexdigest, files]
    end

    def load_or_build_corpus_coverage(bin_path, build_id, ids_info, corpus_dir, showmap_path, cache_path, label: "corpus baseline")
      fingerprint, corpus_files = corpus_dir_fingerprint(corpus_dir)
      if fingerprint.nil?
        return {
          "available" => false,
          "reason" => "corpus directory not found: #{corpus_dir}",
          "dir" => corpus_dir
        }
      end
      if corpus_files.empty?
        return {
          "available" => false,
          "reason" => "corpus directory is empty: #{corpus_dir}",
          "dir" => corpus_dir
        }
      end

      if File.file?(cache_path)
        begin
          cached = JSON.parse(File.read(cache_path))
          if cached["available"] &&
             cached["build_id"] == build_id &&
             cached["corpus_fingerprint"] == fingerprint &&
             cached["ids_sha256"] == ids_info[:sha256]
            return cached
          end
        rescue JSON::ParserError
          # Rebuild stale or corrupt cache.
        end
      end

      puts "Collecting afl-showmap #{label} (#{corpus_files.size} files)..."
      inputs = {}
      corpus_files.each_with_index { |p, i| inputs[i.to_s] = p }
      batch = collect_showmap_batch(inputs, bin_path, showmap_path)
      unless batch[:ok]
        return {
          "available" => false,
          "reason" => batch[:reason],
          "dir" => corpus_dir,
          "build_id" => build_id
        }
      end

      df = Hash.new(0)
      batch[:maps].each_value do |edges|
        edges.each_key { |edge_id| df[edge_id.to_i] += 1 }
      end

      result = {
        "available" => true,
        "dir" => corpus_dir,
        "binary" => normalize_repo_path(bin_path),
        "build_id" => build_id,
        "ids_sha256" => ids_info[:sha256],
        "corpus_fingerprint" => fingerprint,
        "corpus_count" => corpus_files.size,
        "edge_df" => df.sort.to_h { |k, v| [k.to_s, v] },
        "edge_functions" => ids_info[:edge_functions]
      }
      result["edge_domains"] = ids_info[:edge_domains] if ids_info[:edge_domains] && !ids_info[:edge_domains].empty?
      write_json_atomic(cache_path, result)
      result
    end

    def populate_coverage_stage(
      bin_path:,
      ids_path:,
      empty_reason:,
      showmap_path:,
      metas_by_dir:,
      target_dirs:,
      dirty_dirs:,
      field_key:,
      cache_path:,
      stage_label:,
      corpus_dir: env_corpus_dir
    )
      cov_disabled_reason = if bin_path.empty?
                              empty_reason
                            elsif !File.executable?(bin_path)
                              "reference binary not found or not executable: #{bin_path}"
                            elsif showmap_path.nil?
                              "afl-showmap not found in PATH"
                            end

      ref_binary_meta = {
        "available" => false,
        "path" => bin_path.empty? ? nil : normalize_repo_path(bin_path),
        "build_id" => nil,
        "ids_path" => nil,
        "ids_available" => false,
        "edge_count_total" => nil
      }

      if cov_disabled_reason
        corpus_info = { "available" => false, "reason" => cov_disabled_reason, "dir" => corpus_dir }
        target_dirs.each do |dir|
          meta = metas_by_dir[dir]
          next if meta[field_key] && meta[field_key]["available"] == false && meta[field_key]["reason"] == cov_disabled_reason

          meta[field_key] = { "available" => false, "reason" => cov_disabled_reason }
          dirty_dirs.add(dir)
        end
        return [ref_binary_meta, corpus_info]
      end

      build_id = binary_build_id(bin_path)
      ids_info = load_coverage_ids(ids_path)
      ref_binary_meta = {
        "available" => true,
        "path" => normalize_repo_path(bin_path),
        "build_id" => build_id,
        "ids_path" => ids_info[:path] ? normalize_repo_path(ids_info[:path]) : nil,
        "ids_available" => ids_info[:available],
        "edge_count_total" => ids_info[:edge_count_total]
      }

      corpus_info = load_or_build_corpus_coverage(
        bin_path,
        build_id,
        ids_info,
        corpus_dir,
        showmap_path,
        cache_path,
        label: "#{stage_label} corpus baseline"
      )

      stale_inputs = {}
      target_dirs.each do |dir|
        meta = metas_by_dir[dir]
        min_path = File.join(dir, "input.min")
        next unless File.file?(min_path)

        cov = meta[field_key]
        next if cov && cov["available"] == true && cov["build_id"] == build_id

        stale_inputs[dir] = min_path
      end

      unless stale_inputs.empty?
        puts "Collecting afl-showmap #{stage_label} bucket coverage (#{stale_inputs.size} buckets)..."
        batch = collect_showmap_batch(stale_inputs, bin_path, showmap_path)
        if batch[:ok]
          stale_inputs.each_key do |dir|
            edges = batch[:maps][dir]
            metas_by_dir[dir][field_key] = if edges
                                              {
                                                "available" => true,
                                                "binary" => normalize_repo_path(bin_path),
                                                "build_id" => build_id,
                                                "edge_count" => edges.size,
                                                "edges" => edges
                                              }
                                            else
                                              {
                                                "available" => false,
                                                "binary" => normalize_repo_path(bin_path),
                                                "build_id" => build_id,
                                                "reason" => "no coverage map produced"
                                              }
                                            end
            dirty_dirs.add(dir)
          end
        else
          ref_binary_meta["available"] = false
          ref_binary_meta["reason"] = batch[:reason]
          stale_inputs.each_key do |dir|
            metas_by_dir[dir][field_key] = { "available" => false, "reason" => batch[:reason] }
            dirty_dirs.add(dir)
          end
        end
      end

      [ref_binary_meta, corpus_info]
    end
  end
end
