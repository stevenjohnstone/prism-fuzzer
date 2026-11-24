# frozen_string_literal: true

require_relative "helpers"
require_relative "charts"
require_relative "../../runtime/common"

module PrismFuzzerReport
  module StatsIngest
    module_function

    def safe_mtime_i(path, fallback: 0)
      File.mtime(path).to_i
    rescue Errno::ENOENT, Errno::ESTALE
      fallback
    rescue SystemCallError => e
      warn "StatsIngest: failed to stat #{path}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
      fallback
    end

    def parse_fuzzer_stats(path)
      return {} unless File.exist?(path)

      stats = {}
      File.foreach(path) do |line|
        k, v = PrismFuzzer::Common.utf8_safe(line).split(":", 2)
        next unless k && v

        stats[k.strip] = v.strip
      end
      stats
    rescue Errno::ENOENT, Errno::ESTALE
      {}
    rescue SystemCallError, IOError => e
      warn "StatsIngest: failed to read fuzzer_stats #{path}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
      {}
    end

    def normalize_sync_source(src, consumer_worker: nil, topo_ctx: nil)
      if (gram_w = Helpers.resolve_grammar_sync_worker(consumer_worker, src, topo_ctx: topo_ctx))
        return gram_w
      end

      aliases = (topo_ctx && topo_ctx[:aliases]) || { "seeds" => "grammar" }
      return aliases[src] if aliases.key?(src)
      return "grammar" if src =~ /\A(?:grammar|seeds)(?:_\d+)?\z/
      return "ijon" if src =~ /\Aijon(?:_\d+|_peer)?\z/
      return "diff" if src =~ /\Adiff(?:_\d+|_peer)?\z/

      src
    end

    def worker_root_dirs(afl_dir, topo_ctx: nil)
      dirs = []
      topo = topo_ctx && topo_ctx[:topology]
      if topo && defined?(PrismFuzzer::Topology)
        dirs.concat(PrismFuzzer::Topology.sync_group_dirs(topo, base_dir: File.dirname(File.expand_path(afl_dir))))
      end
      dirs.concat([afl_dir, "#{afl_dir}-ijon"])
      dirs.map { |d| File.expand_path(d) }.uniq.select { |d| Dir.exist?(d) }
    end

    def discover_fuzzer_dirs(afl_dir, topo_ctx: nil)
      by_name = {}
      worker_root_dirs(afl_dir, topo_ctx: topo_ctx).each do |root|
        Dir.glob(File.join(root, "*")).sort.each do |d|
          name = File.basename(d)
          next if name.start_with?(".") || !File.directory?(d)
          next unless File.exist?(File.join(d, "fuzzer_stats")) || File.exist?(File.join(d, "plot_data"))

          by_name[name] ||= d
        end
      end
      by_name
    end

    def parse_generator_plot_data(path)
      return [] unless File.exist?(path)

      rows = []
      File.foreach(path) do |line|
        line = PrismFuzzer::Common.utf8_safe(line).strip
        next if line.empty? || line.start_with?("#")

        parts = line.split(",").map(&:strip)
        next if parts.size < 4

        rows << {
          relative_time: parts[0].to_i,
          files_created: parts[1].to_i,
          files_per_sec: parts[2].to_f,
          avg_files_per_sec: parts[3].to_f,
          attempts_done: (parts[4] || parts[1]).to_i,
          files_valid: parts[5].to_i,
          files_invalid: parts[6].to_i,
          corpus_count: parts[1].to_i,
          execs_per_sec: parts[2].to_f,
          total_execs: (parts[4] || parts[1]).to_i,
          cycles_done: 0,
          cur_item: 0,
          pending_total: 0,
          pending_favs: 0,
          map_size: 0.0,
          saved_crashes: 0,
          saved_hangs: 0,
          max_depth: 0,
          edges_found: 0,
          total_crashes: 0
        }
      end
      rows
    rescue Errno::ENOENT, Errno::ESTALE
      []
    rescue SystemCallError, IOError => e
      warn "StatsIngest: failed to read generator plot_data #{path}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
      []
    end

    def parse_plot_data(path)
      return [] unless File.exist?(path)

      rows = []
      File.foreach(path) do |line|
        line = PrismFuzzer::Common.utf8_safe(line).strip
        next if line.empty? || line.start_with?("#")

        parts = line.split(",").map(&:strip)
        next if parts.size < 13

        rows << {
          relative_time: parts[0].to_i,
          cycles_done: parts[1].to_i,
          cur_item: parts[2].to_i,
          corpus_count: parts[3].to_i,
          pending_total: parts[4].to_i,
          pending_favs: parts[5].to_i,
          map_size: parts[6].delete_suffix("%").to_f,
          saved_crashes: parts[7].to_i,
          saved_hangs: parts[8].to_i,
          max_depth: parts[9].to_i,
          execs_per_sec: parts[10].to_f,
          total_execs: parts[11].to_i,
          edges_found: parts[12].to_i,
          total_crashes: parts[13].to_i
        }
      end
      rows
    rescue Errno::ENOENT, Errno::ESTALE
      []
    rescue SystemCallError, IOError => e
      warn "StatsIngest: failed to read plot_data #{path}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
      []
    end

    # Scan <fuzzer>/queue/id:* filenames to classify each queue ID (0..N-1) as
    # :seed (orig:), :sync (sync:<source>), or :local (mutated locally), and record
    # the source fuzzer for synced entries. Because AFL++ assigns sequential 0-based
    # IDs as items enter the queue, corpus_count at any plot_data sample t corresponds
    # to queue IDs 0...(corpus_count - 1).
    def parse_queue_origins(queue_dir, fuzzer_name: nil, topo_ctx: nil)
      empty_res = { prefix_sync: [0], prefix_local: [0], prefix_seed: [0], by_source: {}, max_src_by_source: {} }
      return empty_res unless Dir.exist?(queue_dir)

      eff_worker = fuzzer_name || File.basename(File.dirname(queue_dir))
      max_id = -1
      item_kind = {}
      item_source = {}
      max_src_by_source = Hash.new(0)

      Dir.children(queue_dir).each do |raw_fname|
        fname = PrismFuzzer::Common.utf8_safe(raw_fname)
        id = fname[/\Aid:(\d+),/, 1]&.to_i
        next unless id

        max_id = id if id > max_id
        if fname =~ /\Aid:\d+,sync:([^,]+)/
          src_name = normalize_sync_source(Regexp.last_match(1), consumer_worker: eff_worker, topo_ctx: topo_ctx)
          item_kind[id] = :sync
          item_source[id] = src_name
          if fname =~ /\Aid:\d+,sync:[^,]+,src:(?:id:)?(\d+)(?:[,+]|$)/
            src_end = Regexp.last_match(1).to_i + 1
            max_src_by_source[src_name] = src_end if src_end > max_src_by_source[src_name]
          end
        elsif fname =~ /\Aid:\d+(?:,time:\d+,execs:\d+)?,orig:/
          item_kind[id] = :seed
        else
          item_kind[id] = :local
        end
      end

      return empty_res if max_id < 0

      prefix_sync = Array.new(max_id + 2, 0)
      prefix_local = Array.new(max_id + 2, 0)
      prefix_seed = Array.new(max_id + 2, 0)
      sources = item_source.values.uniq
      by_source = sources.to_h { |src| [src, Array.new(max_id + 2, 0)] }

      (0..max_id).each do |id|
        kind = item_kind[id] || :local
        prefix_sync[id + 1] = prefix_sync[id] + (kind == :sync ? 1 : 0)
        prefix_local[id + 1] = prefix_local[id] + (kind == :local ? 1 : 0)
        prefix_seed[id + 1] = prefix_seed[id] + (kind == :seed ? 1 : 0)
        src = item_source[id]
        sources.each do |s|
          by_source[s][id + 1] = by_source[s][id] + (src == s ? 1 : 0)
        end
      end

      {
        prefix_sync: prefix_sync,
        prefix_local: prefix_local,
        prefix_seed: prefix_seed,
        by_source: by_source,
        max_src_by_source: max_src_by_source
      }
    rescue Errno::ENOENT, Errno::ENOTDIR
      empty_res
    rescue SystemCallError => e
      warn "StatsIngest: failed to scan queue #{queue_dir}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
      empty_res
    end

    def parse_synced_cursors(fuzzer_dir, topo_ctx: nil)
      synced_dir = File.join(fuzzer_dir, ".synced")
      return {} unless Dir.exist?(synced_dir)

      owner_worker = File.basename(fuzzer_dir)
      cursors = {}
      Dir.children(synced_dir).each do |raw_fname|
        fname = PrismFuzzer::Common.utf8_safe(raw_fname)
        next if fname.start_with?(".") || fname.end_with?(".max")

        cursor_path = File.join(synced_dir, raw_fname)
        raw = begin
                File.binread(cursor_path)
              rescue Errno::ENOENT, Errno::ESTALE, Errno::EISDIR
                next
              rescue SystemCallError, IOError => e
                warn "StatsIngest: failed to read sync cursor #{cursor_path}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
                next
              end
        val = raw.bytesize >= 4 ? raw.unpack1("V") : 0
        cursors[fname] = val
        norm = normalize_sync_source(fname, consumer_worker: owner_worker, topo_ctx: topo_ctx)
        cursors[norm] = [cursors[norm].to_i, val].max
      end
      cursors
    rescue Errno::ENOENT, Errno::ENOTDIR
      {}
    rescue SystemCallError => e
      warn "StatsIngest: failed to scan sync cursors in #{synced_dir}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
      {}
    end

    def lookup_prefix(prefix_arr, count)
      return 0 if prefix_arr.empty? || count <= 0

      idx = [count, prefix_arr.size - 1].min
      prefix_arr[idx]
    end

    def sort_fuzzer_names(names, topo_ctx: nil)
      topo_order = (topo_ctx && topo_ctx[:order]) || []
      priority = { "main" => 0, "grammar" => 1, "msan" => 2, "ijon" => 3, "slow" => 4, "diff" => 5 }
      names.sort_by do |name|
        topo_idx = topo_order.index(name)
        if topo_idx
          [0, topo_idx, 0, name]
        elsif priority.key?(name)
          [1, priority[name], 0, name]
        elsif name =~ /\Adiff-(\d+)\z/
          [1, priority["diff"], Regexp.last_match(1).to_i, name]
        elsif name =~ /\Amain-(\d+)\z/
          [2, Regexp.last_match(1).to_i, 0, name]
        else
          [3, 0, 0, name]
        end
      end
    end

    def topology_worker_schedule(name, topo_ctx: nil)
      topo = topo_ctx && topo_ctx[:topology]
      return nil unless topo.is_a?(Hash)

      w = Array(topo["workers"]).find { |item| item.is_a?(Hash) && item["id"].to_s == name.to_s }
      return nil unless w

      if w["kind"].to_s == "generator"
        gid = w["generator"].to_s
        s = topo.dig("generators", gid, "schedule").to_s
        return s.empty? ? "grammar" : s
      end

      s = w["schedule"].to_s
      s.empty? ? nil : s
    end

    # Builds Synced Imports by Source Fuzzer time-series for a given worker.
    def fuzzer_sync_source_series(fuzzer, color_by_name:, topo_ctx: nil)
      topo_colors = (topo_ctx && topo_ctx[:colors]) || {}
      s = fuzzer[:samples]
      sort_fuzzer_names(fuzzer[:origins][:by_source].keys, topo_ctx: topo_ctx).each_with_index.map do |src, s_idx|
        prefix_arr = fuzzer[:origins][:by_source][src]
        {
          name: "from #{src}",
          color: color_by_name[src] || topo_colors[src] || Helpers::PALETTE[s_idx % Helpers::PALETTE.size],
          points: s.map { |r| [r[:relative_time], lookup_prefix(prefix_arr, r[:corpus_count])] }
        }
      end
    end

    def read_cursor_file(path)
      raw = File.binread(path)
      raw.bytesize >= 4 ? raw.unpack1("V") : 0
    rescue Errno::ENOENT, Errno::ESTALE, Errno::EISDIR
      0
    rescue SystemCallError, IOError => e
      warn "StatsIngest: failed to read #{path}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
      0
    end

    def resolve_group_masters(afl_fuzzers, expanded_afl_dir:, topo_ctx: nil)
      topo = topo_ctx && topo_ctx[:topology]
      topo_workers = topo.is_a?(Hash) ? Array(topo["workers"]).select { |w| w.is_a?(Hash) } : []
      worker_spec_by_id = topo_workers.each_with_object({}) { |w, h| h[w["id"].to_s] = w }

      explicit_master = lambda do |f|
        if (wspec = worker_spec_by_id[f[:name]])
          wspec["afl_role"].to_s == "main"
        else
          f[:stats]["command_line"].to_s.match?(/(?:\A|\s)-M(?:\s|\z)/)
        end
      end

      explicit_secondary = lambda do |f|
        if (wspec = worker_spec_by_id[f[:name]])
          wspec["afl_role"] && wspec["afl_role"].to_s != "main"
        else
          f[:stats]["command_line"].to_s.match?(/(?:\A|\s)-S(?:\s|\z)/)
        end
      end

      by_group_dir = afl_fuzzers.group_by { |f| File.expand_path(File.dirname(f[:dir])) }
      master_by_group_dir = {}
      by_group_dir.each do |gdir, g_fuzzers|
        master = g_fuzzers.find { |gf| explicit_master.call(gf) }
        if master.nil? && g_fuzzers.none? { |gf| explicit_secondary.call(gf) }
          master = g_fuzzers.find { |gf| gf[:name] == "main" } || (gdir == expanded_afl_dir ? g_fuzzers.first : nil)
        elsif master.nil?
          master = g_fuzzers.find { |gf| gf[:name] == "main" && !explicit_secondary.call(gf) }
        end
        master_by_group_dir[gdir] = master if master
      end

      [master_by_group_dir, worker_spec_by_id]
    end

    def build_afl_sync_entry(src_fuzzer, dst_fuzzer, sync_mode:, peer_alias: nil)
      peer_name = src_fuzzer[:name]
      dst_name = dst_fuzzer[:name]
      same_sync_dir = File.expand_path(File.dirname(src_fuzzer[:dir])) == File.expand_path(File.dirname(dst_fuzzer[:dir]))
      peer_total = src_fuzzer[:corpus_count]

      dst_cursors = dst_fuzzer[:synced_cursors] || {}
      dst_max_src = dst_fuzzer[:origins][:max_src_by_source] || {}
      dst_by_source = dst_fuzzer[:origins][:by_source] || {}

      watermark = if sync_mode == :shadow_peer && peer_alias && !peer_alias.empty?
                    alias_wm = dst_cursors[peer_alias] || read_cursor_file(File.join(dst_fuzzer[:dir], ".synced", peer_alias))
                    [alias_wm, dst_cursors[peer_name].to_i].max
                  else
                    dst_cursors[peer_name] || 0
                  end
      in_flight = dst_max_src[peer_name] || 0

      if sync_mode == :foreign_queue && in_flight > 0
        # Foreign-synced fuzzer (-F, legacy fallback when .synced/<peer_alias> is absent):
        # consumer scanned every peer queue file whose mtime was <= the mtime of the highest imported peer item.
        qdir = File.join(src_fuzzer[:dir], "queue")
        last_imp_prefix = format("id:%06d", in_flight - 1)
        if Dir.exist?(qdir)
          qfiles = Dir.children(qdir).select { |fn| fn.start_with?("id:") }
          imp_fn = qfiles.find { |fn| fn.start_with?(last_imp_prefix) }
          if imp_fn
            imp_mtime = safe_mtime_i(File.join(qdir, imp_fn), fallback: 0)
            if imp_mtime > 0
              scanned = qfiles.count { |fn| safe_mtime_i(File.join(qdir, fn), fallback: imp_mtime + 1) <= imp_mtime }
              watermark = [watermark, scanned].max
            end
          end
        end
      end

      cursor = [[watermark, in_flight].max, peer_total].min
      skipped_from_main = same_sync_dir ? lookup_prefix(src_fuzzer[:origins][:by_source][dst_name] || [], cursor) : 0
      tested_by_main = [cursor - skipped_from_main, 0].max
      imported_by_main = lookup_prefix(dst_by_source[peer_name] || [], dst_fuzzer[:corpus_count])
      rejected_by_main = [tested_by_main - imported_by_main, 0].max
      unsynced_backlog = [peer_total - cursor, 0].max
      sync_pct = peer_total > 0 ? (cursor * 100.0 / peer_total) : 100.0
      yield_pct = tested_by_main > 0 ? (imported_by_main * 100.0 / tested_by_main) : 0.0

      peer_from_main_wm = src_fuzzer[:synced_cursors][dst_name] || 0
      peer_from_main_max = src_fuzzer[:origins][:max_src_by_source][dst_name] || 0
      peer_from_main_cursor = [[peer_from_main_wm, peer_from_main_max].max, dst_fuzzer[:corpus_count]].min
      peer_from_main_pct = dst_fuzzer[:corpus_count] > 0 ? (peer_from_main_cursor * 100.0 / dst_fuzzer[:corpus_count]) : 100.0

      {
        is_generator: false,
        sync_mode: sync_mode,
        peer_alias: peer_alias,
        source_fuzzer: src_fuzzer,
        source_name: peer_name,
        consumer_fuzzer: dst_fuzzer,
        consumer_name: dst_name,
        peer_total: peer_total,
        watermark: watermark,
        cursor: cursor,
        skipped_from_main: skipped_from_main,
        tested_by_main: tested_by_main,
        imported_by_main: imported_by_main,
        rejected_by_main: rejected_by_main,
        unsynced_backlog: unsynced_backlog,
        sync_pct: sync_pct,
        yield_pct: yield_pct,
        peer_from_main_cursor: peer_from_main_cursor,
        peer_from_main_pct: peer_from_main_pct
      }
    end

    def compute_peer_sync(fuzzers:, afl_fuzzers:, main_fuzzer:, afl_dir:, master_by_group_dir: {}, worker_spec_by_id: {}, topo_ctx: nil)
      aliases = (topo_ctx && topo_ctx[:aliases]) || { "seeds" => "grammar" }
      main_name = main_fuzzer[:name]
      expanded_afl_dir = File.expand_path(afl_dir)
      afl_by_name = afl_fuzzers.each_with_object({}) { |af, h| h[af[:name]] = af }
      topo = topo_ctx && topo_ctx[:topology]
      topo_workers = topo.is_a?(Hash) ? Array(topo["workers"]).select { |w| w.is_a?(Hash) } : []

      peer_import_stats = {}
      bridges_from_src = Hash.new { |h, k| h[k] = [] }
      topo_workers.each do |dst_w|
        dst_f = afl_by_name[dst_w["id"].to_s]
        next unless dst_f

        Array(dst_w["peer_imports"]).each do |pi|
          next unless pi.is_a?(Hash)

          src_f = afl_by_name[pi["worker"].to_s]
          next unless src_f

          entry = build_afl_sync_entry(src_f, dst_f, sync_mode: :shadow_peer, peer_alias: pi["alias"].to_s)
          peer_import_stats[[src_f[:name], dst_f[:name]]] = entry
          bridges_from_src[src_f[:name]] << entry
        end
      end

      peer_sync_by_name = {}
      fuzzers.each do |f|
        peer_name = f[:name]
        if f[:role] == :generator
          gen_wspec = worker_spec_by_id[peer_name]
          gen_id = gen_wspec ? gen_wspec["generator"].to_s : peer_name
          topo_consumer_w = topo_workers.find do |cw|
            cw["kind"].to_s != "generator" && Array(cw["foreign_sync"]).map(&:to_s).include?(gen_id)
          end
          intake_fuzzer = topo_consumer_w && afl_by_name[topo_consumer_w["id"].to_s]
          intake_fuzzer ||= afl_fuzzers.max_by { |af| lookup_prefix(af[:origins][:by_source][peer_name] || [], af[:corpus_count]) }
          if intake_fuzzer.nil? || (topo_consumer_w.nil? && lookup_prefix(intake_fuzzer[:origins][:by_source][peer_name] || [], intake_fuzzer[:corpus_count]).zero?)
            intake_fuzzer = afl_fuzzers.find { |af| af[:name] == "ijon" } || main_fuzzer
          end
          peer_total = [f[:files_created].to_i, 0].max
          imported_count = lookup_prefix(intake_fuzzer[:origins][:by_source][peer_name] || [], intake_fuzzer[:corpus_count])
          pending = [f[:pending_files].to_i, 0].max
          scanned = [peer_total - pending, imported_count].max
          peer_total = [peer_total, scanned].max
          backlog = [peer_total - scanned, 0].max
          sync_pct = peer_total > 0 ? (scanned * 100.0 / peer_total) : 100.0
          tested_count = [scanned, imported_count].max
          rejected_count = [tested_count - imported_count, 0].max
          yield_pct = tested_count > 0 ? (imported_count * 100.0 / tested_count) : 0.0
          peer_sync_by_name[peer_name] = {
            is_generator: true,
            sync_mode: :foreign_seeds,
            source_fuzzer: f,
            source_name: peer_name,
            intake_fuzzer: intake_fuzzer,
            intake_name: intake_fuzzer[:name],
            consumer_fuzzer: intake_fuzzer,
            consumer_name: intake_fuzzer[:name],
            peer_total: peer_total,
            watermark: scanned,
            cursor: scanned,
            skipped_from_main: 0,
            tested_by_main: tested_count,
            imported_by_main: imported_count,
            rejected_by_main: rejected_count,
            unsynced_backlog: backlog,
            sync_pct: sync_pct,
            yield_pct: yield_pct,
            peer_from_main_cursor: 0,
            peer_from_main_pct: 0.0
          }
          next
        end

        gdir = File.expand_path(File.dirname(f[:dir]))
        group_master = master_by_group_dir[gdir]

        if group_master && group_master[:name] != peer_name
          peer_sync_by_name[peer_name] = build_afl_sync_entry(f, group_master, sync_mode: :peer)
          next
        end

        next if peer_name == main_name

        # Group master (or masterless worker) outside the primary hub: resolve explicit peer_import
        # consumer if configured, or fall back to legacy shadow/foreign sync when no topology is loaded.
        src_bridges = bridges_from_src[peer_name]
        if src_bridges.any?
          chosen = src_bridges.find { |b| b[:consumer_name] == main_name } || src_bridges.first
          peer_sync_by_name[peer_name] = chosen
        elsif topo.nil? && gdir != expanded_afl_dir
          peer_alias = aliases.key(peer_name) || (peer_name == "ijon" ? "ijon_peer" : nil)
          shadow_path = peer_alias ? File.join(main_fuzzer[:dir], ".synced", peer_alias) : nil
          mode = (shadow_path && File.file?(shadow_path)) ? :shadow_peer : :foreign_queue
          peer_sync_by_name[peer_name] = build_afl_sync_entry(f, main_fuzzer, sync_mode: mode, peer_alias: peer_alias)
        end
      end

      sync_rows = []
      fuzzers.each do |f|
        primary_ps = peer_sync_by_name[f[:name]]
        sync_rows << primary_ps if primary_ps
        bridges_from_src[f[:name]].each do |bridge_ps|
          next if primary_ps && primary_ps[:consumer_name] == bridge_ps[:consumer_name] && primary_ps[:sync_mode] == bridge_ps[:sync_mode]

          sync_rows << bridge_ps
        end
      end

      [peer_sync_by_name, sync_rows, peer_import_stats]
    end

    # Ingests AFL++ fuzzer_stats, plot_data, queue origins, and peer sync snapshots for a fleet.
    def ingest_fuzzers(afl_dir, topo_ctx: nil)
      raise InputError, "AFL directory not found: #{afl_dir}" unless Dir.exist?(afl_dir)

      fuzzer_dir_by_name = discover_fuzzer_dirs(afl_dir, topo_ctx: topo_ctx)
      fuzzer_names = sort_fuzzer_names(fuzzer_dir_by_name.keys, topo_ctx: topo_ctx)
      raise InputError, "No fuzzer directories with fuzzer_stats or plot_data found in #{afl_dir}" if fuzzer_names.empty?

      topo_colors = (topo_ctx && topo_ctx[:colors]) || {}

      fuzzers = fuzzer_names.each_with_index.map do |name, idx|
        dir = fuzzer_dir_by_name[name]
        stats = parse_fuzzer_stats(File.join(dir, "fuzzer_stats"))
        is_generator = stats["fuzzer_role"] == "generator"
        raw_plot = if is_generator
                     parse_generator_plot_data(File.join(dir, "plot_data"))
                   else
                     parse_plot_data(File.join(dir, "plot_data"))
                   end
        origins = parse_queue_origins(File.join(dir, "queue"), fuzzer_name: name, topo_ctx: topo_ctx)
        synced_cursors = parse_synced_cursors(dir, topo_ctx: topo_ctx)

        run_time = stats["run_time"]&.to_i || raw_plot.last&.dig(:relative_time) || 0
        if is_generator && raw_plot.size < 2 && stats["files_created"]
          fc = stats["files_created"].to_i
          fps = (stats["files_per_sec"] || stats["avg_files_per_sec"]).to_f
          avg_fps = (stats["avg_files_per_sec"] || fps).to_f
          att = (stats["attempts_done"] || fc).to_i
          fv = stats["files_valid"].to_i
          fi = stats["files_invalid"].to_i
          raw_plot = [
            { relative_time: 0, files_created: 0, files_per_sec: fps, avg_files_per_sec: avg_fps, attempts_done: 0, files_valid: 0, files_invalid: 0, corpus_count: 0, execs_per_sec: fps, total_execs: 0, cycles_done: 0, cur_item: 0, pending_total: 0, pending_favs: 0, map_size: 0.0, saved_crashes: 0, saved_hangs: 0, max_depth: 0, edges_found: 0, total_crashes: 0 },
            { relative_time: [run_time, 1].max, files_created: fc, files_per_sec: fps, avg_files_per_sec: avg_fps, attempts_done: att, files_valid: fv, files_invalid: fi, corpus_count: fc, execs_per_sec: fps, total_execs: att, cycles_done: 0, cur_item: 0, pending_total: 0, pending_favs: 0, map_size: 0.0, saved_crashes: 0, saved_hangs: 0, max_depth: 0, edges_found: 0, total_crashes: 0 }
          ]
        end

        sampled = Charts.downsample(raw_plot).map do |r|
          cc = r[:corpus_count]
          if is_generator
            r.merge(synced_count: 0, local_count: cc, seed_count: 0)
          else
            r.merge(
              synced_count: lookup_prefix(origins[:prefix_sync], cc),
              local_count: lookup_prefix(origins[:prefix_local], cc),
              seed_count: lookup_prefix(origins[:prefix_seed], cc)
            )
          end
        end

        sched = stats["power_mode"] || stats["command_line"]&.[](/-p\s+(\S+)/, 1) || topology_worker_schedule(name, topo_ctx: topo_ctx) || "default"
        edges_found = stats["edges_found"]&.to_i || sampled.last&.dig(:edges_found) || 0
        total_edges = stats["total_edges"]&.to_i || 0
        bitmap_cvg = stats["bitmap_cvg"]&.delete_suffix("%")&.to_f || sampled.last&.dig(:map_size) || 0.0
        execs_done = stats["execs_done"]&.to_i || sampled.last&.dig(:total_execs) || 0
        execs_per_sec = stats["execs_per_sec"]&.to_f || sampled.last&.dig(:execs_per_sec) || 0.0
        corpus_count = stats["corpus_count"]&.to_i || sampled.last&.dig(:corpus_count) || 0
        corpus_found = stats["corpus_found"]&.to_i || sampled.last&.dig(:local_count) || 0
        corpus_imported = stats["corpus_imported"]&.to_i || sampled.last&.dig(:synced_count) || 0
        pending_total = stats["pending_total"]&.to_i || sampled.last&.dig(:pending_total) || 0
        pending_favs = stats["pending_favs"]&.to_i || sampled.last&.dig(:pending_favs) || 0
        saved_crashes = stats["saved_crashes"]&.to_i || sampled.last&.dig(:saved_crashes) || 0
        saved_hangs = stats["saved_hangs"]&.to_i || sampled.last&.dig(:saved_hangs) || 0
        cycles_done = stats["cycles_done"]&.to_i || sampled.last&.dig(:cycles_done) || 0
        max_depth = stats["max_depth"]&.to_i || sampled.last&.dig(:max_depth) || 0
        stability = stats["stability"] || "100.00%"
        banner = stats["afl_banner"] || "./tmp/fuzz/build/fuzz"

        files_created = (stats["files_created"] || corpus_count).to_i
        pending_files = stats["pending_files"].to_i
        max_pending_files = (stats["max_pending_files"] || "50000").to_i
        files_pruned = stats["files_pruned"].to_i
        files_per_sec = (stats["files_per_sec"] || stats["avg_files_per_sec"] || execs_per_sec).to_f
        avg_files_per_sec = (stats["avg_files_per_sec"] || files_per_sec).to_f
        attempts_done = (stats["attempts_done"] || execs_done).to_i
        files_valid = stats["files_valid"].to_i
        files_invalid = stats["files_invalid"].to_i
        duplicates_skipped = stats["duplicates_skipped"].to_i

        {
          name: name,
          dir: dir,
          role: is_generator ? :generator : :fuzzer,
          color: topo_colors[name] || Helpers::PALETTE[idx % Helpers::PALETTE.size],
          sched: sched,
          banner: banner,
          stats: stats,
          origins: origins,
          synced_cursors: synced_cursors,
          samples: sampled,
          sample_count: raw_plot.size,
          edges_found: edges_found,
          total_edges: total_edges,
          bitmap_cvg: bitmap_cvg,
          execs_done: execs_done,
          execs_per_sec: execs_per_sec,
          corpus_count: corpus_count,
          corpus_found: corpus_found,
          corpus_imported: corpus_imported,
          pending_total: pending_total,
          pending_favs: pending_favs,
          saved_crashes: saved_crashes,
          saved_hangs: saved_hangs,
          cycles_done: cycles_done,
          max_depth: max_depth,
          run_time: run_time,
          stability: stability,
          files_created: files_created,
          pending_files: pending_files,
          max_pending_files: max_pending_files,
          files_pruned: files_pruned,
          files_per_sec: files_per_sec,
          avg_files_per_sec: avg_files_per_sec,
          attempts_done: attempts_done,
          files_valid: files_valid,
          files_invalid: files_invalid,
          duplicates_skipped: duplicates_skipped
        }
      end

      color_by_name = fuzzers.to_h { |f| [f[:name], f[:color]] }
      afl_fuzzers = fuzzers.reject { |f| f[:role] == :generator }
      gen_fuzzers = fuzzers.select { |f| f[:role] == :generator }
      expanded_afl_dir = File.expand_path(afl_dir)
      master_by_group_dir, worker_spec_by_id = resolve_group_masters(afl_fuzzers, expanded_afl_dir: expanded_afl_dir, topo_ctx: topo_ctx)
      main_fuzzer = master_by_group_dir[expanded_afl_dir] ||
                    master_by_group_dir.values.first ||
                    afl_fuzzers.find { |f| f[:name] == "main" } ||
                    afl_fuzzers.first ||
                    fuzzers.first

      peer_sync_by_name, sync_rows, peer_import_stats = compute_peer_sync(
        fuzzers: fuzzers,
        afl_fuzzers: afl_fuzzers,
        main_fuzzer: main_fuzzer,
        afl_dir: afl_dir,
        master_by_group_dir: master_by_group_dir,
        worker_spec_by_id: worker_spec_by_id,
        topo_ctx: topo_ctx
      )

      {
        fuzzers: fuzzers,
        afl_fuzzers: afl_fuzzers,
        gen_fuzzers: gen_fuzzers,
        main_fuzzer: main_fuzzer,
        main_name: main_fuzzer[:name],
        group_masters: master_by_group_dir.values.map { |m| m[:name] }.uniq,
        color_by_name: color_by_name,
        worker_by_name: fuzzers.each_with_object({}) { |f, h| h[f[:name]] = f },
        peer_sync_by_name: peer_sync_by_name,
        sync_rows: sync_rows,
        peer_import_stats: peer_import_stats,
        fleet_execs: afl_fuzzers.sum { |f| f[:execs_done] },
        fleet_speed: afl_fuzzers.sum { |f| f[:execs_per_sec] },
        fleet_crashes: fuzzers.sum { |f| f[:saved_crashes] },
        fleet_hangs: afl_fuzzers.sum { |f| f[:saved_hangs] },
        fleet_max_corpus: afl_fuzzers.map { |f| f[:corpus_count] }.max || 0,
        fleet_max_runtime: fuzzers.map { |f| f[:run_time] }.max || 0
      }
    end
  end
end
