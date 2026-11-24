#!/usr/bin/env ruby
# frozen_string_literal: true

require "rbconfig"

module PrismFuzzer
  # Terminal dashboard and queue/origin metrics collector for running AFL++ and
  # grammar-generator workers.
  module Status
    topology_lib = File.join(__dir__, "topology.rb")
    require topology_lib if File.file?(topology_lib)

    BOLD = "\e[1m"
    DIM = "\e[2m"
    RED = "\e[31m"
    GREEN = "\e[32m"
    YELLOW = "\e[33m"
    CYAN = "\e[36m"
    RESET = "\e[0m"

    DEFAULT_ALIASES = { "seeds" => "grammar" }.freeze
    DEFAULT_GENERATOR = {
      gid: "grammar",
      worker_id: "grammar",
      seeds_dir: "/tmp/afl-tmpdir/grammar/seeds",
      schedule: "lrama"
    }.freeze
    DEFAULT_GRAMMAR_SEEDS_DIR = DEFAULT_GENERATOR[:seeds_dir]

    module_function

    def default_context
      {
        topo: nil,
        aliases: DEFAULT_ALIASES,
        generators: { "grammar" => DEFAULT_GENERATOR },
        consumer_grammar_workers: {},
        seed_basename_workers: {}
      }
    end

    def build_context(afl_dir = nil, topo: nil)
      resolved_topo = if !topo.nil?
                        topo == false ? nil : topo
                      elsif defined?(PrismFuzzer::Topology)
                        afl_dir ? PrismFuzzer::Topology.discover(afl_dir: afl_dir) : PrismFuzzer::Topology.discover
                      end
      aliases = if defined?(PrismFuzzer::Topology)
                  PrismFuzzer::Topology.sync_aliases(resolved_topo)
                else
                  DEFAULT_ALIASES
                end

      gens_by_id = {}
      if resolved_topo && resolved_topo["generators"].is_a?(Hash)
        resolved_topo["generators"].each do |gid, gspec|
          next unless gspec.is_a?(Hash) && gspec["kind"] == "grammar"

          gens_by_id[gid.to_s] = {
            gid: gid.to_s,
            seeds_dir: gspec["seeds_dir"] || "/tmp/afl-tmpdir/#{gid}/seeds",
            schedule: gspec["schedule"] || "lrama"
          }
        end
      end

      generators = {}
      if resolved_topo && resolved_topo["workers"].is_a?(Array)
        resolved_topo["workers"].each do |w|
          next unless w.is_a?(Hash) && w["kind"] == "generator"

          gid = w["generator"].to_s
          gcfg = gens_by_id[gid]
          next unless gcfg

          wid = w["id"].to_s
          generators[wid] = gcfg.merge(worker_id: wid)
        end
      end

      # Include any grammar generator definitions without explicit worker entries,
      # or fallback cleanly when no topology is discovered.
      gens_by_id.each do |gid, gcfg|
        next if generators.values.any? { |entry| entry[:gid] == gid }

        generators[gid] = gcfg.merge(worker_id: gid)
      end

      if generators.empty? && (resolved_topo.nil? || gens_by_id.empty?)
        generators["grammar"] = DEFAULT_GENERATOR.dup
      end

      # Map each AFL consumer worker ID (and unique non-"seeds" seed directory basenames)
      # back to the canonical grammar generator worker ID for contribution tracking.
      consumer_grammar_workers = {}
      if resolved_topo && resolved_topo["workers"].is_a?(Array)
        worker_by_gid = generators.values.each_with_object({}) { |cfg, h| h[cfg[:gid]] = cfg[:worker_id] }
        resolved_topo["workers"].each do |w|
          next unless w.is_a?(Hash) && w["kind"] != "generator"

          f_gens = Array(w["foreign_sync"]).map(&:to_s).filter_map { |gid| worker_by_gid[gid] }.uniq
          consumer_grammar_workers[w["id"].to_s] = f_gens unless f_gens.empty?
        end
      end

      counts = Hash.new(0)
      candidates = {}
      generators.each_value do |cfg|
        base = File.basename(cfg[:seeds_dir].to_s)
        next if base.empty? || base == "seeds" || base == "grammar"

        counts[base] += 1
        candidates[base] = cfg[:worker_id]
      end
      seed_basename_workers = candidates.select { |base, _| counts[base] == 1 }

      {
        topo: resolved_topo,
        aliases: aliases,
        generators: generators,
        consumer_grammar_workers: consumer_grammar_workers,
        seed_basename_workers: seed_basename_workers
      }
    end

    def format_int(num)
      num.to_i.to_s.reverse.gsub(/(\d{3})(?=\d)/, '\\1,').reverse
    end

    def format_fit(num, width)
      full = format_int(num)
      return full if full.length <= width

      n = num.to_f
      if n >= 1_000_000_000
        format("%.1fB", n / 1_000_000_000.0)
      elsif n >= 1_000_000
        s = format("%.2fM", n / 1_000_000.0)
        s.length <= width ? s : format("%.1fM", n / 1_000_000.0)
      elsif n >= 1_000
        s = format("%.1fK", n / 1_000.0)
        s.length <= width ? s : format("%dK", (n / 1_000.0).round)
      else
        full
      end
    end

    def format_rate(rate)
      r = rate.to_f
      if r >= 10.0
        "#{format_int(r.round)}/s"
      else
        format("%.1f/s", r)
      end
    end

    def format_duration(seconds)
      seconds = seconds.to_i
      return "0s" if seconds <= 0

      hours = seconds / 3600
      mins = (seconds % 3600) / 60
      secs = seconds % 60

      if hours > 0
        format("%dh %02dm %02ds", hours, mins, secs)
      elsif mins > 0
        format("%dm %02ds", mins, secs)
      else
        format("%ds", secs)
      end
    end

    def grammar_sync_worker(fuzzer, sync_tag, ctx: default_context)
      seed_basename_workers = ctx[:seed_basename_workers]
      generators = ctx[:generators]
      consumer_grammar_workers = ctx[:consumer_grammar_workers]

      return seed_basename_workers[sync_tag] if seed_basename_workers.key?(sync_tag)

      stripped = sync_tag.sub(/_\d+\z/, "")
      return seed_basename_workers[stripped] if seed_basename_workers.key?(stripped)

      if generators.key?(sync_tag)
        return sync_tag
      end

      if (matched_gen = generators.values.find { |cfg| cfg[:gid] == sync_tag || cfg[:gid] == stripped })
        return matched_gen[:worker_id]
      end

      if sync_tag =~ /\A(?:grammar|seeds)(?:_\d+)?\z/
        f_gens = consumer_grammar_workers[fuzzer]
        return f_gens.first if f_gens && f_gens.size == 1
        return generators.keys.first if generators.size == 1

        return "grammar"
      end

      nil
    end

    def grammar_origin?(name, ctx: default_context)
      name == "grammar" || ctx[:generators].key?(name)
    end

    def normalize_origin(origin, ctx: default_context)
      aliases = ctx[:aliases]
      return aliases[origin] if aliases.key?(origin)
      return "grammar" if origin =~ /\A(?:grammar|seeds)(?:_\d+)?\z/
      return "ijon" if origin =~ /\Aijon(?:_\d+|_peer)?\z/
      return "diff" if origin =~ /\Adiff(?:_\d+|_peer)?\z/

      origin
    end

    def worker_root_dirs(afl_dir, ctx: default_context)
      dirs = []
      topo = ctx[:topo]
      if topo && defined?(PrismFuzzer::Topology)
        dirs.concat(PrismFuzzer::Topology.sync_group_dirs(topo, base_dir: File.dirname(File.expand_path(afl_dir))))
      end
      dirs.concat([afl_dir, "#{afl_dir}-ijon"])
      dirs.map { |d| File.expand_path(d) }.uniq.select { |d| Dir.exist?(d) }
    end

    def find_worker_dir(afl_dir, name, ctx: default_context)
      worker_root_dirs(afl_dir, ctx: ctx).each do |root|
        d = File.join(root, name)
        return d if Dir.exist?(d)
      end
      File.join(afl_dir, name)
    end

    def pid_alive?(pid)
      return false if pid <= 0

      Process.kill(0, pid)
      true
    rescue Errno::ESRCH
      false
    rescue Errno::EPERM
      true
    end

    def parse_stats_file(path)
      stats = {}
      File.foreach(path) do |line|
        key, val = line.split(":", 2)
        next unless key && val

        stats[key.strip] = val.strip
      end
      stats
    rescue Errno::ENOENT, Errno::ENOTDIR
      {}
    rescue IOError, SystemCallError => e
      warn "[status] failed to read stats file #{path}: #{e.class}: #{e.message}"
      {}
    end

    def parse_queue_entry(fuzzer, fname, ctx: default_context)
      raw_id = fname[/\Aid:(\d+),/, 1]
      return :skip unless raw_id

      id = raw_id.to_i.to_s
      if fname =~ /\Aid:\d+,sync:([^,]+),src:(?:id:)?([^,+]+)/
        raw_peer = Regexp.last_match(1)
        src_ref = Regexp.last_match(2)
        if (gen_worker = grammar_sync_worker(fuzzer, raw_peer, ctx: ctx))
          [:grammar_sync, id, src_ref, gen_worker].freeze
        else
          peer = normalize_origin(raw_peer, ctx: ctx)
          src_key = src_ref =~ /\A\d+\z/ ? src_ref.to_i.to_s : src_ref
          [:peer_sync, id, peer, src_key].freeze
        end
      elsif fname =~ /\Aid:\d+(?:,time:\d+,execs:\d+)?,orig:/
        [:seed, id].freeze
      else
        srcs = (fname[/\Aid:\d+,src:([0-9+]+)/, 1]&.split("+") || []).map { |s| s.to_i.to_s }.freeze
        [:local, id, srcs].freeze
      end
    end

    def compute_contributions(afl_dir, queue_entry_cache = (@queue_entry_cache ||= {}), topo: nil, ctx: nil)
      ctx ||= build_context(afl_dir, topo: topo)
      origin = Hash.new { |h, k| h[k] = {} }
      sync_items = []
      local_items = []
      grammar_shared_srcs = Hash.new { |h, k| h[k] = {} }

      worker_root_dirs(afl_dir, ctx: ctx).flat_map { |r| Dir.glob(File.join(r, "*/queue")) }.each do |qdir|
        next if File.symlink?(qdir)

        fuzzer = File.basename(File.dirname(qdir))
        entries = begin
          Dir.children(qdir)
        rescue Errno::ENOENT, Errno::ENOTDIR
          next
        rescue SystemCallError => e
          warn "[status] failed to list queue dir #{qdir}: #{e.class}: #{e.message}"
          next
        end
        fuzzer_cache = (queue_entry_cache[fuzzer] ||= {})
        if fuzzer_cache.size > entries.size + 1024
          present = entries.each_with_object({}) { |fn, h| h[fn] = true }
          fuzzer_cache.select! { |fn, _| present[fn] }
        end

        entries.each do |f|
          parsed = (fuzzer_cache[f] ||= parse_queue_entry(fuzzer, f, ctx: ctx))
          next if parsed == :skip

          case parsed[0]
          when :grammar_sync
            gen_name = parsed[3] || "grammar"
            origin[fuzzer][parsed[1]] = gen_name
            grammar_shared_srcs[gen_name][parsed[2]] = true
          when :peer_sync
            origin[fuzzer][parsed[1]] = parsed[2]
            sync_items << [fuzzer, parsed[1], parsed[2], parsed[3]]
          when :seed
            origin[fuzzer][parsed[1]] = :seed
          when :local
            origin[fuzzer][parsed[1]] = fuzzer
            local_items << [fuzzer, parsed[1], parsed[2]]
          end
        end
      end

      # Propagate transitive origins to fixed point across multi-hop syncs
      # (e.g. grammar -> ijon -> main -> main-4 -> main -> msan)
      16.times do
        changed = false
        sync_items.each do |fuzzer, id, peer, src_ref|
          src_orig = origin[peer][src_ref]
          new_orig = (src_orig && src_orig != :seed) ? src_orig : peer
          if origin[fuzzer][id] != new_orig
            origin[fuzzer][id] = new_orig
            changed = true
          end
        end
        local_items.each do |fuzzer, id, srcs|
          foreign = srcs.filter_map { |s| origin[fuzzer][s] }.reject { |o| o == :seed || o == fuzzer }.uniq
          gram_orig = foreign.find { |o| grammar_origin?(o, ctx: ctx) }
          new_orig = gram_orig || foreign.first || fuzzer
          if origin[fuzzer][id] != new_orig
            origin[fuzzer][id] = new_orig
            changed = true
          end
        end
        break unless changed
      end

      shared_ids = Hash.new { |h, k| h[k] = {} }
      sync_items.each do |_fuzzer, _id, peer, src_ref|
        src_orig = origin[peer][src_ref]
        if src_orig.nil? || src_orig == :seed || src_orig == peer
          shared_ids[peer][src_ref] = true
        end
      end

      shared = Hash.new(0)
      shared_ids.each { |peer, ids| shared[peer] = ids.size }
      grammar_shared_srcs.each { |gen_name, srcs| shared[gen_name] = srcs.size }

      descendants = Hash.new(0)
      local_items.each do |fuzzer, _id, srcs|
        foreign = srcs.filter_map { |s| origin[fuzzer][s] }.reject { |o| o == :seed || o == fuzzer }.uniq
        foreign.each { |o| descendants[o] += 1 }
      end

      { shared: shared, descendants: descendants }
    rescue SystemCallError, IOError => e
      warn "[status] compute_contributions failed for #{afl_dir}: #{e.class}: #{e.message}"
      { shared: Hash.new(0), descendants: Hash.new(0) }
    end

    def collect_fuzzer_rows(afl_dir, expected_fuzzers, started_at, now, topo: nil, ctx: nil)
      ctx ||= build_context(afl_dir, topo: topo)
      generators = ctx[:generators]
      discovered = worker_root_dirs(afl_dir, ctx: ctx).flat_map { |r| Dir.glob(File.join(r, "*/fuzzer_stats")) }.map { |p| File.basename(File.dirname(p)) }
      names = (expected_fuzzers + discovered).uniq

      names.map do |name|
        stats_path = File.join(find_worker_dir(afl_dir, name, ctx: ctx), "fuzzer_stats")
        if File.exist?(stats_path)
          stats = parse_stats_file(stats_path)
          pid = stats["fuzzer_pid"].to_i
          alive = pid_alive?(pid)
          sched = stats["power_mode"] || stats["command_line"]&.[](/-p\s+(\S+)/, 1) || "fast"
          is_generator = stats["fuzzer_role"] == "generator"
          files_created = (stats["files_created"] || stats["corpus_count"]).to_i
          start_t = stats["start_time"].to_i
          elapsed = start_t > 0 ? [now - start_t, 1].max : [now - started_at, 1].max
          avg_files_rate = if stats["avg_files_per_sec"]
                             stats["avg_files_per_sec"].to_f
                           else
                             files_created.to_f / elapsed
                           end
          files_rate = stats["files_per_sec"] ? stats["files_per_sec"].to_f : avg_files_rate
          {
            name: name,
            role: is_generator ? :generator : :fuzzer,
            state: alive ? :alive : :dead,
            sched: sched,
            execs_per_sec: stats["execs_per_sec"].to_f,
            execs_done: stats["execs_done"].to_i,
            attempts_done: (stats["attempts_done"] || stats["execs_done"]).to_i,
            files_created: files_created,
            pending_files: stats["pending_files"].to_i,
            max_pending_files: (stats["max_pending_files"] || "50000").to_i,
            files_pruned: stats["files_pruned"].to_i,
            duplicates_skipped: stats["duplicates_skipped"].to_i,
            files_per_sec: files_rate,
            avg_files_per_sec: avg_files_rate,
            cycles_done: stats["cycles_done"].to_i,
            corpus_count: stats["corpus_count"].to_i,
            pending_total: stats["pending_total"].to_i,
            pending_favs: stats["pending_favs"].to_i,
            bitmap_cvg: stats["bitmap_cvg"] || "0.00%",
            edges_found: stats["edges_found"].to_i,
            total_edges: stats["total_edges"].to_i,
            saved_crashes: stats["saved_crashes"].to_i,
            saved_hangs: stats["saved_hangs"].to_i,
            last_find: stats["last_find"].to_i,
            start_time: start_t
          }
        elsif (gen_cfg = generators[name]) && Dir.exist?(gen_cfg[:seeds_dir])
          pending = begin
            Dir.children(gen_cfg[:seeds_dir]).count { |f| !f.start_with?(".") }
          rescue Errno::ENOENT, Errno::ENOTDIR
            0
          rescue SystemCallError => e
            warn "[status] failed to list generator seeds dir #{gen_cfg[:seeds_dir]}: #{e.class}: #{e.message}"
            0
          end
          elapsed = [now - started_at, 1].max
          rate = pending.to_f / elapsed
          {
            name: name,
            role: :generator,
            state: pending > 0 ? :alive : :starting,
            sched: gen_cfg[:schedule],
            execs_per_sec: 0.0,
            execs_done: 0,
            attempts_done: pending,
            files_created: pending,
            pending_files: pending,
            max_pending_files: 50_000,
            files_pruned: 0,
            duplicates_skipped: 0,
            files_per_sec: rate,
            avg_files_per_sec: rate,
            cycles_done: 0,
            corpus_count: pending,
            pending_total: 0,
            pending_favs: 0,
            bitmap_cvg: "-",
            edges_found: 0,
            total_edges: 0,
            saved_crashes: 0,
            saved_hangs: 0,
            last_find: pending > 0 ? now : 0,
            start_time: started_at
          }
        else
          is_gen = generators.key?(name) || name == "grammar"
          {
            name: name,
            role: is_gen ? :generator : :fuzzer,
            state: :starting,
            sched: is_gen ? (generators.dig(name, :schedule) || "lrama") : "-",
            execs_per_sec: 0.0,
            execs_done: 0,
            attempts_done: 0,
            files_created: 0,
            pending_files: 0,
            max_pending_files: 50_000,
            files_pruned: 0,
            duplicates_skipped: 0,
            files_per_sec: 0.0,
            avg_files_per_sec: 0.0,
            cycles_done: 0,
            corpus_count: 0,
            pending_total: 0,
            pending_favs: 0,
            bitmap_cvg: "0.00%",
            edges_found: 0,
            total_edges: 0,
            saved_crashes: 0,
            saved_hangs: 0,
            last_find: 0,
            start_time: 0
          }
        end
      end
    end

    def state_badge(state, pad = nil)
      label = case state
              when :alive then "RUNNING"
              when :starting then "STARTING"
              else "STOPPED"
              end
      color = case state
              when :alive then GREEN
              when :starting then YELLOW
              else RED
              end
      formatted = pad ? format("%-#{pad}s", label) : label
      "#{color}#{formatted}#{RESET}"
    end

    def render(afl_dir, expected_fuzzers, started_at, page, contribs, topo: nil, ctx: nil)
      ctx ||= build_context(afl_dir, topo: topo)
      now = Time.now.to_i
      rows = collect_fuzzer_rows(afl_dir, expected_fuzzers, started_at, now, ctx: ctx)
      afl_rows = rows.reject { |r| r[:role] == :generator }
      gen_rows = rows.select { |r| r[:role] == :generator }

      alive_count = afl_rows.count { |r| r[:state] == :alive }
      total_execs_sec = afl_rows.select { |r| r[:state] == :alive }.sum { |r| r[:execs_per_sec] }
      total_execs = afl_rows.sum { |r| r[:execs_done] }
      max_corpus = afl_rows.map { |r| r[:corpus_count] }.max || 0
      max_cvg = afl_rows.map { |r| r[:bitmap_cvg].to_f }.max || 0.0
      total_crashes = rows.sum { |r| r[:saved_crashes] }
      total_hangs = afl_rows.sum { |r| r[:saved_hangs] }
      earliest_start = rows.map { |r| r[:start_time] }.reject(&:zero?).min || started_at
      uptime = format_duration(now - earliest_start)

      page1_tab = page == 1 ? "#{BOLD}#{CYAN}[1: Overview]#{RESET}" : "#{DIM} 1: Overview #{RESET}"
      page2_tab = page == 2 ? "#{BOLD}#{CYAN}[2: Queue & Sync]#{RESET}" : "#{DIM} 2: Queue & Sync #{RESET}"

      out = +"\e[H\e[J"
      out << "#{BOLD}#{CYAN}Prism AFL++ Fleet Dashboard#{RESET} "
      out << "#{DIM}(uptime: #{uptime}, dir: #{afl_dir})#{RESET}   #{page1_tab} #{page2_tab}\n\n"

      crash_color = total_crashes > 0 ? "#{BOLD}#{RED}" : GREEN
      hang_color = total_hangs > 0 ? "#{BOLD}#{YELLOW}" : GREEN
      out << format(
        "  #{BOLD}Fuzzers:#{RESET} %d/%d alive   " \
        "#{BOLD}Speed:#{RESET} %s/s   " \
        "#{BOLD}Execs:#{RESET} %s   " \
        "#{BOLD}Corpus:#{RESET} %s   " \
        "#{BOLD}Max Cov:#{RESET} %.2f%%   " \
        "#{BOLD}Crashes:#{RESET} #{crash_color}%d#{RESET}   " \
        "#{BOLD}Hangs:#{RESET} #{hang_color}%d#{RESET}\n\n",
        alive_count, afl_rows.size,
        format_int(total_execs_sec.round),
        format_int(total_execs),
        format_int(max_corpus),
        max_cvg,
        total_crashes,
        total_hangs
      )

      name_width = ([10] + rows.map { |r| r[:name].to_s.length }).max
      sched_width = ([8] + rows.map { |r| r[:sched].to_s.length }).max

      header = if page == 1
                 format(
                   "%-#{name_width}s %-9s %-#{sched_width}s %12s %8s %17s %8s %6s",
                   "FUZZER", "STATE", "SCHED", "EXEC/S", "COV %", "EDGES", "CRASHES", "HANGS"
                 )
               else
                 format(
                   "%-#{name_width}s %-9s %-#{sched_width}s %12s %14s %6s %8s %8s %11s %14s %8s %8s",
                   "FUZZER", "STATE", "SCHED", "EXEC/S", "TOTAL EXECS", "CYCLES",
                   "CORPUS", "SHARED", "DESCENDANTS", "LAST FIND", "PENDING", "PEND FAV"
                 )
               end
      out << "#{BOLD}#{header}#{RESET}\n"
      out << ("-" * header.length) << "\n"

      afl_rows.each do |r|
        state_str = state_badge(r[:state], 9)

        if page == 1
          crashes_str = if r[:saved_crashes] > 0
                          "#{BOLD}#{RED}#{format('%8d', r[:saved_crashes])}#{RESET}"
                        else
                          format("%8d", 0)
                        end

          hangs_str = if r[:saved_hangs] > 0
                        "#{BOLD}#{YELLOW}#{format('%6d', r[:saved_hangs])}#{RESET}"
                      else
                        format("%6d", 0)
                      end

          edges_str = if r[:total_edges] > 0
                        "#{format_int(r[:edges_found])} / #{format_int(r[:total_edges])}"
                      else
                        "-"
                      end

          out << format(
            "%-#{name_width}s %s %-#{sched_width}s %12s %8s %17s %s %s\n",
            r[:name],
            state_str,
            r[:sched],
            "#{format_int(r[:execs_per_sec].round)}/s",
            r[:bitmap_cvg],
            edges_str,
            crashes_str,
            hangs_str
          )
        else
          last_find_str = if r[:last_find] > 0 && now >= r[:last_find]
                            "#{format_duration(now - r[:last_find])} ago"
                          else
                            "-"
                          end

          shared_count = contribs[:shared][r[:name]] || 0
          desc_count = contribs[:descendants][r[:name]] || 0

          out << format(
            "%-#{name_width}s %s %-#{sched_width}s %12s %14s %6d %8s %8s %11s %14s %8s %8s\n",
            r[:name],
            state_str,
            r[:sched],
            "#{format_int(r[:execs_per_sec].round)}/s",
            format_int(r[:execs_done]),
            r[:cycles_done],
            format_int(r[:corpus_count]),
            format_int(shared_count),
            format_int(desc_count),
            last_find_str,
            format_int(r[:pending_total]),
            format_int(r[:pending_favs])
          )
        end
      end

      out << ("-" * header.length) << "\n"

      if gen_rows.any?
        gen_header = if page == 1
                       format(
                         "%-#{name_width}s %-9s %-#{sched_width}s %12s %8s %17s %8s %6s",
                         "GENERATOR", "STATE", "MODE", "FILES/S", "CREATED", "PENDING", "CRASHES", "PRUNED"
                       )
                     else
                       format(
                         "%-#{name_width}s %-9s %-#{sched_width}s %12s %14s %6s %8s %8s %11s %14s %8s %8s",
                         "GENERATOR", "STATE", "MODE", "FILES/S", "ATTEMPTS", "UNIQ %",
                         "CREATED", "SHARED", "DESCENDANTS", "LAST FIND", "PENDING", "PRUNED"
                       )
                     end
        out << "\n#{BOLD}#{gen_header}#{RESET}\n"
        out << ("-" * gen_header.length) << "\n"

        gen_rows.each do |g|
          state_str = state_badge(g[:state], 9)
          pend_raw = format("%17s", "#{format_int(g[:pending_files])} / #{format_int(g[:max_pending_files])}")
          pend_str = g[:pending_files] >= g[:max_pending_files] ? "#{YELLOW}#{pend_raw}#{RESET}" : pend_raw
          crashes_str = if g[:saved_crashes] > 0
                          "#{BOLD}#{RED}#{format('%8d', g[:saved_crashes])}#{RESET}"
                        else
                          format("%8d", 0)
                        end

          if page == 1
            out << format(
              "%-#{name_width}s %s %-#{sched_width}s %12s %8s %s %s %6s\n",
              g[:name],
              state_str,
              g[:sched],
              format_rate(g[:files_per_sec]),
              format_fit(g[:files_created], 8),
              pend_str,
              crashes_str,
              format_fit(g[:files_pruned], 6)
            )
          else
            last_find_str = if g[:last_find] > 0 && now >= g[:last_find]
                              "#{format_duration(now - g[:last_find])} ago"
                            else
                              "-"
                            end
            uniq_pct = g[:attempts_done] > 0 ? format("%.1f%%", g[:files_created] * 100.0 / g[:attempts_done]) : "-"
            shared_count = contribs[:shared][g[:name]] || 0
            desc_count = contribs[:descendants][g[:name]] || 0

            out << format(
              "%-#{name_width}s %s %-#{sched_width}s %12s %14s %6s %8s %8s %11s %14s %8s %8s\n",
              g[:name],
              state_str,
              g[:sched],
              format_rate(g[:files_per_sec]),
              format_fit(g[:attempts_done], 14),
              uniq_pct,
              format_fit(g[:files_created], 8),
              format_fit(shared_count, 8),
              format_fit(desc_count, 11),
              last_find_str,
              format_fit(g[:pending_files], 8),
              format_fit(g[:files_pruned], 8)
            )
          end
        end
        out << ("-" * gen_header.length) << "\n"
      end

      out << "#{DIM}[Tab/Space/1/2] Switch page   [Ctrl+B, w] Fuzzer window   [Ctrl+B, n/p] Next/Prev   [Ctrl+B, 0] Dashboard   [Ctrl+B, d] Detach   [Ctrl+C] Stop all#{RESET}\n"
      $stdout.write(out)
      $stdout.flush
    rescue Errno::EPIPE
      exit 0
    end

    def run_cli(argv = ARGV)
      default_topo = defined?(PrismFuzzer::Topology) ? PrismFuzzer::Topology.discover : nil
      afl_dir = argv[0] || (default_topo ? PrismFuzzer::Topology.workspace_paths(default_topo)[:afl_dir] : "./tmp/fuzz/afl")
      expected_fuzzers = argv[1..] || []
      ctx = build_context(afl_dir)

      if $stdin.tty?
        system("stty -icanon -echo 2>/dev/null")
      end
      $stdout.write("\e[?25l")
      at_exit do
        if $stdin.tty?
          system("stty icanon echo 2>/dev/null")
        end
        begin
          $stdout.write("\e[?25h\n")
          $stdout.flush
        rescue Errno::EPIPE
          nil
        end
      end

      Signal.trap("INT") { exit(0) }
      Signal.trap("TERM") { exit(0) }

      started_at = Time.now.to_i
      script_mtime = File.mtime(__FILE__)
      page = 1
      contribs = { shared: Hash.new(0), descendants: Hash.new(0) }
      last_contrib_update = 0
      stdin_open = !$stdin.closed?

      loop do
        if File.exist?(__FILE__) && File.mtime(__FILE__) != script_mtime
          exec(RbConfig.ruby, __FILE__, *argv)
        end
        now = Time.now.to_i
        if page == 2 && (now - last_contrib_update >= 15)
          contribs = compute_contributions(afl_dir, ctx: ctx)
          last_contrib_update = Time.now.to_i
        end
        render(afl_dir, expected_fuzzers, started_at, page, contribs, ctx: ctx)
        if stdin_open
          if IO.select([$stdin], nil, nil, 1.0)
            begin
              key = $stdin.read_nonblock(16)
              case key
              when "1"
                page = 1
              when "2"
                page = 2
              when "\t", " ", "\e[C", "\e[D", "h", "l", "n", "p"
                page = page == 1 ? 2 : 1
              end
            rescue IO::WaitReadable
              # ignore
            rescue EOFError, IOError, Errno::EBADF
              stdin_open = false
              sleep 1.0
            end
          end
        else
          sleep 1.0
        end
      end
    end
  end
end

if __FILE__ == $PROGRAM_NAME && ENV["STATUS_LIB_ONLY"] != "1"
  PrismFuzzer::Status.run_cli(ARGV)
end
