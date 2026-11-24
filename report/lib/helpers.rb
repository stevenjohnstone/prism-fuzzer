# frozen_string_literal: true

require "cgi/escape"
require "json"

module PrismFuzzerReport
  class InputError < StandardError; end

  module Helpers
    PLOT_COLUMNS = %i[
      relative_time
      cycles_done
      cur_item
      corpus_count
      pending_total
      pending_favs
      map_size
      saved_crashes
      saved_hangs
      max_depth
      execs_per_sec
      total_execs
      edges_found
      total_crashes
      servers_count
    ].freeze

    PALETTE = [
      "#60a5fa", # blue
      "#34d399", # emerald
      "#f472b6", # pink
      "#fbbf24", # amber
      "#a78bfa", # purple
      "#38bdf8", # sky
      "#fb7185", # rose
      "#4ade80", # green
      "#f97316", # orange
      "#2dd4bf", # teal
      "#e879f9", # fuchsia
      "#facc15"  # yellow
    ].freeze

    module_function

    # Encodes a string as an HTML-escaped JSON string literal for inline JS handlers.
    def topo_js_arg(str)
      CGI.escapeHTML(JSON.generate(str.to_s))
    end

    def format_int(num)
      num.to_i.to_s.reverse.gsub(/(\d{3})(?=\d)/, '\\1,').reverse
    end

    def format_compact(num)
      n = num.to_f
      return "0" if n.zero?

      if n.abs >= 1_000_000_000
        format("%.2fB", n / 1_000_000_000.0).sub(/\.?0+B$/, "B")
      elsif n.abs >= 1_000_000
        format("%.2fM", n / 1_000_000.0).sub(/\.?0+M$/, "M")
      elsif n.abs >= 10_000
        format("%.1fK", n / 1_000.0).sub(/\.?0+K$/, "K")
      elsif n == n.to_i
        format_int(n.to_i)
      else
        format("%.2f", n).sub(/\.?0+$/, "")
      end
    end

    def format_duration(seconds)
      seconds = seconds.to_i
      return "0s" if seconds <= 0

      hours = seconds / 3600
      mins = (seconds % 3600) / 60
      secs = seconds % 60

      if hours > 0
        format("%dh %02dm", hours, mins)
      elsif mins > 0
        format("%dm %02ds", mins, secs)
      else
        format("%ds", secs)
      end
    end

    def build_grammar_lookup(topo)
      gens_by_id = {}
      if topo.is_a?(Hash) && topo["generators"].is_a?(Hash)
        topo["generators"].each do |gid, gspec|
          next unless gspec.is_a?(Hash) && gspec["kind"].to_s == "grammar"

          gens_by_id[gid.to_s] = {
            gid: gid.to_s,
            seeds_dir: gspec["seeds_dir"] || "/tmp/afl-tmpdir/#{gid}/seeds",
            schedule: gspec["schedule"] || "lrama"
          }
        end
      end

      generators = {}
      if topo.is_a?(Hash) && topo["workers"].is_a?(Array)
        topo["workers"].each do |w|
          next unless w.is_a?(Hash) && w["kind"].to_s == "generator"

          gid = w["generator"].to_s
          gcfg = gens_by_id[gid]
          next unless gcfg

          wid = w["id"].to_s
          generators[wid] = gcfg.merge(worker_id: wid)
        end
      end

      gens_by_id.each do |gid, gcfg|
        next if generators.values.any? { |entry| entry[:gid] == gid }

        generators[gid] = gcfg.merge(worker_id: gid)
      end

      consumer_grammar_workers = {}
      if topo.is_a?(Hash) && topo["workers"].is_a?(Array)
        worker_by_gid = generators.values.each_with_object({}) { |cfg, h| h[cfg[:gid]] = cfg[:worker_id] }
        topo["workers"].each do |w|
          next unless w.is_a?(Hash) && w["kind"].to_s != "generator"

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
      grammar_workers = (["grammar"] + generators.keys).uniq

      {
        generators: generators,
        grammar_workers: grammar_workers,
        consumer_grammar_workers: consumer_grammar_workers,
        seed_basename_workers: seed_basename_workers
      }
    end

    def grammar_worker?(name, topo_ctx: nil)
      s = name.to_s
      return true if s == "grammar"

      gw = topo_ctx && topo_ctx[:grammar_workers]
      gw ? gw.include?(s) : false
    end

    def resolve_grammar_sync_worker(consumer_worker, sync_tag, topo_ctx: nil)
      tag = sync_tag.to_s
      return nil if tag.empty?

      generators = (topo_ctx && topo_ctx[:generators]) || {}
      consumer_map = (topo_ctx && topo_ctx[:consumer_grammar_workers]) || {}
      basename_map = (topo_ctx && topo_ctx[:seed_basename_workers]) || {}

      return basename_map[tag] if basename_map.key?(tag)

      stripped = tag.sub(/_\d+\z/, "")
      return basename_map[stripped] if basename_map.key?(stripped)
      return tag if generators.key?(tag)

      if (matched = generators.values.find { |cfg| cfg[:gid] == tag || cfg[:gid] == stripped })
        return matched[:worker_id]
      end

      if tag =~ /\A(?:grammar|seeds)(?:_(\d+))?\z/
        idx = Regexp.last_match(1)&.to_i || 0
        f_gens = consumer_worker ? consumer_map[consumer_worker.to_s] : nil
        return (f_gens[idx] || f_gens.first) if f_gens && !f_gens.empty?
        return generators.keys.first if generators.size == 1

        return "grammar"
      end

      nil
    end

    # Captures resolved topology metadata once per report invocation without global constants.
    def topology_context(topo)
      has_topo_mod = defined?(PrismFuzzer::Topology)
      gram = build_grammar_lookup(topo)
      {
        topology: topo,
        aliases: has_topo_mod ? PrismFuzzer::Topology.sync_aliases(topo) : { "seeds" => "grammar" },
        order: has_topo_mod ? PrismFuzzer::Topology.worker_order(topo) : [],
        colors: has_topo_mod ? PrismFuzzer::Topology.worker_colors(topo) : {},
        generators: gram[:generators],
        grammar_workers: gram[:grammar_workers],
        consumer_grammar_workers: gram[:consumer_grammar_workers],
        seed_basename_workers: gram[:seed_basename_workers]
      }
    end
  end
end
