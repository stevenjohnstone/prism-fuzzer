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

    # Captures resolved topology metadata once per report invocation without global constants.
    def topology_context(topo)
      has_topo_mod = defined?(PrismFuzzer::Topology)
      {
        topology: topo,
        aliases: has_topo_mod ? PrismFuzzer::Topology.sync_aliases(topo) : { "seeds" => "grammar" },
        order: has_topo_mod ? PrismFuzzer::Topology.worker_order(topo) : [],
        colors: has_topo_mod ? PrismFuzzer::Topology.worker_colors(topo) : {}
      }
    end
  end
end
