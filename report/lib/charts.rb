# frozen_string_literal: true

require "cgi/escape"
require "digest"
require "json"
require_relative "helpers"

module PrismFuzzerReport
  module Charts
    module_function

    def downsample(rows, max_points = 350)
      return rows if rows.size <= max_points

      step = (rows.size - 1).to_f / (max_points - 1)
      (0...max_points).map { |i| rows[(i * step).round] }.uniq { |r| r[:relative_time] }
    end

    def nice_ceil(val)
      return 1.0 if val <= 0

      exp = Math.log10(val).floor
      f = val / (10.0**exp)
      nf = if f <= 1.0
             1.0
           elsif f <= 2.0
             2.0
           elsif f <= 2.5
             2.5
           elsif f <= 5.0
             5.0
           else
             10.0
           end
      nf * (10.0**exp)
    end

    # Renders an interactive SVG time-series chart card with XSS-safe gradient IDs and tooltips.
    def render_svg_chart(title:, subtitle:, series:, y_format: :compact, fill_area: false, zero_base: true, chart_id: nil)
      width = 580
      height = 270
      pad_l = 62
      pad_r = 22
      pad_t = 22
      pad_b = 40
      plot_w = width - pad_l - pad_r
      plot_h = height - pad_t - pad_b

      non_empty = series.reject { |s| s[:points].empty? }
      if non_empty.empty?
        return <<~HTML
          <div class="chart-card">
            <div class="chart-header">
              <div>
                <h3>#{CGI.escapeHTML(title)}</h3>
                <p class="chart-sub">#{CGI.escapeHTML(subtitle)}</p>
              </div>
            </div>
            <div class="empty-chart">No plot_data samples recorded yet</div>
          </div>
        HTML
      end

      all_x = non_empty.flat_map { |s| s[:points].map { |p| p[0] } }
      all_y = non_empty.flat_map { |s| s[:points].map { |p| p[1] } }

      min_x = all_x.min.to_f
      max_x = all_x.max.to_f
      max_x = min_x + 1.0 if (max_x - min_x).abs < 1e-9

      raw_min_y = zero_base ? [0.0, all_y.min.to_f].min : all_y.min.to_f
      raw_max_y = all_y.max.to_f

      if (raw_max_y - raw_min_y).abs < 1e-9
        min_y = zero_base ? 0.0 : raw_min_y - 1.0
        max_y = raw_max_y + (raw_max_y.zero? ? 1.0 : raw_max_y.abs * 0.1)
      elsif zero_base
        min_y = 0.0
        max_y = nice_ceil(raw_max_y * 1.05)
      else
        span = raw_max_y - raw_min_y
        min_y = [0.0, raw_min_y - span * 0.08].max
        max_y = raw_max_y + span * 0.08
      end

      format_y = lambda do |v|
        case y_format
        when :percent
          format("%.2f%%", v).sub(/\.00%$/, "%")
        when :int
          Helpers.format_int(v.round)
        when :rate
          "#{Helpers.format_compact(v)}/s"
        when :file_rate
          "#{Helpers.format_compact(v)} files/s"
        else
          Helpers.format_compact(v)
        end
      end

      x_to_px = ->(x) { pad_l + ((x - min_x) / (max_x - min_x)) * plot_w }
      y_to_px = ->(y) { pad_t + plot_h - ((y - min_y) / (max_y - min_y)) * plot_h }

      y_ticks = 4
      grid_svg = +""
      (0..y_ticks).each do |i|
        val = min_y + ((max_y - min_y) * i / y_ticks.to_f)
        py = y_to_px.call(val).round(2)
        grid_svg << %(<line x1="#{pad_l}" y1="#{py}" x2="#{width - pad_r}" y2="#{py}" class="grid-line" />\n)
        grid_svg << %(<text x="#{pad_l - 8}" y="#{py + 4}" text-anchor="end" class="axis-label">#{CGI.escapeHTML(format_y.call(val))}</text>\n)
      end

      x_ticks = 5
      (0..x_ticks).each do |i|
        val = min_x + ((max_x - min_x) * i / x_ticks.to_f)
        px = x_to_px.call(val).round(2)
        grid_svg << %(<line x1="#{px}" y1="#{pad_t + plot_h}" x2="#{px}" y2="#{pad_t + plot_h + 5}" class="axis-tick" />\n)
        grid_svg << %(<text x="#{px}" y="#{height - 12}" text-anchor="middle" class="axis-label">#{CGI.escapeHTML(Helpers.format_duration(val))}</text>\n)
      end

      defs_svg = +""
      paths_svg = +""
      legend_html = +""

      safe_chart_id = if chart_id.to_s =~ /\A[A-Za-z0-9_.-]+\z/
                        chart_id.to_s
                      else
                        "#{chart_id.to_s.gsub(/[^A-Za-z0-9_.-]+/, '-').sub(/\A-+|-+\z/, '')}-#{Digest::SHA256.hexdigest(chart_id.to_s)[0, 8]}"
                      end

      non_empty.each_with_index do |s, idx|
        color = s[:color] || Helpers::PALETTE[idx % Helpers::PALETTE.size]
        safe_s_name = CGI.escapeHTML(s[:name])
        pts = s[:points]
        coords = pts.map { |x, y| [x_to_px.call(x).round(2), y_to_px.call(y).round(2)] }
        line_d = coords.each_with_index.map { |(px, py), i| "#{i.zero? ? 'M' : 'L'}#{px},#{py}" }.join(" ")
        paths_svg << %(<g class="series-group" data-series-name="#{safe_s_name}">\n)

        if fill_area && coords.size >= 2
          grad_id = "grad-#{safe_chart_id}-#{idx}"
          defs_svg << <<~SVG
            <linearGradient id="#{grad_id}" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stop-color="#{color}" stop-opacity="0.28" />
              <stop offset="100%" stop-color="#{color}" stop-opacity="0.02" />
            </linearGradient>
          SVG
          base_y = (pad_t + plot_h).round(2)
          area_d = "#{line_d} L#{coords.last[0]},#{base_y} L#{coords.first[0]},#{base_y} Z"
          paths_svg << %(<path d="#{area_d}" fill="url(##{grad_id})" class="series-area" />\n)
        end

        stroke_w = non_empty.size > 4 ? 1.8 : 2.2
        paths_svg << %(<path d="#{line_d}" fill="none" stroke="#{color}" stroke-width="#{stroke_w}" stroke-linecap="round" stroke-linejoin="round" class="series-line" />\n)
        paths_svg << %(<path d="#{line_d}" fill="none" stroke="transparent" stroke-width="14" stroke-linecap="round" stroke-linejoin="round" class="series-hit" data-series-name="#{safe_s_name}"><title>#{safe_s_name}</title></path>\n)

        last_x, last_y = coords.last
        last_val = pts.last[1]
        paths_svg << %(<circle cx="#{last_x}" cy="#{last_y}" r="3.2" fill="#{color}" class="series-dot" />\n)
        paths_svg << %(</g>\n)

        legend_html << <<~HTML
          <span class="legend-item" data-series-name="#{safe_s_name}">
            <span class="legend-dot" style="background:#{color}"></span>
            <span class="legend-name">#{safe_s_name}</span>
            <span class="legend-val">#{CGI.escapeHTML(format_y.call(last_val))}</span>
          </span>
        HTML
      end

      series_json = non_empty.each_with_index.map do |s, idx|
        {
          name: s[:name],
          color: s[:color] || Helpers::PALETTE[idx % Helpers::PALETTE.size],
          points: s[:points].map { |x, y| [x, y.round(2), format_y.call(y), y_to_px.call(y).round(2)] }
        }
      end.to_json

      <<~HTML
        <div class="chart-card" data-series="#{CGI.escapeHTML(series_json)}" data-min-x="#{min_x}" data-max-x="#{max_x}" data-pad-l="#{pad_l}" data-plot-w="#{plot_w}">
          <div class="chart-header">
            <div>
              <h3>#{CGI.escapeHTML(title)}</h3>
              <p class="chart-sub">#{CGI.escapeHTML(subtitle)}</p>
            </div>
            <div class="chart-legend">#{legend_html}</div>
          </div>
          <div class="svg-wrap">
            <svg viewBox="0 0 #{width} #{height}" preserveAspectRatio="none" class="plot-svg">
              <defs>#{defs_svg}</defs>
              #{grid_svg}
              #{paths_svg}
              <line x1="0" y1="#{pad_t}" x2="0" y2="#{pad_t + plot_h}" class="hover-line" style="display:none" />
              <circle cx="0" cy="0" r="5" class="hover-dot" style="display:none" />
            </svg>
            <div class="line-badge" style="display:none"></div>
            <div class="chart-tooltip" style="display:none"></div>
          </div>
        </div>
      HTML
    end

    def render_overview_charts(fleet, gen_import_series:)
      afl_fuzzers = fleet[:afl_fuzzers]
      gen_fuzzers = fleet[:gen_fuzzers]

      chart_specs = [
        {
          title: "Edge Coverage (%)",
          subtitle: "Percentage of instrumented CFG edges reached over time (map_size)",
          y_format: :percent,
          zero_base: false,
          chart_id: "ov-cvg",
          field: :map_size
        },
        {
          title: "Edges Discovered",
          subtitle: "Absolute number of edges hit in each worker's coverage map (edges_found)",
          y_format: :int,
          zero_base: false,
          chart_id: "ov-edges",
          field: :edges_found
        },
        {
          title: "Corpus Size Growth",
          subtitle: "Total interesting inputs in queue per worker (corpus_count)",
          y_format: :compact,
          zero_base: true,
          chart_id: "ov-corpus",
          field: :corpus_count
        },
        {
          title: "Execution Throughput (execs/sec)",
          subtitle: "Instantaneous execution speed across workers",
          y_format: :rate,
          zero_base: true,
          chart_id: "ov-speed",
          field: :execs_per_sec
        },
        {
          title: "Cumulative Executions",
          subtitle: "Total target executions completed per worker (total_execs)",
          y_format: :compact,
          zero_base: true,
          chart_id: "ov-execs",
          field: :total_execs
        },
        {
          title: "Pending Favored Queue",
          subtitle: "Unfuzzed favored entries remaining per worker (pending_favs)",
          y_format: :compact,
          zero_base: true,
          chart_id: "ov-favs",
          field: :pending_favs
        },
        {
          title: "Synced Queue Items (Foreign Imports)",
          subtitle: "Cumulative queue entries imported from other fuzzers over time (sync:<source>)",
          y_format: :compact,
          zero_base: true,
          chart_id: "ov-synced",
          field: :synced_count
        },
        {
          title: "Locally Discovered Queue Items",
          subtitle: "Cumulative queue entries discovered by each worker's own mutations (excluding initial seeds & syncs)",
          y_format: :compact,
          zero_base: true,
          chart_id: "ov-local",
          field: :local_count
        }
      ]

      list = chart_specs.map do |spec|
        render_svg_chart(
          title: spec[:title],
          subtitle: spec[:subtitle],
          y_format: spec[:y_format],
          zero_base: spec[:zero_base],
          chart_id: spec[:chart_id],
          series: afl_fuzzers.map do |f|
            { name: f[:name], color: f[:color], points: f[:samples].map { |r| [r[:relative_time], r[spec[:field]]] } }
          end
        )
      end

      if gen_fuzzers.any?
        list << render_svg_chart(
          title: "Grammar Seeds Imported (-F)",
          subtitle: "Cumulative grammar-generated seeds imported into the fuzzer queue via foreign sync",
          y_format: :int,
          fill_area: true,
          zero_base: true,
          chart_id: "ov-gen-imports",
          series: gen_import_series
        )
        list << render_svg_chart(
          title: "Grammar File Creation Rate (files/sec)",
          subtitle: "Seed file creation rate over time (rolling and cumulative average)",
          y_format: :file_rate,
          zero_base: true,
          chart_id: "ov-gen-rate",
          series: gen_fuzzers.flat_map do |gf|
            [
              { name: "#{gf[:name]} (files/s)", color: gf[:color], points: gf[:samples].map { |r| [r[:relative_time], r[:files_per_sec]] } },
              { name: "#{gf[:name]} (avg)", color: "#38bdf8", points: gf[:samples].map { |r| [r[:relative_time], r[:avg_files_per_sec]] } }
            ]
          end
        )
      end

      list.join("\n")
    end

    def render_generator_charts(gf, intake_name:, intake_points:)
      s = gf[:samples]
      name = gf[:name]
      [
        render_svg_chart(
          title: "Cumulative Files Created",
          subtitle: "Unique seed files written to disk vs. total generation attempts",
          y_format: :compact,
          fill_area: true,
          zero_base: true,
          chart_id: "#{name}-files",
          series: [
            { name: "files_created", color: gf[:color], points: s.map { |r| [r[:relative_time], r[:files_created]] } },
            { name: "attempts_done", color: "#9ca3af", points: s.map { |r| [r[:relative_time], r[:attempts_done]] } }
          ]
        ),
        render_svg_chart(
          title: "File Creation Rate (files/sec)",
          subtitle: "Seed file creation rate over time (rolling interval and cumulative average)",
          y_format: :file_rate,
          fill_area: true,
          zero_base: true,
          chart_id: "#{name}-rate",
          series: [
            { name: "files_per_sec", color: "#a78bfa", points: s.map { |r| [r[:relative_time], r[:files_per_sec]] } },
            { name: "avg_files_per_sec", color: "#38bdf8", points: s.map { |r| [r[:relative_time], r[:avg_files_per_sec]] } }
          ]
        ),
        render_svg_chart(
          title: "Valid vs. Invalid Generated Files",
          subtitle: "Breakdown of syntactically valid vs. error-injected Ruby seeds created",
          y_format: :compact,
          fill_area: false,
          zero_base: true,
          chart_id: "#{name}-validity",
          series: [
            { name: "files_valid", color: "#34d399", points: s.map { |r| [r[:relative_time], r[:files_valid]] } },
            { name: "files_invalid", color: "#fbbf24", points: s.map { |r| [r[:relative_time], r[:files_invalid]] } }
          ]
        ),
        render_svg_chart(
          title: "Imports into #{intake_name} Queue",
          subtitle: "Cumulative #{name} seed files imported by #{intake_name} via -F foreign sync",
          y_format: :compact,
          fill_area: true,
          zero_base: true,
          chart_id: "#{name}-imports",
          series: [
            {
              name: "imported_by_#{intake_name}",
              color: "#34d399",
              points: intake_points
            }
          ]
        )
      ].join("\n")
    end

    def render_fuzzer_charts(f, sync_source_series:)
      s = f[:samples]
      name = f[:name]
      [
        render_svg_chart(
          title: "Coverage & Edges Discovered",
          subtitle: "Instrumented edges reached (#{f[:total_edges] > 0 ? "out of #{Helpers.format_int(f[:total_edges])} total" : 'edges_found'})",
          y_format: :int,
          fill_area: true,
          zero_base: false,
          chart_id: "#{name}-edges",
          series: [{ name: "edges_found", color: f[:color], points: s.map { |r| [r[:relative_time], r[:edges_found]] } }]
        ),
        render_svg_chart(
          title: "Map Density (%)",
          subtitle: "Bitmap coverage percentage over time (map_size)",
          y_format: :percent,
          fill_area: true,
          zero_base: false,
          chart_id: "#{name}-map",
          series: [{ name: "map_size", color: "#38bdf8", points: s.map { |r| [r[:relative_time], r[:map_size]] } }]
        ),
        render_svg_chart(
          title: "Queue & Pending Corpus",
          subtitle: "Total queue size vs. pending unfuzzed and pending favored items",
          y_format: :compact,
          fill_area: false,
          zero_base: true,
          chart_id: "#{name}-corpus",
          series: [
            { name: "corpus_count", color: "#34d399", points: s.map { |r| [r[:relative_time], r[:corpus_count]] } },
            { name: "pending_total", color: "#fbbf24", points: s.map { |r| [r[:relative_time], r[:pending_total]] } },
            { name: "pending_favs", color: "#f472b6", points: s.map { |r| [r[:relative_time], r[:pending_favs]] } }
          ]
        ),
        render_svg_chart(
          title: "Queue Origin Breakdown (Local vs. Synced)",
          subtitle: "Total queue split into locally mutated finds, foreign synced imports, and initial seeds",
          y_format: :compact,
          fill_area: false,
          zero_base: true,
          chart_id: "#{name}-origins",
          series: [
            { name: "corpus_count", color: "#9ca3af", points: s.map { |r| [r[:relative_time], r[:corpus_count]] } },
            { name: "local_finds", color: "#34d399", points: s.map { |r| [r[:relative_time], r[:local_count]] } },
            { name: "synced_imports", color: "#60a5fa", points: s.map { |r| [r[:relative_time], r[:synced_count]] } },
            { name: "initial_seeds", color: "#fbbf24", points: s.map { |r| [r[:relative_time], r[:seed_count]] } }
          ]
        ),
        render_svg_chart(
          title: "Synced Imports by Source Fuzzer",
          subtitle: "Which foreign fuzzers contributed synced queue entries to #{name} over time",
          y_format: :compact,
          fill_area: false,
          zero_base: true,
          chart_id: "#{name}-sync-src",
          series: sync_source_series
        ),
        render_svg_chart(
          title: "Execution Speed (execs/sec)",
          subtitle: "Target executions per second over time",
          y_format: :rate,
          fill_area: true,
          zero_base: true,
          chart_id: "#{name}-speed",
          series: [{ name: "execs_per_sec", color: "#a78bfa", points: s.map { |r| [r[:relative_time], r[:execs_per_sec]] } }]
        ),
        render_svg_chart(
          title: "Cumulative Executions",
          subtitle: "Total executions completed by #{name}",
          y_format: :compact,
          fill_area: true,
          zero_base: true,
          chart_id: "#{name}-execs",
          series: [{ name: "total_execs", color: "#60a5fa", points: s.map { |r| [r[:relative_time], r[:total_execs]] } }]
        ),
        render_svg_chart(
          title: "Crashes, Hangs & Queue Depth",
          subtitle: "Saved crashes, saved hangs, cycles done, and max mutation depth",
          y_format: :int,
          fill_area: false,
          zero_base: true,
          chart_id: "#{name}-findings",
          series: [
            { name: "saved_crashes", color: "#fb7185", points: s.map { |r| [r[:relative_time], r[:saved_crashes]] } },
            { name: "saved_hangs", color: "#fbbf24", points: s.map { |r| [r[:relative_time], r[:saved_hangs]] } },
            { name: "max_depth", color: "#38bdf8", points: s.map { |r| [r[:relative_time], r[:max_depth]] } },
            { name: "cycles_done", color: "#4ade80", points: s.map { |r| [r[:relative_time], r[:cycles_done]] } }
          ]
        )
      ].join("\n")
    end
  end
end
