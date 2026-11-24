# frozen_string_literal: true

require "cgi/escape"
require "time"
require_relative "helpers"
require_relative "stats_ingest"
require_relative "charts"
require_relative "lineage"
require_relative "topology_view"
require_relative "triage_view"
require_relative "coverage_view"

module PrismFuzzerReport
  module PageRenderer
    REPORT_CSS = File.read(File.expand_path("assets/report.css", __dir__)).freeze
    REPORT_JS = File.read(File.expand_path("assets/report.js", __dir__)).freeze

    module_function

    def render_peer_sync_rows(fleet)
      main_name = fleet[:main_name]
      worker_by_name = fleet[:worker_by_name] || {}
      rows = fleet[:sync_rows] || fleet[:fuzzers].filter_map { |f| fleet[:peer_sync_by_name][f[:name]] }
      rows.filter_map do |ps|
        f = ps[:source_fuzzer] || worker_by_name[ps[:source_name]]
        next unless f

        consumer = ps[:consumer_name] || main_name
        alias_label = ps[:peer_alias] && !ps[:peer_alias].empty? ? ps[:peer_alias] : "#{f[:name]}_peer"
        total = [ps[:peer_total], 1].max.to_f
        imp_w = (ps[:imported_by_main] * 100.0 / total).round(2)
        rej_w = (ps[:rejected_by_main] * 100.0 / total).round(2)
        skp_w = (ps[:skipped_from_main] * 100.0 / total).round(2)
        uns_w = [100.0 - imp_w - rej_w - skp_w, 0.0].max.round(2)
        tip = case ps[:sync_mode]
              when :foreign_seeds
                "#{f[:name]} → #{consumer} (-F foreign seeds, created: #{Helpers.format_int(ps[:peer_total])}) — " \
                "Tested by #{consumer}: #{Helpers.format_int(ps[:tested_by_main])} (#{format('%.1f%%', ps[:sync_pct])}) | " \
                "Imported by #{consumer}: #{Helpers.format_int(ps[:imported_by_main])} (#{format('%.2f%%', ps[:yield_pct])} of tested) | " \
                "Rejected by #{consumer}: #{Helpers.format_int(ps[:rejected_by_main])} | " \
                "Pending backlog: #{Helpers.format_int(ps[:unsynced_backlog])}"
              when :foreign_queue
                "#{f[:name]} → #{consumer} (-F foreign queue: #{Helpers.format_int(ps[:peer_total])}) — " \
                "Scanned (mtime watermark): #{Helpers.format_int(ps[:cursor])} (#{format('%.1f%%', ps[:sync_pct])}) | " \
                "Tested by #{consumer}: #{Helpers.format_int(ps[:tested_by_main])} | " \
                "Imported by #{consumer}: #{Helpers.format_int(ps[:imported_by_main])} (#{format('%.2f%%', ps[:yield_pct])} of tested) | " \
                "Rejected by #{consumer}: #{Helpers.format_int(ps[:rejected_by_main])} | " \
                "Unsynced backlog: #{Helpers.format_int(ps[:unsynced_backlog])}"
              when :shadow_peer
                "#{f[:name]} → #{consumer} (#{consumer}/.synced/#{alias_label}, queue: #{Helpers.format_int(ps[:peer_total])}) — " \
                "Cursor: #{Helpers.format_int(ps[:cursor])} (#{format('%.1f%%', ps[:sync_pct])}) | " \
                "Tested by #{consumer}: #{Helpers.format_int(ps[:tested_by_main])} | " \
                "Imported by #{consumer}: #{Helpers.format_int(ps[:imported_by_main])} (#{format('%.2f%%', ps[:yield_pct])} of tested) | " \
                "Rejected by #{consumer}: #{Helpers.format_int(ps[:rejected_by_main])} | " \
                "Unsynced backlog: #{Helpers.format_int(ps[:unsynced_backlog])}"
              else
                "#{f[:name]} → #{consumer} (#{consumer}/.synced/#{f[:name]}, queue: #{Helpers.format_int(ps[:peer_total])}) — " \
                "Cursor: #{Helpers.format_int(ps[:cursor])} (#{format('%.1f%%', ps[:sync_pct])}) | " \
                "Tested by #{consumer}: #{Helpers.format_int(ps[:tested_by_main])} | " \
                "Imported by #{consumer}: #{Helpers.format_int(ps[:imported_by_main])} (#{format('%.2f%%', ps[:yield_pct])} of tested) | " \
                "Rejected by #{consumer}: #{Helpers.format_int(ps[:rejected_by_main])} | " \
                "Skipped (sync:#{consumer}): #{Helpers.format_int(ps[:skipped_from_main])} | " \
                "Unsynced backlog: #{Helpers.format_int(ps[:unsynced_backlog])}"
              end
        route_suffix = if ps[:sync_mode] == :foreign_seeds || ps[:sync_mode] == :foreign_queue
                         " (-F)"
                       elsif ps[:sync_mode] == :shadow_peer
                         " (peer)"
                       else
                         ""
                       end
        <<~HTML
          <div class="sync-row" title="#{CGI.escapeHTML(tip)}" onclick="selectTab(#{Helpers.topo_js_arg(f[:name])})">
            <div class="sync-peer">
              <span class="legend-dot" style="background:#{f[:color]}"></span>
              <strong>#{CGI.escapeHTML(f[:name])}</strong>
              <span class="muted" style="font-size:0.75rem;font-weight:400">&rarr; #{CGI.escapeHTML(consumer)}#{route_suffix}</span>
            </div>
            <div class="sync-bar-wrap">
              <div class="sync-bar">
                <div class="sync-seg sync-seg-imported" style="width:#{imp_w}%"></div>
                <div class="sync-seg sync-seg-rejected" style="width:#{rej_w}%"></div>
                <div class="sync-seg sync-seg-skipped" style="width:#{skp_w}%"></div>
                <div class="sync-seg sync-seg-unsynced" style="width:#{uns_w}%"></div>
              </div>
            </div>
            <div class="sync-stat">
              <span class="sync-primary">#{Helpers.format_int(ps[:cursor])} / #{Helpers.format_int(ps[:peer_total])}</span>
              <span class="sync-pct">(#{format("%.0f%%", ps[:sync_pct])})</span>
            </div>
            <div class="sync-stat">
              <span class="sync-imported">+#{Helpers.format_int(ps[:imported_by_main])}</span>
              <span class="sync-secondary">/ #{Helpers.format_int(ps[:tested_by_main])} tested (#{format("%.1f%%", ps[:yield_pct])})</span>
            </div>
          </div>
        HTML
      end.join("\n")
    end

    def render_peer_sync_card(fleet)
      rows = fleet[:sync_rows] || fleet[:peer_sync_by_name].values
      return "" unless rows.any?

      main_name = fleet[:main_name]
      by_consumer = rows.group_by { |ps| ps[:consumer_name] || main_name }
      ordered_consumers = ([main_name] + by_consumer.keys).uniq.select { |c| by_consumer.key?(c) }
      consumer_summaries = ordered_consumers.map do |cname|
        list = by_consumer[cname]
        tested = list.sum { |ps| ps[:tested_by_main] }
        imported = list.sum { |ps| ps[:imported_by_main] }
        backlog = list.sum { |ps| ps[:unsynced_backlog] }
        yld = tested > 0 ? (imported * 100.0 / tested) : 0.0
        "into <code>#{CGI.escapeHTML(cname)}</code>: <strong>+#{Helpers.format_int(imported)}</strong> imported / " \
          "<strong>#{Helpers.format_int(tested)}</strong> tested = <strong>#{format('%.2f%%', yld)}</strong> yield, " \
          "<strong>#{Helpers.format_int(backlog)}</strong> unsynced backlog"
      end.join("; ")
      synced_path_hint = ordered_consumers.size == 1 ? "#{CGI.escapeHTML(ordered_consumers.first)}/.synced/&lt;peer&gt;" : "&lt;master&gt;/.synced/&lt;peer&gt;"
      skipped_legend = ordered_consumers.size == 1 ? "Skipped (sync:#{CGI.escapeHTML(ordered_consumers.first)})" : "Skipped (from consumer)"
      <<~HTML
        <div class="chart-card sync-overview-card">
          <div class="chart-header">
            <div>
              <h3>Queue &amp; Foreign Sync Snapshot</h3>
              <p class="chart-sub">How far each source has been scanned by its consumer via foreign sync (<code>-F</code>) or peer sync (<code>#{synced_path_hint}</code>), and how many inputs yielded novel coverage vs. were rejected or skipped (#{consumer_summaries})</p>
            </div>
            <div class="chart-legend">
              <span class="legend-item"><span class="legend-dot" style="background:#34d399"></span><span class="legend-name">Imported (Novel)</span></span>
              <span class="legend-item"><span class="legend-dot" style="background:#3b82f6"></span><span class="legend-name">Tested &amp; Rejected</span></span>
              <span class="legend-item"><span class="legend-dot" style="background:#475569"></span><span class="legend-name">#{skipped_legend}</span></span>
              <span class="legend-item"><span class="legend-dot" style="background:#1e293b;border:1px solid #475569"></span><span class="legend-name">Unsynced Backlog</span></span>
            </div>
          </div>
          <div class="sync-rows-head">
            <div>Source &rarr; Consumer</div>
            <div>Sync Breakdown</div>
            <div style="text-align:right">Scanned / Total</div>
            <div style="text-align:right">Imported / Tested (Yield)</div>
          </div>
          <div class="sync-rows">
            #{render_peer_sync_rows(fleet)}
          </div>
        </div>
      HTML
    end

    def render_summary_rows(fleet, cov_info)
      peer_sync_by_name = fleet[:peer_sync_by_name]
      cov_worker_pairs = cov_info[:cov_worker_pairs]
      cov_pairs_by_id = cov_info[:cov_pairs_by_id]
      multi_master = Array(fleet[:group_masters]).size > 1

      fleet[:afl_fuzzers].map do |f|
        ps = peer_sync_by_name[f[:name]]
        wpairs = CoverageView.resolve_worker_pairs(f[:name], cov_worker_pairs, cov_pairs_by_id)
        src_cov_cell, rep_cell = CoverageView.render_worker_cov_overview_cells(wpairs)
        edges_str = f[:total_edges] > 0 ? "#{Helpers.format_int(f[:edges_found])} / #{Helpers.format_int(f[:total_edges])}" : Helpers.format_int(f[:edges_found])
        crash_cls = f[:saved_crashes] > 0 ? "badge-danger" : "badge-muted"
        hang_cls = f[:saved_hangs] > 0 ? "badge-warn" : "badge-muted"
        if ps
          via = multi_master ? " <span class=\"muted\">&rarr; #{CGI.escapeHTML(ps[:consumer_name].to_s)}</span>" : ""
          main_sync_cell = "#{Helpers.format_int(ps[:cursor])} / #{Helpers.format_int(ps[:peer_total])} <span class=\"muted\">(#{format('%.0f%%', ps[:sync_pct])})</span>#{via}"
          main_yield_cell = "<strong>+#{Helpers.format_int(ps[:imported_by_main])}</strong> / #{Helpers.format_int(ps[:tested_by_main])} <span class=\"muted\">(#{format('%.1f%%', ps[:yield_pct])})</span>"
        else
          main_sync_cell = "<span class=\"muted\">hub</span>"
          main_yield_cell = "<span class=\"muted\">&mdash;</span>"
        end
        <<~HTML
          <tr class="clickable-row" onclick="selectTab(#{Helpers.topo_js_arg(f[:name])})">
            <td>
              <span class="legend-dot" style="background:#{f[:color]}"></span>
              <strong>#{CGI.escapeHTML(f[:name])}</strong>
            </td>
            <td><code>#{CGI.escapeHTML(File.basename(f[:banner]))}</code></td>
            <td><span class="sched-pill">#{CGI.escapeHTML(f[:sched])}</span></td>
            <td class="num">#{Helpers.format_int(f[:execs_per_sec].round)}/s</td>
            <td class="num">#{Helpers.format_compact(f[:execs_done])}</td>
            <td class="num"><strong>#{format("%.2f%%", f[:bitmap_cvg])}</strong></td>
            <td class="num">#{edges_str}</td>
            <td class="num">#{src_cov_cell}</td>
            <td class="num">#{Helpers.format_int(f[:corpus_count])}</td>
            <td class="num">#{Helpers.format_int(f[:corpus_found])}</td>
            <td class="num">#{Helpers.format_int(f[:corpus_imported])}</td>
            <td class="num">#{main_sync_cell}</td>
            <td class="num">#{main_yield_cell}</td>
            <td class="num">#{Helpers.format_int(f[:pending_favs])} / #{Helpers.format_int(f[:pending_total])}</td>
            <td class="num"><span class="badge #{crash_cls}">#{f[:saved_crashes]}</span></td>
            <td class="num"><span class="badge #{hang_cls}">#{f[:saved_hangs]}</span></td>
            <td class="num">#{rep_cell}</td>
          </tr>
        HTML
      end.join("\n")
    end

    def render_generator_table(fleet, cov_info)
      gen_fuzzers = fleet[:gen_fuzzers]
      return "" unless gen_fuzzers.any?

      peer_sync_by_name = fleet[:peer_sync_by_name]
      cov_worker_pairs = cov_info[:cov_worker_pairs]
      cov_pairs_by_id = cov_info[:cov_pairs_by_id]

      gen_rows = gen_fuzzers.map do |gf|
        ps = peer_sync_by_name[gf[:name]]
        wpairs = CoverageView.resolve_worker_pairs(gf[:name], cov_worker_pairs, cov_pairs_by_id)
        src_cov_cell, rep_cell = CoverageView.render_worker_cov_overview_cells(wpairs)
        yield_cell = if ps
                       "<strong>+#{Helpers.format_int(ps[:imported_by_main])}</strong> / #{Helpers.format_int(ps[:tested_by_main])} <span class=\"muted\">(#{format('%.1f%%', ps[:yield_pct])} into #{CGI.escapeHTML(ps[:intake_name])})</span>"
                     else
                       "<span class=\"muted\">&mdash;</span>"
                     end
        <<~ROW
          <tr class="clickable-row" onclick="selectTab(#{Helpers.topo_js_arg(gf[:name])})">
            <td>
              <span class="legend-dot" style="background:#{gf[:color]}"></span>
              <strong>#{CGI.escapeHTML(gf[:name])}</strong>
            </td>
            <td><code>#{CGI.escapeHTML(File.basename(gf[:banner]))}</code></td>
            <td><span class="sched-pill">#{CGI.escapeHTML(gf[:sched])}</span></td>
            <td class="num">#{Helpers.format_compact(gf[:files_per_sec])} files/s</td>
            <td class="num">#{Helpers.format_compact(gf[:avg_files_per_sec])} files/s</td>
            <td class="num">#{Helpers.format_int(gf[:pending_files])} <span class="muted">/ #{Helpers.format_int(gf[:max_pending_files])}</span></td>
            <td class="num">#{Helpers.format_int(gf[:files_created])}</td>
            <td class="num">#{Helpers.format_int(gf[:files_pruned])}</td>
            <td class="num">#{Helpers.format_int(gf[:duplicates_skipped])}</td>
            <td class="num">#{yield_cell}</td>
            <td class="num">#{src_cov_cell}</td>
            <td class="num">#{rep_cell}</td>
          </tr>
        ROW
      end.join("\n")

      <<~GEN_TABLE
        <div class="table-card" style="margin-top: 18px;">
          <table>
            <thead>
              <tr>
                <th>Seed Generator</th>
                <th>Engine</th>
                <th>Mode</th>
                <th class="num">Rate</th>
                <th class="num">Avg Rate</th>
                <th class="num">Pending</th>
                <th class="num">Created</th>
                <th class="num">Pruned</th>
                <th class="num">Duplicates</th>
                <th class="num">Foreign Sync Yield (-F)</th>
                <th class="num">Source Coverage</th>
                <th class="num">Report</th>
              </tr>
            </thead>
            <tbody>
              #{gen_rows}
            </tbody>
          </table>
        </div>
      GEN_TABLE
    end

    def render_nav_tabs(fleet, topo:, triage_view:, sankey_sec:, cov_info:)
      tab_buttons_html = +%(<button class="tab-btn active" data-tab="overview" onclick="selectTab('overview')">Fleet Overview (#{fleet[:fuzzers].size})</button>\n)
      if topo
        tab_buttons_html << <<~HTML
          <button class="tab-btn" data-tab="topology" onclick="selectTab('topology')">
            <span class="legend-dot" style="background:#38bdf8"></span>
            Topology
          </button>
        HTML
      end
      if triage_view
        tab_buttons_html << <<~HTML
          <button class="tab-btn" data-tab="triage" onclick="selectTab('triage')">
            <span class="legend-dot" style="background:#fb7185"></span>
            Triage (#{triage_view[:clusters].size})
          </button>
        HTML
      end
      if sankey_sec
        tab_buttons_html << <<~HTML
          <button class="tab-btn" data-tab="sankey" onclick="selectTab('sankey')">
            <span class="legend-dot" style="background:#a78bfa"></span>
            Triage Sankey (#{sankey_sec[:cluster_count]})
          </button>
        HTML
      end
      primary_cov_pair = cov_info[:primary_cov_pair]
      active_cov_pairs = cov_info[:active_cov_pairs]
      if primary_cov_pair
        cov_tab_suffix = if active_cov_pairs.size > 1
                           "#{active_cov_pairs.size} Pairs"
                         else
                           format("%.2f%%", primary_cov_pair.dig("totals", "lines", "percent").to_f)
                         end
        tab_buttons_html << <<~HTML
          <button class="tab-btn" data-tab="coverage" onclick="selectTab('coverage')">
            <span class="legend-dot" style="background:#34d399"></span>
            Source Coverage (#{CGI.escapeHTML(cov_tab_suffix)})
          </button>
        HTML
      end
      tab_buttons_html
    end

    def render_worker_nav(fleet)
      fuzzers = fleet[:fuzzers]
      return "" unless fuzzers.any?

      afl_fuzzers = fleet[:afl_fuzzers]
      gen_fuzzers = fleet[:gen_fuzzers]

      afl_worker_options = afl_fuzzers.map do |f|
        c_suffix = f[:saved_crashes] > 0 ? " • #{f[:saved_crashes]}c" : ""
        label = "#{f[:name]} (#{f[:sched]}#{c_suffix})"
        %(<option value="#{CGI.escapeHTML(f[:name])}" data-color="#{CGI.escapeHTML(f[:color])}">#{CGI.escapeHTML(label)}</option>)
      end.join("\n")

      gen_worker_options = gen_fuzzers.map do |gf|
        label = "#{gf[:name]} (#{gf[:sched]} • generator)"
        %(<option value="#{CGI.escapeHTML(gf[:name])}" data-color="#{CGI.escapeHTML(gf[:color])}">#{CGI.escapeHTML(label)}</option>)
      end.join("\n")

      groups_html = +""
      groups_html << %(<optgroup label="AFL++ Fuzzers (#{afl_fuzzers.size})">\n#{afl_worker_options}\n</optgroup>\n) if afl_fuzzers.any?
      groups_html << %(<optgroup label="Seed Generators (#{gen_fuzzers.size})">\n#{gen_worker_options}\n</optgroup>\n) if gen_fuzzers.any?

      <<~HTML
        <div class="worker-nav" id="worker-nav-wrap">
          <span class="legend-dot" id="worker-nav-dot" style="background:#64748b"></span>
          <select id="worker-tab-select" class="worker-select" aria-label="Select individual worker tab" onchange="if (this.value) selectTab(this.value);">
            <option value="">Inspect worker (#{fuzzers.size})…</option>
            #{groups_html}
          </select>
          <button type="button" class="worker-step-btn" onclick="stepWorkerTab(-1)" title="Previous worker">&lsaquo;</button>
          <button type="button" class="worker-step-btn" onclick="stepWorkerTab(1)" title="Next worker">&rsaquo;</button>
        </div>
      HTML
    end

    def render_generator_panel(gf, fleet:, fleet_lineage:, cov_info:, topo_ctx:)
      name = gf[:name]
      safe_name = CGI.escapeHTML(name)
      cmd_line = gf[:stats]["command_line"] || ""
      ps = fleet[:peer_sync_by_name][name]
      intake = ps ? ps[:intake_fuzzer] : fleet[:main_fuzzer]
      intake_name = intake[:name]
      imp_prefix = intake[:origins][:by_source][name] || []
      intake_points = intake[:samples].map { |r| [r[:relative_time], StatsIngest.lookup_prefix(imp_prefix, r[:corpus_count])] }
      unique_pct = gf[:attempts_done] > 0 ? (gf[:files_created] * 100.0 / gf[:attempts_done]) : 100.0
      gen_charts = Charts.render_generator_charts(gf, intake_name: intake_name, intake_points: intake_points)
      gen_wpairs = CoverageView.resolve_worker_pairs(name, cov_info[:cov_worker_pairs], cov_info[:cov_pairs_by_id])
      gen_cov_btn = CoverageView.render_worker_cov_banner_buttons(gen_wpairs)

      gen_lin = (fleet_lineage[:by_generator] && fleet_lineage[:by_generator][name]) || fleet_lineage
      sync_kpi = if ps
                   <<~SYNC_KPI
                     <div class="kpi-card">
                       <div class="kpi-label">Imported by #{CGI.escapeHTML(intake_name)}</div>
                       <div class="kpi-value">+#{Helpers.format_int(ps[:imported_by_main])} <span class="muted">(#{format("%.1f%%", ps[:yield_pct])})</span></div>
                       <div class="kpi-sub">#{Helpers.format_int(gen_lin[:total_grammar_queue_items])} fleet queue items &bull; #{Helpers.format_int(gen_lin[:total_grammar_crashes])} crashes (#{gen_lin[:unique_grammar_crash_seeds]} seeds)</div>
                     </div>
                   SYNC_KPI
                 else
                   ""
                 end

      <<~HTML
        <section id="tab-#{safe_name}" class="tab-panel">
          <div class="fuzzer-banner">
            <div>
              <h2><span class="legend-dot" style="background:#{gf[:color]}"></span> #{safe_name}</h2>
              <p class="cmd-line"><code>#{CGI.escapeHTML(cmd_line)}</code></p>
            </div>
            <div class="fuzzer-meta">
              <span class="sched-pill">Role: Seed Generator (#{CGI.escapeHTML(gf[:sched])})</span>
              <span class="sched-pill">Runtime: #{Helpers.format_duration(gf[:run_time])}</span>
              <span class="sched-pill">Samples: #{Helpers.format_int(gf[:sample_count])}</span>
              #{gen_cov_btn}
            </div>
          </div>

          <div class="kpi-grid">
            <div class="kpi-card">
              <div class="kpi-label">Files Created</div>
              <div class="kpi-value">#{Helpers.format_int(gf[:files_created])}</div>
              <div class="kpi-sub">#{format("%.1f%%", unique_pct)} unique of #{Helpers.format_int(gf[:attempts_done])} generated (#{Helpers.format_int(gf[:duplicates_skipped])} dup)</div>
            </div>
            <div class="kpi-card">
              <div class="kpi-label">File Creation Rate</div>
              <div class="kpi-value">#{Helpers.format_compact(gf[:files_per_sec])} files/s</div>
              <div class="kpi-sub">avg #{Helpers.format_compact(gf[:avg_files_per_sec])} files/s over #{Helpers.format_duration(gf[:run_time])}</div>
            </div>
            <div class="kpi-card">
              <div class="kpi-label">Valid / Invalid Split</div>
              <div class="kpi-value">#{Helpers.format_int(gf[:files_valid])} / #{Helpers.format_int(gf[:files_invalid])}</div>
              <div class="kpi-sub">valid vs. mutated/invalid Ruby seeds</div>
            </div>
            #{sync_kpi}
          </div>

          <div class="charts-grid">
            #{gen_charts}
          </div>

          #{Lineage.render_grammar_lineage_section(fleet_lineage, fleet[:color_by_name], generator_name: name, topo_ctx: topo_ctx)}
        </section>
      HTML
    end

    def render_fuzzer_panel(f, fleet:, fleet_lineage:, cov_info:, topo_ctx:)
      name = f[:name]
      safe_name = CGI.escapeHTML(name)
      cmd_line = f[:stats]["command_line"] || ""
      main_name = fleet[:main_name]
      main_fuzzer = fleet[:main_fuzzer]
      peer_sync_by_name = fleet[:peer_sync_by_name]
      color_by_name = fleet[:color_by_name]

      sync_src_series = StatsIngest.fuzzer_sync_source_series(f, color_by_name: color_by_name, topo_ctx: topo_ctx)
      fuzzer_charts = Charts.render_fuzzer_charts(f, sync_source_series: sync_src_series)
      wpairs = CoverageView.resolve_worker_pairs(name, cov_info[:cov_worker_pairs], cov_info[:cov_pairs_by_id])
      worker_cov_btn = CoverageView.render_worker_cov_banner_buttons(wpairs)

      upstream_gen_entry = peer_sync_by_name.find { |_gn, gps| gps[:is_generator] && gps[:consumer_name] == name }
      sync_kpis = if (ps = peer_sync_by_name[name])
                    consumer_name = ps[:consumer_name] || main_name
                    consumer_fuzzer = ps[:consumer_fuzzer] || (fleet[:worker_by_name] && fleet[:worker_by_name][consumer_name]) || main_fuzzer
                    safe_consumer = CGI.escapeHTML(consumer_name)
                    if ps[:sync_mode] == :foreign_queue || ps[:sync_mode] == :shadow_peer
                      intake_kpi = if upstream_gen_entry
                                     gen_name, gen_ps = upstream_gen_entry
                                     <<~INTAKE_KPI
                                       <div class="kpi-card">
                                         <div class="kpi-label">Intake from #{CGI.escapeHTML(gen_name)} (-F)</div>
                                         <div class="kpi-value">+#{Helpers.format_int(gen_ps[:imported_by_main])} <span class="muted">(#{format("%.1f%%", gen_ps[:yield_pct])})</span></div>
                                         <div class="kpi-sub">#{Helpers.format_int(gen_ps[:tested_by_main])} seeds tested &bull; standalone master (-M)</div>
                                       </div>
                                     INTAKE_KPI
                                   else
                                     <<~INTAKE_KPI
                                       <div class="kpi-card">
                                         <div class="kpi-label">Sync Role</div>
                                         <div class="kpi-value">Master (-M)</div>
                                         <div class="kpi-sub">sync group master (bridges to #{safe_consumer})</div>
                                       </div>
                                     INTAKE_KPI
                                   end
                      sync_to_label = ps[:sync_mode] == :shadow_peer ? "Sync to #{safe_consumer}" : "Foreign Sync to #{safe_consumer} (-F)"
                      cursor_word = ps[:sync_mode] == :shadow_peer ? "cursor" : "scanned"
                      <<~SYNC_KPI
                        <div class="kpi-card">
                          <div class="kpi-label">#{sync_to_label}</div>
                          <div class="kpi-value">+#{Helpers.format_int(ps[:imported_by_main])} <span class="muted">(#{format("%.1f%%", ps[:yield_pct])})</span></div>
                          <div class="kpi-sub">#{Helpers.format_int(ps[:tested_by_main])} tested &bull; #{cursor_word} #{Helpers.format_int(ps[:cursor])}/#{Helpers.format_int(ps[:peer_total])} (#{format("%.0f%%", ps[:sync_pct])})</div>
                        </div>
                        #{intake_kpi}
                      SYNC_KPI
                    else
                      <<~SYNC_KPI
                        <div class="kpi-card">
                          <div class="kpi-label">Sync to #{safe_consumer}</div>
                          <div class="kpi-value">+#{Helpers.format_int(ps[:imported_by_main])} <span class="muted">(#{format("%.1f%%", ps[:yield_pct])})</span></div>
                          <div class="kpi-sub">#{Helpers.format_int(ps[:tested_by_main])} tested &bull; cursor #{Helpers.format_int(ps[:cursor])}/#{Helpers.format_int(ps[:peer_total])} (#{format("%.0f%%", ps[:sync_pct])})</div>
                        </div>
                        <div class="kpi-card">
                          <div class="kpi-label">Sync from #{safe_consumer}</div>
                          <div class="kpi-value">#{format("%.0f%%", ps[:peer_from_main_pct])}</div>
                          <div class="kpi-sub">cursor #{Helpers.format_int(ps[:peer_from_main_cursor])} / #{Helpers.format_int(consumer_fuzzer[:corpus_count])} in #{safe_consumer}</div>
                        </div>
                      SYNC_KPI
                    end
                  elsif upstream_gen_entry
                    gen_name, gen_ps = upstream_gen_entry
                    <<~INTAKE_KPI
                      <div class="kpi-card">
                        <div class="kpi-label">Intake from #{CGI.escapeHTML(gen_name)} (-F)</div>
                        <div class="kpi-value">+#{Helpers.format_int(gen_ps[:imported_by_main])} <span class="muted">(#{format("%.1f%%", gen_ps[:yield_pct])})</span></div>
                        <div class="kpi-sub">#{Helpers.format_int(gen_ps[:tested_by_main])} seeds tested &bull; primary hub master (-M)</div>
                      </div>
                    INTAKE_KPI
                  else
                    ""
                  end

      worker_paths = (fleet_lineage[:pathways] || []).select { |p| p[:hops].include?(name) }
      lineage_html = if worker_paths.any?
                       direct_cnt = worker_paths.select { |p| p[:crash_worker] == name }.sum { |p| p[:count] }
                       assist_cnt = worker_paths.reject { |p| p[:crash_worker] == name }.sum { |p| p[:count] }
                       Lineage.render_crash_lineage_table(
                         worker_paths,
                         worker_paths.sum { |p| p[:count] },
                         color_by_name,
                         id_prefix: "w-lineage-#{name.gsub(/[^a-zA-Z0-9_-]/, '_')}",
                         title: "Crash Lineage Involving <code>#{safe_name}</code> (#{Helpers.format_int(direct_cnt)} Direct Crashes &bull; #{Helpers.format_int(assist_cnt)} Forwarded to Peers)",
                         subtitle: "Pathways where #{safe_name} either discovered the crash directly or mutated/forwarded an ancestor queue item that later crashed in another worker.",
                         topo_ctx: topo_ctx
                       )
                     else
                       ""
                     end

      <<~HTML
        <section id="tab-#{safe_name}" class="tab-panel">
          <div class="fuzzer-banner">
            <div>
              <h2><span class="legend-dot" style="background:#{f[:color]}"></span> #{safe_name}</h2>
              <p class="cmd-line"><code>#{CGI.escapeHTML(cmd_line)}</code></p>
            </div>
            <div class="fuzzer-meta">
              <span class="sched-pill">Schedule: #{CGI.escapeHTML(f[:sched])}</span>
              <span class="sched-pill">Stability: #{CGI.escapeHTML(f[:stability])}</span>
              <span class="sched-pill">Samples: #{Helpers.format_int(f[:sample_count])}</span>
              #{worker_cov_btn}
            </div>
          </div>

          <div class="kpi-grid">
            <div class="kpi-card">
              <div class="kpi-label">AFL++ Map Coverage</div>
              <div class="kpi-value">#{format("%.2f%%", f[:bitmap_cvg])}</div>
              <div class="kpi-sub">#{Helpers.format_int(f[:edges_found])}#{f[:total_edges] > 0 ? " / #{Helpers.format_int(f[:total_edges])}" : ""} edges</div>
            </div>
            <div class="kpi-card">
              <div class="kpi-label">Throughput</div>
              <div class="kpi-value">#{Helpers.format_int(f[:execs_per_sec].round)}/s</div>
              <div class="kpi-sub">#{Helpers.format_compact(f[:execs_done])} total execs</div>
            </div>
            <div class="kpi-card">
              <div class="kpi-label">Corpus Queue</div>
              <div class="kpi-value">#{Helpers.format_int(f[:corpus_count])}</div>
              <div class="kpi-sub">+#{Helpers.format_int(f[:corpus_found])} local, #{Helpers.format_int(f[:corpus_imported])} synced</div>
            </div>
            <div class="kpi-card">
              <div class="kpi-label">Pending (Fav / Total)</div>
              <div class="kpi-value">#{Helpers.format_int(f[:pending_favs])}</div>
              <div class="kpi-sub">of #{Helpers.format_int(f[:pending_total])} unfuzzed</div>
            </div>
            <div class="kpi-card">
              <div class="kpi-label">Cycles / Max Depth</div>
              <div class="kpi-value">#{f[:cycles_done]}</div>
              <div class="kpi-sub">max depth #{f[:max_depth]}</div>
            </div>
            <div class="kpi-card">
              <div class="kpi-label">Crashes / Hangs</div>
              <div class="kpi-value #{f[:saved_crashes] > 0 ? 'text-danger' : ''}">#{f[:saved_crashes]} / #{f[:saved_hangs]}</div>
              <div class="kpi-sub"> Peak RSS: #{f[:stats]['peak_rss_mb'] || '-'} MB</div>
            </div>
            #{sync_kpis}
          </div>

          <div class="charts-grid">
            #{fuzzer_charts}
          </div>

          #{lineage_html}
        </section>
      HTML
    end

    def render_page(afl_dir:, title:, triage_dir:, fleet:, fleet_lineage:, triage_view:, cov_info:, topo_ctx:)
      topo = topo_ctx[:topology]
      topo_colors = topo_ctx[:colors]
      sankey_sec = triage_view && triage_view[:sankey_sec]
      active_cov_pairs = cov_info[:active_cov_pairs]
      main_fuzzer = fleet[:main_fuzzer]
      gen_fuzzers = fleet[:gen_fuzzers]

      gen_import_series = gen_fuzzers.map do |gf|
        ps = fleet[:peer_sync_by_name][gf[:name]]
        intake = ps ? ps[:intake_fuzzer] : main_fuzzer
        imp_prefix = intake[:origins][:by_source][gf[:name]] || []
        {
          name: "#{gf[:name]} -> #{intake[:name]}",
          color: "#34d399",
          points: intake[:samples].map { |r| [r[:relative_time], StatsIngest.lookup_prefix(imp_prefix, r[:corpus_count])] }
        }
      end
      overview_charts = Charts.render_overview_charts(fleet, gen_import_series: gen_import_series)

      topology_overview_html = if topo
                                 TopologyView.render_topology_overview_card(
                                   topo,
                                   diagram_svg: TopologyView.render_topology_diagram_svg(
                                     topo,
                                     worker_by_name: fleet[:worker_by_name],
                                     color_by_name: fleet[:color_by_name],
                                     peer_sync_by_name: fleet[:peer_sync_by_name],
                                     peer_import_stats: fleet[:peer_import_stats] || {},
                                     id_prefix: "ov-topo",
                                     topo_colors: topo_colors
                                   )
                                 )
                               else
                                 ""
                               end

      tab_buttons_html = render_nav_tabs(fleet, topo: topo, triage_view: triage_view, sankey_sec: sankey_sec, cov_info: cov_info)
      worker_nav_html = render_worker_nav(fleet)

      tab_panels_html = +""
      if topo
        tab_panels_html << TopologyView.render_topology_tab_html(
          topo,
          diagram_svg: TopologyView.render_topology_diagram_svg(
            topo,
            worker_by_name: fleet[:worker_by_name],
            color_by_name: fleet[:color_by_name],
            peer_sync_by_name: fleet[:peer_sync_by_name],
            peer_import_stats: fleet[:peer_import_stats] || {},
            id_prefix: "tab-topo",
            topo_colors: topo_colors
          )
        )
      end
      if triage_view
        tab_panels_html << TriageView.render_triage_tab_html(
          triage_view,
          triage_dir: triage_dir,
          has_sankey: !sankey_sec.nil?
        )
      end
      tab_panels_html << CoverageView.render_coverage_tab_html(cov_info) if active_cov_pairs.any?
      if sankey_sec
        tab_panels_html << <<~HTML
          <section id="tab-sankey" class="tab-panel">
            #{triage_view ? '<div style="margin-bottom:12px;"><button class="cov-btn cov-btn-secondary" type="button" onclick="selectTab(\'triage\')">&larr; View Triage Clusters &amp; Reproducers</button></div>' : ""}
            #{sankey_sec[:html]}
          </section>
        HTML
      end

      fleet[:fuzzers].each do |f|
        tab_panels_html << if f[:role] == :generator
                             render_generator_panel(f, fleet: fleet, fleet_lineage: fleet_lineage, cov_info: cov_info, topo_ctx: topo_ctx)
                           else
                             render_fuzzer_panel(f, fleet: fleet, fleet_lineage: fleet_lineage, cov_info: cov_info, topo_ctx: topo_ctx)
                           end
      end

      cov_header_btns = if active_cov_pairs.any?
                          btns = active_cov_pairs.filter_map do |p|
                            href = p["report_rel_path"].to_s
                            next nil if href.empty?

                            lbl = active_cov_pairs.size > 1 ? "#{CGI.escapeHTML(p['label'].to_s)} llvm-cov" : "llvm-cov HTML"
                            %(<a class="cov-btn" href="#{CGI.escapeHTML(href)}" target="_blank" rel="noopener">#{lbl} &nearr;</a>)
                          end.join(" ")
                          btns.empty? ? "" : %(<div class="fuzzer-meta">#{btns}</div>)
                        else
                          ""
                        end

      gen_kpi_html = if gen_fuzzers.any?
                       gen_total_files = gen_fuzzers.sum { |gf| gf[:files_created] }
                       gen_total_rate = gen_fuzzers.sum { |gf| gf[:files_per_sec] }
                       <<~GEN_KPI
                         <div class="kpi-card">
                           <div class="kpi-label">Grammar Seeds</div>
                           <div class="kpi-value">#{Helpers.format_int(gen_total_files)}</div>
                           <div class="kpi-sub">#{Helpers.format_compact(gen_total_rate)} files/s</div>
                         </div>
                       GEN_KPI
                     else
                       ""
                     end

      triage_kpi_html = if triage_view
                          tc = triage_view[:clusters].size
                          tb = triage_view[:summary]["bucket_count"] || triage_view[:clusters].sum { |c| c["bucket_count"].to_i }
                          <<~TRI_KPI
                            <div class="kpi-card clickable-row" onclick="selectTab('triage')">
                              <div class="kpi-label">Triage Clusters</div>
                              <div class="kpi-value">#{Helpers.format_int(tc)}</div>
                              <div class="kpi-sub">#{Helpers.format_int(tb)} deduplicated bucket#{tb == 1 ? '' : 's'}</div>
                            </div>
                          TRI_KPI
                        else
                          ""
                        end

      report_title = title || "Prism Fuzzing Report"
      peer_sync_card_html = render_peer_sync_card(fleet)
      summary_rows_html = render_summary_rows(fleet, cov_info)
      generator_table_html = render_generator_table(fleet, cov_info)
      overview_crash_lineage_html = Lineage.render_overview_crash_lineage(fleet_lineage, fleet[:color_by_name], topo_ctx: topo_ctx)

      <<~HTML
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1" />
          <title>#{CGI.escapeHTML(report_title)}</title>
          <style>
            #{REPORT_CSS}
            #{sankey_sec ? sankey_sec[:styles] : ""}
          </style>
        </head>
        <body>
          <header>
            <div class="header-top">
              <div class="header-title">
                <h1>#{CGI.escapeHTML(report_title)}</h1>
                <span class="header-sub">Source: <code>#{CGI.escapeHTML(afl_dir)}</code> &bull; Runtime: #{Helpers.format_duration(fleet[:fleet_max_runtime])} &bull; Generated: #{Time.now.strftime("%Y-%m-%d %H:%M:%S")}</span>
              </div>
              #{cov_header_btns}
            </div>
            <nav class="tabs-bar">
              <div class="tabs-primary">
                #{tab_buttons_html}
              </div>
              #{worker_nav_html}
            </nav>
          </header>

          <main>
            <section id="tab-overview" class="tab-panel active">
              <div class="kpi-grid">
                <div class="kpi-card">
                  <div class="kpi-label">Fuzzer Workers</div>
                  <div class="kpi-value">#{fleet[:afl_fuzzers].size}</div>
                  <div class="kpi-sub">Uptime #{Helpers.format_duration(fleet[:fleet_max_runtime])}</div>
                </div>
                <div class="kpi-card">
                  <div class="kpi-label">Fleet Speed</div>
                  <div class="kpi-value">#{Helpers.format_int(fleet[:fleet_speed].round)}/s</div>
                  <div class="kpi-sub">#{Helpers.format_compact(fleet[:fleet_execs])} total execs</div>
                </div>
                <div class="kpi-card">
                  <div class="kpi-label">#{main_fuzzer[:name] == "main" ? "Main Coverage" : "Hub Coverage (#{CGI.escapeHTML(main_fuzzer[:name])})"}</div>
                  <div class="kpi-value">#{format("%.2f%%", main_fuzzer[:bitmap_cvg])}</div>
                  <div class="kpi-sub">#{Helpers.format_int(main_fuzzer[:edges_found])} / #{Helpers.format_int(main_fuzzer[:total_edges])} edges</div>
                </div>
                <div class="kpi-card">
                  <div class="kpi-label">Max Queue Size</div>
                  <div class="kpi-value">#{Helpers.format_int(fleet[:fleet_max_corpus])}</div>
                  <div class="kpi-sub">across AFL++ workers</div>
                </div>
                #{gen_kpi_html}
                <div class="kpi-card">
                  <div class="kpi-label">Saved Crashes</div>
                  <div class="kpi-value #{fleet[:fleet_crashes] > 0 ? 'text-danger' : ''}">#{fleet[:fleet_crashes]}</div>
                  <div class="kpi-sub">#{fleet_lineage[:total_grammar_crashes]} grammar &bull; #{fleet_lineage[:total_corpus_crashes]} corpus &bull; #{fleet[:fleet_hangs]} hangs</div>
                </div>
                #{triage_kpi_html}
                #{CoverageView.render_overview_cov_kpi_cards(active_cov_pairs)}
              </div>

              #{topology_overview_html}

              <div class="charts-grid">
                #{overview_charts}
              </div>

              #{peer_sync_card_html}

              <div class="table-card">
                <table>
                  <thead>
                    <tr>
                      <th>Fuzzer</th>
                      <th>Binary</th>
                      <th>Schedule</th>
                      <th class="num">Speed</th>
                      <th class="num">Total Execs</th>
                      <th class="num">Map %</th>
                      <th class="num">Edges</th>
                      <th class="num">Source Coverage</th>
                      <th class="num">Corpus</th>
                      <th class="num">Local Finds</th>
                      <th class="num">Synced</th>
                      <th class="num">#{Array(fleet[:group_masters]).size > 1 ? "Master Sync" : "Main Sync"}</th>
                      <th class="num">#{Array(fleet[:group_masters]).size > 1 ? "Master Yield (Imp / Tested)" : "Main Yield (Imp / Tested)"}</th>
                      <th class="num">Pending (Fav/All)</th>
                      <th class="num">Crashes</th>
                      <th class="num">Hangs</th>
                      <th class="num">Report</th>
                    </tr>
                  </thead>
                  <tbody>
                    #{summary_rows_html}
                  </tbody>
                </table>
              </div>

              #{generator_table_html}
              #{overview_crash_lineage_html}
            </section>

            #{tab_panels_html}
          </main>

          <script>
            #{REPORT_JS}
            #{sankey_sec ? sankey_sec[:script] : ""}
          </script>
        </body>
        </html>
      HTML
    end
  end
end
