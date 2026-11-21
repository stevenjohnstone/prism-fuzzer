# frozen_string_literal: true

require "cgi/escape"
require "json"
require "pathname"
require_relative "helpers"
require_relative "../../runtime/common"

module PrismFuzzerReport
  module CoverageView
    module_function

    def ingest_coverage(cov_json_path:, out_dir_abs:, fuzzers:, topo_ctx: nil)
      coverage_data = PrismFuzzer::Common.read_json(cov_json_path, context: "CoverageView")
      coverage_data = nil unless coverage_data.is_a?(Hash)

      cov_pairs = []
      cov_pairs_by_id = {}
      cov_worker_pairs = {}
      if coverage_data
        if coverage_data["pairs"].is_a?(Array) && !coverage_data["pairs"].empty?
          cov_pairs = coverage_data["pairs"]
          cov_worker_pairs = coverage_data["worker_pairs"].is_a?(Hash) ? coverage_data["worker_pairs"] : {}
        elsif (legacy_totals = coverage_data.dig("data", 0, "totals") || coverage_data["totals"])
          cov_pairs = [
            {
              "id" => "default__native",
              "label" => "prism (native)",
              "source" => "prism",
              "target" => "native",
              "target_label" => "native",
              "has_coverage" => true,
              "report_rel_path" => "../coverage/report/index.html",
              "lcov_rel_path" => "../coverage/lcov.info",
              "summary_rel_path" => "../coverage/summary.txt",
              "file_report_prefix" => "../coverage/report/coverage/",
              "totals" => legacy_totals,
              "files" => coverage_data.dig("data", 0, "files") || []
            }
          ]
        end
      end

      topo = topo_ctx && topo_ctx[:topology]
      if cov_worker_pairs.empty? && topo && defined?(PrismFuzzer::Topology)
        cov_worker_pairs = PrismFuzzer::Topology.worker_coverage_pairs(topo)
      end

      cov_pairs.each { |p| cov_pairs_by_id[p["id"].to_s] = p }
      if cov_worker_pairs.empty? && cov_pairs.size == 1
        only_pid = cov_pairs.first["id"].to_s
        fuzzers.each { |f| cov_worker_pairs[f[:name]] = [only_pid] }
      end

      cov_dir_abs = File.expand_path(File.dirname(cov_json_path))
      normalize_cov_rel = lambda do |raw_rel|
        s = raw_rel.to_s
        return nil if s.empty?

        sub = if (idx = s.index("pairs/")) && (idx.zero? || s[idx - 1] == "/")
                s[idx..]
              elsif s.start_with?("coverage/")
                s.delete_prefix("coverage/")
              elsif s.start_with?("../coverage/")
                s.delete_prefix("../coverage/")
              end
        return s unless sub

        rel = Pathname.new(File.join(cov_dir_abs, sub)).relative_path_from(out_dir_abs).to_s
        s.end_with?("/") && !rel.end_with?("/") ? "#{rel}/" : rel
      end

      cov_pairs.each do |p|
        %w[report_rel_path lcov_rel_path summary_rel_path file_report_prefix].each do |k|
          p[k] = normalize_cov_rel.call(p[k]) if p[k]
        end
        Array(p["files"]).each do |fe|
          fe["report_rel_path"] = normalize_cov_rel.call(fe["report_rel_path"]) if fe.is_a?(Hash) && fe["report_rel_path"]
        end
      end

      active_cov_pairs = cov_pairs.select { |p| p["has_coverage"] }
      primary_cov_pair = active_cov_pairs.find { |p| p["id"] == coverage_data&.dig("primary_pair_id") } || active_cov_pairs.first

      {
        coverage_data: coverage_data,
        cov_pairs: cov_pairs,
        cov_pairs_by_id: cov_pairs_by_id,
        cov_worker_pairs: cov_worker_pairs,
        active_cov_pairs: active_cov_pairs,
        primary_cov_pair: primary_cov_pair
      }
    end

    def resolve_worker_pairs(name, cov_worker_pairs, cov_pairs_by_id)
      ids = Array(cov_worker_pairs[name.to_s])
      ids.filter_map { |pid| cov_pairs_by_id[pid.to_s] }
    end

    def render_worker_cov_overview_cells(worker_pairs)
      cov_list = worker_pairs.select { |p| p["has_coverage"] }
      if cov_list.empty?
        return ["<span class=\"muted\">&mdash;</span>", "<span class=\"muted\">&mdash;</span>"]
      end

      if cov_list.size == 1
        p = cov_list.first
        l_pct = p.dig("totals", "lines", "percent").to_f
        b_pct = p.dig("totals", "branches", "percent").to_f
        label = CGI.escapeHTML(p["label"].to_s)
        href = CGI.escapeHTML(p["report_rel_path"].to_s)
        pair_dom = CGI.escapeHTML("cov-pair-#{p['id']}")
        cov_cell = %(<div class="cov-pair-stat"><a class="pair-chip" href="javascript:void(0)" onclick="event.stopPropagation(); jumpToCoveragePair('#{pair_dom}')">#{label}</a> <strong>#{format('%.2f%%', l_pct)}</strong> <span class="muted">(#{format('%.1f%%', b_pct)} B)</span></div>)
        rep_cell = href.empty? ? "<span class=\"muted\">&mdash;</span>" : %(<a class="cov-link" href="#{href}" target="_blank" rel="noopener" onclick="event.stopPropagation()">HTML &nearr;</a>)
        return [cov_cell, rep_cell]
      end

      cov_lines = cov_list.map do |p|
        l_pct = p.dig("totals", "lines", "percent").to_f
        b_pct = p.dig("totals", "branches", "percent").to_f
        label = CGI.escapeHTML(p["label"].to_s)
        pair_dom = CGI.escapeHTML("cov-pair-#{p['id']}")
        %(<div class="cov-pair-stat"><a class="pair-chip" href="javascript:void(0)" onclick="event.stopPropagation(); jumpToCoveragePair('#{pair_dom}')">#{label}</a> <strong>#{format('%.2f%%', l_pct)}</strong> <span class="muted">(#{format('%.1f%%', b_pct)} B)</span></div>)
      end.join("\n")

      rep_links = cov_list.filter_map do |p|
        href = p["report_rel_path"].to_s
        next nil if href.empty?

        label = CGI.escapeHTML(p["label"].to_s)
        %(<div><a class="cov-link" href="#{CGI.escapeHTML(href)}" target="_blank" rel="noopener" onclick="event.stopPropagation()">#{label} &nearr;</a></div>)
      end.join("\n")

      [cov_lines, rep_links.empty? ? "<span class=\"muted\">&mdash;</span>" : rep_links]
    end

    def render_worker_cov_banner_buttons(worker_pairs)
      cov_list = worker_pairs.select { |p| p["has_coverage"] }
      return "" if cov_list.empty?

      cov_list.map do |p|
        href = p["report_rel_path"].to_s
        next nil if href.empty?

        label = CGI.escapeHTML(p["label"].to_s)
        %(<a class="cov-btn" href="#{CGI.escapeHTML(href)}" target="_blank" rel="noopener">#{label} llvm-cov &nearr;</a>)
      end.compact.join(" ")
    end

    def render_overview_cov_kpi_cards(active_cov_pairs)
      return "" if active_cov_pairs.empty?

      active_cov_pairs.map do |p|
        pair_dom = CGI.escapeHTML("cov-pair-#{p['id']}")
        cl_tot = p.dig("totals", "lines") || {}
        cb_tot = p.dig("totals", "branches") || {}
        src_name = p["source"].to_s
        target_lbl = p["target_label"].to_s
        if target_lbl.empty? && p["label"].to_s =~ /\A#{Regexp.escape(src_name)}\s*\((.+)\)\z/
          target_lbl = Regexp.last_match(1).to_s
        end
        lbl_txt = src_name.empty? ? "Source Coverage" : "Source Coverage &bull; #{CGI.escapeHTML(src_name)}"
        target_html = target_lbl.empty? ? "" : %(<div class="kpi-pair-target">#{CGI.escapeHTML(target_lbl)}</div>)

        <<~COV_KPI
          <div class="kpi-card clickable-row" onclick="jumpToCoveragePair('#{pair_dom}')" title="#{CGI.escapeHTML(p['label'].to_s)} — click to view detailed coverage">
            <div class="kpi-label">#{lbl_txt}</div>
            <div class="kpi-value">#{format("%.2f%%", cl_tot["percent"].to_f)}</div>
            #{target_html}
            <div class="kpi-sub">#{Helpers.format_int(cl_tot["covered"].to_i)} / #{Helpers.format_int(cl_tot["count"].to_i)} lines &bull; #{format("%.1f%%", cb_tot["percent"].to_f)} branches</div>
          </div>
        COV_KPI
      end.join("\n")
    end

    def render_coverage_tab_html(cov_info)
      active_cov_pairs = cov_info[:active_cov_pairs]
      return "" if active_cov_pairs.empty?

      cov_pairs = cov_info[:cov_pairs]
      coverage_data = cov_info[:coverage_data]

      pairs_summary_section = if cov_pairs.size > 1
        pair_rows = cov_pairs.each_with_index.map do |p, p_idx|
          pt = p["totals"] || {}
          pl = pt["lines"] || {}
          pb = pt["branches"] || {}
          pr = pt["regions"] || {}
          pf = pt["functions"] || {}
          color = Helpers::PALETTE[p_idx % Helpers::PALETTE.size]
          pair_dom = CGI.escapeHTML("cov-pair-#{p['id']}")
          links = []
          links << %(<a class="cov-link" href="#{CGI.escapeHTML(p['report_rel_path'])}" target="_blank" rel="noopener" onclick="event.stopPropagation()">HTML &nearr;</a>) if p["report_rel_path"]
          links << %(<a class="cov-link muted" href="#{CGI.escapeHTML(p['summary_rel_path'])}" target="_blank" rel="noopener" onclick="event.stopPropagation()">Txt &nearr;</a>) if p["summary_rel_path"]
          links << %(<a class="cov-link muted" href="#{CGI.escapeHTML(p['lcov_rel_path'])}" target="_blank" rel="noopener" onclick="event.stopPropagation()">LCOV &nearr;</a>) if p["lcov_rel_path"]
          workers_list = Array(p["workers"]).map { |w| "<code>#{CGI.escapeHTML(w)}</code>" }.join(" ")
          lines_cell = if p["has_coverage"]
                         <<~CELL
                           <div><strong>#{format("%.2f%%", pl["percent"].to_f)}</strong> <span class="muted">(#{Helpers.format_int(pl["covered"].to_i)} / #{Helpers.format_int(pl["count"].to_i)})</span></div>
                           <div class="sync-bar" style="height: 6px; margin-top: 4px;">
                             <div class="sync-seg" style="width:#{pl["percent"].to_f.round(2)}%;background:#{color}"></div>
                           </div>
                         CELL
                       else
                         "<span class=\"muted\">&mdash;</span>"
                       end
          branches_cell = if p["has_coverage"] && pb["count"].to_i > 0
                            <<~CELL
                              <div><strong>#{format("%.2f%%", pb["percent"].to_f)}</strong> <span class="muted">(#{Helpers.format_int(pb["covered"].to_i)} / #{Helpers.format_int(pb["count"].to_i)})</span></div>
                              <div class="sync-bar" style="height: 6px; margin-top: 4px;">
                                <div class="sync-seg" style="width:#{pb["percent"].to_f.round(2)}%;background:#38bdf8"></div>
                              </div>
                            CELL
                          else
                            "<span class=\"muted\">&mdash;</span>"
                          end
          <<~ROW
            <tr class="clickable-row" onclick="jumpToCoveragePair('#{pair_dom}')">
              <td><span class="legend-dot" style="background:#{color}"></span> <strong>#{CGI.escapeHTML(p["label"].to_s)}</strong></td>
              <td><code>#{CGI.escapeHTML(p["source"].to_s)}</code></td>
              <td><code>#{CGI.escapeHTML(p["target_label"].to_s)}</code></td>
              <td>#{workers_list.empty? ? "<span class=\"muted\">&mdash;</span>" : workers_list}</td>
              <td class="num">#{Helpers.format_int(p["input_count"].to_i)}</td>
              <td class="num" style="min-width: 200px;">#{lines_cell}</td>
              <td class="num" style="min-width: 200px;">#{branches_cell}</td>
              <td class="num">#{p["has_coverage"] ? format("%.2f%%", pr["percent"].to_f) : "<span class=\"muted\">&mdash;</span>"}</td>
              <td class="num">#{p["has_coverage"] ? format("%.2f%%", pf["percent"].to_f) : "<span class=\"muted\">&mdash;</span>"}</td>
              <td class="num">#{links.empty? ? "<span class=\"muted\">&mdash;</span>" : links.join(" &bull; ")}</td>
            </tr>
          ROW
        end.join("\n")

        <<~SUMMARY_CARD
          <div class="table-card" style="margin-bottom: 22px;">
            <div class="table-card-header">
              <div>
                <h3>Coverage by (Source, Target) Pair</h3>
                <p class="chart-sub">Each <code>(source revision, compilation target)</code> pair builds an independent coverage binary and replays compatible inputs from its associated workers and seeds.</p>
              </div>
            </div>
            <table>
              <thead>
                <tr>
                  <th>Pair</th>
                  <th>Source</th>
                  <th>Target</th>
                  <th>Workers</th>
                  <th class="num">Inputs</th>
                  <th class="num">Lines</th>
                  <th class="num">Branches</th>
                  <th class="num">Regions %</th>
                  <th class="num">Functions %</th>
                  <th class="num">llvm-cov Reports</th>
                </tr>
              </thead>
              <tbody>
                #{pair_rows}
              </tbody>
            </table>
          </div>
        SUMMARY_CARD
      else
        ""
      end

      pair_sections_html = cov_pairs.each_with_index.map do |p, p_idx|
        pair_dom = CGI.escapeHTML("cov-pair-#{p['id']}")
        color = Helpers::PALETTE[p_idx % Helpers::PALETTE.size]
        src_meta_bits = []
        src_meta_bits << "Source: <code>#{CGI.escapeHTML(p['source'].to_s)}</code>"
        src_meta_bits << "Target: <code>#{CGI.escapeHTML(p['target_label'].to_s)}</code>"
        if p["source_commit"] && !p["source_commit"].to_s.empty?
          src_meta_bits << "Commit: <code>#{CGI.escapeHTML(p['source_commit'].to_s[0, 10])}</code>"
        elsif p["source_ref"] && !p["source_ref"].to_s.empty?
          src_meta_bits << "Ref: <code>#{CGI.escapeHTML(p['source_ref'].to_s)}</code>"
        end
        src_meta_bits << "#{Helpers.format_int(p['input_count'].to_i)} deduplicated inputs"
        if Array(p["workers"]).any?
          src_meta_bits << "Workers: #{Array(p['workers']).map { |w| "<code>#{CGI.escapeHTML(w)}</code>" }.join(', ')}"
        end

        action_btns = []
        action_btns << %(<a class="cov-btn" href="#{CGI.escapeHTML(p['report_rel_path'])}" target="_blank" rel="noopener">Open llvm-cov HTML Report &nearr;</a>) if p["report_rel_path"]
        action_btns << %(<a class="cov-btn cov-btn-secondary" href="#{CGI.escapeHTML(p['summary_rel_path'])}" target="_blank" rel="noopener">Text Summary &nearr;</a>) if p["summary_rel_path"]
        action_btns << %(<a class="cov-btn cov-btn-secondary" href="#{CGI.escapeHTML(p['lcov_rel_path'])}" target="_blank" rel="noopener">LCOV (IDE Gutters) &nearr;</a>) if p["lcov_rel_path"]

        unless p["has_coverage"]
          next <<~EMPTY_PAIR
            <div id="#{pair_dom}" style="margin-bottom: 28px;">
              <div class="fuzzer-banner">
                <div>
                  <h2><span class="legend-dot" style="background:#{color}"></span> #{CGI.escapeHTML(p["label"].to_s)}</h2>
                  <p class="cmd-line">#{src_meta_bits.join(" &bull; ")}</p>
                </div>
              </div>
              <div class="table-card" style="padding: 18px; color: var(--muted);">
                No coverage profile data collected for this pair yet.
              </div>
            </div>
          EMPTY_PAIR
        end

        pt = p["totals"] || {}
        pl = pt["lines"] || {}
        pb = pt["branches"] || {}
        pr = pt["regions"] || {}
        pf = pt["functions"] || {}
        file_prefix = p["file_report_prefix"].to_s

        file_rows = (p["files"] || []).map do |cf_entry|
          fname = cf_entry["filename"].to_s
          cs = cf_entry["summary"] || {}
          fl = cs["lines"] || {}
          fb = cs["branches"] || {}
          fr = cs["regions"] || {}
          ff = cs["functions"] || {}
          next if fl["count"].to_i.zero? && ff["count"].to_i.zero?

          missed_l = fl["count"].to_i - fl["covered"].to_i
          missed_b = fb["count"].to_i - fb["covered"].to_i
          file_href = cf_entry["report_rel_path"].to_s
          file_href = "#{file_prefix}#{fname}.html" if file_href.empty? && !file_prefix.empty?
          file_link_html = if !file_href.empty?
                             %(<a class="cov-link" href="#{CGI.escapeHTML(file_href)}" target="_blank" rel="noopener"><code>#{CGI.escapeHTML(fname)}</code> &nearr;</a>)
                           else
                             "<code>#{CGI.escapeHTML(fname)}</code>"
                           end
          <<~ROW
            <tr>
              <td>#{file_link_html}</td>
              <td class="num">
                <strong>#{format("%.2f%%", fl["percent"].to_f)}</strong>
                <span class="muted">(#{Helpers.format_int(fl["covered"].to_i)}/#{Helpers.format_int(fl["count"].to_i)})</span>
              </td>
              <td class="num">#{missed_l > 0 ? "<span class=\"text-warn\">#{Helpers.format_int(missed_l)}</span>" : "<span class=\"muted\">0</span>"}</td>
              <td class="num">
                #{fb["count"].to_i > 0 ? "<strong>#{format('%.2f%%', fb['percent'].to_f)}</strong> <span class=\"muted\">(#{Helpers.format_int(fb['covered'].to_i)}/#{Helpers.format_int(fb['count'].to_i)})</span>" : "<span class=\"muted\">&mdash;</span>"}
              </td>
              <td class="num">#{fb["count"].to_i > 0 ? (missed_b > 0 ? "<span class=\"text-warn\">#{Helpers.format_int(missed_b)}</span>" : "<span class=\"muted\">0</span>") : "<span class=\"muted\">&mdash;</span>"}</td>
              <td class="num">#{format("%.2f%%", fr["percent"].to_f)}</td>
              <td class="num">#{format("%.2f%%", ff["percent"].to_f)}</td>
            </tr>
          ROW
        end.compact.join("\n")

        <<~PAIR_SEC
          <div id="#{pair_dom}" style="margin-bottom: 28px;">
            <div class="fuzzer-banner">
              <div>
                <h2><span class="legend-dot" style="background:#{color}"></span> #{CGI.escapeHTML(p["label"].to_s)}</h2>
                <p class="cmd-line">#{src_meta_bits.join(" &bull; ")}</p>
              </div>
              <div class="fuzzer-meta">
                #{action_btns.join("\n")}
              </div>
            </div>

            <div class="kpi-grid">
              <div class="kpi-card">
                <div class="kpi-label">Line Coverage</div>
                <div class="kpi-value">#{format("%.2f%%", pl["percent"].to_f)}</div>
                <div class="kpi-sub">#{Helpers.format_int(pl["covered"].to_i)} / #{Helpers.format_int(pl["count"].to_i)} lines (#{Helpers.format_int(pl["count"].to_i - pl["covered"].to_i)} missed)</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">Branch Coverage</div>
                <div class="kpi-value">#{format("%.2f%%", pb["percent"].to_f)}</div>
                <div class="kpi-sub">#{Helpers.format_int(pb["covered"].to_i)} / #{Helpers.format_int(pb["count"].to_i)} branches (#{Helpers.format_int(pb["count"].to_i - pb["covered"].to_i)} missed)</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">Region Coverage</div>
                <div class="kpi-value">#{format("%.2f%%", pr["percent"].to_f)}</div>
                <div class="kpi-sub">#{Helpers.format_int(pr["covered"].to_i)} / #{Helpers.format_int(pr["count"].to_i)} regions (#{Helpers.format_int(pr["count"].to_i - pr["covered"].to_i)} missed)</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">Function Coverage</div>
                <div class="kpi-value">#{format("%.2f%%", pf["percent"].to_f)}</div>
                <div class="kpi-sub">#{Helpers.format_int(pf["covered"].to_i)} / #{Helpers.format_int(pf["count"].to_i)} functions (#{Helpers.format_int(pf["count"].to_i - pf["covered"].to_i)} missed)</div>
              </div>
            </div>

            <div class="table-card">
              <div class="table-card-header">
                <div>
                  <h3>Per-File Coverage &mdash; <code>#{CGI.escapeHTML(p["label"].to_s)}</code></h3>
                  <p class="chart-sub">Click any source file to open its annotated HTML coverage view.</p>
                </div>
              </div>
              <table>
                <thead>
                  <tr>
                    <th>Source File</th>
                    <th class="num">Lines</th>
                    <th class="num">Missed L</th>
                    <th class="num">Branches</th>
                    <th class="num">Missed B</th>
                    <th class="num">Regions %</th>
                    <th class="num">Functions %</th>
                  </tr>
                </thead>
                <tbody>
                  #{file_rows}
                </tbody>
              </table>
            </div>
          </div>
        PAIR_SEC
      end.join("\n")

      <<~HTML
        <section id="tab-coverage" class="tab-panel">
          <div class="fuzzer-banner">
            <div>
              <h2><span class="legend-dot" style="background:#34d399"></span> Source Coverage by (Source, Target) Pair</h2>
              <p class="cmd-line">#{cov_pairs.size} coverage target#{cov_pairs.size == 1 ? "" : "s"} &bull; Collected: #{CGI.escapeHTML(coverage_data["generated_at"].to_s)}</p>
            </div>
          </div>
          #{pairs_summary_section}
          #{pair_sections_html}
        </section>
      HTML
    end
  end
end
