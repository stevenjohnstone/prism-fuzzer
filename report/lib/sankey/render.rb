# frozen_string_literal: true

require "cgi/escape"
require "json"
require "time"

module FuzzSankey
  SANKEY_CSS = File.read(File.expand_path("assets/sankey.css", __dir__)).freeze
  SANKEY_JS = File.read(File.expand_path("assets/sankey.js", __dir__)).freeze

  module_function

  def format_int(n)
    n.to_i.to_s.reverse.gsub(/(\d{3})(?=\d)/, '\\1,').reverse
  end

  def json_for_script(obj)
    JSON.generate(obj)
      .gsub("&", "\\u0026")
      .gsub("<", "\\u003c")
      .gsub(">", "\\u003e")
      .gsub("\u2028", "\\u2028")
      .gsub("\u2029", "\\u2029")
  end

  def cubic_ribbon_path(x0, sy0, sy1, x1, ty0, ty1, min_thickness: 1.2)
    # Enforce subtle minimum visible thickness on tiny edges while keeping
    # endpoints centered in their proportional slot.
    s_thick = sy1 - sy0
    t_thick = ty1 - ty0
    if s_thick < min_thickness
      mid = (sy0 + sy1) * 0.5
      sy0 = mid - min_thickness * 0.5
      sy1 = mid + min_thickness * 0.5
    end
    if t_thick < min_thickness
      mid = (ty0 + ty1) * 0.5
      ty0 = mid - min_thickness * 0.5
      ty1 = mid + min_thickness * 0.5
    end
    cx = (x0 + x1) * 0.5
    format(
      "M%.2f,%.2f C%.2f,%.2f %.2f,%.2f %.2f,%.2f L%.2f,%.2f C%.2f,%.2f %.2f,%.2f %.2f,%.2f Z",
      x0, sy0, cx, sy0, cx, ty0, x1, ty0,
      x1, ty1, cx, ty1, cx, sy1, x0, sy1
    )
  end

  def render_svg(layout, title: nil, metric_label: nil, interactive: true)
    w = layout[:width]
    h = layout[:height]
    nodes = layout[:placed_nodes]
    links = layout[:placed_links]
    layers = layout[:layers]

    if layout[:total_weight].to_i <= 0 || nodes.empty?
      return <<~SVG
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 #{w} 180" width="100%" height="180" style="background:#0b0f19;border-radius:8px;">
          <text x="#{w / 2}" y="95" text-anchor="middle" fill="#9ca3af" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif" font-size="14">No matching triage findings to display for this filter.</text>
        </svg>
      SVG
    end

    col_headers = layout[:col_x].each_with_index.map do |cx, idx|
      anchor = if idx == 0 || idx == layers.size - 1
                 "start"
               else
                 "middle"
               end
      hx = if idx == 0 || idx == layers.size - 1
             cx
           else
             cx + layout[:node_w] * 0.5
           end
      %(<text x="#{hx.round(1)}" y="24" text-anchor="#{anchor}" fill="#9ca3af" font-size="11" font-weight="700" letter-spacing="0.06em">#{CGI.escapeHTML(layer_title(layers[idx]).upcase)}</text>)
    end.join("\n")

    links_svg = links.map do |l|
      snode = nodes[l[:src]]
      dnode = nodes[l[:dst]]
      path_d = cubic_ribbon_path(snode[:x] + snode[:w], l[:sy0], l[:sy1], dnode[:x], l[:ty0], l[:ty1])
      pct_s = snode[:value] > 0 ? (l[:value] * 100.0 / snode[:value]).round(1) : 0.0
      pct_d = dnode[:value] > 0 ? (l[:value] * 100.0 / dnode[:value]).round(1) : 0.0
      tip = "#{snode[:label]} -> #{dnode[:label]}: #{format_int(l[:value])} (#{pct_s}% of #{snode[:label]}, #{pct_d}% of #{dnode[:label]})"
      attrs = if interactive
                %( class="sk-link" data-src="#{CGI.escapeHTML(l[:src])}" data-dst="#{CGI.escapeHTML(l[:dst])}" data-val="#{l[:value]}" data-pct-s="#{pct_s}" data-pct-d="#{pct_d}")
              else
                ""
              end
      %(<path#{attrs} d="#{path_d}" fill="#{l[:color]}" fill-opacity="0.34" stroke="none"><title>#{CGI.escapeHTML(tip)}</title></path>)
    end.join("\n")

    nodes_svg = layout[:col_lists].each_with_index.flat_map do |keys, c|
      is_first = (c == 0)
      is_last = (c == layers.size - 1)
      keys.map do |k|
        n = nodes[k]
        pct_tot = layout[:total_weight] > 0 ? (n[:value] * 100.0 / layout[:total_weight]).round(1) : 0.0
        tip = "#{n[:label]} (#{layer_title(n[:layer])}): #{format_int(n[:value])} (#{pct_tot}%)"
        tip += " | #{n[:headline]}" if n[:headline] && !n[:headline].empty?

        lbl_text = if is_last || is_first
                     "#{n[:label]} (#{format_int(n[:value])})"
                   else
                     "#{n[:label]} · #{format_int(n[:value])}"
                   end

        if is_first
          lx = n[:x] - 8.0
          anchor = "end"
        else
          lx = n[:x] + n[:w] + 8.0
          anchor = "start"
        end
        ly = n[:y] + n[:h] * 0.5 + 4.0

        rect_attrs = if interactive
                       %( class="sk-node" data-key="#{CGI.escapeHTML(k)}" data-col="#{c}" data-raw-id="#{CGI.escapeHTML(n[:raw_id])}" data-val="#{n[:value]}" data-pct="#{pct_tot}")
                     else
                       ""
                     end
        text_attrs = interactive ? %( class="sk-label" data-key="#{CGI.escapeHTML(k)}") : ""

        <<~NODE.chomp
          <g class="sk-node-group" data-key="#{CGI.escapeHTML(k)}">
            <rect#{rect_attrs} x="#{n[:x].round(2)}" y="#{n[:y].round(2)}" width="#{n[:w].round(2)}" height="#{n[:h].round(2)}" rx="3" fill="#{n[:color]}" stroke="#0b0f19" stroke-width="1"><title>#{CGI.escapeHTML(tip)}</title></rect>
            <text#{text_attrs} x="#{lx.round(2)}" y="#{ly.round(2)}" text-anchor="#{anchor}" fill="#e5e7eb" font-size="11.5" font-weight="#{is_first || is_last ? '600' : '500'}" style="paint-order:stroke;stroke:#0b0f19;stroke-width:4px;stroke-linejoin:round;">#{CGI.escapeHTML(lbl_text)}</text>
          </g>
        NODE
      end
    end.join("\n")

    title_bar = title ? %(<title>#{CGI.escapeHTML(title)}#{metric_label ? " (#{CGI.escapeHTML(metric_label)})" : ""}</title>) : ""

    <<~SVG
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 #{w} #{h}" width="100%" height="auto" class="sankey-svg" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Inter,sans-serif">
        #{title_bar}
        <rect width="#{w}" height="#{h}" fill="#0b0f19" rx="8"/>
        #{col_headers}
        <g class="sk-links">
          #{links_svg}
        </g>
        <g class="sk-nodes">
          #{nodes_svg}
        </g>
      </svg>
    SVG
  end

  def render_table_rows(dataset, graph, metric:, topo: nil)
    eff_topo = topo.nil? ? (dataset[:topology] || graph[:topology]) : topo
    nodes = dataset[:clusters]
    worker_cluster = Hash.new { |h, k| h[k] = Hash.new(0) }
    cluster_origins = Hash.new { |h, k| h[k] = Hash.new(0) }

    dataset[:records].each do |rec|
      next if graph[:group] != "all" && rec[:group] != graph[:group]

      w = record_weight(rec, metric)
      next if w <= 0

      worker_cluster[rec[:cluster_id]][rec[:worker]] += w
      cluster_origins[rec[:cluster_id]][rec[:origin]] += w if rec[:origin]
    end

    sorted_cids = worker_cluster.keys.sort_by do |cid|
      total = worker_cluster[cid].values.sum
      cm = nodes[cid]
      [-total, cm ? cm[:rank] : 9999, cid]
    end

    sorted_cids.map do |cid|
      cm = nodes[cid] || {}
      wmap = worker_cluster[cid]
      tot = wmap.values.sum
      worker_pills = wmap.sort_by { |wn, cnt| [-cnt, worker_sort_rank(wn, topo: eff_topo)] }.map do |wn, cnt|
        c = color_for(wn, layer_kind: :worker, topo: eff_topo)
        %(<span class="hop-pill"><span class="legend-dot" style="background:#{c}"></span>#{CGI.escapeHTML(wn)}: #{format_int(cnt)}</span>)
      end.join(" ")

      origin_str = if cluster_origins[cid].empty?
                     "-"
                   else
                     cluster_origins[cid].sort_by { |o, cnt| [-cnt, o.to_s] }
                       .map { |o, cnt| "#{o}: #{format_int(cnt)}" }.join(", ")
                   end

      group_badge = case cm[:group]
                    when "diff_parse_y" then '<span class="badge-diff">diff_parse_y</span>'
                    when "diff_prism" then '<span class="badge-pdiff">diff_prism</span>'
                    when "cruby_crash" then '<span class="badge-cruby">cruby_crash</span>'
                    else '<span class="badge-flaw">prism_flaw</span>'
                    end
      loupe_link = if cm[:loupe_url]
                     %(<a class="cov-link" href="#{CGI.escapeHTML(cm[:loupe_url])}" target="_blank" rel="noopener">Loupe &nearr;</a>)
                   else
                     ""
                   end

      <<~ROW
        <tr data-cluster-id="#{CGI.escapeHTML(cid)}">
          <td><code>#{CGI.escapeHTML(cid)}</code><div style="margin-top:3px;">#{group_badge}</div></td>
          <td class="num"><strong>#{format_int(tot)}</strong></td>
          <td class="num">#{format_int(cm[:bucket_count].to_i)}</td>
          <td>#{worker_pills}</td>
          <td style="font-size:0.8rem;color:#9ca3af;">#{CGI.escapeHTML(origin_str)}</td>
          <td>
            <div style="font-weight:600;">#{CGI.escapeHTML(cm[:label].to_s)}</div>
            <div style="font-size:0.78rem;color:#9ca3af;margin-top:2px;"><code>#{CGI.escapeHTML(cm[:rep_bucket].to_s)}</code> #{loupe_link}</div>
            <div style="font-size:0.76rem;color:#9ca3af;word-break:break-word;">#{CGI.escapeHTML(cm[:headline].to_s[0, 140])}</div>
          </td>
        </tr>
      ROW
    end.join("\n")
  end

  def render_sankey_sections(dataset, default_metric: "occurrences", default_group: "all", default_layers: "auto", default_max_clusters: DEFAULT_MAX_CLUSTERS, section_title: nil, topo: nil)
    eff_topo = topo.nil? ? dataset[:topology] : topo
    metrics = %w[occurrences buckets]
    groups_present = dataset[:records].map { |r| r[:group] }.uniq
    groups = ["all"]
    groups << "prism_flaw" if groups_present.include?("prism_flaw")
    groups << "cruby_crash" if groups_present.include?("cruby_crash")
    groups << "diff_parse_y" if groups_present.include?("diff_parse_y")
    groups << "diff_prism" if groups_present.include?("diff_prism")
    groups.concat((groups_present - groups).sort)

    layer_choices = dataset[:has_origins] ? %w[origin_worker_category_cluster worker_category_cluster worker_cluster] : %w[worker_category_cluster worker_cluster]
    default_layer_key = case normalize_layers_mode(default_layers, has_origins: dataset[:has_origins])
                        when %i[origin worker category cluster] then "origin_worker_category_cluster"
                        when %i[worker category cluster] then "worker_category_cluster"
                        else "worker_cluster"
                        end
    default_layer_key = layer_choices.first unless layer_choices.include?(default_layer_key)

    cap_choices = default_max_clusters.to_i > 0 && dataset[:clusters].size > default_max_clusters.to_i ? [default_max_clusters.to_i, 0] : [default_max_clusters.to_i]

    views = {}
    views_meta = {}
    metrics.each do |m|
      groups.each do |g|
        layer_choices.each do |lk|
          cap_choices.each do |cap|
            vk = "#{m}|#{g}|#{lk}|#{cap}"
            graph = build_sankey_graph(dataset, metric: m, group: g, layers_mode: lk, max_clusters: cap, topo: eff_topo)
            layout = compute_sankey_layout(graph, topo: eff_topo)
            views[vk] = render_svg(layout, title: section_title, metric_label: m, interactive: true)
            views_meta[vk] = {
              total: layout[:total_weight],
              clusters: layout[:cluster_count_visible],
              collapsed: layout[:other_cluster_count],
              nodeMeta: layout[:placed_nodes].transform_values do |n|
                {
                  label: n[:label],
                  sub: n[:sub],
                  value: n[:value],
                  headline: n[:headline],
                  rep_bucket: n[:rep_bucket],
                  loupe_url: n[:loupe_url],
                  bucket_count: n[:bucket_count],
                  occurrences: n[:occurrences]
                }
              end
            }
          end
        end
      end
    end

    active_metric = metrics.include?(default_metric) ? default_metric : "occurrences"
    active_group = groups.include?(default_group) ? default_group : "all"
    default_key = "#{active_metric}|#{active_group}|#{default_layer_key}|#{cap_choices.first}"
    default_graph = build_sankey_graph(dataset, metric: default_metric, group: default_group, layers_mode: default_layer_key, max_clusters: cap_choices.first, topo: eff_topo)

    total_occ = dataset[:records].sum { |r| r[:occurrences] }
    zero_note = if dataset[:zero_crash_workers].any?
                  %(<div class="kpi-card"><div class="kpi-label">0-Crash Workers</div><div class="kpi-value" style="font-size:1.15rem;">#{CGI.escapeHTML(dataset[:zero_crash_workers].join(', '))}</div><div class="kpi-sub">Active without crashes in triage</div></div>)
                else
                  ""
                end

    layer_labels = {
      "origin_worker_category_cluster" => "Origin &rarr; Fuzzer &rarr; Invariant &rarr; Cluster",
      "worker_category_cluster" => "Fuzzer &rarr; Invariant &rarr; Cluster",
      "worker_cluster" => "Fuzzer &rarr; Cluster"
    }

    svgs_html = views.map do |vk, svg|
      active_cls = vk == default_key ? " active" : ""
      %(<div class="sankey-view#{active_cls}" data-view-key="#{CGI.escapeHTML(vk)}">#{svg}</div>)
    end.join("\n")

    table_rows_html = render_table_rows(dataset, default_graph, metric: "occurrences", topo: eff_topo)

    group_ctrl_html = if groups.size > 1
                        btns = groups.map do |g|
                          lbl = { "all" => "All Clusters", "prism_flaw" => "Prism Flaws", "cruby_crash" => "CRuby Crashes", "diff_parse_y" => "Diff parse.y", "diff_prism" => "Diff Prism" }[g] || g
                          %(<button class="ctrl-btn#{g == active_group ? ' active' : ''}" data-val="#{CGI.escapeHTML(g)}">#{CGI.escapeHTML(lbl)}</button>)
                        end.join
                        <<~GRP
                          <div class="ctrl-group" data-axis="group">
                            <span class="ctrl-label">Group:</span>
                            #{btns}
                          </div>
                        GRP
                      else
                        ""
                      end

    cap_ctrl_html = if cap_choices.size > 1
                      btns = cap_choices.map do |cap|
                        lbl = cap == 0 ? "All (#{dataset[:clusters].size})" : "Top #{cap}"
                        %(<button class="ctrl-btn#{cap == cap_choices.first ? ' active' : ''}" data-val="#{cap}">#{lbl}</button>)
                      end.join
                      <<~CAP
                        <div class="ctrl-group" data-axis="cap">
                          <span class="ctrl-label">Clusters:</span>
                          #{btns}
                        </div>
                      CAP
                    else
                      ""
                    end

    metric_btns = metrics.map do |m|
      lbl = { "occurrences" => "Occurrences (All Finds)", "buckets" => "Worker &times; Bucket Pairs" }[m]
      %(<button class="ctrl-btn#{m == active_metric ? ' active' : ''}" data-val="#{m}">#{lbl}</button>)
    end.join

    layer_btns = layer_choices.map do |lk|
      %(<button class="ctrl-btn#{lk == default_layer_key ? ' active' : ''}" data-val="#{lk}">#{layer_labels[lk] || lk}</button>)
    end.join

    body_html = <<~HTML
      <div class="sankey-root">
        <div class="kpi-grid">
          <div class="kpi-card">
            <div class="kpi-label">Total Crash Occurrences</div>
            <div class="kpi-value">#{format_int(total_occ)}</div>
            <div class="kpi-sub">across #{dataset[:active_workers].size} finding workers</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">Triage Buckets</div>
            <div class="kpi-value">#{format_int(dataset[:bucket_total])}</div>
            <div class="kpi-sub">across #{format_int(dataset[:clusters].size)} root-cause clusters</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">Root-Cause Clusters</div>
            <div class="kpi-value">#{format_int(dataset[:clusters].size)}</div>
            <div class="kpi-sub">#{groups_present.map { |gp| "#{dataset[:clusters].values.count { |c| c[:group] == gp }} #{CGI.escapeHTML(gp.to_s)}" }.join(' &bull; ')}</div>
          </div>
          #{zero_note}
        </div>

        <div class="panel-card">
          <div class="controls-bar">
            <div class="ctrl-group" data-axis="metric">
              <span class="ctrl-label">Flow Metric:</span>
              #{metric_btns}
            </div>
            #{group_ctrl_html}
            <div class="ctrl-group" data-axis="layers">
              <span class="ctrl-label">Columns:</span>
              #{layer_btns}
            </div>
            #{cap_ctrl_html}
          </div>

          <div class="status-strip">
            <span id="sk-summary-line">Showing #{format_int(default_graph[:total_weight])} flow units across #{default_graph[:cluster_count_visible]} clusters. Hover to trace connected pathways; click a node to lock highlight.</span>
            <button class="ctrl-btn" id="sk-clear-pin" style="display:none;">Clear Selection</button>
          </div>

          #{svgs_html}
        </div>

        <div class="panel-card">
          <h3 style="margin:0 0 10px 0;font-size:1rem;">Cluster Breakdown by Discovering Worker</h3>
          <table>
            <thead>
              <tr>
                <th>Cluster</th>
                <th class="num">Occurrences</th>
                <th class="num">Buckets</th>
                <th>Discovered By (Occurrences)</th>
                <th>Seed Origin</th>
                <th>Representative Bug</th>
              </tr>
            </thead>
            <tbody>
              #{table_rows_html}
            </tbody>
          </table>
        </div>
      </div>

      <div id="sk-tooltip"></div>
    HTML

    initial_state = {
      metric: active_metric,
      group: active_group,
      layers: default_layer_key,
      cap: cap_choices.first.to_s,
      pinned: nil
    }

    script = <<~JS
      (function() {
      #{SANKEY_JS}
        mountSankeyView(#{json_for_script(views_meta)}, #{json_for_script(initial_state)});
      })();
    JS

    {
      styles: SANKEY_CSS,
      html: body_html,
      script: script,
      views_meta: views_meta,
      initial_state: initial_state,
      cluster_count: dataset[:clusters].size,
      bucket_total: dataset[:bucket_total],
      total_occurrences: total_occ
    }
  end

  def generate_html_report(dataset, title: "Prism Fuzzing Flow: Fuzzer → Cluster Sankey", default_metric: "occurrences", default_group: "all", default_layers: "auto", default_max_clusters: DEFAULT_MAX_CLUSTERS, topo: nil)
    eff_topo = topo.nil? ? dataset[:topology] : topo
    sec = render_sankey_sections(
      dataset,
      default_metric: default_metric,
      default_group: default_group,
      default_layers: default_layers,
      default_max_clusters: default_max_clusters,
      section_title: title,
      topo: eff_topo
    )

    <<~HTML
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="utf-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1"/>
        <title>Prism Fuzzing Flow — Fuzzer to Cluster Sankey</title>
        <style>
          :root {
            --bg: #0b0f19;
            --panel: #111827;
            --panel-border: #1f2937;
            --text: #e5e7eb;
            --muted: #9ca3af;
            --accent: #60a5fa;
          }
          * { box-sizing: border-box; }
          body {
            margin: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.45;
          }
          header {
            background: #0f172a;
            border-bottom: 1px solid var(--panel-border);
            padding: 18px 28px;
          }
          header h1 { margin: 0; font-size: 1.3rem; letter-spacing: -0.02em; }
          .header-sub { color: var(--muted); font-size: 0.84rem; margin-top: 4px; }
          main { max-width: 1460px; margin: 0 auto; padding: 22px 28px 48px 28px; }
          #{sec[:styles]}
        </style>
      </head>
      <body>
        <header>
          <h1>#{CGI.escapeHTML(title.to_s)}</h1>
          <div class="header-sub">
            Clusters: <code>#{CGI.escapeHTML(dataset[:clusters_path])}</code> &bull;
            Metadata: <code>#{CGI.escapeHTML(dataset[:metadata_path])}</code>
            #{dataset[:afl_dir] ? "&bull; Lineages: <code>#{CGI.escapeHTML(dataset[:afl_dir])}</code>" : ""}
            &bull; Generated: #{Time.now.strftime("%Y-%m-%d %H:%M:%S")}
          </div>
        </header>

        <main>
          #{sec[:html]}
        </main>

        <script>
          #{sec[:script]}
        </script>
      </body>
      </html>
    HTML
  end

  def generate_json_report(dataset, metric: "occurrences", group: "all", layers_mode: "auto", max_clusters: DEFAULT_MAX_CLUSTERS, topo: nil)
    eff_topo = topo.nil? ? dataset[:topology] : topo
    graph = build_sankey_graph(dataset, metric: metric, group: group, layers_mode: layers_mode, max_clusters: max_clusters, topo: eff_topo)
    links = graph[:edges].each_with_index.flat_map do |emap, c|
      emap.map do |(sk, dk), w|
        {
          "column" => c,
          "from_layer" => graph[:layers][c].to_s,
          "to_layer" => graph[:layers][c + 1].to_s,
          "from" => graph[:nodes][sk][:raw_id],
          "to" => graph[:nodes][dk][:raw_id],
          "value" => w
        }
      end
    end

    {
      "schema_version" => 1,
      "metric" => metric,
      "group" => group,
      "layers" => graph[:layers].map(&:to_s),
      "total_weight" => graph[:total_weight],
      "active_workers" => dataset[:active_workers],
      "zero_crash_workers" => dataset[:zero_crash_workers],
      "nodes" => graph[:nodes].values.map do |n|
        {
          "layer" => n[:layer].to_s,
          "id" => n[:raw_id],
          "label" => n[:label],
          "value" => n[:value]
        }
      end,
      "links" => links
    }
  end
end
