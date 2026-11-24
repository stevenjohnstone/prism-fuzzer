# frozen_string_literal: true

require "cgi/escape"
require "json"
require "pathname"
require_relative "helpers"

module PrismFuzzerReport
  module TriageView
    module_function

    def triage_group_badge_class(group)
      case group.to_s
      when "prism_flaw" then "badge-danger"
      when "diff_parse_y", "diff_prism" then "badge-warn"
      when "cruby_crash" then "badge-purple"
      else "badge-muted"
      end
    end

    def load_triage_view_data(triage_dir:, afl_dir:, out_dir_abs:, sankey_top: nil, topo: nil)
      return nil unless triage_dir && File.directory?(triage_dir)

      meta_path = File.join(triage_dir, "metadata.json")
      clus_path = File.join(triage_dir, "clusters.json")
      has_meta_file = File.file?(meta_path) || File.file?(clus_path)
      has_bucket_metas = !Dir.glob(File.join(triage_dir, "*", "*", "meta.json")).empty?
      return nil unless has_meta_file || has_bucket_metas

      clusters_report = nil
      metadata = nil
      clusters = []
      if defined?(FuzzInspect) && (File.file?(meta_path) || File.file?(clus_path))
        begin
          clusters_report, metadata, _src = FuzzInspect.load_triage_report(triage_dir: triage_dir, refresh: true)
          clusters = FuzzInspect.enrich_clusters(clusters_report, metadata, triage_dir: triage_dir, read_files: true)
        rescue FuzzInspect::ConfigError, JSON::ParserError, SystemCallError, IOError => e
          warn "TriageView: failed to load triage report from #{triage_dir}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
          clusters_report = nil
          metadata = nil
          clusters = []
        end
      end

      sankey_sec = nil
      if defined?(FuzzSankey)
        sankey_dataset = begin
                           FuzzSankey.extract_dataset(triage_dir: triage_dir, afl_dir: afl_dir, trace_origins: true, topo: topo)
                         rescue SystemExit, JSON::ParserError, SystemCallError, IOError => e
                           unless (e.is_a?(SystemExit) && e.success?) || ENV["FUZZ_QUIET"] == "1"
                             warn "TriageView: failed to extract Sankey dataset from #{triage_dir}: #{e.class}: #{e.message}"
                           end
                           nil
                         end
        if sankey_dataset && !sankey_dataset[:clusters].empty?
          max_clusters = sankey_top || FuzzSankey::DEFAULT_MAX_CLUSTERS
          sankey_sec = FuzzSankey.render_sankey_sections(
            sankey_dataset,
            default_max_clusters: max_clusters,
            section_title: "Triage Flow: Seed Origin → Fuzzer → Cluster Sankey",
            topo: topo
          )
          if clusters_report.nil?
            clusters = Array(sankey_dataset[:clusters].values).sort_by { |c| c[:rank].to_i }.map do |c|
              {
                "cluster_id" => c[:id],
                "group" => c[:group],
                "bucket_count" => c[:bucket_count].to_i,
                "occurrences" => c[:occurrences].to_i,
                "representative" => { "bucket_id" => c[:rep_bucket], "headline" => c[:headline] },
                "buckets" => []
              }
            end
          end
        end
      end

      return nil if clusters_report.nil? && metadata.nil? && sankey_sec.nil?

      triage_rel = Pathname.new(File.expand_path(triage_dir)).relative_path_from(out_dir_abs).to_s
      summary = (clusters_report && clusters_report["summary"]) || (metadata && metadata["summary"]) || {}
      {
        clusters: clusters,
        metadata: metadata,
        report: clusters_report,
        summary: summary,
        triage_rel: triage_rel,
        sankey_sec: sankey_sec
      }
    end

    def render_triage_tab_html(triage_view, triage_dir:, has_sankey:, format_int_fn: Helpers.method(:format_int))
      clusters = triage_view[:clusters] || []
      summary = triage_view[:summary] || {}
      metadata = triage_view[:metadata] || {}
      trel = triage_view[:triage_rel]

      total_buckets = summary["bucket_count"] || clusters.sum { |c| c["bucket_count"].to_i }
      total_occ = summary["total_occurrences"] || clusters.sum { |c| c["occurrences"].to_i }
      by_group = Hash.new(0)
      clusters.each { |c| by_group[c["group"].to_s.empty? ? "prism_flaw" : c["group"].to_s] += 1 }

      meta_links = []
      meta_links << %(<a class="cov-btn cov-btn-secondary" href="#{CGI.escapeHTML("#{trel}/clusters.json")}" target="_blank" rel="noopener">clusters.json &nearr;</a>) if File.file?(File.join(triage_dir, "clusters.json"))
      meta_links << %(<a class="cov-btn cov-btn-secondary" href="#{CGI.escapeHTML("#{trel}/metadata.json")}" target="_blank" rel="noopener">metadata.json &nearr;</a>) if File.file?(File.join(triage_dir, "metadata.json"))
      meta_links << %(<button class="cov-btn" type="button" onclick="selectTab('sankey')">View Origin Sankey &rarr;</button>) if has_sankey

      ver = metadata["versions"] || (triage_view[:report] && triage_view[:report]["versions"]) || {}
      prism_v = ver.dig("fuzz", "prism", "git_short") || ver.dig("triage", "prism", "git_short") || ver.dig("prism", "git_short")
      ruby_obj = ver.dig("fuzz", "ruby_parse_y") ||
                 ver.dig("triage", "ruby_parse_y") ||
                 ver["ruby_parse_y"] ||
                 Array(ver.dig("observed", "ruby_parse_y")).first
      ruby_v = if ruby_obj.is_a?(Hash) && !ruby_obj.empty?
                 if defined?(FuzzClustering) && FuzzClustering.respond_to?(:format_ruby_version_tag)
                   FuzzClustering.format_ruby_version_tag(ruby_obj)
                 else
                   rv_ver = ruby_obj["version"].to_s
                   rv_rev = ruby_obj["revision"].to_s[0, 10]
                   rv_short = ruby_obj["git_short"].to_s
                   main_v = !rv_ver.empty? ? rv_ver : (!rv_rev.empty? ? rv_rev : rv_short)
                   if main_v.empty?
                     nil
                   elsif !rv_rev.empty? && rv_rev != main_v
                     "#{main_v} (#{rv_rev})"
                   else
                     main_v
                   end
                 end
               end
      meta_by_id = Array(metadata["buckets"]).each_with_object({}) do |b, h|
        h[b["bucket_id"].to_s] = b if b.is_a?(Hash) && b["bucket_id"]
      end
      ver_bits = []
      ver_bits << "Prism: <code>#{CGI.escapeHTML(prism_v.to_s)}</code>" if prism_v && !prism_v.to_s.empty?
      ver_bits << "CRuby: <code>#{CGI.escapeHTML(ruby_v.to_s)}</code>" if ruby_v && !ruby_v.to_s.empty?
      ver_bits << "#{format_int_fn.call(clusters.size)} root-cause cluster#{clusters.size == 1 ? '' : 's'}"
      ver_bits << "#{format_int_fn.call(total_buckets)} bucket#{total_buckets == 1 ? '' : 's'}"
      ver_bits << "#{format_int_fn.call(total_occ)} occurrence#{total_occ == 1 ? '' : 's'}"

      group_pills_sub = by_group.empty? ? "0 groups" : by_group.map { |g, cnt| "#{cnt} #{CGI.escapeHTML(g)}" }.join(" &bull; ")

      body_card = if clusters.empty?
                    <<~EMPTY
                      <div class="table-card" style="padding: 24px; color: var(--muted); text-align: center;">
                        Triage completed with 0 crash or differential divergence buckets.
                      </div>
                    EMPTY
                  else
                    group_buttons = ([["all", "All (#{clusters.size})"]] + by_group.map { |g, cnt| [g, "#{g} (#{cnt})"] }).each_with_index.map do |(gk, glabel), i|
                      cls = i.zero? ? "cov-btn" : "cov-btn cov-btn-secondary"
                      %(<button type="button" class="#{cls}" data-triage-group="#{CGI.escapeHTML(gk)}" onclick="filterTriageClusters(#{Helpers.topo_js_arg(gk)}, this)">#{CGI.escapeHTML(glabel)}</button>)
                    end.join(" ")

                    rows_html = clusters.each_with_index.map do |c, idx|
                      cid = c["cluster_id"].to_s
                      group = c["group"].to_s.empty? ? "prism_flaw" : c["group"].to_s
                      rep = c["representative"].is_a?(Hash) ? c["representative"] : {}
                      headline = rep["headline"].to_s.gsub(/\s*\[detail:.*$/, "").strip
                      reasons = Array(c["reasons"]&.keys)
                      reasons = Array(c["buckets"]).filter_map { |b| b["reason"] }.uniq if reasons.empty?
                      if headline.empty?
                        r0 = reasons.first.to_s
                        repro = rep["reproduced_by"].to_s
                        headline = if r0 == "hang"
                                     repro.empty? ? "Timeout / hang (no stderr output)" : "Timeout / hang in #{repro} (no stderr output)"
                                   elsif !r0.empty? && r0 != "unknown"
                                     repro.empty? ? "Fatal signal #{r0} (no stderr output)" : "Fatal signal #{r0} in #{repro} (no stderr output)"
                                   else
                                     "(no headline)"
                                   end
                      end
                      top_frame = rep["top_prism_frame"].to_s
                      digest_line = defined?(FuzzInspect) ? FuzzInspect.format_cluster_digest_line(c, rep) : ""
                      preview = rep["source_preview"].to_s
                      occ = c["occurrences"].to_i
                      bcnt = c["bucket_count"].to_i
                      first_str = (defined?(FuzzInspect) && !c["first_elapsed_ms"].nil?) ? FuzzInspect.format_elapsed(c["first_elapsed_ms"]) : "-"
                      reason_badges = reasons.first(3).map { |r| %(<span class="sched-pill">#{CGI.escapeHTML(r.to_s)}</span>) }.join(" ")

                      workers_map = if c["by_worker"].is_a?(Hash) && !c["by_worker"].empty?
                                      c["by_worker"]
                                    else
                                      agg = Hash.new(0)
                                      Array(c["buckets"]).each do |mb|
                                        raw_bw = meta_by_id.dig(mb["bucket_id"].to_s, "occurrences", "by_worker")
                                        next unless raw_bw.is_a?(Hash)

                                        raw_bw.each { |w, cnt| agg[w.to_s] += cnt.to_i if cnt.to_i > 0 }
                                      end
                                      agg
                                    end
                      worker_pills = workers_map.sort_by { |w, cnt| [-cnt.to_i, w.to_s] }.first(4).map do |w, cnt|
                        %(<span class="excl-pill"><code>#{CGI.escapeHTML(w.to_s)}</code> <strong>#{format_int_fn.call(cnt.to_i)}</strong></span>)
                      end.join(" ")

                      member_buckets = Array(c["buckets"])
                      member_buckets = [rep] if member_buckets.empty? && !rep.empty?
                      drawer_id = "triage-drawer-#{idx}"
                      search_blob = [
                        cid, group, headline, top_frame, digest_line, preview,
                        reasons.join(" "), workers_map.keys.join(" "),
                        member_buckets.map { |b| "#{b['bucket_id']} #{b['source_preview']} #{b['headline']}" }.join(" ")
                      ].join(" ").downcase

                      trace_lines = Array(rep["prism_trace"]).first(6).map { |fr| CGI.escapeHTML(fr.to_s) }.join(" &rarr; ")
                      opts_lbl = rep["options_label"].to_s
                      header_hex = rep["header_hex"].to_s
                      loupe_btn = if rep["loupe_url"] && !rep["loupe_url"].to_s.empty?
                                    %(<a class="cov-link" href="#{CGI.escapeHTML(rep['loupe_url'].to_s)}" target="_blank" rel="noopener" onclick="event.stopPropagation()">Loupe &nearr;</a>)
                                  else
                                    ""
                                  end

                      bucket_rows = member_buckets.map do |b|
                        bid = b["bucket_id"].to_s
                        b_occ = b["occurrences"].to_i
                        b_repro = b["reproduced_by"].to_s
                        b_size = b["min_size_bytes"]
                        b_prev = b["source_preview"].to_s
                        b_opts = b["options_label"].to_s
                        b_hex = b["header_hex"].to_s
                        b_tags = defined?(FuzzInspect) ? FuzzInspect.format_bucket_digest_tags(b["digest"]) : ""
                        links = []
                        unless bid.empty?
                          links << %(<a class="cov-link" href="#{CGI.escapeHTML("#{trel}/#{bid}/input.min")}" target="_blank" rel="noopener">input.min</a>) if File.file?(File.join(triage_dir, bid, "input.min"))
                          links << %(<a class="cov-link muted" href="#{CGI.escapeHTML("#{trel}/#{bid}/meta.json")}" target="_blank" rel="noopener">meta.json</a>) if File.file?(File.join(triage_dir, bid, "meta.json"))
                          links << %(<a class="cov-link muted" href="#{CGI.escapeHTML("#{trel}/#{bid}/verify.sh")}" target="_blank" rel="noopener">verify.sh</a>) if File.file?(File.join(triage_dir, bid, "verify.sh"))
                        end
                        links << %(<a class="cov-link" href="#{CGI.escapeHTML(b['loupe_url'].to_s)}" target="_blank" rel="noopener">Loupe &nearr;</a>) if b["loupe_url"] && !b["loupe_url"].to_s.empty?
                        opt_cell = [b_opts.empty? ? nil : b_opts, b_hex.empty? ? nil : "hdr:#{b_hex}", b_tags.strip.empty? ? nil : b_tags.strip].compact.join(" &bull; ")

                        <<~BROW
                          <tr>
                            <td><code>#{CGI.escapeHTML(bid)}</code></td>
                            <td class="num">#{format_int_fn.call(b_occ)}</td>
                            <td><code>#{CGI.escapeHTML(b_repro.empty? ? "-" : File.basename(b_repro))}</code></td>
                            <td class="num">#{b_size ? "#{b_size}B" : "&mdash;"}</td>
                            <td class="muted">#{opt_cell.empty? ? "&mdash;" : CGI.escapeHTML(opt_cell)}</td>
                            <td><code class="triage-snippet">#{CGI.escapeHTML(b_prev.empty? ? "-" : b_prev)}</code></td>
                            <td style="white-space:nowrap;">#{links.empty? ? "<span class=\"muted\">&mdash;</span>" : links.join(" &middot; ")}</td>
                          </tr>
                        BROW
                      end.join("\n")

                      meta_chips = []
                      meta_chips << "<span>Explain: <code>./campaigns/default.rb explain -- #{CGI.escapeHTML(cid)}</code></span>"
                      meta_chips << "<span>Verify: <code>./campaigns/default.rb verify -- --cluster #{CGI.escapeHTML(cid)}</code></span>"
                      meta_chips << "<span>Options: <code>#{CGI.escapeHTML(opts_lbl)}</code> (#{CGI.escapeHTML(header_hex)})</span>" unless opts_lbl.empty? && header_hex.empty?

                      <<~CROW
                        <tr class="clickable-row triage-cluster-row" data-drawer-id="#{drawer_id}" data-group="#{CGI.escapeHTML(group)}" data-search="#{CGI.escapeHTML(search_blob)}" onclick="toggleHunkDrawer('#{drawer_id}')">
                          <td>
                            <span id="caret-#{drawer_id}" class="caret">&#9656;</span>
                            <strong>#{CGI.escapeHTML(cid)}</strong>
                            <div style="margin-top:4px;"><span class="badge #{triage_group_badge_class(group)}">#{CGI.escapeHTML(group)}</span></div>
                          </td>
                          <td>
                            <div><strong>#{CGI.escapeHTML(headline)}</strong></div>
                            #{top_frame.empty? ? "" : "<div class=\"muted\">in <code>#{CGI.escapeHTML(top_frame)}</code></div>"}
                            #{digest_line.empty? ? "" : "<div class=\"muted\" style=\"margin-top:2px;\">#{CGI.escapeHTML(digest_line)}</div>"}
                            #{preview.empty? ? "" : "<pre class=\"evo-preview\" style=\"max-height:54px;margin-top:5px;\">#{CGI.escapeHTML(preview)}</pre>"}
                          </td>
                          <td>#{reason_badges.empty? ? "<span class=\"muted\">&mdash;</span>" : reason_badges}</td>
                          <td>#{worker_pills.empty? ? "<span class=\"muted\">&mdash;</span>" : worker_pills}</td>
                          <td class="num">#{CGI.escapeHTML(first_str)}</td>
                          <td class="num">#{format_int_fn.call(bcnt)}</td>
                          <td class="num"><strong>#{format_int_fn.call(occ)}</strong></td>
                          <td class="num" onclick="event.stopPropagation()">#{loupe_btn}</td>
                        </tr>
                        <tr id="#{drawer_id}" class="hunk-drawer-row" style="display:none;">
                          <td colspan="8" style="background: rgba(15, 23, 42, 0.72); padding: 14px 18px;">
                            <div style="display:flex;flex-wrap:wrap;gap:14px;font-size:0.78rem;color:var(--muted);margin-bottom:10px;">
                              #{meta_chips.join(" ")}
                            </div>
                            #{trace_lines.empty? ? "" : "<div class=\"muted\" style=\"margin-bottom:10px;\">Trace: <code>#{trace_lines}</code></div>"}
                            <div class="table-card" style="background:#0b0f19;">
                              <table>
                                <thead>
                                  <tr>
                                    <th>Bucket</th>
                                    <th class="num">Occ</th>
                                    <th>Repro Binary</th>
                                    <th class="num">Min Size</th>
                                    <th>Options / Digest</th>
                                    <th>Payload Preview</th>
                                    <th>Artifacts</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  #{bucket_rows}
                                </tbody>
                              </table>
                            </div>
                          </td>
                        </tr>
                      CROW
                    end.join("\n")

                    <<~CLUSTERS_TABLE
                      <div class="table-card" style="margin-bottom: 22px;">
                        <div class="table-card-header">
                          <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
                            <input id="triage-search" type="search" placeholder="Search cluster, bucket, headline, frame, or payload..." oninput="filterTriageClusters(null, null)" class="triage-search-input"/>
                            <div id="triage-group-filters" style="display:flex;gap:6px;flex-wrap:wrap;">
                              #{group_buttons}
                            </div>
                          </div>
                          <button type="button" class="cov-btn cov-btn-secondary" data-expand-label="Expand All Clusters" data-collapse-label="Collapse All Clusters" onclick="toggleVisibleHunks(this, 'triage-clusters-tbody')">Expand All Clusters</button>
                        </div>
                        <table>
                          <thead>
                            <tr>
                              <th>Cluster</th>
                              <th>Symptom &amp; Reproducer</th>
                              <th>Reason</th>
                              <th>Workers</th>
                              <th class="num">First Seen</th>
                              <th class="num">Buckets</th>
                              <th class="num">Occ</th>
                              <th class="num">Inspect</th>
                            </tr>
                          </thead>
                          <tbody id="triage-clusters-tbody">
                            #{rows_html}
                          </tbody>
                        </table>
                      </div>
                    CLUSTERS_TABLE
                  end

      <<~HTML
        <section id="tab-triage" class="tab-panel">
          <div class="fuzzer-banner">
            <div>
              <h2><span class="legend-dot" style="background:#fb7185"></span> Triage Clusters &amp; Reproducers</h2>
              <p class="cmd-line">#{ver_bits.join(" &bull; ")}</p>
            </div>
            <div class="fuzzer-meta">
              #{meta_links.join(" ")}
            </div>
          </div>
          <div class="kpi-grid">
            <div class="kpi-card">
              <div class="kpi-label">Root-Cause Clusters</div>
              <div class="kpi-value">#{format_int_fn.call(clusters.size)}</div>
              <div class="kpi-sub">#{group_pills_sub}</div>
            </div>
            <div class="kpi-card">
              <div class="kpi-label">Unique Buckets</div>
              <div class="kpi-value">#{format_int_fn.call(total_buckets)}</div>
              <div class="kpi-sub">deduplicated signatures</div>
            </div>
            <div class="kpi-card">
              <div class="kpi-label">Triaged Occurrences</div>
              <div class="kpi-value #{total_occ > 0 ? 'text-danger' : ''}">#{format_int_fn.call(total_occ)}</div>
              <div class="kpi-sub">across archived crashes &amp; hangs</div>
            </div>
          </div>
          #{body_card}
        </section>
      HTML
    end
  end
end
