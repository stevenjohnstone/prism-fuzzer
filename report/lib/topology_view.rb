# frozen_string_literal: true

require "cgi/escape"
require "json"
require_relative "helpers"

module PrismFuzzerReport
  module TopologyView
    module_function

    def topo_trunc(text, max_len = 36)
      s = text.to_s
      return s if s.length <= max_len || max_len <= 3

      "#{s[0, max_len - 1]}…"
    end

    def topo_fuzzer_badges(fspec)
      return [] unless fspec.is_a?(Hash)

      badges = []
      shape = fspec["shape"].to_s
      case shape
      when "prism_parse"
        badges << "parse(#{fspec['source']})"
      when "prism_diff_ruby"
        badges << "diff(#{fspec['prism']} vs #{fspec['ruby']})"
      when "prism_diff_prism"
        badges << "diff(#{fspec['prism_a']} vs #{fspec['prism_b']})"
      when "prism_cross_oracle"
        badges << "cross:#{fspec['arch']}(#{fspec['source']})"
      else
        badges << shape unless shape.empty?
      end
      badges << "slow" if fspec["mode"].to_s == "slow"
      sans = Array(fspec["sanitizers"]).map(&:to_s).reject(&:empty?)
      badges << sans.join("+") unless sans.empty?
      badges << "IJON" if fspec["ijon"]
      badges << "cmplog" if fspec["afl"].to_s == "cmplog"
      badges << "sand" if fspec["afl"].to_s == "sand"
      if fspec["defines"].is_a?(Hash)
        fspec["defines"].each do |k, v|
          badges << (v == true ? k.to_s : "#{k}=#{v}")
        end
      end
      Array(fspec["cflags"]).each { |c| badges << c.to_s }
      badges
    end

    def topo_worker_card_svg(b, fspec:, wf:, col:, peer_sync: nil, companion: nil)
      w = b[:spec]
      wid = w["id"].to_s
      fid = w["fuzzer"].to_s
      is_main = w["afl_role"].to_s == "main"
      sched = w["schedule"].to_s.empty? ? "default" : w["schedule"].to_s
      badges = topo_fuzzer_badges(fspec)
      line2 = "#{fid} · #{badges.join(' · ')}"

      meta_parts = []
      meta_parts << "self_pass" if w.dig("seeds", "filter") == "self_pass"
      if w.dig("seeds", "shard_total").to_i > 1
        meta_parts << "shard #{w.dig('seeds', 'shard_index').to_i + 1}/#{w.dig('seeds', 'shard_total').to_i}"
      end
      if !is_main && wf
        imp_to_main = peer_sync && peer_sync[:imported_by_main].to_i
        synced_in = wf[:corpus_imported].to_i
        meta_parts << "↑+#{Helpers.format_compact(imp_to_main)}→M" if imp_to_main && imp_to_main > 0
        meta_parts << "↓#{Helpers.format_compact(synced_in)}" if synced_in > 0
      end

      stat_txt = if wf && wf[:execs_done].to_i > 0
                   "#{Helpers.format_compact(wf[:execs_done])} execs"
                 elsif wf
                   "0 execs"
                 else
                   "configured"
                 end
      crashes = wf ? wf[:saved_crashes].to_i : 0
      role_tag = is_main ? "MASTER -M" : "-S"
      role_w = is_main ? 62 : 26
      role_fill = is_main ? "#1d4ed8" : "#1e293b"
      role_txt = is_main ? "#dbeafe" : "#94a3b8"
      sched_w = 56
      sched_x = b[:x] + b[:w] - sched_w - 10
      role_x = sched_x - role_w - 4

      card_fill = is_main ? "#152238" : "#131c2e"
      card_stroke = is_main ? "#2d4a7c" : "#283548"
      clickable = !wf.nil?
      cls = clickable ? "topo-node topo-clickable" : "topo-node"
      onclk = clickable ? %( onclick="selectTab(#{Helpers.topo_js_arg(wid)})") : ""

      crash_svg = if crashes > 0
                    lbl = "#{crashes}c"
                    cw = [lbl.length * 6 + 12, 32].max
                    cx = b[:x] + b[:w] - 86 - cw
                    tx = cx + cw * 0.5
                    <<~CR
                      <rect x="#{cx}" y="#{b[:y] + 49}" width="#{cw}" height="15" rx="4" fill="rgba(251,113,133,0.22)" />
                      <text x="#{tx.round(1)}" y="#{b[:y] + 60}" text-anchor="middle" fill="#fb7185" font-size="9.5" font-weight="700">#{lbl}</text>
                    CR
                  else
                    ""
                  end

      companion_svg = if companion
                        cy = b[:y] + b[:h] - 25
                        cw = b[:w] - 24
                        clbl = "#{companion[:kind]}: #{companion[:fuzzer]}"
                        <<~COMP
                          <rect x="#{b[:x] + 12}" y="#{cy}" width="#{cw}" height="18" rx="4" fill="#0b1220" stroke="#334155" stroke-width="0.9" />
                          <text x="#{b[:x] + 20}" y="#{cy + 12}" fill="#7dd3fc" font-size="9.2" font-weight="600">⇄ companion</text>
                          <text x="#{b[:x] + cw + 4}" y="#{cy + 12}" text-anchor="end" fill="#cbd5e1" font-size="9.2" font-family="ui-monospace, SFMono-Regular, Menlo, monospace">#{CGI.escapeHTML(topo_trunc(clbl, 34))}</text>
                        COMP
                      else
                        ""
                      end

      <<~SVG
        <g class="#{cls}"#{onclk}>
          <title>Worker #{CGI.escapeHTML(wid)} (#{role_tag}, #{CGI.escapeHTML(sched)}) — #{CGI.escapeHTML(line2)}#{companion ? "\nCompanion: #{CGI.escapeHTML(companion[:kind])} #{CGI.escapeHTML(companion[:fuzzer])}" : ""}#{clickable ? "\nClick to open worker page" : ""}</title>
          <rect class="topo-card-bg" x="#{b[:x]}" y="#{b[:y]}" width="#{b[:w]}" height="#{b[:h]}" rx="8" fill="#{card_fill}" stroke="#{card_stroke}" stroke-width="#{is_main ? 1.5 : 1.2}" />
          <rect x="#{b[:x]}" y="#{b[:y]}" width="4" height="#{b[:h]}" rx="2" fill="#{CGI.escapeHTML(col)}" />
          <circle cx="#{b[:x] + 15}" cy="#{b[:y] + 19}" r="4.5" fill="#{CGI.escapeHTML(col)}" />
          <text x="#{b[:x] + 25}" y="#{b[:y] + 23}" fill="#f3f4f6" font-size="12.5" font-weight="700">#{CGI.escapeHTML(topo_trunc(wid, is_main ? 20 : 18))}</text>
          <rect x="#{role_x}" y="#{b[:y] + 10}" width="#{role_w}" height="16" rx="4" fill="#{role_fill}" />
          <text x="#{(role_x + role_w * 0.5).round(1)}" y="#{b[:y] + 21}" text-anchor="middle" fill="#{role_txt}" font-size="9.2" font-weight="700">#{role_tag}</text>
          <rect x="#{sched_x}" y="#{b[:y] + 10}" width="#{sched_w}" height="16" rx="4" fill="#1e293b" />
          <text x="#{(sched_x + sched_w * 0.5).round(1)}" y="#{b[:y] + 21}" text-anchor="middle" fill="#cbd5e1" font-size="9.5" font-weight="600">#{CGI.escapeHTML(topo_trunc(sched, 8))}</text>
          <text x="#{b[:x] + 14}" y="#{b[:y] + 42}" fill="#cbd5e1" font-size="9.8">#{CGI.escapeHTML(topo_trunc(line2, b[:w] >= 355 ? 68 : 64))}</text>
          <text x="#{b[:x] + 14}" y="#{b[:y] + 61}" fill="#64748b" font-size="9.3">#{CGI.escapeHTML(topo_trunc(meta_parts.join(' · '), crashes > 0 ? 36 : 46))}</text>
          #{crash_svg}
          <text x="#{b[:x] + b[:w] - 10}" y="#{b[:y] + 60}" text-anchor="end" fill="#9ca3af" font-size="9.5" font-variant-numeric="tabular-nums">#{CGI.escapeHTML(stat_txt)}</text>
          #{companion_svg}
        </g>
      SVG
    end

    def topo_grammar_card_svg(b, wf:, has_consumer:)
      gspec = b[:spec]
      gw = b[:worker]
      gwid = gw ? gw["id"].to_s : b[:id].to_s
      col = wf ? wf[:color] : (gspec["color"] || "#34d399")
      sched = (wf && wf[:sched]) || gspec["schedule"] || "grammar"
      fuz_name = gspec["fuzzer"].to_s
      sub = fuz_name.empty? ? "lrama · #{gspec['source']}" : "lrama · #{gspec['source']} (#{fuz_name})"
      stats_txt = if wf
                    rate = wf[:files_per_sec].to_f > 0 ? " · #{Helpers.format_compact(wf[:files_per_sec])}/s" : ""
                    "#{Helpers.format_compact(wf[:files_created])} files#{rate}"
                  else
                    has_consumer ? "configured (-F)" : "configured"
                  end
      clickable = wf && gw
      cls = clickable ? "topo-node topo-clickable" : "topo-node"
      onclk = clickable ? %( onclick="selectTab(#{Helpers.topo_js_arg(gwid)})") : ""

      <<~SVG
        <g class="#{cls}"#{onclk}>
          <title>#{clickable ? "Live grammar generator #{CGI.escapeHTML(gwid)} — click to open telemetry page" : "Grammar generator #{CGI.escapeHTML(gwid)}"}</title>
          <rect class="topo-card-bg" x="#{b[:x]}" y="#{b[:y]}" width="#{b[:w]}" height="#{b[:h]}" rx="8" fill="#111827" stroke="#283548" stroke-width="1.2" />
          <rect x="#{b[:x]}" y="#{b[:y]}" width="4" height="#{b[:h]}" rx="2" fill="#{CGI.escapeHTML(col)}" />
          <circle cx="#{b[:x] + 15}" cy="#{b[:y] + 19}" r="4.2" fill="#{CGI.escapeHTML(col)}" />
          <text x="#{b[:x] + 25}" y="#{b[:y] + 23}" fill="#f3f4f6" font-size="12" font-weight="700">#{CGI.escapeHTML(topo_trunc(gwid, 14))}</text>
          <rect x="#{b[:x] + b[:w] - 118}" y="#{b[:y] + 10}" width="54" height="16" rx="4" fill="#064e3b" />
          <text x="#{b[:x] + b[:w] - 91}" y="#{b[:y] + 21}" text-anchor="middle" fill="#6ee7b7" font-size="9" font-weight="700">grammar</text>
          <rect x="#{b[:x] + b[:w] - 60}" y="#{b[:y] + 10}" width="50" height="16" rx="4" fill="#1e293b" />
          <text x="#{b[:x] + b[:w] - 35}" y="#{b[:y] + 21}" text-anchor="middle" fill="#cbd5e1" font-size="9.2" font-weight="600">#{CGI.escapeHTML(topo_trunc(sched, 7))}</text>
          <text x="#{b[:x] + 13}" y="#{b[:y] + 42}" fill="#9ca3af" font-size="10">#{CGI.escapeHTML(topo_trunc(sub, 34))}</text>
          <text x="#{b[:x] + 13}" y="#{b[:y] + 60}" fill="#64748b" font-size="9.5">lrama generator</text>
          <text x="#{b[:x] + b[:w] - 10}" y="#{b[:y] + 60}" text-anchor="end" fill="#cbd5e1" font-size="9.5" font-variant-numeric="tabular-nums">#{CGI.escapeHTML(stats_txt)}</text>
        </g>
      SVG
    end

    def topo_sync_spine_svg(gb:, masters:, secondaries:, worker_boxes:, id_prefix:)
      return ["", ""] if secondaries.empty? && masters.size <= 1

      edges = +""
      labels = +""
      spine_x = (gb[:x] + gb[:w] * 0.5).round(1)

      if secondaries.size == 1 && masters.size <= 1
        sb = worker_boxes[secondaries.first["id"].to_s]
        return ["", ""] unless sb

        sx = (sb[:x] + sb[:w] * 0.5).round(1)
        if masters.size == 1
          mb = worker_boxes[masters.first["id"].to_s]
          return ["", ""] unless mb

          y1 = mb[:y] + mb[:h]
          y2 = sb[:y]
          edges << %(<line x1="#{sx}" y1="#{y1}" x2="#{sx}" y2="#{y2}" stroke="#3b82f6" stroke-width="1.8" stroke-opacity="0.75" marker-start="url(##{id_prefix}-arr-blue)" marker-end="url(##{id_prefix}-arr-blue)" />)
          mid_y = ((y1 + y2) * 0.5).round(1)
          labels << %(<g transform="translate(#{sx},#{mid_y})"><rect x="-34" y="-8" width="68" height="16" rx="4" fill="#0d1320" stroke="#2d4a7c" stroke-width="1"/><text x="0" y="3" text-anchor="middle" fill="#93c5fd" font-size="8.8" font-weight="600">queue sync</text></g>)
        end
        return [edges, labels]
      end

      sec_boxes = secondaries.filter_map { |w| worker_boxes[w["id"].to_s] }
      return ["", ""] if sec_boxes.empty?

      last_sy = sec_boxes.map { |sb| sb[:y] + sb[:h] * 0.5 }.max.round(1)

      if masters.size == 1
        mb = worker_boxes[masters.first["id"].to_s]
        if mb
          y_top = mb[:y] + mb[:h]
          edges << %(<line x1="#{spine_x}" y1="#{y_top}" x2="#{spine_x}" y2="#{last_sy}" stroke="#3b82f6" stroke-width="1.8" stroke-opacity="0.72" marker-start="url(##{id_prefix}-arr-blue)" />)
          pill_y = (y_top + 19).round(1)
          labels << %(<g transform="translate(#{spine_x},#{pill_y})"><rect x="-34" y="-8" width="68" height="16" rx="4" fill="#0d1320" stroke="#2d4a7c" stroke-width="1"/><text x="0" y="3" text-anchor="middle" fill="#93c5fd" font-size="8.8" font-weight="600">queue sync</text></g>)
        end
      elsif masters.size >= 2
        m_boxes = masters.filter_map { |w| worker_boxes[w["id"].to_s] }
        unless m_boxes.empty?
          bus_y = m_boxes.map { |mb| mb[:y] + mb[:h] }.max + 14
          x_min = m_boxes.map { |mb| mb[:x] + mb[:w] * 0.5 }.min.round(1)
          x_max = m_boxes.map { |mb| mb[:x] + mb[:w] * 0.5 }.max.round(1)
          m_boxes.each do |mb|
            mx = (mb[:x] + mb[:w] * 0.5).round(1)
            edges << %(<line x1="#{mx}" y1="#{mb[:y] + mb[:h]}" x2="#{mx}" y2="#{bus_y}" stroke="#3b82f6" stroke-width="1.6" stroke-opacity="0.7" marker-start="url(##{id_prefix}-arr-blue)" />)
          end
          edges << %(<line x1="#{x_min}" y1="#{bus_y}" x2="#{x_max}" y2="#{bus_y}" stroke="#3b82f6" stroke-width="1.6" stroke-opacity="0.7" />)
          edges << %(<line x1="#{spine_x}" y1="#{bus_y}" x2="#{spine_x}" y2="#{last_sy}" stroke="#3b82f6" stroke-width="1.8" stroke-opacity="0.72" />)
        end
      else
        # Secondary-only sync pool: top horizontal bar dropping down center spine
        top_sy = sec_boxes.map { |sb| sb[:y] }.min - 14
        edges << %(<line x1="#{spine_x}" y1="#{top_sy}" x2="#{spine_x}" y2="#{last_sy}" stroke="#475569" stroke-width="1.6" stroke-opacity="0.75" />)
        labels << %(<g transform="translate(#{spine_x},#{top_sy})"><rect x="-34" y="-8" width="68" height="16" rx="4" fill="#0d1320" stroke="#334155" stroke-width="1"/><text x="0" y="3" text-anchor="middle" fill="#94a3b8" font-size="8.8" font-weight="600">queue sync</text></g>)
      end

      sec_boxes.each do |sb|
        sy = (sb[:y] + sb[:h] * 0.5).round(1)
        target_x = sb[:x] < spine_x ? (sb[:x] + sb[:w]) : sb[:x]
        edges << %(<line x1="#{spine_x}" y1="#{sy}" x2="#{target_x}" y2="#{sy}" stroke="#3b82f6" stroke-width="1.5" stroke-opacity="0.68" marker-end="url(##{id_prefix}-arr-blue)" />)
        edges << %(<circle cx="#{spine_x}" cy="#{sy}" r="3.2" fill="#60a5fa" />)
      end

      [edges, labels]
    end

    def render_topology_diagram_svg(topo, worker_by_name:, color_by_name:, peer_sync_by_name:, peer_import_stats: {}, id_prefix: "topo", topo_colors: {})
      return "" unless topo.is_a?(Hash)

      generators = topo["generators"].is_a?(Hash) ? topo["generators"] : {}
      fuzzers_cfg = topo["fuzzers"].is_a?(Hash) ? topo["fuzzers"] : {}
      sync_groups = topo["sync_groups"].is_a?(Hash) ? topo["sync_groups"] : {}
      workers = Array(topo["workers"])

      gen_worker_by_gid = {}
      afl_workers_by_sg = Hash.new { |h, k| h[k] = [] }
      workers.each do |w|
        next unless w.is_a?(Hash)

        if w["kind"].to_s == "generator"
          gen_worker_by_gid[w["generator"].to_s] = w
        else
          afl_workers_by_sg[w["sync_group"].to_s] << w
        end
      end

      grammar_gens = generators.select { |_gid, gs| gs.is_a?(Hash) && gs["kind"].to_s == "grammar" }
      has_grammar = !grammar_gens.empty?
      has_peers = workers.any? { |w| !Array(w["peer_imports"]).empty? }

      left_x = 18
      left_w = 228
      grp_x = has_grammar ? (left_x + left_w + 76) : 18
      sec_w = 342
      master_w = 358
      spine_gap = 48
      grp_pad_x = 18
      grp_head_h = 38
      master_gap_y = 40
      row_gap_y = 14
      grp_pad_b = 16

      card_height_for = lambda do |w|
        has_comp = (w["cmplog"] && !w["cmplog"].to_s.empty?) || (w["aux_fuzzer"] && !w["aux_fuzzer"].to_s.empty?)
        has_comp ? 96 : 74
      end

      companion_for = lambda do |w|
        if w["cmplog"] && !w["cmplog"].to_s.empty?
          { kind: "cmplog (-c)", fuzzer: w["cmplog"].to_s }
        elsif w["aux_fuzzer"] && !w["aux_fuzzer"].to_s.empty?
          { kind: "aux_fuzzer", fuzzer: w["aux_fuzzer"].to_s }
        end
      end

      any_two_col = afl_workers_by_sg.values.any? do |list|
        m_cnt = list.count { |w| w["afl_role"].to_s == "main" }
        s_cnt = list.size - m_cnt
        m_cnt >= 2 || s_cnt >= 2
      end
      unified_box_w = any_two_col ? (grp_pad_x * 2 + sec_w * 2 + spine_gap) : (grp_pad_x * 2 + [master_w, sec_w].max + 120)

      sg_order = sync_groups.keys.sort_by { |gid| [sync_groups[gid]["primary"] ? 0 : 1, sync_groups.keys.index(gid)] }
      cur_y = 18
      sg_boxes = {}
      sg_roles = {}
      worker_boxes = {}

      place_two_col = lambda do |list, spine_x, start_y, gid|
        y_pos = start_y
        list.each_slice(2) do |row|
          rh = row.map { |w| card_height_for.call(w) }.max
          row.each_with_index do |w, c|
            wx = c.zero? ? (spine_x - spine_gap * 0.5 - sec_w).round : (spine_x + spine_gap * 0.5).round
            worker_boxes[w["id"].to_s] = { x: wx, y: y_pos, w: sec_w, h: rh, sg: gid, spec: w, companion: companion_for.call(w) }
          end
          y_pos += rh + row_gap_y
        end
        y_pos - row_gap_y
      end

      sg_order.each do |gid|
        sg = sync_groups[gid]
        list = afl_workers_by_sg[gid]
        masters = list.select { |w| w["afl_role"].to_s == "main" }
        secondaries = list.reject { |w| w["afl_role"].to_s == "main" }
        sg_roles[gid] = { masters: masters, secondaries: secondaries }

        box_w = unified_box_w
        spine_x = grp_x + box_w * 0.5
        inner_y = cur_y + grp_head_h

        if masters.size == 1
          wm = masters.first
          mh = card_height_for.call(wm)
          mx = (spine_x - master_w * 0.5).round
          worker_boxes[wm["id"].to_s] = { x: mx, y: inner_y, w: master_w, h: mh, sg: gid, spec: wm, companion: companion_for.call(wm) }
          inner_y += mh
        elsif masters.size >= 2
          inner_y = place_two_col.call(masters, spine_x, inner_y, gid)
        end

        if !secondaries.empty?
          inner_y += masters.empty? ? 22 : master_gap_y
          if secondaries.size == 1 && masters.size <= 1
            ws = secondaries.first
            sh = card_height_for.call(ws)
            sx = (spine_x - sec_w * 0.5).round
            worker_boxes[ws["id"].to_s] = { x: sx, y: inner_y, w: sec_w, h: sh, sg: gid, spec: ws, companion: companion_for.call(ws) }
            inner_y += sh
          else
            inner_y = place_two_col.call(secondaries, spine_x, inner_y, gid)
          end
        end

        inner_y += 28 if list.empty?
        box_h = (inner_y - cur_y) + grp_pad_b
        sg_boxes[gid] = {
          x: grp_x, y: cur_y, w: box_w, h: box_h, spec: sg,
          masters_count: masters.size, secondaries_count: secondaries.size
        }
        cur_y += box_h + 20
      end

      gen_boxes = {}
      min_gen_y = 18
      grammar_gens.each do |gid, gspec|
        h = 72
        consumers = workers.select { |w| w["kind"].to_s != "generator" && Array(w["foreign_sync"]).map(&:to_s).include?(gid) }
        target_y = if !consumers.empty? && (wb = worker_boxes[consumers.first["id"].to_s])
                     wb[:y] + (wb[:h] - h) * 0.5
                   elsif gspec["sync_group"] && (gb = sg_boxes[gspec["sync_group"].to_s])
                     gb[:y] + 38
                   else
                     min_gen_y
                   end
        gy = [target_y.round, min_gen_y].max
        gen_boxes[gid] = {
          id: gid, x: left_x, y: gy, w: left_w, h: h, spec: gspec,
          worker: gen_worker_by_gid[gid], consumers: consumers
        }
        min_gen_y = gy + h + 16
      end

      right_edge = grp_x + unified_box_w
      total_w = has_peers ? (right_edge + 148) : (right_edge + 24)
      total_h = [cur_y + 8, min_gen_y + 8, 170].max

      edges_svg = +""
      labels_svg = +""

      sg_boxes.each do |gid, gb|
        roles = sg_roles[gid]
        e_str, l_str = topo_sync_spine_svg(
          gb: gb,
          masters: roles[:masters],
          secondaries: roles[:secondaries],
          worker_boxes: worker_boxes,
          id_prefix: id_prefix
        )
        edges_svg << e_str
        labels_svg << l_str
      end

      gen_boxes.each do |_gid, genb|
        gw = genb[:worker]
        gwid = gw ? gw["id"].to_s : genb[:id].to_s
        wf = worker_by_name[gwid]
        gx1 = genb[:x] + genb[:w]
        gy1 = genb[:y] + genb[:h] * 0.5
        genb[:consumers].each do |cw|
          cid = cw["id"].to_s
          wb = worker_boxes[cid]
          next unless wb

          x2 = wb[:x]
          y2 = wb[:y] + wb[:h] * 0.5
          mid_x = ((gx1 + x2) * 0.5).round(1)
          edges_svg << %(<path d="M#{gx1},#{gy1.round(1)} C#{mid_x},#{gy1.round(1)} #{mid_x},#{y2.round(1)} #{x2},#{y2.round(1)}" fill="none" stroke="#34d399" stroke-width="2.1" stroke-opacity="0.92" marker-end="url(##{id_prefix}-arr-green)" />)
          ps = wf && peer_sync_by_name[gwid]
          tag = if ps && ps[:consumer_name] == cid && ps[:imported_by_main].to_i > 0
                  "-F +#{Helpers.format_compact(ps[:imported_by_main])}"
                else
                  "-F foreign_sync"
                end
          pw = [tag.length * 6 + 12, 32].max
          lx = (x2 - grp_x >= 120 ? (grp_x + (x2 - grp_x) * 0.5) : ((gx1 + x2) * 0.5)).round(1)
          ly = ((gy1 + y2) * 0.5).round(1)
          labels_svg << %(<g transform="translate(#{lx},#{ly})"><rect x="#{-pw / 2}" y="-9" width="#{pw}" height="17" rx="4" fill="#064e3b" stroke="#34d399" stroke-width="1"/><text x="0" y="3" text-anchor="middle" fill="#6ee7b7" font-size="8.8" font-weight="700">#{CGI.escapeHTML(tag)}</text></g>)
        end
      end

      peer_idx = 0
      workers.each do |dst_w|
        dst_id = dst_w["id"].to_s
        dst_wb = worker_boxes[dst_id]
        next unless dst_wb

        Array(dst_w["peer_imports"]).each do |pi|
          src_id = pi["worker"].to_s
          src_wb = worker_boxes[src_id]
          next unless src_wb

          x1 = src_wb[:x] + src_wb[:w]
          y1 = src_wb[:y] + src_wb[:h] * 0.5
          x2 = dst_wb[:x] + dst_wb[:w]
          y2 = dst_wb[:y] + dst_wb[:h] * 0.5
          lane_x = right_edge + 38 + (peer_idx % 4) * 28
          col = color_by_name[src_id] || "#a78bfa"
          edges_svg << %(<path d="M#{x1},#{y1.round(1)} C#{lane_x},#{y1.round(1)} #{lane_x},#{y2.round(1)} #{x2},#{y2.round(1)}" fill="none" stroke="#{CGI.escapeHTML(col)}" stroke-width="2" stroke-opacity="0.9" marker-end="url(##{id_prefix}-arr-purple)" />)

          ps = peer_import_stats[[src_id, dst_id]]
          ps ||= peer_sync_by_name[src_id] if peer_sync_by_name.dig(src_id, :consumer_name) == dst_id
          lbl = pi["alias"].to_s.empty? ? src_id : pi["alias"].to_s
          tag = if ps
                  "+#{Helpers.format_int(ps[:imported_by_main])}/#{Helpers.format_int(ps[:tested_by_main])}"
                else
                  "peer:#{topo_trunc(lbl, 11)}"
                end
          pill_w = [tag.length * 6 + 12, 48].max
          mid_x = (0.125 * (x1 + x2) + 0.75 * lane_x).round(1)
          mid_y = ((y1 + y2) * 0.5).round(1)
          labels_svg << %(<g transform="translate(#{mid_x},#{mid_y})"><rect x="#{-pill_w / 2}" y="-9" width="#{pill_w}" height="17" rx="5" fill="#0f172a" stroke="#{CGI.escapeHTML(col)}" stroke-width="1"/><text x="0" y="3" text-anchor="middle" fill="#e2e8f0" font-size="9" font-weight="600">#{CGI.escapeHTML(tag)}</text></g>)
          peer_idx += 1
        end
      end

      groups_svg = +""
      sg_boxes.each do |gid, gb|
        sg = gb[:spec]
        is_prim = sg["primary"] == true
        stroke = is_prim ? "#334155" : "#283548"
        role_summary = []
        role_summary << "#{gb[:masters_count]} master" if gb[:masters_count] > 0
        if gb[:secondaries_count] > 0
          role_summary << (gb[:secondaries_count] == 1 ? "1 secondary" : "#{gb[:secondaries_count]} secondaries")
        end
        role_txt = role_summary.empty? ? "0 workers" : role_summary.join(", ")
        groups_svg << <<~SVG
          <g class="topo-group">
            <rect x="#{gb[:x]}" y="#{gb[:y]}" width="#{gb[:w]}" height="#{gb[:h]}" rx="10" fill="#0d1320" stroke="#{stroke}" stroke-width="1.3" stroke-dasharray="5 3" />
            <text x="#{gb[:x] + 16}" y="#{gb[:y] + 22}" fill="#cbd5e1" font-size="11.5" font-weight="700">sync_group: #{CGI.escapeHTML(gid)}</text>
            <text x="#{gb[:x] + gb[:w] - 16}" y="#{gb[:y] + 22}" text-anchor="end" fill="#64748b" font-size="10">#{is_prim ? 'primary · ' : ''}#{CGI.escapeHTML(sg['dir'].to_s)} (#{CGI.escapeHTML(role_txt)})</text>
          </g>
        SVG
      end

      nodes_svg = +""
      gen_boxes.each_value do |b|
        gwid = b[:worker] ? b[:worker]["id"].to_s : b[:id].to_s
        nodes_svg << topo_grammar_card_svg(b, wf: worker_by_name[gwid], has_consumer: !b[:consumers].empty?)
      end

      worker_boxes.each do |wid, b|
        w = b[:spec]
        fspec = fuzzers_cfg[w["fuzzer"].to_s] || {}
        nodes_svg << topo_worker_card_svg(
          b,
          fspec: fspec,
          wf: worker_by_name[wid],
          col: color_by_name[wid] || topo_colors[wid] || w["color"] || "#60a5fa",
          peer_sync: peer_sync_by_name[wid],
          companion: b[:companion]
        )
      end

      <<~SVG
        <svg class="topo-svg" viewBox="0 0 #{total_w} #{total_h}" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Campaign fuzzing architecture diagram">
          <defs>
            <marker id="#{id_prefix}-arr-muted" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#64748b" />
            </marker>
            <marker id="#{id_prefix}-arr-blue" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#60a5fa" />
            </marker>
            <marker id="#{id_prefix}-arr-green" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#34d399" />
            </marker>
            <marker id="#{id_prefix}-arr-purple" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#a78bfa" />
            </marker>
          </defs>
          <g class="topo-groups">#{groups_svg}</g>
          <g class="topo-edges">#{edges_svg}</g>
          <g class="topo-nodes">#{nodes_svg}</g>
          <g class="topo-edge-labels">#{labels_svg}</g>
        </svg>
      SVG
    end

    def render_topology_context_html(topo)
      return "" unless topo.is_a?(Hash)

      sources = topo["sources"].is_a?(Hash) ? topo["sources"] : {}
      corpus_gens = (topo["generators"].is_a?(Hash) ? topo["generators"] : {}).select { |_, g| g.is_a?(Hash) && g["kind"].to_s == "corpus" }

      src_chips = sources.filter_map do |sid, spec|
        next unless spec.is_a?(Hash)

        kind = spec["kind"].to_s
        commit = spec["commit"].to_s
        ref_txt = commit.empty? ? (spec["ref"].to_s.empty? ? "local" : spec["ref"].to_s) : commit[0, 10]
        applied = Array(spec.dig("resolved", "applied_patches")).size
        detail = applied > 0 ? "+#{applied}p" : (kind == "ruby" ? "oracle" : "clean")
        accent_cls = kind == "ruby" ? "topo-chip-orange" : "topo-chip-blue"
        %(<span class="topo-chip"><span class="topo-chip-badge #{accent_cls}">#{CGI.escapeHTML(kind)}</span><strong>#{CGI.escapeHTML(sid)}</strong><code>#{CGI.escapeHTML(topo_trunc(ref_txt, 14))}</code><span class="muted">#{CGI.escapeHTML(detail)}</span></span>)
      end

      seed_chips = corpus_gens.map do |gid, gspec|
        %(<span class="topo-chip"><span class="topo-chip-badge topo-chip-amber">startup -i</span><strong>#{CGI.escapeHTML(gid)}</strong><span class="muted">from #{CGI.escapeHTML(gspec['source'].to_s)}</span></span>)
      end

      return "" if src_chips.empty? && seed_chips.empty?

      <<~HTML
        <div class="topo-context-strip">
          #{src_chips.empty? ? "" : %(<div class="topo-context-group"><span class="topo-context-label">Targets</span>#{src_chips.join}</div>)}
          #{seed_chips.empty? ? "" : %(<div class="topo-context-group"><span class="topo-context-label">Initial Corpus</span>#{seed_chips.join}</div>)}
        </div>
      HTML
    end

    def render_topology_legend_html(topo, include_json_btn: false)
      gens = topo["generators"].is_a?(Hash) ? topo["generators"] : {}
      has_grammar = gens.values.any? { |g| g.is_a?(Hash) && g["kind"].to_s == "grammar" }
      has_peers = Array(topo["workers"]).any? { |w| w.is_a?(Hash) && !Array(w["peer_imports"]).empty? }
      items = [
        %(<span class="topo-leg-item"><span class="legend-dot" style="background:#3b82f6"></span> Master (-M) &harr; Secondary (-S) sync</span>)
      ]
      items << %(<span class="topo-leg-item"><span class="legend-dot" style="background:#34d399"></span> foreign_sync (-F)</span>) if has_grammar
      items << %(<span class="topo-leg-item"><span class="legend-dot" style="background:#a78bfa"></span> peer_import bridge</span>) if has_peers
      items << %(<button type="button" class="cov-btn cov-btn-secondary" onclick="selectTab('topology')">View Definition JSON &rarr;</button>) if include_json_btn
      items.join("\n          ")
    end

    def render_topology_overview_card(topo, diagram_svg:)
      return "" unless topo.is_a?(Hash) && !diagram_svg.to_s.empty?

      name = topo["name"].to_s
      src_count = topo["sources"].is_a?(Hash) ? topo["sources"].size : 0
      fuz_count = topo["fuzzers"].is_a?(Hash) ? topo["fuzzers"].size : 0
      grp_count = topo["sync_groups"].is_a?(Hash) ? topo["sync_groups"].size : 0
      wrk_count = Array(topo["workers"]).size

      <<~HTML
        <details class="chart-card topo-overview-card" open style="margin-bottom: 20px;">
          <summary class="chart-header topo-summary-head">
            <div>
              <h3>Runtime Architecture &mdash; <code>#{CGI.escapeHTML(name)}</code></h3>
              <p class="chart-sub">#{grp_count} sync group#{grp_count == 1 ? '' : 's'} &bull; #{wrk_count} running worker#{wrk_count == 1 ? '' : 's'} &bull; #{fuz_count} fuzzer binary#{fuz_count == 1 ? '' : 'ies'} &bull; #{src_count} target#{src_count == 1 ? '' : 's'} &bull; Click any worker node to open its page</p>
            </div>
            <div class="topo-legend" onclick="event.preventDefault(); event.stopPropagation();">
              #{render_topology_legend_html(topo, include_json_btn: true)}
            </div>
          </summary>
          #{render_topology_context_html(topo)}
          <div class="topo-svg-wrap">
            #{diagram_svg}
          </div>
        </details>
      HTML
    end

    def render_topology_tab_html(topo, diagram_svg:, inner_only: false)
      return "" unless topo.is_a?(Hash)

      name = topo["name"].to_s
      defaults = topo["defaults"].is_a?(Hash) ? topo["defaults"] : {}
      lc = topo["lifecycle"].is_a?(Hash) ? topo["lifecycle"] : {}
      src_rows = (topo["sources"].is_a?(Hash) ? topo["sources"] : {}).map do |sid, s|
        next unless s.is_a?(Hash)

        applied = Array(s.dig("resolved", "applied_patches"))
        skipped = Array(s.dig("resolved", "skipped_patches"))
        patch_str = applied.empty? ? (skipped.empty? ? "none" : "skipped #{skipped.size}") : applied.join(", ")
        <<~ROW
          <tr>
            <td><strong><code>#{CGI.escapeHTML(sid)}</code></strong></td>
            <td><span class="sched-pill">#{CGI.escapeHTML(s["kind"].to_s)}</span></td>
            <td><code>#{CGI.escapeHTML((s["requested_ref"] || s["ref"] || s["dir"] || "-").to_s)}</code></td>
            <td><code>#{CGI.escapeHTML((s["commit"] || "-").to_s)}</code></td>
            <td><span class="muted">#{CGI.escapeHTML(patch_str)}</span></td>
          </tr>
        ROW
      end.compact.join("\n")

      fuzzer_rows = (topo["fuzzers"].is_a?(Hash) ? topo["fuzzers"] : {}).map do |fid, fspec|
        next unless fspec.is_a?(Hash)

        badges = topo_fuzzer_badges(fspec).map { |b| %(<span class="sched-pill">#{CGI.escapeHTML(b)}</span>) }.join(" ")
        <<~ROW
          <tr>
            <td><strong><code>#{CGI.escapeHTML(fid)}</code></strong></td>
            <td><code>#{CGI.escapeHTML(fspec["shape"].to_s)}</code></td>
            <td>#{badges}</td>
            <td><code>#{CGI.escapeHTML(File.basename(fspec["binary"].to_s))}</code></td>
          </tr>
        ROW
      end.compact.join("\n")

      pretty_json = JSON.pretty_generate(topo)
      meta_bits = []
      meta_bits << "Schema v#{topo['schema_version']}" if topo["schema_version"]
      meta_bits << "Max input #{defaults['max_input_size']} B" if defaults["max_input_size"]
      meta_bits << "Max alloc #{defaults['max_allocated_mb']} MB" if defaults["max_allocated_mb"]
      meta_bits << "Duration #{Helpers.format_duration(lc['duration_seconds'])}" if lc["duration_seconds"].to_i > 0

      inner_html = <<~HTML
        <div class="fuzzer-banner">
          <div>
            <h2><span class="legend-dot" style="background:#38bdf8"></span> Campaign Topology &mdash; <code>#{CGI.escapeHTML(name)}</code></h2>
            <p class="cmd-line">#{CGI.escapeHTML(meta_bits.join(" • "))}</p>
          </div>
          <div class="fuzzer-meta">
            <button type="button" class="cov-btn cov-btn-secondary" onclick="copyTopologyJson(this)">Copy JSON</button>
            <button type="button" class="cov-btn" onclick="downloadTopologyJson(#{Helpers.topo_js_arg(name)})">Download topology.json</button>
          </div>
        </div>

        <div class="chart-card topo-overview-card" style="margin-bottom: 20px;">
          <div class="chart-header">
            <div>
              <h3>Runtime Architecture</h3>
              <p class="chart-sub">Masters (-M), synchronized Secondaries (-S), companions, and live generator feeds. Click any node to open its page.</p>
            </div>
            <div class="topo-legend">
              #{render_topology_legend_html(topo, include_json_btn: false)}
            </div>
          </div>
          #{render_topology_context_html(topo)}
          <div class="topo-svg-wrap">
            #{diagram_svg}
          </div>
        </div>

        <div class="table-card" style="margin-bottom: 20px;">
          <div class="table-card-header">
            <h3>Sources</h3>
          </div>
          <table>
            <thead>
              <tr>
                <th>Source ID</th>
                <th>Kind</th>
                <th>Requested Ref / Dir</th>
                <th>Resolved Commit</th>
                <th>Patches</th>
              </tr>
            </thead>
            <tbody>#{src_rows}</tbody>
          </table>
        </div>

        <div class="table-card" style="margin-bottom: 20px;">
          <div class="table-card-header">
            <h3>Fuzzer Targets</h3>
          </div>
          <table>
            <thead>
              <tr>
                <th>Fuzzer ID</th>
                <th>Shape</th>
                <th>Configuration</th>
                <th>Binary</th>
              </tr>
            </thead>
            <tbody>#{fuzzer_rows}</tbody>
          </table>
        </div>

        <div class="chart-card">
          <div class="chart-header">
            <div>
              <h3>Resolved Topology Definition (JSON)</h3>
              <p class="chart-sub">Complete static IR specification captured for this campaign.</p>
            </div>
          </div>
          <pre id="topology-json-pre" class="topo-json-pre"><code>#{CGI.escapeHTML(pretty_json)}</code></pre>
        </div>
      HTML
      return inner_html if inner_only

      <<~HTML
        <section id="tab-topology" class="tab-panel">
          #{inner_html}
        </section>
      HTML
    end
  end
end
