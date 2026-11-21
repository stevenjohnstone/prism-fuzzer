# frozen_string_literal: true

require "set"

module FuzzSankey
  module_function

  # Resolves a deterministic hex color for a node/worker using explicit topology overrides first.
  def color_for(name, layer_kind: nil, topo: nil)
    _ = layer_kind
    return OTHER_COLOR if name == "__other__"

    topo_colors = (topo && defined?(PrismFuzzer::Topology)) ? PrismFuzzer::Topology.worker_colors(topo) : {}
    return topo_colors[name] if topo_colors.key?(name)
    return WORKER_COLORS[name] if WORKER_COLORS.key?(name)

    case name
    when /\Adiff-\d+\z/
      idx = name.delete_prefix("diff-").to_i
      %w[#fb923c #fdba74 #f59e0b #ea580c #fbbf24][(idx - 2) % 5]
    when /\Aoracle_arm32/, "arm32"
      "#2dd4bf"
    when /\Aoracle_ppc/, "ppc"
      "#e879f9"
    when /\Adiff_prism/, "diff_prism"
      "#facc15"
    when /\Adiff_parse_y/, "diff_parse_y"
      "#f97316"
    when "stream_diff"
      "#a78bfa"
    when "node_location", "diagnostic", "node_relation"
      "#34d399"
    when "recursion_depth"
      "#f472b6"
    else
      h = name.to_s.bytes.reduce(0) { |acc, b| (acc * 31 + b) & 0x7fffffff }
      FALLBACK_PALETTE[h % FALLBACK_PALETTE.size]
    end
  end

  # Computes deterministic worker ordering respecting topology worker_order when provided.
  def worker_sort_rank(name, topo: nil)
    topo_order = (topo && defined?(PrismFuzzer::Topology)) ? PrismFuzzer::Topology.worker_order(topo) : []
    t_idx = topo_order.index(name)
    return [0, t_idx, name] if t_idx

    order = %w[grammar corpus main main-2 ijon msan slow arm32 ppc diff prism_diff]
    idx = order.index(name)
    return [1, idx, name] if idx
    return [2, $1.to_i, name] if name =~ /\Adiff-(\d+)\z/

    [3, 0, name]
  end

  def normalize_layers_mode(raw, has_origins:)
    case raw.to_s
    when "2", "worker_cluster"
      %i[worker cluster]
    when "3", "worker_oracle_cluster", "worker_category_cluster"
      %i[worker category cluster]
    when "3o", "origin_worker_cluster"
      has_origins ? %i[origin worker cluster] : %i[worker cluster]
    when "4", "origin_worker_oracle_cluster", "origin_worker_category_cluster", "auto"
      has_origins ? %i[origin worker category cluster] : %i[worker category cluster]
    else
      has_origins ? %i[origin worker category cluster] : %i[worker category cluster]
    end
  end

  def layer_title(layer_sym)
    case layer_sym
    when :origin then "Seed Origin"
    when :worker then "Fuzzer Worker"
    when :category then "Invariant / Reason"
    when :cluster then "Root-Cause Cluster"
    else layer_sym.to_s
    end
  end

  def record_weight(rec, metric)
    case metric.to_s
    when "occurrences" then rec[:occurrences]
    when "buckets" then rec[:bucket_presence]
    else rec[:occurrences]
    end
  end

  # Builds weighted consecutive-layer edges from filtered records, aggregating
  # tail clusters beyond max_clusters BEFORE splitting into layer pairs so
  # intermediate nodes satisfy exact inflow == outflow conservation.
  def build_sankey_graph(dataset, metric: "occurrences", group: "all", layers_mode: "auto", max_clusters: DEFAULT_MAX_CLUSTERS, topo: nil)
    eff_topo = topo.nil? ? dataset[:topology] : topo
    layers = normalize_layers_mode(layers_mode, has_origins: dataset[:has_origins])
    cluster_weights = Hash.new(0)
    filtered = []

    dataset[:records].each do |rec|
      next if group != "all" && rec[:group] != group

      w = record_weight(rec, metric)
      next if w <= 0

      cluster_weights[rec[:cluster_id]] += w
      filtered << [rec, w]
    end

    kept_clusters = Set.new
    ordered_cids = cluster_weights.keys.sort_by do |cid|
      cm = dataset[:clusters][cid]
      [-cluster_weights[cid], cm ? cm[:rank] : 9999, cid]
    end

    limit = max_clusters.to_i
    if limit > 0 && ordered_cids.size > limit
      ordered_cids.first(limit - 1).each { |cid| kept_clusters.add(cid) }
    else
      ordered_cids.each { |cid| kept_clusters.add(cid) }
    end

    other_cids = ordered_cids.reject { |cid| kept_clusters.include?(cid) }

    node_meta = {}
    layer_nodes = Array.new(layers.size) { Set.new }
    edge_weights = Array.new(layers.size - 1) { Hash.new(0) }
    edge_origins = Array.new(layers.size - 1) { Hash.new { |h, k| h[k] = Hash.new(0) } }

    node_key = ->(col, raw_id) { "#{col}:#{raw_id}" }

    display_info = lambda do |col_sym, raw_id|
      case col_sym
      when :origin
        lbl = raw_id == "grammar" ? "grammar (lrama)" : (raw_id == "corpus" ? "initial corpus" : raw_id.to_s)
        { label: lbl, sub: "seed origin", color: color_for(raw_id, layer_kind: :origin, topo: eff_topo) }
      when :worker
        { label: raw_id.to_s, sub: "AFL++ worker", color: color_for(raw_id, layer_kind: :worker, topo: eff_topo) }
      when :category
        { label: raw_id.to_s.sub(/\Adiff_parse_y:\s*/, "diff: "), sub: "invariant / reason", color: color_for(raw_id, layer_kind: :category, topo: eff_topo) }
      when :cluster
        if raw_id == "__other__"
          {
            label: "Other clusters (#{other_cids.size})",
            sub: "collapsed tail clusters",
            color: OTHER_COLOR,
            headline: "Contains #{other_cids.first(6).join(', ')}#{other_cids.size > 6 ? ', ...' : ''}"
          }
        else
          cm = dataset[:clusters][raw_id] || {}
          {
            label: cm[:label] || raw_id.to_s,
            sub: cm[:group].to_s,
            color: case cm[:group]
                   when "diff_parse_y" then "#f97316"
                   when "diff_prism" then "#facc15"
                   when "cruby_crash" then "#a78bfa"
                   else "#60a5fa"
                   end,
            headline: cm[:headline],
            rep_bucket: cm[:rep_bucket],
            loupe_url: cm[:loupe_url],
            bucket_count: cm[:bucket_count],
            occurrences: cm[:occurrences],
            first_elapsed_ms: cm[:first_elapsed_ms]
          }
        end
      end
    end

    filtered.each do |(rec, w)|
      vals = layers.map do |sym|
        if sym == :cluster
          kept_clusters.include?(rec[:cluster_id]) ? rec[:cluster_id] : "__other__"
        else
          rec[sym].to_s
        end
      end

      vals.each_with_index do |raw_id, col_idx|
        k = node_key.call(col_idx, raw_id)
        layer_nodes[col_idx].add(k)
        unless node_meta.key?(k)
          info = display_info.call(layers[col_idx], raw_id)
          node_meta[k] = info.merge(key: k, col: col_idx, layer: layers[col_idx], raw_id: raw_id, value: 0)
        end
        node_meta[k][:value] += w
      end

      worker_color_key = rec[:worker].to_s
      (0...(layers.size - 1)).each do |c|
        sk = node_key.call(c, vals[c])
        dk = node_key.call(c + 1, vals[c + 1])
        edge_weights[c][[sk, dk]] += w
        edge_origins[c][[sk, dk]][worker_color_key] += w
      end
    end

    {
      metric: metric.to_s,
      group: group.to_s,
      layers: layers,
      topology: eff_topo,
      total_weight: filtered.sum { |_, w| w },
      cluster_count_visible: ordered_cids.size,
      other_cluster_count: other_cids.size,
      nodes: node_meta,
      layer_nodes: layer_nodes.map(&:to_a),
      edges: edge_weights,
      edge_workers: edge_origins
    }
  end

  # Assigns 2D column positions, barycenter ordering, and non-overlapping ribbon attachment slots.
  def compute_sankey_layout(graph, width: 1320, height: 700, min_node_h: 6.0, node_gap: 9.0, node_w: 18.0, topo: nil)
    eff_topo = topo.nil? ? graph[:topology] : topo
    layers = graph[:layers]
    n_cols = layers.size
    return graph.merge(width: width, height: 220, node_w: node_w, placed_nodes: {}, placed_links: []) if graph[:total_weight] <= 0

    margin_top = 42.0
    margin_bottom = 24.0
    margin_left = 175.0
    margin_right = 400.0
    plot_w = [width - margin_left - margin_right - node_w, 260.0].max
    col_step = n_cols > 1 ? (plot_w / (n_cols - 1)) : 0.0

    nodes = graph[:nodes]
    col_lists = graph[:layer_nodes].map(&:dup)

    # Initial deterministic order: worker order on :worker, descending value otherwise.
    col_lists.each_with_index do |keys, c|
      sym = layers[c]
      keys.sort_by! do |k|
        n = nodes[k]
        other_last = n[:raw_id] == "__other__" ? 1 : 0
        if sym == :worker
          [other_last] + worker_sort_rank(n[:raw_id], topo: eff_topo)
        else
          [other_last, -n[:value], n[:label]]
        end
      end
    end

    # Adjacency maps for barycenter crossing minimization.
    in_neighbors = Hash.new { |h, k| h[k] = [] }
    out_neighbors = Hash.new { |h, k| h[k] = [] }
    graph[:edges].each do |edge_map|
      edge_map.each do |(sk, dk), w|
        out_neighbors[sk] << [dk, w]
        in_neighbors[dk] << [sk, w]
      end
    end

    barycenter_sort = lambda do |col_idx, neighbor_map|
      ref_pos = {}
      adj_col = neighbor_map.equal?(in_neighbors) ? col_idx - 1 : col_idx + 1
      col_lists[adj_col].each_with_index { |k, idx| ref_pos[k] = idx.to_f }

      col_lists[col_idx].sort_by! do |k|
        n = nodes[k]
        other_last = n[:raw_id] == "__other__" ? 1 : 0
        nbrs = neighbor_map[k]
        w_sum = 0.0
        pos_sum = 0.0
        nbrs.each do |nk, w|
          p = ref_pos[nk]
          next unless p

          pos_sum += p * w
          w_sum += w
        end
        bary = w_sum > 0 ? (pos_sum / w_sum) : Float::INFINITY
        [other_last, bary, -n[:value], n[:label]]
      end
    end

    if n_cols >= 2
      8.times do
        (1...n_cols).each { |c| barycenter_sort.call(c, in_neighbors) }
        (n_cols - 2).downto(0) { |c| barycenter_sort.call(c, out_neighbors) }
      end
    end

    max_col_nodes = col_lists.map(&:size).max
    needed_h = [height.to_f, max_col_nodes * (min_node_h + node_gap) + margin_top + margin_bottom + 20.0].max
    avail_h = needed_h - margin_top - margin_bottom

    # Find largest linear scale ky where every column (after applying min_node_h
    # floor and node_gap spacing) fits within avail_h.
    col_fits = lambda do |ky|
      col_lists.all? do |keys|
        next true if keys.empty?

        h_sum = keys.sum { |k| [nodes[k][:value] * ky, min_node_h].max } + [keys.size - 1, 0].max * node_gap
        h_sum <= avail_h + 1e-6
      end
    end

    raw_ky = avail_h / [graph[:total_weight].to_f, 1.0].max
    lo = 0.0
    hi = raw_ky
    32.times do
      mid = (lo + hi) * 0.5
      if col_fits.call(mid)
        lo = mid
      else
        hi = mid
      end
    end
    ky = lo

    placed_nodes = {}
    col_x = Array.new(n_cols) { |c| margin_left + c * col_step }

    col_lists.each_with_index do |keys, c|
      heights = keys.map { |k| [nodes[k][:value] * ky, min_node_h].max }
      used = heights.sum + [keys.size - 1, 0].max * node_gap
      y = margin_top + [(avail_h - used) * 0.5, 0.0].max

      keys.each_with_index do |k, i|
        h = heights[i]
        placed_nodes[k] = nodes[k].merge(
          x: col_x[c],
          y: y,
          w: node_w,
          h: h,
          cy: y + h * 0.5,
          out_offset: 0.0,
          in_offset: 0.0
        )
        y += h + node_gap
      end
    end

    # Allocate non-overlapping ribbon attachment slots on each node's right and
    # left edges ordered by partner vertical center so ribbons never twist.
    out_groups = Hash.new { |h, k| h[k] = [] }
    in_groups = Hash.new { |h, k| h[k] = [] }
    links = []

    graph[:edges].each_with_index do |edge_map, c|
      edge_map.each do |(sk, dk), w|
        dom_worker = graph[:edge_workers][c][[sk, dk]].max_by { |wk, ww| [ww, wk] }&.first
        link = {
          col: c,
          src: sk,
          dst: dk,
          value: w,
          color: dom_worker ? color_for(dom_worker, layer_kind: :worker, topo: eff_topo) : placed_nodes[sk][:color],
          dom_worker: dom_worker
        }
        links << link
        out_groups[sk] << link
        in_groups[dk] << link
      end
    end

    slot_span = lambda do |node, link_val|
      # Distribute slots proportional to node's visual height so links stay
      # inside [y, y + h] cleanly even when min_node_h expanded tiny bars.
      node_val = [node[:value].to_f, 1.0].max
      (link_val.to_f / node_val) * node[:h]
    end

    out_groups.each do |sk, grp|
      snode = placed_nodes[sk]
      grp.sort_by! { |l| [placed_nodes[l[:dst]][:cy], -l[:value], l[:dst]] }
      cur_y = snode[:y]
      grp.each do |l|
        sh = slot_span.call(snode, l[:value])
        l[:sy0] = cur_y
        l[:sy1] = cur_y + sh
        cur_y += sh
      end
    end

    in_groups.each do |dk, grp|
      dnode = placed_nodes[dk]
      grp.sort_by! { |l| [placed_nodes[l[:src]][:cy], -l[:value], l[:src]] }
      cur_y = dnode[:y]
      grp.each do |l|
        th = slot_span.call(dnode, l[:value])
        l[:ty0] = cur_y
        l[:ty1] = cur_y + th
        cur_y += th
      end
    end

    links.sort_by! { |l| [-l[:value], placed_nodes[l[:src]][:y], placed_nodes[l[:dst]][:y]] }

    graph.merge(
      width: width,
      height: needed_h.ceil,
      node_w: node_w,
      margin_top: margin_top,
      col_x: col_x,
      col_lists: col_lists,
      placed_nodes: placed_nodes,
      placed_links: links
    )
  end
end
