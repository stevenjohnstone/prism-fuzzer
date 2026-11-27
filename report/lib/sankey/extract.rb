# frozen_string_literal: true

require "json"
require "set"
require_relative "../../../runtime/common"

module FuzzSankey
  module_function

  # Maps a raw AFL++ sync:<source> token to a canonical worker name
  # using the provided topology's sync_aliases and legacy naming fallbacks.
  def normalize_sync_source(src, topo: nil, worker: nil)
    aliases = defined?(PrismFuzzer::Topology) && topo ? PrismFuzzer::Topology.sync_aliases(topo) : {}
    return aliases[src] if aliases.key?(src)
    return "ijon" if src =~ /\Aijon(?:_\d+|_peer)?\z/
    return "diff" if src =~ /\Adiff(?:_\d+|_peer)?\z/

    src
  end

  # Returns existing AFL++ sync root directories relevant to afl_dir and topo.
  def sync_roots_for_afl(afl_dir, topo: nil)
    roots = []
    if topo && defined?(PrismFuzzer::Topology) && afl_dir && !afl_dir.to_s.empty?
      roots.concat(PrismFuzzer::Topology.sync_group_dirs(topo, base_dir: File.dirname(File.expand_path(afl_dir))))
    end
    roots.concat([afl_dir, "#{afl_dir}-ijon"]) if afl_dir && !afl_dir.to_s.empty?
    roots.map { |d| File.expand_path(d) }.uniq.select { |d| Dir.exist?(d) }
  end

  # Resolves an explicit or workspace-inferred AFL++ output directory.
  def resolve_afl_dir(triage_dir, explicit_afl_dir)
    return explicit_afl_dir if explicit_afl_dir && !explicit_afl_dir.empty?

    cands = if defined?(PrismFuzzer::Topology) && PrismFuzzer::Topology.respond_to?(:triage_workspace_candidates)
              PrismFuzzer::Topology.triage_workspace_candidates(triage_dir)
            else
              [File.dirname(File.expand_path(triage_dir))]
            end
    cands.map { |r| File.join(r, "afl") }.find { |d| Dir.exist?(d) }
  end

  # Builds a memoized lambda tracing an AFL++ queue/crash file back to its root origin.
  def build_origin_tracer(afl_dir, topo: nil)
    return nil unless afl_dir && Dir.exist?(afl_dir)

    roots = sync_roots_for_afl(afl_dir, topo: topo)
    q_index = {}
    roots.each do |root|
      Dir.glob(File.join(root, "*/queue")).each do |qdir|
        next if File.symlink?(qdir)

        worker = File.basename(File.dirname(qdir))
        Dir.children(qdir).each do |fname|
          next unless fname.start_with?("id:")

          id = fname[/\Aid:(\d+)/, 1]
          q_index[[worker, id.to_i]] = File.join(qdir, fname) if id
        end
      end
    end

    return nil if q_index.empty?

    memo = {}
    trace_root = lambda do |path, seen = {}|
      return memo[path] if memo.key?(path)
      return "unknown" if seen[path]

      seen = seen.merge(path => true)
      base = File.basename(path)
      worker = File.basename(File.dirname(File.dirname(path)))
      kind = File.basename(File.dirname(path))

      root = if base =~ /\Aid:\d+(?:,sig:\d+)?,sync:([^,]+),src:(?:id:)?(\d+)/
               peer = normalize_sync_source(Regexp.last_match(1), topo: topo, worker: worker)
               parent = q_index[[peer, Regexp.last_match(2).to_i]]
               parent ? trace_root.call(parent, seen) : "sync:#{peer}"
             elsif base =~ /\Aid:\d+(?:,sig:\d+)?,src:(\d+)(?:\+(\d+))?/
               p1 = q_index[[worker, Regexp.last_match(1).to_i]]
               p2 = Regexp.last_match(2) ? q_index[[worker, Regexp.last_match(2).to_i]] : nil
               r1 = p1 ? trace_root.call(p1, seen) : nil
               r2 = p2 ? trace_root.call(p2, seen) : nil
               r1 || r2 || "local"
             elsif base =~ /\Aid:\d+(?:,time:\d+,execs:\d+)?,orig:/
               "corpus"
             else
               "unknown"
             end
      memo[path] = root if kind == "queue"
      root
    end

    trace_root
  end

  def bucket_category(bucket_meta)
    inv = bucket_meta.dig("symptom", "invariant")
    if inv.is_a?(Hash) && !inv["namespace"].to_s.empty?
      ns = inv["namespace"].to_s
      kind = inv.dig("fields", "kind").to_s
      return (%w[diff_parse_y cruby_pipeline cruby_compile].include?(ns) && !kind.empty?) ? "#{ns}: #{kind}" : ns
    end

    reason = bucket_meta["reason"].to_s
    reason.empty? ? "unknown" : reason
  end

  def concise_cluster_title(cluster)
    rep = cluster["representative"] || {}
    headline = rep["headline"].to_s.gsub(/\s*\[detail:.*$/, "").strip
    cid = cluster["cluster_id"].to_s

    short = case headline
            when /\AINVARIANT\[diff_parse_y\]:\s*kind=syntax_mismatch\s+sub=(\S+)/
              sub = Regexp.last_match(1)
              ctx = headline[/\bctx=([A-Za-z0-9_.:<>+-]+)/, 1]
              ctx && !%w[top none].include?(ctx) ? "diff: #{sub} (#{ctx})" : "diff: #{sub}"
            when /\AINVARIANT\[diff_parse_y\]:\s*kind=ast_preexe_order_mismatch/
              "diff: preexe_order"
            when /\AINVARIANT\[diff_parse_y\]:\s*kind=ast_tree_mismatch(?:\s+sub=(\S+))?(?:\s+ctx=\S+)?(?:\s+prism=(\S+)\s+cruby=(\S+))?/
              tag = [Regexp.last_match(2), Regexp.last_match(3)].compact.join(" vs ")
              tag.empty? ? "diff: ast_tree (#{Regexp.last_match(1)})" : "diff: tree #{tag}"
            when /\AINVARIANT\[diff_parse_y\]:\s*kind=(\S+)(?:\s+node=(\S+))?/
              node = Regexp.last_match(2)
              node ? "diff: #{Regexp.last_match(1).sub(/_mismatch\z/, '')} #{node}" : "diff: #{Regexp.last_match(1)}"
            when /\AINVARIANT\[([^\]]+)\]:\s*(.+)/
              ns = Regexp.last_match(1)
              rest = Regexp.last_match(2)
              type_m = rest[/\btype=([A-Za-z0-9_]+)/, 1]
              site_m = rest[/\bsite=([A-Za-z0-9_]+)/, 1]
              sub_m = rest[/\bsub=([A-Za-z0-9_]+)/, 1]
              sec_m = rest[/\bsection=([A-Za-z0-9_]+)/, 1]
              kind_m = rest[/\bkind=([A-Za-z0-9_]+)/, 1]
              site_label = if site_m
                             inferred = site_m[/\Apm_([a-z0-9_]+?)_node_(?:[a-z0-9_]+_)?(?:create|new)\z/, 1]
                             inferred ? inferred.upcase : site_m
                           end
              clean_type = type_m&.delete_prefix("PM_")&.delete_suffix("_NODE")
              detail = if ns == "stream_diff" && sub_m
                         clean_type ? "#{sub_m} (#{clean_type})" : sub_m
                       elsif (ns.start_with?("oracle_") || ns == "diff_prism") && sec_m
                         clean_type ? "#{sec_m}: #{clean_type}" : sec_m
                       else
                         clean_type || site_label || kind_m || rest[0, 32]
                       end
              "#{ns}: #{detail}"
            when /\A(?:==\d+==)?ERROR:\s*\w+Sanitizer:\s*(detected memory leaks|[A-Za-z0-9_-]+)(?:\s+in\s+([A-Za-z0-9_]+))?/
              kind = Regexp.last_match(1).tr(" ", "-")
              fn = Regexp.last_match(2) || rep["top_prism_frame"].to_s.split("@", 2).first
              fn && !fn.empty? ? "#{kind} (#{fn})" : kind
            when /\ASUMMARY:\s*\w+Sanitizer:\s*([^(\n]+)/
              Regexp.last_match(1).strip[0, 34]
            else
              headline[0, 34]
            end

    if short.nil? || short.empty?
      r0 = Array(cluster["reasons"]&.keys).first.to_s
      repro = rep["reproduced_by"].to_s
      short = (!r0.empty? && !repro.empty?) ? "#{r0} (#{repro})" : rep["bucket_id"].to_s
    end
    short = "#{short[0, 33]}..." if short.length > 36
    "#{cid} · #{short}"
  end

  def load_triage_sources(triage_dir:, metadata_path: nil, clusters_path: nil)
    m_path = metadata_path || File.join(triage_dir, "metadata.json")
    c_path = clusters_path || File.join(triage_dir, "clusters.json")

    metadata = PrismFuzzer::Common.read_json(m_path, context: "FuzzSankey")
    metadata = nil unless metadata.is_a?(Hash)
    clusters = PrismFuzzer::Common.read_json(c_path, context: "FuzzSankey")
    clusters = nil unless clusters.is_a?(Hash)

    if metadata.nil? && Dir.exist?(triage_dir)
      buckets = Dir.glob(File.join(triage_dir, "*", "*", "meta.json")).sort.filter_map do |p|
        data = PrismFuzzer::Common.read_json(p, context: "FuzzSankey")
        data if data.is_a?(Hash)
      end
      metadata = { "buckets" => buckets } unless buckets.empty?
    end

    abort "Missing triage metadata in '#{m_path}'" if metadata.nil?

    if clusters.nil?
      cluster_rb = File.expand_path("../../../triage/cluster.rb", __dir__)
      if File.file?(cluster_rb)
        require cluster_rb
        clusters = FuzzClustering.cluster_metadata(metadata, metadata_path: m_path)
      else
        buckets = Array(metadata["buckets"])
        clusters = {
          "clusters" => buckets.each_with_index.map do |b, i|
            {
              "cluster_id" => format("bucket-%02d", i + 1),
              "group" => case b["verify_profile"].to_s
                         when "diff_parse_y" then "diff_parse_y"
                         when "diff_prism" then "diff_prism"
                         else "prism_flaw"
                         end,
              "bucket_count" => 1,
              "occurrences" => b.dig("occurrences", "count").to_i,
              "reasons" => { b["reason"].to_s => 1 },
              "representative" => {
                "bucket_id" => b["bucket_id"],
                "headline" => b.dig("symptom", "headline").to_s,
                "loupe_url" => b.dig("input", "loupe_url")
              },
              "buckets" => [{ "bucket_id" => b["bucket_id"] }]
            }
          end
        }
      end
    end

    [metadata, clusters, m_path, c_path]
  end

  # Reads occurrences.jsonl from each bucket directory when present to obtain
  # per-occurrence AFL++ seed origins.
  def collect_bucket_occurrence_details(triage_dir, bucket_meta, origin_tracer)
    bid = bucket_meta["bucket_id"].to_s
    occ_path = File.join(triage_dir, bid, "occurrences.jsonl")
    by_origin_worker = Hash.new(0)

    if File.file?(occ_path) && origin_tracer
      begin
        File.foreach(occ_path) do |line|
          next if line.strip.empty?

          rec = begin
                  JSON.parse(line)
                rescue JSON::ParserError, EncodingError => e
                  warn "FuzzSankey: malformed JSONL line in #{occ_path}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
                  next
                end
          next unless rec.is_a?(Hash)

          w = rec["worker"].to_s
          next if w.empty?

          orig = origin_tracer.call(rec["path"].to_s)
          by_origin_worker[[orig, w]] += 1
        end
      rescue Errno::ENOENT, Errno::ESTALE
        nil
      rescue SystemCallError, IOError => e
        warn "FuzzSankey: failed to read #{occ_path}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
      end
    end

    {
      by_origin_worker: by_origin_worker
    }
  end

  # Extracts a self-contained Sankey dataset (including its discovered/bound topology).
  def extract_dataset(triage_dir:, metadata_path: nil, clusters_path: nil, afl_dir: nil, trace_origins: true, topo: nil)
    metadata, clusters_doc, m_path, c_path = load_triage_sources(
      triage_dir: triage_dir,
      metadata_path: metadata_path,
      clusters_path: clusters_path
    )

    resolved_afl = trace_origins ? resolve_afl_dir(triage_dir, afl_dir) : nil
    topo = defined?(PrismFuzzer::Topology) ? PrismFuzzer::Topology.discover(triage_dir: triage_dir, afl_dir: resolved_afl || afl_dir) : nil if topo.nil?
    origin_tracer = resolved_afl ? build_origin_tracer(resolved_afl, topo: topo) : nil

    buckets_by_id = {}
    Array(metadata["buckets"]).each do |b|
      next unless b.is_a?(Hash) && b["bucket_id"]

      buckets_by_id[b["bucket_id"].to_s] = b
    end

    # Collect active fleet workers (even those with 0 crashes) for footer telemetry.
    zero_crash_workers = []
    if resolved_afl && Dir.exist?(resolved_afl)
      skip_names = Set.new(%w[ijon_peer])
      if topo
        skip_names.merge(Array(topo.dig("generators")&.keys))
        skip_names.merge(topo.fetch("sync_aliases", {}).keys)
        Array(topo["workers"]).each do |w|
          skip_names.add(w["id"].to_s) if w.is_a?(Hash) && w["kind"].to_s == "generator"
        end
      end
      sync_roots_for_afl(resolved_afl, topo: topo).each do |root|
        Dir.children(root).sort.each do |w|
          next if w.start_with?(".") || skip_names.include?(w) || File.symlink?(File.join(root, w, "queue"))
          stats_p = File.join(root, w, "fuzzer_stats")
          next unless File.file?(stats_p)
          next if File.read(stats_p, 2048).to_s.match?(/^\s*fuzzer_role\s*:\s*generator\s*$/)

          zero_crash_workers << w
        end
      end
      zero_crash_workers.uniq!
    end

    cluster_meta = {}
    records = []
    seen_bucket_ids = Set.new

    Array(clusters_doc["clusters"]).each_with_index do |c, idx|
      cid = c["cluster_id"].to_s
      group = c["group"].to_s
      group = "prism_flaw" if group.empty?
      label = concise_cluster_title(c)
      rep = c["representative"] || {}
      rep_b = buckets_by_id[rep["bucket_id"].to_s] || {}

      cluster_meta[cid] = {
        id: cid,
        rank: idx,
        group: group,
        label: label,
        headline: rep["headline"].to_s,
        rep_bucket: rep["bucket_id"].to_s,
        loupe_url: rep["loupe_url"] || rep_b.dig("input", "loupe_url"),
        bucket_count: c["bucket_count"].to_i,
        occurrences: c["occurrences"].to_i,
        first_elapsed_ms: c["first_elapsed_ms"]
      }

      Array(c["buckets"]).each do |cb|
        bid = cb["bucket_id"].to_s
        b = buckets_by_id[bid]
        next unless b

        seen_bucket_ids.add(bid)
        cat = bucket_category(b)
        by_worker = b.dig("occurrences", "by_worker") || {}
        by_worker = { "unknown" => [cb["occurrences"].to_i, 1].max } if by_worker.empty?

        details = collect_bucket_occurrence_details(triage_dir, b, origin_tracer)

        # Normalize per-worker origin counts so occurrences always sum exactly to by_worker.
        occ_by_origin_by_worker = Hash.new { |h, k| h[k] = Hash.new(0) }
        details[:by_origin_worker].each do |(orig, w), cnt|
          occ_by_origin_by_worker[w][orig] += cnt
        end

        by_worker.each do |w, raw_cnt|
          cnt = raw_cnt.to_i
          next if cnt <= 0

          origin_slices = if origin_tracer
                            slice_map = occ_by_origin_by_worker[w]
                            if slice_map.empty?
                              { "unknown" => cnt }
                            else
                              diff_cnt = cnt - slice_map.values.sum
                              if diff_cnt > 0
                                out_s = slice_map.dup
                                out_s["unknown"] = (out_s["unknown"] || 0) + diff_cnt
                                out_s
                              else
                                slice_map
                              end
                            end
                          else
                            { nil => cnt }
                          end

          primary_orig = origin_slices.max_by { |o, n| [n, o.to_s] }&.first

          origin_slices.each do |orig, occ_weight|
            next if occ_weight <= 0

            is_primary = (orig == primary_orig)
            records << {
              origin: orig,
              worker: w,
              category: cat,
              bucket_id: bid,
              cluster_id: cid,
              group: group,
              occurrences: occ_weight,
              bucket_presence: is_primary ? 1 : 0
            }
          end
        end
      end
    end

    discovered_workers = records.map { |r| r[:worker] }.uniq
    zero_crash_workers -= discovered_workers

    {
      metadata_path: m_path,
      clusters_path: c_path,
      afl_dir: resolved_afl,
      topology: topo,
      has_origins: !origin_tracer.nil?,
      clusters: cluster_meta,
      records: records,
      active_workers: discovered_workers.sort_by { |w| worker_sort_rank(w, topo: topo) },
      zero_crash_workers: zero_crash_workers.sort_by { |w| worker_sort_rank(w, topo: topo) },
      bucket_total: seen_bucket_ids.size
    }
  end
end
