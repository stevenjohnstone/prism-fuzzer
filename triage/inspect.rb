#!/usr/bin/env ruby
# frozen_string_literal: true

require "base64"
require "digest"
require "json"
require "optparse"
require "set"
require "uri"

require_relative "cluster"

module FuzzInspect
  DEFAULT_SOURCE_PREVIEW_MAX = 160

  class ConfigError < StandardError; end

  module_function

  def parse_csv_env(key)
    ENV.fetch(key, "").split(",").map(&:strip).reject(&:empty?)
  end

  def format_source_preview(source_bytes, max_chars: DEFAULT_SOURCE_PREVIEW_MAX)
    bytes = source_bytes.to_s.b
    return "" if bytes.empty?

    limit = [max_chars.to_i, 4].max
    max_scan_bytes = (limit + 1) * 4
    scan_bytes = bytes.bytesize > max_scan_bytes ? bytes.byteslice(0, max_scan_bytes) : bytes
    out = +""
    truncated = false

    scan_bytes.dup.force_encoding(Encoding::UTF_8).each_char do |ch|
      tok = if ch.valid_encoding?
              case ch
              when "\0" then "\\0"
              when "\n" then "\\n"
              when "\r" then "\\r"
              when "\t" then "\\t"
              when "\\" then "\\\\"
              else
                ord = ch.ord
                ord < 0x20 || ord == 0x7f ? format("\\x%02x", ord) : ch
              end
            else
              ch.bytes.map { |b| format("\\x%02x", b) }.join
            end

      if out.length + tok.length > limit
        truncated = true
        break
      end
      out << tok
    end

    return "#{out[0, [limit - 3, 0].max]}..." if truncated || bytes.bytesize > scan_bytes.bytesize

    out
  end

  def load_triage_report(triage_dir:, clusters_file: nil, metadata_path: nil, refresh: true, include_unreproducible: false)
    resolved_meta_path = metadata_path || File.join(triage_dir, "metadata.json")
    has_meta = File.file?(resolved_meta_path)
    metadata = has_meta ? JSON.parse(File.read(resolved_meta_path)) : nil

    if clusters_file
      raise ConfigError, "Missing clusters file: #{clusters_file}" unless File.file?(clusters_file)

      report = JSON.parse(File.read(clusters_file))
      unless report.is_a?(Hash) && report["clusters"].is_a?(Array)
        raise ConfigError, "Invalid clusters file (missing clusters array): #{clusters_file}"
      end
      return [report, metadata, clusters_file]
    end

    default_clusters = File.join(triage_dir, "clusters.json")
    if include_unreproducible && metadata
      report = FuzzClustering.cluster_metadata(metadata, include_unreproducible: true, metadata_path: resolved_meta_path)
      return [report, metadata, resolved_meta_path]
    end

    clusters_fresh = File.file?(default_clusters) && (!has_meta || !refresh || File.mtime(default_clusters) >= File.mtime(resolved_meta_path))
    if clusters_fresh
      report = JSON.parse(File.read(default_clusters))
      return [report, metadata, default_clusters] if report.is_a?(Hash) && report["clusters"].is_a?(Array)
    end

    raise ConfigError, "Missing clusters.json and metadata.json under '#{triage_dir}'" unless metadata

    report = FuzzClustering.cluster_metadata(metadata, metadata_path: resolved_meta_path)
    begin
      FuzzClustering.write_json_atomic(default_clusters, report)
    rescue SystemCallError
      # Ignore read-only mount errors when writing cache.
    end
    [report, metadata, default_clusters]
  end

  def enrich_bucket_entry(entry, meta_bucket, triage_dir:, read_files:)
    out = entry.dup
    if meta_bucket
      opt_meta = FuzzClustering.extract_bucket_options_meta(meta_bucket)
      sym_summary = FuzzClustering.extract_bucket_symptom_summary(meta_bucket)

      out["verify_profile"] ||= meta_bucket["verify_profile"] unless meta_bucket["verify_profile"].to_s.empty?
      out["reproduced_by"] ||= meta_bucket["reproduced_by"] unless meta_bucket["reproduced_by"].to_s.empty?
      out["header_hex"] ||= opt_meta[:header_hex] if opt_meta[:header_hex]
      out["options"] ||= opt_meta[:non_default_options] if opt_meta[:non_default_options]
      out["options_label"] ||= opt_meta[:options_label] if opt_meta[:options_label]
      out["has_shebang_prefix"] = true if !out.key?("has_shebang_prefix") && opt_meta[:has_shebang_prefix]
      out["loupe_url"] ||= opt_meta[:loupe_url] if opt_meta[:loupe_url]
      out["payload_sha256"] ||= opt_meta[:payload_sha256] if opt_meta[:payload_sha256]
      out["source_preview"] = opt_meta[:source_preview] if !out.key?("source_preview") && !opt_meta[:source_preview].nil?
      out["symptom"] ||= sym_summary if sym_summary
      if out["digest"].nil? && (dg = FuzzClustering.extract_bucket_digest(meta_bucket))
        out["digest"] = dg
      end
      if out["prism_trace"].nil?
        oracle = FuzzClustering.oracle_family(meta_bucket)
        tr = FuzzClustering.extract_prism_trace(meta_bucket["frames"], oracle: oracle)
        out["prism_trace"] = tr if tr.size > 1
      end
    end

    if read_files && triage_dir && (!out.key?("source_preview") || out["payload_sha256"].nil? || out["header_hex"].nil?)
      bid = out["bucket_id"].to_s
      min_path = bid.empty? ? nil : File.join(triage_dir, bid, "input.min")
      if min_path && File.file?(min_path)
        raw = File.binread(min_path)
        if raw.bytesize >= 4
          out["header_hex"] ||= raw.byteslice(0, 4).bytes.map { |b| format("%02x", b) }.join
          body = raw.byteslice(4..) || "".b
        else
          body = raw
        end
        out["payload_sha256"] ||= Digest::SHA256.hexdigest(body)
        out["source_preview"] = format_source_preview(body) unless out.key?("source_preview")
      end
    end

    out
  end

  def fallback_bucket_variant_data(bucket, cluster_group:, meta_bucket:)
    src = meta_bucket || bucket
    oracle = meta_bucket ? FuzzClustering.oracle_family(meta_bucket) : (cluster_group == "diff_parse_y" ? "diff_parse_y" : "crash_or_inv")
    diff_fields = src.is_a?(Hash) ? (FuzzClustering.extract_diff_fields(src) || bucket.dig("symptom", "invariant", "fields")) : nil
    {
      oracle: oracle,
      diff_fields: diff_fields,
      digest: bucket["digest"],
      symptom: bucket["symptom"],
      top_prism_frame: bucket["top_prism_frame"],
      reason: bucket["reason"],
      occurrences: bucket["occurrences"].to_i,
      min_size_bytes: bucket["min_size_bytes"]
    }
  end

  def enrich_clusters(report, metadata, triage_dir:, read_files: true)
    by_id = {}
    if metadata.is_a?(Hash)
      Array(metadata["buckets"]).each do |b|
        by_id[b["bucket_id"].to_s] = b if b.is_a?(Hash) && b["bucket_id"]
      end
    end

    Array(report["clusters"]).map do |c|
      copy = c.dup
      buckets = Array(c["buckets"]).map do |b|
        bid = b["bucket_id"].to_s
        enrich_bucket_entry(b, by_id[bid], triage_dir: triage_dir, read_files: read_files)
      end
      rep = c["representative"].is_a?(Hash) ? c["representative"] : {}
      rep_bid = rep["bucket_id"].to_s
      copy["representative"] = enrich_bucket_entry(rep, by_id[rep_bid], triage_dir: triage_dir, read_files: read_files)
      copy["buckets"] = buckets
      copy["verify_profiles"] ||= buckets.filter_map { |b| b["verify_profile"] }.uniq.sort
      copy["verify_profiles"] = nil if copy["verify_profiles"].empty?
      copy["options_labels"] ||= buckets.filter_map { |b| b["options_label"] }.uniq.sort
      copy["options_labels"] = nil if copy["options_labels"].empty?

      v_data = buckets.map { |b| fallback_bucket_variant_data(b, cluster_group: c["group"], meta_bucket: by_id[b["bucket_id"].to_s]) }
      copy["variants"] ||= FuzzClustering.summarize_cluster_variants(v_data)
      copy["digest_summary"] ||= FuzzClustering.summarize_cluster_digest(v_data)
      unless copy["by_worker"].is_a?(Hash) && !copy["by_worker"].empty?
        bw = Hash.new(0)
        buckets.each do |b|
          mb = by_id[b["bucket_id"].to_s]
          raw_bw = mb&.dig("occurrences", "by_worker") || b["by_worker"]
          next unless raw_bw.is_a?(Hash)

          raw_bw.each { |w, cnt| bw[w.to_s] += cnt.to_i if cnt.to_i > 0 }
        end
        copy["by_worker"] = bw.sort_by { |w, cnt| [-cnt, w] }.to_h unless bw.empty?
      end
      copy.compact
    end
  end

  def matches_cluster_filter?(cluster, patterns)
    return true if patterns.empty?

    cid = cluster["cluster_id"].to_s
    cid_num = cid[/\d+\z/]&.to_i
    members = Array(cluster["buckets"])

    patterns.any? do |raw_pat|
      pat = raw_pat.strip
      next false if pat.empty?

      if pat.match?(/\A\d{1,15}\z/) && !cid_num.nil? && cid_num == pat.to_i
        true
      elsif cid.casecmp?(pat) || File.fnmatch?(pat.downcase, cid.downcase, File::FNM_PATHNAME)
        true
      else
        allow_glob = pat.include?("/") || pat.match?(/[*?\[]/)
        members.any? do |b|
          bid = b["bucket_id"].to_s
          bid == pat || b["signature"].to_s == pat || (allow_glob && File.fnmatch?(pat, bid, File::FNM_PATHNAME))
        end
      end
    end
  end

  def normalize_group_filter(raw)
    case raw.to_s.strip.downcase
    when "prism", "prism_flaw", "prism_flaws" then "prism_flaw"
    when "diff", "diff_parse_y", "parse_y" then "diff_parse_y"
    when "prism_diff", "diff_prism" then "diff_prism"
    when "cruby", "cruby_crash", "cruby_crashes" then "cruby_crash"
    else
      raw.to_s.strip.downcase
    end
  end

  def matches_invariant_spec?(bucket, specs)
    return true if specs.empty?

    inv = bucket.dig("symptom", "invariant")
    headline = bucket["headline"].to_s
    specs.any? do |raw|
      spec = raw.strip
      next true if spec.empty?

      if spec.include?("=")
        k, v = spec.split("=", 2)
        if inv.is_a?(Hash)
          inv["namespace"].to_s == v && k == "namespace" ||
            inv.dig("fields", k).to_s == v
        else
          headline.include?(spec)
        end
      elsif inv.is_a?(Hash)
        inv["namespace"].to_s == spec ||
          inv["fields"]&.values&.any? { |fv| fv.to_s == spec } ||
          headline.include?(spec)
      else
        headline.include?(spec)
      end
    end
  end

  def matches_digest_filter?(cluster, specs, field_key)
    return true if specs.empty?

    buckets = [cluster["representative"]] + Array(cluster["buckets"])
    buckets.compact.any? do |b|
      val = b.dig("digest", field_key).to_s
      !val.empty? && specs.any? { |s| val.casecmp?(s) || val.include?(s) }
    end
  end

  def matches_anomaly_filter?(cluster, specs)
    return true if specs.empty?

    buckets = [cluster["representative"]] + Array(cluster["buckets"])
    buckets.compact.any? do |b|
      Array(b.dig("digest", "anomalies")).any? do |a|
        next false unless a.is_a?(Hash)

        specs.any? do |s|
          a["kind"].to_s == s || a["category"].to_s == s || a["node"].to_s == s || a["field"].to_s == s
        end
      end
    end
  end

  def filter_clusters(clusters, options)
    groups = options[:groups].map { |g| normalize_group_filter(g) }
    reasons = options[:reasons]
    profiles = options[:profiles]
    invariants = options[:invariants]
    syntax_statuses = options[:syntax_statuses]
    iseq_statuses = options[:iseq_statuses]
    anomalies = options[:anomalies]

    selected = clusters.select do |c|
      next false unless matches_cluster_filter?(c, options[:clusters])
      next false unless groups.empty? || groups.include?(c["group"].to_s.downcase)
      if options[:min_occurrences] && c["occurrences"].to_i < options[:min_occurrences]
        next false
      end
      unless reasons.empty?
        c_reasons = Array(c["reasons"]&.keys) + Array(c["buckets"]).map { |b| b["reason"].to_s }
        next false unless (reasons & c_reasons).any?
      end
      unless profiles.empty?
        c_profiles = Array(c["verify_profiles"]) + Array(c["buckets"]).filter_map { |b| b["verify_profile"] }
        next false unless (profiles & c_profiles).any?
      end
      unless invariants.empty?
        matched_inv = Array(c["buckets"]).any? { |b| matches_invariant_spec?(b, invariants) } ||
                      matches_invariant_spec?(c["representative"] || {}, invariants)
        next false unless matched_inv
      end
      next false unless matches_digest_filter?(c, syntax_statuses, "syntax_status")
      next false unless matches_digest_filter?(c, iseq_statuses, "iseq_status")
      next false unless matches_anomaly_filter?(c, anomalies)
      if options[:non_default_options]
        has_opts = !Array(c["options_labels"]).empty? ||
                   Array(c["buckets"]).any? { |b| b["options"].is_a?(Hash) && !b["options"].empty? }
        next false unless has_opts
      end
      true
    end

    case options[:sort]
    when "occurrences"
      selected.sort_by { |c| [-c["occurrences"].to_i, -c["bucket_count"].to_i, c["cluster_id"].to_s] }
    when "buckets"
      selected.sort_by { |c| [-c["bucket_count"].to_i, -c["occurrences"].to_i, c["cluster_id"].to_s] }
    when "first_seen"
      selected.sort_by do |c|
        [
          c["first_elapsed_ms"].nil? ? Float::INFINITY : c["first_elapsed_ms"].to_i,
          c["first_seen"].to_s.empty? ? "~" : c["first_seen"].to_s,
          c["cluster_id"].to_s
        ]
      end
    else
      selected
    end
  end

  def extract_loupe_code_sha256(url)
    cleaned = url.to_s.gsub("&amp;", "&")
    query = URI.parse(cleaned).query
    return nil unless query

    code_b64 = URI.decode_www_form(query).find { |k, _| k == "code" }&.last
    return nil if code_b64.nil? || code_b64.empty?

    decoded = Base64.decode64(code_b64.tr(" ", "+"))
    Digest::SHA256.hexdigest(decoded)
  rescue URI::InvalidURIError, ArgumentError
    nil
  end

  def symptom_match_key(cluster)
    rep = cluster["representative"] || {}
    sym = rep["symptom"].is_a?(Hash) ? rep["symptom"] : {}
    if sym["invariant"].is_a?(Hash)
      inv = sym["invariant"]
      fields = inv["fields"].is_a?(Hash) ? inv["fields"].sort.to_h : {}
      return ["invariant", cluster["group"].to_s, inv["namespace"].to_s, fields]
    end
    if sym["assertion"].is_a?(Hash)
      a = sym["assertion"]
      return ["assertion", cluster["group"].to_s, a["file"].to_s, a["line"], a["expr"].to_s]
    end
    if sym["ubsan"].is_a?(Hash)
      u = sym["ubsan"]
      return ["ubsan", cluster["group"].to_s, u["file"].to_s, u["line"], u["check"].to_s]
    end

    headline = rep["headline"].to_s.sub(/\s*\[detail:.*\]\z/, "").strip
    return nil if headline.empty?

    ["headline", cluster["group"].to_s, headline]
  end

  def load_baseline_clusters(since_path)
    raise ConfigError, "Missing baseline snapshot file: #{since_path}" unless File.file?(since_path)

    doc = JSON.parse(File.read(since_path))
    if doc.is_a?(Hash) && doc["clusters"].is_a?(Array)
      return enrich_clusters(doc, nil, triage_dir: nil, read_files: false)
    end
    if doc.is_a?(Hash) && doc["buckets"].is_a?(Array)
      report = FuzzClustering.cluster_metadata(doc, metadata_path: since_path)
      return enrich_clusters(report, doc, triage_dir: nil, read_files: false)
    end

    raise ConfigError, "Snapshot must be clusters.json or metadata.json: #{since_path}"
  end

  def cluster_identity_sets(cluster)
    buckets = Set.new
    sigs = Set.new
    payloads = Set.new
    ([cluster["representative"]] + Array(cluster["buckets"])).compact.each do |b|
      bid = b["bucket_id"].to_s
      buckets << bid unless bid.empty?
      sig = b["signature"].to_s
      sig = bid.split("/", 2).last.to_s if sig.empty? && bid.include?("/")
      sigs << sig unless sig.empty?
      psha = b["payload_sha256"].to_s
      psha = extract_loupe_code_sha256(b["loupe_url"]) if psha.empty? && b["loupe_url"]
      payloads << psha if psha && !psha.empty?
    end
    { buckets: buckets, sigs: sigs, payloads: payloads, symptom_key: symptom_match_key(cluster) }
  end

  def match_snapshot_clusters(current_clusters, baseline_clusters)
    curr_ids = current_clusters.map { |c| cluster_identity_sets(c) }
    base_ids = baseline_clusters.map { |c| cluster_identity_sets(c) }
    matched_base = Set.new
    diffs_by_cid = {}

    # Greedily pair highest-confidence matches across campaigns (buckets > payload_sha256 > symptom_key).
    candidates = []
    current_clusters.each_with_index do |c, ci|
      ca = curr_ids[ci]
      baseline_clusters.each_with_index do |p, pi|
        next if c["group"] != p["group"]

        pa = base_ids[pi]
        bucket_ov = (ca[:buckets] & pa[:buckets]).size
        sig_ov = (ca[:sigs] & pa[:sigs]).size
        payload_ov = (ca[:payloads] & pa[:payloads]).size
        sym_match = ca[:symptom_key] && ca[:symptom_key] == pa[:symptom_key] ? 1 : 0

        next if bucket_ov == 0 && sig_ov == 0 && payload_ov == 0 && sym_match == 0

        score = [bucket_ov, sig_ov, payload_ov, sym_match]
        candidates << [score, ci, pi]
      end
    end

    candidates.sort_by { |score, ci, pi| [-score[0], -score[1], -score[2], -score[3], ci, pi] }.each do |score, ci, pi|
      c = current_clusters[ci]
      cid = c["cluster_id"].to_s
      next if diffs_by_cid.key?(cid) || matched_base.include?(pi)

      matched_base.add(pi)
      prev = baseline_clusters[pi]
      delta_occ = c["occurrences"].to_i - prev["occurrences"].to_i
      delta_bkts = c["bucket_count"].to_i - prev["bucket_count"].to_i
      status = if delta_occ > 0 || delta_bkts > 0
                 "grown"
               elsif delta_occ < 0 || delta_bkts < 0
                 "shrunk"
               else
                 "unchanged"
               end
      matched_by = if score[0] > 0 then "bucket_id"
                   elsif score[1] > 0 then "signature"
                   elsif score[2] > 0 then "payload_sha256"
                   else "symptom"
                   end
      diffs_by_cid[cid] = {
        "status" => status,
        "matched_by" => matched_by,
        "prev_cluster_id" => prev["cluster_id"],
        "prev_occurrences" => prev["occurrences"].to_i,
        "prev_bucket_count" => prev["bucket_count"].to_i,
        "delta_occurrences" => delta_occ,
        "delta_buckets" => delta_bkts
      }
    end

    current_clusters.each do |c|
      cid = c["cluster_id"].to_s
      next if diffs_by_cid.key?(cid)

      diffs_by_cid[cid] = {
        "status" => "new",
        "delta_occurrences" => c["occurrences"].to_i,
        "delta_buckets" => c["bucket_count"].to_i
      }
    end

    resolved = []
    baseline_clusters.each_with_index do |p, pi|
      next if matched_base.include?(pi)

      resolved << {
        "cluster_id" => p["cluster_id"],
        "group" => p["group"],
        "bucket_count" => p["bucket_count"].to_i,
        "occurrences" => p["occurrences"].to_i,
        "representative" => p["representative"]&.slice("bucket_id", "headline", "source_preview", "loupe_url")
      }.compact
    end

    { by_cluster_id: diffs_by_cid, resolved: resolved }
  end

  def format_elapsed(ms)
    return "-" if ms.nil?

    sec = [(ms.to_f / 1000.0).round, 0].max
    format("%dh%02dm%02ds", sec / 3600, (sec % 3600) / 60, sec % 60)
  end

  def format_delta(n)
    n >= 0 ? "+#{n}" : n.to_s
  end

  def format_bucket_digest_tags(digest)
    return "" unless digest.is_a?(Hash) && !digest.empty?

    tags = []
    tags << "iseq=#{digest['iseq_status']}" if digest["iseq_status"]
    tags << "syntax=#{digest['syntax_status']}" if digest["syntax_status"] && !digest["iseq_status"]
    anom_kinds = Array(digest["anomalies"]).filter_map { |a| a["kind"] if a.is_a?(Hash) }.uniq.first(2)
    tags << "anom=#{anom_kinds.join(',')}" unless anom_kinds.empty?
    errs = digest["errors"] || digest["prism_errors_count"]
    tags << "err=#{errs}" if errs.to_i > 0
    if (sc = digest["stream_compare"]).is_a?(Hash) &&
       (sc["prettyprint_equal"] == false || sc["serialize_equal"] == false)
      tags << "stream_eq=false"
    end
    tags << "c_explain=aborted" if digest["c_explain_aborted"]
    tags.empty? ? "" : " [#{tags.join(' ')}]"
  end

  def format_cluster_digest_line(cluster, rep)
    dg = rep["digest"].is_a?(Hash) ? rep["digest"] : {}
    ds = cluster["digest_summary"].is_a?(Hash) ? cluster["digest_summary"] : {}
    return "" if dg.empty? && ds.empty?

    parts = []
    parts << "syntax=#{dg['syntax_status']}" if dg["syntax_status"]
    parts << "iseq=#{dg['iseq_status']}" if dg["iseq_status"]
    if (iseqs = ds["iseq_statuses"]).is_a?(Hash) && iseqs.size > 1
      parts << "iseqs={#{iseqs.map { |k, v| "#{k}:#{v}" }.join(',')}}"
    end

    if !dg["parsed_size"].nil?
      p_tags = []
      p_tags << dg["encoding"] if dg["encoding"] && dg["encoding"] != "UTF-8"
      p_tags << "stream" if dg["stream_mode"]
      suffix = p_tags.empty? ? "" : "(#{p_tags.join(',')})"
      parts << "parsed=#{dg['parsed_size']}B#{suffix}"
    end

    errs = dg["errors"] || dg["prism_errors_count"]
    parts << "err=#{errs}" if errs.to_i > 0
    parts << "warn=#{dg['warnings']}" if dg["warnings"].to_i > 0

    rep_anoms = Array(dg["anomalies"]).select { |a| a.is_a?(Hash) }
    anom_kinds = ds["anomaly_kinds"].is_a?(Hash) ? ds["anomaly_kinds"] : {}
    if cluster["bucket_count"].to_i <= 1 && !rep_anoms.empty?
      shown = rep_anoms.first(3).map do |a|
        target = a["node"].to_s
        target = "#{target}.#{a['field']}" if !target.empty? && a["field"]
        target.empty? ? a["kind"].to_s : "#{a['kind']}@#{target}"
      end
      extra = dg["anomaly_count"].to_i - shown.size
      shown << "+#{extra}" if extra > 0
      parts << "anomalies=#{shown.join(',')}"
    elsif !anom_kinds.empty?
      parts << "anomalies=#{anom_kinds.first(4).map { |k, v| "#{k}(#{v})" }.join(',')}"
    elsif dg["anomaly_count"].to_i > 0
      parts << "anomalies=#{dg['anomaly_count']}"
    end

    if (sc = dg["stream_compare"]).is_a?(Hash)
      ps = Array(sc["parsed_size"])
      diffs = []
      diffs << "size=#{ps[0]}/#{ps[1]}" if ps.size == 2 && ps[0] != ps[1]
      diffs << "pp" if sc["prettyprint_equal"] == false
      if sc["serialize_equal"] == false
        off = sc["serialize_diff_offset"]
        diffs << (off ? "ser@#{off}" : "ser")
      end
      parts << (diffs.empty? ? "stream_compare=equal" : "stream_compare=mismatch(#{diffs.join(',')})")
    end

    parts << "c_explain=aborted#{dg['c_explain_exit'] ? "(#{dg['c_explain_exit']})" : ''}" if dg["c_explain_aborted"]
    parts << "diff=#{dg['disasm_diff_preview'].inspect}" if dg["disasm_diff_preview"]
    parts << "parse.y=#{dg['parse_y_error'].inspect}" if dg["parse_y_error"]
    parts << "prism=#{dg['prism_error'].inspect}" if dg["prism_error"]
    parts.join("  ")
  end

  def format_text_report(clusters, report:, options:, diff: nil, resolved: [])
    lines = []
    summary = report["summary"] || {}
    lines << "Clusters shown: #{clusters.size}/#{summary['cluster_count'] || clusters.size} (total occurrences=#{clusters.sum { |c| c['occurrences'].to_i }})"
    if diff
      counts = Hash.new(0)
      clusters.each { |c| counts[c.dig("diff", "status") || "new"] += 1 }
      lines << "Snapshot diff vs #{options[:since]}: new=#{counts['new']}, grown=#{counts['grown']}, shrunk=#{counts['shrunk']}, unchanged=#{counts['unchanged']}, resolved=#{resolved.size}"
    end

    clusters.each do |c|
      rep = c["representative"] || {}
      reasons_str = Array(c["reasons"]).map { |r, n| "#{r}=#{n}" }.join(",")
      profiles = Array(c["verify_profiles"]).join(",")
      opts_labels = Array(c["options_labels"])
      first_str = format_elapsed(c["first_elapsed_ms"])

      tags = [c["group"].to_s, "#{c['bucket_count']} bkts", "#{c['occurrences']} occ"]
      if c["bucket_count"].to_i > 1
        if !c["min_merge_similarity"].nil? && !c["mean_pairwise_similarity"].nil?
          tags << format("sim=%.2f..%.2f", c["min_merge_similarity"].to_f, c["mean_pairwise_similarity"].to_f)
        end
        if (sr = c.dig("digest_summary", "size_range")).is_a?(Array) && sr.size == 2
          tags << "size=#{sr[0]}..#{sr[1]}B"
        end
      end
      tags << "first=#{first_str}" unless first_str == "-"
      tags << "profile=#{profiles}" unless profiles.empty?
      tags << reasons_str unless reasons_str.empty?

      diff_tag = if (d = c["diff"])
                   st = d["status"].upcase
                   if d["prev_cluster_id"]
                     " [#{st} vs #{d['prev_cluster_id']}: #{format_delta(d['delta_occurrences'])} occ, #{format_delta(d['delta_buckets'])} bkts via #{d['matched_by']}]"
                   else
                     " [#{st}]"
                   end
                 else
                   ""
                 end

      lines << ""
      lines << "#{c['cluster_id']} (#{tags.join(' | ')})#{diff_tag}"
      lines << "  rep:      #{rep['bucket_id']}#{rep['reproduced_by'] ? " (#{rep['reproduced_by']})" : ''}  size=#{rep['min_size_bytes']}B#{rep['header_hex'] ? "  hdr=#{rep['header_hex']}" : ''}"
      if !opts_labels.empty?
        lines << "  options:  #{opts_labels.join(' | ')}#{rep['has_shebang_prefix'] ? ' (shebang)' : ''}"
      elsif rep["has_shebang_prefix"]
        lines << "  options:  shebang_prefix"
      end
      if !rep["headline"].to_s.empty?
        lines << "  headline: #{rep['headline']}"
      else
        r0 = Array(c["reasons"]&.keys).first.to_s
        repro = rep["reproduced_by"].to_s
        if r0 == "hang"
          lines << "  headline: #{repro.empty? ? 'Timeout / hang (no stderr output)' : "Timeout / hang in #{repro} (no stderr output)"}"
        elsif !r0.empty? && r0 != "unknown"
          lines << "  headline: #{repro.empty? ? "Fatal signal #{r0} (no stderr output)" : "Fatal signal #{r0} in #{repro} (no stderr output)"}"
        end
      end

      trace = Array(rep["prism_trace"]).reject(&:empty?)
      if !trace.empty?
        lines << "  trace:    #{trace.join(' <- ')}"
      elsif !rep["top_prism_frame"].to_s.empty?
        lines << "  frame:    #{rep['top_prism_frame']}"
      end

      unless options[:brief]
        digest_line = format_cluster_digest_line(c, rep)
        lines << "  digest:   #{digest_line}" unless digest_line.empty?

        variants = Array(c["variants"]).reject { |v| v["label"].to_s.empty? }
        unless variants.empty?
          shown_vars = variants.first(4).map { |v| "#{v['label']} (#{v['buckets']} bkt/#{v['occurrences']} occ)" }
          extra_vars = variants.size - shown_vars.size
          shown_vars << "+#{extra_vars} more" if extra_vars > 0
          lines << "  variants: #{shown_vars.join('; ')}"
        end
      end

      lines << "  source:   #{rep['source_preview']}" unless rep["source_preview"].nil?
      sample_limit = options[:samples].to_i
      if !options[:brief] && sample_limit > 1
        Array(c["buckets"])
          .reject { |b| b["bucket_id"] == rep["bucket_id"] || b["source_preview"].nil? }
          .first(sample_limit - 1)
          .each do |sb|
            lines << "  sample:   #{sb['bucket_id']} (#{sb['min_size_bytes']}B): #{sb['source_preview']}"
          end
      end
      lines << "  loupe:    #{rep['loupe_url']}" if rep["loupe_url"]

      if options[:show_buckets]
        Array(c["buckets"]).each do |b|
          b_opts = b["options_label"] ? " [#{b['options_label']}]" : ""
          b_dg = format_bucket_digest_tags(b["digest"])
          b_src = b["source_preview"] ? "  src=#{b['source_preview']}" : ""
          lines << "  - #{b['bucket_id']} occ=#{b['occurrences']} size=#{b['min_size_bytes']}B hdr=#{b['header_hex'] || '-'}#{b_opts}#{b_dg}#{b_src}"
        end
      end
    end

    if !resolved.empty?
      lines << ""
      lines << "Resolved since #{options[:since]} (#{resolved.size}):"
      resolved.each do |r|
        rep = r["representative"] || {}
        lines << "  - #{r['cluster_id']} (#{r['group']}, #{r['bucket_count']} bkts, #{r['occurrences']} occ) rep=#{rep['bucket_id']} #{rep['headline']}"
      end
    end

    lines.join("\n")
  end

  def default_options
    ws_triage = if defined?(PrismFuzzer::Topology)
                  t = PrismFuzzer::Topology.discover(triage_dir: ENV["TRIAGE_DIR"], start_dir: Dir.pwd)
                  t ? PrismFuzzer::Topology.path_relative_or_abs(PrismFuzzer::Topology.workspace_paths(t)[:triage_dir], Dir.pwd) : nil
                end
    fallback_triage = ws_triage || FuzzClustering::DEFAULT_METADATA_PATH.sub(%r{/metadata\.json\z}, "")
    {
      triage_dir: ENV.fetch("TRIAGE_DIR", fallback_triage),
      clusters_file: ENV["CLUSTERS_FILE"]&.strip,
      metadata_path: nil,
      refresh: true,
      include_unreproducible: false,
      read_files: true,
      clusters: parse_csv_env("CLUSTER"),
      groups: [],
      reasons: [],
      profiles: [],
      invariants: [],
      syntax_statuses: [],
      iseq_statuses: [],
      anomalies: [],
      non_default_options: false,
      min_occurrences: nil,
      limit: nil,
      sort: nil,
      show_buckets: false,
      samples: nil,
      brief: false,
      since: nil,
      only_new: false,
      diff_only: false,
      json: false
    }
  end

  def parse_options(argv)
    options = default_options

    OptionParser.new do |opts|
      opts.banner = "Usage: inspect.rb [OPTIONS]"
      opts.separator ""
      opts.separator "Inspect fuzz triage clusters and diff campaigns."
      opts.separator ""

      opts.on("--triage-dir DIR", "Triage directory (default: #{options[:triage_dir]})") { |v| options[:triage_dir] = v }
      opts.on("--clusters-file PATH", "Explicit clusters.json path") { |v| options[:clusters_file] = v }
      opts.on("--metadata PATH", "Explicit metadata.json path") { |v| options[:metadata_path] = v }
      opts.on("--no-refresh", "Do not recompute stale clusters.json from metadata.json") { options[:refresh] = false }
      opts.on("--include-unreproducible", "Recompute with unreproducible buckets included") { options[:include_unreproducible] = true }
      opts.on("--no-files", "Do not fall back to reading input.min on disk") { options[:read_files] = false }

      opts.separator ""
      opts.separator "Filters & Display:"
      opts.on("-c", "--cluster PATTERN", "Filter cluster ID, numeric index, glob, or member bucket (repeatable)") { |v| options[:clusters].concat(v.split(",").map(&:strip)) }
      opts.on("-g", "--group GROUP", "Filter group: prism_flaw | diff_parse_y | diff_prism | cruby_crash (repeatable)") { |v| options[:groups] << v }
      opts.on("-r", "--reason REASON", "Filter reason (e.g. ABRT, SEGV, undefined-behavior; repeatable)") { |v| options[:reasons] << v }
      opts.on("-p", "--profile PROFILE", "Filter verify_profile (e.g. asan_ubsan, msan_slow, diff_parse_y, diff_prism; repeatable)") { |v| options[:profiles] << v }
      opts.on("--invariant SPEC", "Filter by invariant namespace or key=val (repeatable)") { |v| options[:invariants] << v }
      opts.on("--syntax STATUS", "Filter by CRuby vs Prism syntax_status digest (repeatable)") { |v| options[:syntax_statuses] << v }
      opts.on("--iseq STATUS", "Filter by CRuby vs Prism iseq_status digest (repeatable)") { |v| options[:iseq_statuses] << v }
      opts.on("--anomaly KIND", "Filter by explain.c AST anomaly kind, category, node, or field (repeatable)") { |v| options[:anomalies] << v }
      opts.on("--non-default-options", "Only clusters with non-default 4-byte fuzzer options") { options[:non_default_options] = true }
      opts.on("--min-occurrences N", Integer, "Only clusters with at least N occurrences") { |v| options[:min_occurrences] = v }
      opts.on("-n", "--limit N", Integer, "Limit output to first N matching clusters") { |v| options[:limit] = v }
      opts.on("--sort MODE", "Sort by: default | occurrences | first_seen | buckets") { |v| options[:sort] = v }
      opts.on("--buckets", "List every member bucket under each cluster") { options[:show_buckets] = true }
      opts.on("--samples N", Integer, "Show up to N distinct bucket source previews per cluster") { |v| options[:samples] = v }
      opts.on("--brief", "Omit digest, variant breakdown, and extra sample lines") { options[:brief] = true }
      opts.on("--json", "Emit structured JSON output") { options[:json] = true }

      opts.separator ""
      opts.separator "Campaign Diff:"
      opts.on("--since PATH", "Diff against baseline clusters.json or metadata.json snapshot") { |v| options[:since] = v }
      opts.on("--only-new", "With --since, show only NEW clusters") { options[:only_new] = true }
      opts.on("--diff-only", "With --since, hide UNCHANGED clusters") { options[:diff_only] = true }
    end.parse!(argv)

    options[:clusters].reject!(&:empty?)
    options[:clusters_file] = nil if options[:clusters_file]&.empty?
    options
  end

  def run(argv = ARGV)
    options = parse_options(argv)
    report, metadata, source_path = load_triage_report(
      triage_dir: options[:triage_dir],
      clusters_file: options[:clusters_file],
      metadata_path: options[:metadata_path],
      refresh: options[:refresh],
      include_unreproducible: options[:include_unreproducible]
    )

    all_clusters = enrich_clusters(report, metadata, triage_dir: options[:triage_dir], read_files: options[:read_files])

    diff_res = nil
    if options[:since]
      baseline = load_baseline_clusters(options[:since])
      diff_res = match_snapshot_clusters(all_clusters, baseline)
      all_clusters.each { |c| c["diff"] = diff_res[:by_cluster_id][c["cluster_id"].to_s] }
    end

    selected = filter_clusters(all_clusters, options)
    if options[:only_new] && diff_res
      selected = selected.select { |c| c.dig("diff", "status") == "new" }
    elsif options[:diff_only] && diff_res
      selected = selected.select { |c| c.dig("diff", "status") != "unchanged" }
    end
    selected = selected.first(options[:limit]) if options[:limit] && options[:limit] >= 0

    resolved = diff_res ? diff_res[:resolved] : []
    if options[:json]
      payload = {
        "schema_version" => 1,
        "source_path" => source_path,
        "summary" => {
          "total_clusters" => all_clusters.size,
          "matched_clusters" => selected.size,
          "matched_occurrences" => selected.sum { |c| c["occurrences"].to_i }
        },
        "clusters" => selected
      }
      if diff_res
        payload["since_path"] = options[:since]
        payload["resolved_clusters"] = resolved
      end
      puts JSON.pretty_generate(payload)
    else
      puts format_text_report(selected, report: report, options: options, diff: diff_res, resolved: resolved)
    end
    0
  rescue ConfigError => e
    warn "Error: #{e.message}"
    1
  end
end

exit(FuzzInspect.run(ARGV)) if __FILE__ == $PROGRAM_NAME
