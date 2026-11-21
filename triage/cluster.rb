#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "json"
require "optparse"
require "time"

require_relative "../runtime/common"
require_relative "lib/cluster/constants"
require_relative "lib/cluster/features"
require_relative "lib/cluster/similarity"
require_relative "lib/cluster/formatter"

# Clusters crash triage buckets in metadata.json into root-cause groups without
# re-executing testcases or scraping raw bucket files.
#
# Similarity combines Weighted Jaccard edge coverage (linear in Laplace-smoothed
# corpus IDF), leaf-anchored Prism call frames, and soft crash-reason agreement
# via UPGMA (average-linkage) clustering cut at a calibrated fixed threshold.
# See triage/clustering.md for the derivation and calibration.
module FuzzClustering
  include Features
  include Similarity
  include Formatter
  extend self

  def write_json_atomic(path, payload)
    PrismFuzzer::Common.write_json_atomic(path, payload)
  end

  def prepare_placement_context(
    metadata,
    report: nil,
    threshold: DEFAULT_THRESHOLD,
    diff_threshold: nil,
    reason_weight: DEFAULT_REASON_WEIGHT,
    idf_smoothing: IDF_SMOOTHING,
    frame_decay: FRAME_DECAY,
    frame_blend: FRAME_BLEND_WEIGHT,
    mismatch_penalty: FRAME_MISMATCH_PENALTY,
    setup_weight: SETUP_FUNCTION_WEIGHT,
    encoding_weight: ENCODING_HELPER_WEIGHT,
    recovery_weight: RECOVERY_FUNCTION_WEIGHT,
    dispatcher_weight: DISPATCHER_WEIGHT,
    function_edge_cap: FUNCTION_EDGE_CAP,
    diff_conflict_scale: DIFF_CONFLICT_SCALE,
    diff_match_boost: DIFF_MATCH_BOOST,
    include_unreproducible: false,
    metadata_path: DEFAULT_METADATA_PATH
  )
    eff_thresh, eff_diff_thresh = effective_thresholds(
      threshold: threshold,
      diff_threshold: diff_threshold,
      reason_weight: reason_weight
    )
    feature_ctx = prepare_feature_context(
      metadata,
      idf_smoothing: idf_smoothing,
      frame_decay: frame_decay,
      setup_weight: setup_weight,
      encoding_weight: encoding_weight,
      recovery_weight: recovery_weight,
      dispatcher_weight: dispatcher_weight,
      function_edge_cap: function_edge_cap
    )
    report ||= cluster_metadata(
      metadata,
      threshold: eff_thresh,
      diff_threshold: eff_diff_thresh,
      reason_weight: reason_weight,
      idf_smoothing: idf_smoothing,
      frame_decay: frame_decay,
      frame_blend: frame_blend,
      mismatch_penalty: mismatch_penalty,
      setup_weight: setup_weight,
      encoding_weight: encoding_weight,
      recovery_weight: recovery_weight,
      dispatcher_weight: dispatcher_weight,
      function_edge_cap: function_edge_cap,
      diff_conflict_scale: diff_conflict_scale,
      diff_match_boost: diff_match_boost,
      include_unreproducible: include_unreproducible,
      metadata_path: metadata_path
    )

    features_by_id = {}
    Array(metadata["buckets"]).each do |b|
      next unless b.is_a?(Hash) && b["bucket_id"]

      features_by_id[b["bucket_id"].to_s] = feature_for_bucket(b, feature_ctx)
    end

    {
      report: report,
      feature_ctx: feature_ctx,
      features_by_id: features_by_id,
      threshold: eff_thresh,
      diff_threshold: eff_diff_thresh,
      sim_opts: {
        reason_weight: reason_weight,
        frame_blend: frame_blend,
        mismatch_penalty: mismatch_penalty,
        diff_conflict_scale: diff_conflict_scale,
        diff_match_boost: diff_match_boost
      }
    }
  end

  def place_probe(
    metadata,
    probe_bucket,
    placement_ctx: nil,
    report: nil,
    threshold: DEFAULT_THRESHOLD,
    diff_threshold: nil,
    reason_weight: DEFAULT_REASON_WEIGHT,
    top_n: 5,
    **ctx_opts
  )
    ctx = placement_ctx || prepare_placement_context(
      metadata,
      report: report,
      threshold: threshold,
      diff_threshold: diff_threshold,
      reason_weight: reason_weight,
      **ctx_opts
    )
    probe_feat = feature_for_bucket(probe_bucket, ctx[:feature_ctx])
    features_by_id = ctx[:features_by_id]
    sim_opts = ctx[:sim_opts]

    candidates = []
    ctx[:report]["clusters"].each do |cl|
      m_feats = Array(cl["buckets"]).filter_map { |mb| features_by_id[mb["bucket_id"].to_s] }
      next if m_feats.empty?
      next if probe_feat[:oracle] && m_feats.first[:oracle] && probe_feat[:oracle] != m_feats.first[:oracle]

      cluster_diff_dual = m_feats.all? { |mf| mf[:oracle] == "diff_parse_y" && mf[:diff_cov_available] }
      probe_diff_dual = probe_feat[:oracle] == "diff_parse_y" && probe_feat[:diff_cov_available]
      pair_thresh = (probe_diff_dual && cluster_diff_dual) ? ctx[:diff_threshold] : ctx[:threshold]

      scored_members = m_feats.map { |mf| [pair_similarity(probe_feat, mf, **sim_opts), mf] }
      sims = scored_members.map(&:first)
      avg_sim = sims.sum / sims.size.to_f
      best_member_sim, best_member = scored_members.max_by { |s, mf| [s, -mf[:occurrences], mf[:id]] }
      min_sim = sims.min
      rep_id = cl.dig("representative", "bucket_id").to_s
      rep_feat = features_by_id[rep_id]
      rep_sim = rep_feat ? pair_similarity(probe_feat, rep_feat, **sim_opts) : best_member_sim
      matched = avg_sim >= pair_thresh

      candidates << {
        "cluster_id" => cl["cluster_id"],
        "group" => cl["group"] || cluster_group_for_oracle(probe_feat[:oracle]),
        "algorithm" => cl["algorithm"],
        "matched" => matched,
        "threshold_used" => pair_thresh.round(6),
        "avg_similarity" => avg_sim.round(6),
        "rep_similarity" => rep_sim.round(6),
        "max_similarity" => best_member_sim.round(6),
        "min_similarity" => min_sim.round(6),
        "bucket_count" => cl["bucket_count"],
        "occurrences" => cl["occurrences"],
        "closest_bucket_id" => best_member[:id],
        "representative" => cl["representative"]
      }
    end

    candidates.sort_by! do |c|
      [c["matched"] ? 0 : 1, -c["avg_similarity"], -c["max_similarity"], c["cluster_id"].to_s]
    end
    matched_clusters = candidates.select { |c| c["matched"] }
    shown = top_n && top_n > 0 ? candidates.first(top_n) : candidates

    {
      "status" => matched_clusters.empty? ? "unmatched" : "matched",
      "probe" => {
        "bucket_id" => probe_feat[:id],
        "oracle" => probe_feat[:oracle],
        "group" => cluster_group_for_oracle(probe_feat[:oracle]),
        "reason" => probe_feat[:reason],
        "headline" => probe_feat[:headline],
        "top_prism_frame" => probe_feat[:top_prism_frame],
        "diff_fields" => probe_feat[:diff_fields],
        "cov_available" => probe_feat[:cov_available],
        "diff_cov_available" => probe_feat[:diff_cov_available],
        "threshold_used" => ((probe_feat[:oracle] == "diff_parse_y" && probe_feat[:diff_cov_available]) ? ctx[:diff_threshold] : ctx[:threshold]).round(6)
      },
      "matched_clusters" => matched_clusters,
      "best_cluster" => matched_clusters.first,
      "candidates" => shown
    }
  end

  def cluster_metadata(
    metadata,
    threshold: DEFAULT_THRESHOLD,
    diff_threshold: nil,
    reason_weight: DEFAULT_REASON_WEIGHT,
    idf_smoothing: IDF_SMOOTHING,
    frame_decay: FRAME_DECAY,
    frame_blend: FRAME_BLEND_WEIGHT,
    mismatch_penalty: FRAME_MISMATCH_PENALTY,
    setup_weight: SETUP_FUNCTION_WEIGHT,
    encoding_weight: ENCODING_HELPER_WEIGHT,
    recovery_weight: RECOVERY_FUNCTION_WEIGHT,
    dispatcher_weight: DISPATCHER_WEIGHT,
    function_edge_cap: FUNCTION_EDGE_CAP,
    diff_conflict_scale: DIFF_CONFLICT_SCALE,
    diff_match_boost: DIFF_MATCH_BOOST,
    include_unreproducible: false,
    metadata_path: DEFAULT_METADATA_PATH
  )
    threshold, effective_diff_threshold = effective_thresholds(
      threshold: threshold,
      diff_threshold: diff_threshold,
      reason_weight: reason_weight
    )

    filtered, excluded_unreproducible = filter_clustering_buckets(
      metadata["buckets"],
      include_unreproducible: include_unreproducible
    )

    feature_ctx = prepare_feature_context(
      metadata,
      idf_smoothing: idf_smoothing,
      frame_decay: frame_decay,
      setup_weight: setup_weight,
      encoding_weight: encoding_weight,
      recovery_weight: recovery_weight,
      dispatcher_weight: dispatcher_weight,
      function_edge_cap: function_edge_cap
    )
    features = filtered.map { |b| feature_for_bucket(b, feature_ctx) }
    sim_matrix = compute_similarity_matrix(
      features,
      reason_weight: reason_weight,
      frame_blend: frame_blend,
      mismatch_penalty: mismatch_penalty,
      diff_conflict_scale: diff_conflict_scale,
      diff_match_boost: diff_match_boost
    )

    active, pair_sum, merge_similarities = run_upgma_clustering(
      features,
      sim_matrix,
      threshold: threshold,
      diff_threshold: effective_diff_threshold
    )

    built_clusters = build_cluster_entries(active, features, sim_matrix)
    campaign_first_seen = features.filter_map { |f| f[:first_seen] }.min_by { |ts| timestamp_sort_key(ts) }
    campaign_last_seen = features.filter_map { |f| f[:last_seen] }.max_by { |ts| timestamp_sort_key(ts) }
    clusters_json = finalize_cluster_json(built_clusters, campaign_first_seen)
    inter_pairs = compute_inter_cluster_pairs(built_clusters, pair_sum)

    assemble_cluster_report(
      metadata: metadata,
      metadata_path: metadata_path,
      feature_ctx: feature_ctx,
      features: features,
      clusters_json: clusters_json,
      inter_pairs: inter_pairs,
      merge_similarities: merge_similarities,
      excluded_unreproducible: excluded_unreproducible,
      campaign_first_seen: campaign_first_seen,
      campaign_last_seen: campaign_last_seen,
      threshold: threshold,
      effective_diff_threshold: effective_diff_threshold,
      reason_weight: reason_weight,
      idf_smoothing: idf_smoothing,
      frame_decay: frame_decay,
      frame_blend: frame_blend,
      mismatch_penalty: mismatch_penalty,
      setup_weight: setup_weight,
      encoding_weight: encoding_weight,
      recovery_weight: recovery_weight,
      dispatcher_weight: dispatcher_weight,
      function_edge_cap: function_edge_cap,
      diff_conflict_scale: diff_conflict_scale,
      diff_match_boost: diff_match_boost
    )
  end

  def run_cli(argv = ARGV)
    topo_lib = File.expand_path("../runtime/topology.rb", __dir__)
    require topo_lib if File.file?(topo_lib)
    ws_triage = if defined?(PrismFuzzer::Topology)
                  t = PrismFuzzer::Topology.discover(start_dir: Dir.pwd)
                  t ? PrismFuzzer::Topology.path_relative_or_abs(PrismFuzzer::Topology.workspace_paths(t)[:triage_dir], Dir.pwd) : nil
                end
    def_meta = ws_triage ? File.join(ws_triage, "metadata.json") : DEFAULT_METADATA_PATH
    def_out = ws_triage ? File.join(ws_triage, "clusters.json") : DEFAULT_OUTPUT_PATH
    options = {
      metadata: ENV.fetch("TRIAGE_METADATA", def_meta),
      output: ENV.fetch("CLUSTER_OUTPUT", def_out),
      threshold: Float(ENV.fetch("CLUSTER_THRESHOLD", DEFAULT_THRESHOLD.to_s)),
      diff_threshold: ENV["CLUSTER_DIFF_THRESHOLD"] && !ENV["CLUSTER_DIFF_THRESHOLD"].empty? ? Float(ENV["CLUSTER_DIFF_THRESHOLD"]) : nil,
      reason_weight: Float(ENV.fetch("CLUSTER_REASON_WEIGHT", DEFAULT_REASON_WEIGHT.to_s)),
      include_unreproducible: false,
      quiet: false
    }

    OptionParser.new do |opts|
      opts.banner = "Usage: cluster.rb [OPTIONS]"
      opts.on("--metadata PATH", "Input metadata.json path (default: #{DEFAULT_METADATA_PATH})") do |v|
        options[:metadata] = v
      end
      opts.on("-o", "--output PATH", "Output clusters.json path, or '-' for stdout (default: #{DEFAULT_OUTPUT_PATH})") do |v|
        options[:output] = v
      end
      opts.on("--threshold FLOAT", Float, "UPGMA merge threshold in [0, 1] (default: #{DEFAULT_THRESHOLD})") do |v|
        options[:threshold] = v
      end
      opts.on("--diff-threshold FLOAT", Float, "UPGMA merge threshold for differential parse.y dual-edge clustering (default: #{DIFF_DEFAULT_THRESHOLD})") do |v|
        options[:diff_threshold] = v
      end
      opts.on("--reason-weight FLOAT", Float, "Crash-reason prior weight in [0, 1] (default: #{DEFAULT_REASON_WEIGHT})") do |v|
        options[:reason_weight] = v
      end
      opts.on("--include-unreproducible", "Include unreproducible buckets") do
        options[:include_unreproducible] = true
      end
      opts.on("--quiet", "Suppress terminal summary table") do
        options[:quiet] = true
      end
    end.parse!(argv)

    unless File.file?(options[:metadata])
      abort "Missing metadata file: #{options[:metadata]}"
    end

    metadata = JSON.parse(File.read(options[:metadata]))
    report = cluster_metadata(
      metadata,
      threshold: options[:threshold],
      diff_threshold: options[:diff_threshold],
      reason_weight: options[:reason_weight],
      include_unreproducible: options[:include_unreproducible],
      metadata_path: options[:metadata]
    )

    if options[:output] == "-"
      puts JSON.pretty_generate(report)
      warn format_summary_table(report) unless options[:quiet]
    else
      write_json_atomic(options[:output], report)
      unless options[:quiet]
        puts format_summary_table(report)
        puts "Wrote #{options[:output]}"
      end
    end
  end

  private

  def filter_clustering_buckets(raw_buckets, include_unreproducible:)
    excluded_unreproducible = 0
    filtered = []

    Array(raw_buckets).each do |b|
      next unless b.is_a?(Hash)

      unrepro = b["reason"] == "unreproducible" || b["reproducible"] == false
      if unrepro && !include_unreproducible
        excluded_unreproducible += 1
        next
      end
      filtered << b
    end

    filtered.sort_by! { |b| b["bucket_id"].to_s }
    [filtered, excluded_unreproducible]
  end

  def run_upgma_clustering(features, sim_matrix, threshold:, diff_threshold:)
    n = features.size
    active = Array.new(n) do |idx|
      f = features[idx]
      {
        uid: idx,
        members: [idx],
        min_merge_sim: 1.0,
        canon: f[:id],
        oracle: f[:oracle],
        diff_dual: f[:oracle] == "diff_parse_y" && f[:diff_cov_available]
      }
    end
    pair_sum = Array.new(n) { |i| sim_matrix[i].dup }

    merge_similarities = []
    while active.size > 1
      best = best_upgma_merge(
        active,
        pair_sum,
        features,
        threshold: threshold,
        diff_threshold: diff_threshold
      )
      break if best.nil?

      merge_similarities << best[:sim]
      ci = active[best[:i]]
      cj = active[best[:j]]
      uid_i = ci[:uid]
      uid_j = cj[:uid]

      ci[:members].concat(cj[:members])
      ci[:min_merge_sim] = [ci[:min_merge_sim], best[:sim]].min
      ci[:canon] = cj[:canon] if cj[:canon] < ci[:canon]
      ci[:diff_dual] = ci[:diff_dual] && cj[:diff_dual]

      active.delete_at(best[:j])
      active.each do |ck|
        uid_k = ck[:uid]
        next if uid_k == uid_i

        combined = pair_sum[uid_i][uid_k] + pair_sum[uid_j][uid_k]
        pair_sum[uid_i][uid_k] = combined
        pair_sum[uid_k][uid_i] = combined
      end
    end

    [active, pair_sum, merge_similarities]
  end

  def build_cluster_entries(active, features, sim_matrix)
    # Sort finalized clusters deterministically before computing IDs and inter-cluster neighbors,
    # keeping Prism flaws & crashes separate and ahead of differential parse.y divergences.
    built_clusters = active.map do |c|
      member_feats = c[:members].map { |idx| features[idx] }
      rep = member_feats.min_by { |f| representative_sort_key(f) }
      occ = member_feats.sum { |f| f[:occurrences] }
      reasons = Hash.new(0)
      member_feats.each { |f| reasons[f[:reason]] += 1 }
      sorted_members = member_feats.sort_by { |f| [-f[:occurrences], f[:id]] }
      earliest = member_feats
        .select { |f| f[:first_seen] || f[:first_elapsed_ms] }
        .min_by { |f| [timestamp_sort_key(f[:first_seen]), f[:first_elapsed_ms] || Float::INFINITY, f[:id]] }
      latest = member_feats
        .select { |f| f[:last_seen] }
        .max_by { |f| [timestamp_sort_key(f[:last_seen]), f[:id]] }
      group = cluster_group_for_oracle(c[:oracle])
      cluster_algo = if c[:oracle] == "diff_parse_y"
                       c[:diff_dual] ? "diff_parse_y_dual_edge" : "diff_parse_y_legacy"
                     else
                       "prism_flaw"
                     end

      by_worker = Hash.new(0)
      member_feats.each do |f|
        (f[:by_worker] || {}).each { |w, cnt| by_worker[w.to_s] += cnt.to_i if cnt.to_i > 0 }
      end

      {
        raw_cluster: c,
        group: group,
        cluster_algo: cluster_algo,
        occurrences: occ,
        by_worker: by_worker.sort_by { |w, cnt| [-cnt, w] }.to_h,
        bucket_count: member_feats.size,
        reasons: reasons.sort.to_h,
        verify_profiles: member_feats.filter_map { |f| f[:verify_profile] }.uniq.sort,
        options_labels: member_feats.filter_map { |f| f[:options_label] }.uniq.sort,
        variants: summarize_cluster_variants(member_feats),
        digest_summary: summarize_cluster_digest(member_feats),
        representative: rep,
        first_seen: earliest&.fetch(:first_seen),
        first_elapsed_ms: earliest&.fetch(:first_elapsed_ms),
        first_seen_bucket: earliest&.fetch(:id),
        last_seen: latest&.fetch(:last_seen),
        min_merge_similarity: c[:min_merge_sim],
        mean_pairwise_similarity: cluster_mean_similarity(c[:members], sim_matrix),
        versions: summarize_versions_entries(member_feats),
        buckets: sorted_members.map { |f| format_bucket_entry(f) }
      }
    end

    built_clusters.sort_by! do |entry|
      [%w[diff_parse_y diff_prism].include?(entry[:group]) ? 1 : 0, -entry[:occurrences], -entry[:bucket_count], entry[:representative][:id]]
    end
    built_clusters
  end

  def finalize_cluster_json(built_clusters, campaign_first_seen)
    id_width = [2, built_clusters.size.to_s.length].max
    built_clusters.each_with_index.map do |entry, idx|
      cid = format("cluster-%0*d", id_width, idx + 1)
      entry[:cluster_id] = cid
      buckets_out = entry[:buckets].map { |b| with_fallback_elapsed_ms(b, campaign_first_seen) }
      rep_out = with_fallback_elapsed_ms(format_bucket_entry(entry[:representative]), campaign_first_seen)
      cluster_elapsed_ms = entry[:first_elapsed_ms] || elapsed_ms_between(entry[:first_seen], campaign_first_seen)

      cluster_out = {
        "cluster_id" => cid,
        "group" => entry[:group],
        "algorithm" => entry[:cluster_algo],
        "bucket_count" => entry[:bucket_count],
        "occurrences" => entry[:occurrences],
        "first_seen" => entry[:first_seen],
        "first_elapsed_ms" => cluster_elapsed_ms,
        "first_seen_bucket" => entry[:first_seen_bucket],
        "last_seen" => entry[:last_seen],
        "reasons" => entry[:reasons],
        "representative" => rep_out,
        "min_merge_similarity" => entry[:min_merge_similarity].round(6),
        "mean_pairwise_similarity" => entry[:mean_pairwise_similarity].round(6)
      }
      cluster_out["verify_profiles"] = entry[:verify_profiles] unless entry[:verify_profiles].empty?
      cluster_out["options_labels"] = entry[:options_labels] unless entry[:options_labels].empty?
      cluster_out["variants"] = entry[:variants] if entry[:variants] && !entry[:variants].empty?
      cluster_out["digest_summary"] = entry[:digest_summary] if entry[:digest_summary]
      cluster_out["by_worker"] = entry[:by_worker] if entry[:by_worker] && !entry[:by_worker].empty?
      cluster_out["versions"] = entry[:versions] if entry[:versions]
      cluster_out["buckets"] = buckets_out
      cluster_out
    end
  end

  def compute_inter_cluster_pairs(built_clusters, pair_sum)
    inter_pairs = []
    (0...built_clusters.size).each do |i|
      ci = built_clusters[i]
      uid_i = ci[:raw_cluster][:uid]
      size_i = ci[:bucket_count]
      ((i + 1)...built_clusters.size).each do |j|
        cj = built_clusters[j]
        avg_sim = pair_sum[uid_i][cj[:raw_cluster][:uid]] / (size_i * cj[:bucket_count]).to_f
        inter_pairs << {
          "cluster_a" => ci[:cluster_id],
          "cluster_b" => cj[:cluster_id],
          "similarity" => avg_sim.round(6)
        }
      end
    end
    inter_pairs.sort_by! { |p| [-p["similarity"], p["cluster_a"], p["cluster_b"]] }
    inter_pairs
  end

  def assemble_cluster_report(
    metadata:,
    metadata_path:,
    feature_ctx:,
    features:,
    clusters_json:,
    inter_pairs:,
    merge_similarities:,
    excluded_unreproducible:,
    campaign_first_seen:,
    campaign_last_seen:,
    threshold:,
    effective_diff_threshold:,
    reason_weight:,
    idf_smoothing:,
    frame_decay:,
    frame_blend:,
    mismatch_penalty:,
    setup_weight:,
    encoding_weight:,
    recovery_weight:,
    dispatcher_weight:,
    function_edge_cap:,
    diff_conflict_scale:,
    diff_match_boost:
  )
    corpus = feature_ctx[:corpus]
    diff_corpus = feature_ctx[:diff_corpus]
    diff_cov_model = feature_ctx[:diff_cov_model]
    max_inter = inter_pairs.empty? ? nil : inter_pairs.first["similarity"]
    min_intra = merge_similarities.empty? ? nil : merge_similarities.min.round(6)
    total_occurrences = features.sum { |f| f[:occurrences] }
    diff_dual_buckets = features.count { |f| f[:oracle] == "diff_parse_y" && f[:diff_cov_available] }
    diff_legacy_buckets = features.count { |f| f[:oracle] == "diff_parse_y" && !f[:diff_cov_available] }

    out = {
      "schema_version" => SCHEMA_VERSION,
      "generated_at" => Time.now.utc.iso8601,
      "metadata_path" => metadata_path,
      "algorithm" => {
        "method" => "upgma",
        "coverage_metric" => "weighted_jaccard",
        "threshold" => threshold,
        "diff_threshold" => effective_diff_threshold,
        "reason_weight" => reason_weight,
        "idf_smoothing" => idf_smoothing,
        "frame_decay" => frame_decay,
        "frame_blend_weight" => frame_blend,
        "frame_mismatch_penalty" => mismatch_penalty,
        "setup_function_weight" => setup_weight,
        "encoding_helper_weight" => encoding_weight,
        "recovery_function_weight" => recovery_weight,
        "dispatcher_weight" => dispatcher_weight,
        "function_edge_cap" => function_edge_cap,
        "diff_conflict_scale" => diff_conflict_scale,
        "diff_match_boost" => diff_match_boost,
        "corpus_count" => corpus["corpus_count"].to_i,
        "filtered_boilerplate_functions" => BOILERPLATE_FUNCTIONS,
        "filtered_boilerplate_prefixes" => BOILERPLATE_PREFIXES,
        "filtered_external_frame_boilerplate" => EXTERNAL_FRAME_BOILERPLATE,
        "filtered_setup_functions" => SETUP_FUNCTIONS,
        "downweighted_encoding_functions" => ENCODING_HELPER_FUNCTIONS,
        "downweighted_recovery_functions" => RECOVERY_FUNCTIONS,
        "downweighted_dispatcher_functions" => DISPATCHER_FUNCTIONS,
        "diff_parse_y" => {
          "mode" => diff_dual_buckets > 0 ? "dual_edge_prism_and_parse_y" : "legacy_fallback",
          "edge_metric" => "dual_geom_weighted_jaccard_and_cosine",
          "threshold" => effective_diff_threshold,
          "dual_edge_buckets" => diff_dual_buckets,
          "legacy_fallback_buckets" => diff_legacy_buckets,
          "corpus_count" => diff_corpus["corpus_count"].to_i,
          "has_domains" => !!diff_cov_model[:has_domains],
          "function_edge_cap" => DIFF_FUNCTION_EDGE_CAP,
          "lexer_dispatcher_weight" => DIFF_LEXER_DISPATCHER_WEIGHT,
          "prism_dispatcher_weight" => DIFF_PRISM_DISPATCHER_WEIGHT,
          "identifier_helper_weight" => DIFF_IDENTIFIER_HELPER_WEIGHT,
          "encoding_helper_weight" => DIFF_ENCODING_HELPER_WEIGHT,
          "locals_mismatch_penalty" => DIFF_LOCALS_MISMATCH_PENALTY,
          "cruby_class_mismatch_penalty" => DIFF_CRUBY_CLASS_MISMATCH_PENALTY
        }
      },
      "summary" => {
        "bucket_count" => features.size,
        "excluded_unreproducible" => excluded_unreproducible,
        "cluster_count" => clusters_json.size,
        "total_occurrences" => total_occurrences,
        "singleton_clusters" => clusters_json.count { |c| c["bucket_count"] == 1 },
        "by_group" => summarize_group_counts(clusters_json),
        "first_seen" => campaign_first_seen,
        "last_seen" => campaign_last_seen,
        "min_intra_merge_similarity" => min_intra,
        "max_inter_cluster_similarity" => max_inter,
        "nearest_inter_cluster_pairs" => inter_pairs.first(5)
      },
      "clusters" => clusters_json
    }
    report_versions = metadata["versions"].is_a?(Hash) ? metadata["versions"].dup : {}
    observed_versions = summarize_versions_entries(features)
    report_versions["observed"] = observed_versions if observed_versions && !observed_versions.empty?
    out["versions"] = report_versions unless report_versions.empty?
    out
  end
end

if __FILE__ == $PROGRAM_NAME
  FuzzClustering.run_cli(ARGV)
end
