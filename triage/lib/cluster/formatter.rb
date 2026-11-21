# frozen_string_literal: true

module FuzzClustering
  # Formats cluster JSON entries, version summaries, group counts, and
  # human-readable summary tables.
  module Formatter
    extend self

    def representative_sort_key(feature)
      [
        -feature[:occurrences],
        feature[:min_size_bytes].nil? ? Float::INFINITY : feature[:min_size_bytes],
        feature[:id]
      ]
    end

    def summarize_versions_entries(features)
      prism_seen = {}
      ruby_seen = {}
      container_seen = {}
      fuzz_seen = {}
      triage_seen = {}

      features.each do |f|
        v = f[:versions]
        next unless v.is_a?(Hash)

        pv = v["prism"]
        if pv.is_a?(Hash) && !pv.empty?
          key = [pv["version"], pv["target_ruby_version"], pv["git_commit"], pv["git_short"], pv["git_dirty"]]
          prism_seen[key] ||= pv
        end

        rv = v["ruby_parse_y"]
        if rv.is_a?(Hash) && !rv.empty?
          key = [rv["version"], rv["revision"], rv["release_date"], rv["description"], rv["oracle_dir"]]
          ruby_seen[key] ||= rv
        end

        cv = v["container"]
        if cv.is_a?(Hash) && !cv.empty?
          key = [cv["image_id"], cv["os"], cv["arch"], cv["clang"], cv["aflplusplus"], cv["ruby"]]
          container_seen[key] ||= cv
        end

        fv = v["fuzz"]
        if fv.is_a?(Hash) && !fv.empty?
          key = [fv["binary"], fv["build_id"], fv["snapshot_dir"], fv["prism"], fv["ruby_parse_y"]]
          fuzz_seen[key] ||= fv
        end

        tv = v["triage"]
        if tv.is_a?(Hash) && !tv.empty?
          key = [tv["binary"], tv["build_id"], tv["coverage_binary"], tv["prism"], tv["workspace_git"]]
          triage_seen[key] ||= tv
        end
      end

      out = {}
      out["prism"] = prism_seen.values.sort_by { |p| [p["version"].to_s, p["git_commit"].to_s, p["target_ruby_version"].to_s] } unless prism_seen.empty?
      out["ruby_parse_y"] = ruby_seen.values.sort_by { |r| [r["version"].to_s, r["revision"].to_s] } unless ruby_seen.empty?
      out["container"] = container_seen.values.sort_by { |c| [c["os"].to_s, c["arch"].to_s, c["image_id"].to_s] } unless container_seen.empty?
      out["fuzz"] = fuzz_seen.values.sort_by { |x| [x["binary"].to_s, x["build_id"].to_s] } unless fuzz_seen.empty?
      out["triage"] = triage_seen.values.sort_by { |x| [x["binary"].to_s, x["build_id"].to_s] } unless triage_seen.empty?
      out.empty? ? nil : out
    end

    def format_bucket_entry(feature)
      entry = {
        "bucket_id" => feature[:id],
        "reason" => feature[:reason],
        "signature" => feature[:signature],
        "occurrences" => feature[:occurrences],
        "first_seen" => feature[:first_seen],
        "first_elapsed_ms" => feature[:first_elapsed_ms],
        "last_seen" => feature[:last_seen],
        "min_size_bytes" => feature[:min_size_bytes],
        "headline" => feature[:headline],
        "top_prism_frame" => feature[:top_prism_frame]
      }
      entry["verify_profile"] = feature[:verify_profile] if feature[:verify_profile]
      entry["reproduced_by"] = feature[:reproduced_by] if feature[:reproduced_by]
      entry["header_hex"] = feature[:header_hex] if feature[:header_hex]
      entry["options"] = feature[:options] if feature[:options]
      entry["options_label"] = feature[:options_label] if feature[:options_label]
      entry["has_shebang_prefix"] = true if feature[:has_shebang_prefix]
      entry["loupe_url"] = feature[:loupe_url] if feature[:loupe_url]
      entry["payload_sha256"] = feature[:payload_sha256] if feature[:payload_sha256]
      entry["source_preview"] = feature[:source_preview] unless feature[:source_preview].nil?
      entry["symptom"] = feature[:symptom] if feature[:symptom]
      entry["digest"] = feature[:digest] if feature[:digest]
      entry["prism_trace"] = feature[:prism_trace] if feature[:prism_trace] && feature[:prism_trace].size > 1
      entry["versions"] = feature[:versions] if feature[:versions]
      entry
    end

    def cluster_group_for_oracle(oracle)
      case oracle
      when "diff_parse_y" then "diff_parse_y"
      when "diff_prism" then "diff_prism"
      when "cruby_crash" then "cruby_crash"
      else "prism_flaw"
      end
    end

    def summarize_group_counts(clusters_json)
      summary = {}
      [
        ["prism_flaws", "prism_flaw"],
        ["cruby_crashes", "cruby_crash"],
        ["diff_parse_y", "diff_parse_y"],
        ["diff_prism", "diff_prism"]
      ].each do |key, group_val|
        grp = clusters_json.select { |c| c["group"] == group_val }
        next if grp.empty? && %w[cruby_crashes diff_prism].include?(key)

        summary[key] = {
          "cluster_count" => grp.size,
          "bucket_count" => grp.sum { |c| c["bucket_count"].to_i },
          "occurrences" => grp.sum { |c| c["occurrences"].to_i },
          "singleton_clusters" => grp.count { |c| c["bucket_count"] == 1 }
        }
      end
      summary
    end

    def format_first_seen_cell(cluster, campaign_first_seen = nil)
      ms = cluster["first_elapsed_ms"] || Features.elapsed_ms_between(cluster["first_seen"], campaign_first_seen)

      unless ms.nil?
        sec = [(ms.to_f / 1000.0).round, 0].max
        return format("%2dh%02dm%02ds", sec / 3600, (sec % 3600) / 60, sec % 60)
      end

      fs = cluster["first_seen"].to_s
      return fs[/T(\d{2}:\d{2}:\d{2}Z)\z/, 1] || fs[0, 10] unless fs.empty?

      "-"
    end

    def cluster_diff_section?(cluster)
      group = cluster["group"].to_s
      return group == "diff_parse_y" unless group.empty?

      cluster.dig("representative", "headline").to_s.start_with?("INVARIANT[diff_parse_y]:")
    end

    def format_cluster_table_lines(section_clusters, campaign_first_seen, show_first)
      lines = []
      if show_first
        lines << format("%-12s %7s %8s  %-9s  %-26s  %s", "Cluster", "Buckets", "Occur", "First", "Reasons", "Representative")
        lines << ("-" * 111)
      else
        lines << format("%-12s %7s %8s  %-26s  %s", "Cluster", "Buckets", "Occur", "Reasons", "Representative")
        lines << ("-" * 100)
      end

      section_clusters.each do |c|
        reasons_str = c["reasons"].map { |r, n| "#{r}=#{n}" }.join(",")
        rep = c["representative"]
        headline = rep["headline"].to_s.tr("\n", " ")
        headline = "#{headline[0, 52]}..." if headline.length > 55
        lines << if show_first
          format(
            "%-12s %7d %8d  %-9s  %-26s  %s  %s",
            c["cluster_id"],
            c["bucket_count"],
            c["occurrences"],
            format_first_seen_cell(c, campaign_first_seen),
            reasons_str,
            rep["bucket_id"],
            headline
          )
        else
          format(
            "%-12s %7d %8d  %-26s  %s  %s",
            c["cluster_id"],
            c["bucket_count"],
            c["occurrences"],
            reasons_str,
            rep["bucket_id"],
            headline
          )
        end
      end
      lines
    end

    def format_summary_table(report)
      clusters = report["clusters"]
      summary = report["summary"]
      algo = report["algorithm"]
      lines = []

      if clusters.empty?
        lines << "No clusters (0 buckets)."
        return lines.join("\n")
      end

      campaign_first_seen = summary["first_seen"]
      show_first = clusters.any? { |c| c["first_seen"] || !c["first_elapsed_ms"].nil? }
      diff_clusters, flaw_clusters = clusters.partition { |c| cluster_diff_section?(c) }

      if !flaw_clusters.empty? && !diff_clusters.empty?
        flaw_bkts = flaw_clusters.sum { |c| c["bucket_count"].to_i }
        flaw_occ = flaw_clusters.sum { |c| c["occurrences"].to_i }
        lines << "Prism Flaws & Crashes (#{flaw_bkts} buckets, #{flaw_occ} occurrences -> #{flaw_clusters.size} clusters; algorithm=prism_flaw, threshold=#{algo['threshold']}):"
        lines.concat(format_cluster_table_lines(flaw_clusters, campaign_first_seen, show_first))
        lines << ""

        diff_bkts = diff_clusters.sum { |c| c["bucket_count"].to_i }
        diff_occ = diff_clusters.sum { |c| c["occurrences"].to_i }
        diff_algo = algo.dig("diff_parse_y", "mode") || "legacy_fallback"
        diff_dual_active = diff_algo == "dual_edge_prism_and_parse_y"
        diff_th = diff_dual_active ? (algo.dig("diff_parse_y", "threshold") || algo["diff_threshold"] || algo["threshold"]) : algo["threshold"]
        lines << "Differential parse.y Divergences (#{diff_bkts} buckets, #{diff_occ} occurrences -> #{diff_clusters.size} clusters; algorithm=#{diff_algo}, threshold=#{diff_th}):"
        lines.concat(format_cluster_table_lines(diff_clusters, campaign_first_seen, show_first))
      else
        lines.concat(format_cluster_table_lines(clusters, campaign_first_seen, show_first))
      end

      lines << ""
      margin_info = []
      margin_info << "min_merge=#{summary['min_intra_merge_similarity']}" if summary["min_intra_merge_similarity"]
      margin_info << "max_inter=#{summary['max_inter_cluster_similarity']}" if summary["max_inter_cluster_similarity"]
      margin_suffix = margin_info.empty? ? "" : ", #{margin_info.join(', ')}"
      excl_suffix = summary["excluded_unreproducible"].to_i > 0 ? ", excluded_unrepro=#{summary['excluded_unreproducible']}" : ""
      diff_dual_count = algo.dig("diff_parse_y", "dual_edge_buckets").to_i
      diff_th_suffix = diff_dual_count > 0 && algo["diff_threshold"] && algo["diff_threshold"] != algo["threshold"] ? ", diff_threshold=#{algo['diff_threshold']}" : ""
      lines << "Summary: #{summary['bucket_count']} buckets (#{summary['total_occurrences']} occurrences) -> " \
               "#{summary['cluster_count']} clusters (threshold=#{algo['threshold']}#{diff_th_suffix}, reason_weight=#{algo['reason_weight']}" \
               "#{margin_suffix}#{excl_suffix})"
      versions_line = format_versions_line(report["versions"])
      lines << versions_line if versions_line
      container_line = format_container_line(report["versions"])
      lines << container_line if container_line
      lines.join("\n")
    end

    def format_prism_version_tag(pv)
      return nil unless pv.is_a?(Hash) && !pv.empty?

      ver = pv["version"]
      rev = pv["git_short"] || pv["git_commit"]&.[](0, 9)
      dirty = pv["git_dirty"] ? "-dirty" : ""
      rev_str = rev ? "#{rev}#{dirty}" : nil

      main = ver || rev_str
      return nil unless main

      (rev_str && rev_str != main) ? "#{main} (#{rev_str})" : main.to_s
    end

    def format_ruby_version_tag(rv)
      return nil unless rv.is_a?(Hash) && !rv.empty?

      ver = rv["version"]
      rev = rv["revision"]&.[](0, 10)
      main = ver || rev
      return nil unless main

      (rev && rev != main) ? "#{main} (#{rev})" : main.to_s
    end

    def format_versions_line(versions)
      return nil unless versions.is_a?(Hash) && !versions.empty?

      obs = versions["observed"].is_a?(Hash) ? versions["observed"] : {}
      prism_tags = ([versions["prism"]] + Array(obs["prism"])).compact
                   .filter_map { |pv| format_prism_version_tag(pv) }.uniq
      ruby_tags = ([versions["ruby_parse_y"]] + Array(obs["ruby_parse_y"])).compact
                  .filter_map { |rv| format_ruby_version_tag(rv) }.uniq

      triage_tags = ([versions.dig("triage", "prism")] + Array(obs["triage"]).map { |t| t.is_a?(Hash) ? t["prism"] : nil })
                    .compact.filter_map { |pv| format_prism_version_tag(pv) }.uniq
      extra_triage = triage_tags - prism_tags

      parts = []
      parts << "prism=#{prism_tags.join(' | ')}" unless prism_tags.empty?
      parts << "triage_prism=#{extra_triage.join(' | ')}" unless extra_triage.empty?
      parts << "ruby_parse_y=#{ruby_tags.join(' | ')}" unless ruby_tags.empty?
      parts.empty? ? nil : "Versions: #{parts.join(', ')}"
    end

    def format_container_tag(cv)
      return nil unless cv.is_a?(Hash) && !cv.empty?

      items = []
      if cv["os"] && !cv["os"].to_s.empty?
        items << (cv["arch"] ? "#{cv['os']} (#{cv['arch']})" : cv["os"].to_s)
      elsif cv["arch"]
        items << cv["arch"].to_s
      end
      if cv["clang"] && !cv["clang"].to_s.empty?
        c_ver = cv["clang"].to_s[/clang version ([0-9.]+)/, 1]
        items << (c_ver ? "clang #{c_ver}" : cv["clang"].to_s)
      end
      items << cv["aflplusplus"].to_s if cv["aflplusplus"] && !cv["aflplusplus"].to_s.empty?
      items << "lrama-fuzz #{cv['lrama_fuzz']}" if cv["lrama_fuzz"] && !cv["lrama_fuzz"].to_s.empty?
      items.empty? ? nil : items.join(", ")
    end

    def format_container_line(versions)
      return nil unless versions.is_a?(Hash) && !versions.empty?

      obs = versions["observed"].is_a?(Hash) ? versions["observed"] : {}
      c_tags = ([versions["container"], versions.dig("fuzz", "container"), versions.dig("triage", "container")] +
                Array(obs["container"]) +
                Array(obs["fuzz"]).map { |f| f.is_a?(Hash) ? f["container"] : nil } +
                Array(obs["triage"]).map { |t| t.is_a?(Hash) ? t["container"] : nil })
               .compact.filter_map { |cv| format_container_tag(cv) }.uniq
      c_tags.empty? ? nil : "Container: #{c_tags.join(' | ')}"
    end
  end
end
