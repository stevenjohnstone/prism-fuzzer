# frozen_string_literal: true

module FuzzClustering
  # Computes pairwise coverage, frame, differential parse.y, and reason
  # similarities, plus UPGMA merge selection and cluster pattern matching.
  module Similarity
    extend self

    def sparse_dot(va, vb)
      return 0.0 if va.empty? || vb.empty?

      small, large = va.size <= vb.size ? [va, vb] : [vb, va]
      sum = 0.0
      small.each do |k, w|
        other = large[k]
        sum += w * other if other
      end
      sum
    end

    def coverage_similarity(a, b)
      return 0.0 unless a[:cov_available] && b[:cov_available]

      na2 = a[:cov_norm2]
      nb2 = b[:cov_norm2]
      return 0.0 if na2 <= 0.0 || nb2 <= 0.0

      dot = sparse_dot(a[:cov_vec], b[:cov_vec])
      return 0.0 if dot <= 0.0

      # Because entries are sqrt(w_e), Tanimoto reduces to Weighted Jaccard: sum(min/shared w_e) / sum(union w_e).
      denom = na2 + nb2 - dot
      return 0.0 if denom <= 0.0

      val = dot / denom
      val > 1.0 ? 1.0 : val
    end

    def frame_similarity(a, b)
      na2 = a[:frame_norm2]
      nb2 = b[:frame_norm2]
      return nil if na2 <= 0.0 || nb2 <= 0.0

      dot = sparse_dot(a[:frame_vec], b[:frame_vec])
      return 0.0 if dot <= 0.0

      val = dot / Math.sqrt(na2 * nb2)
      val > 1.0 ? 1.0 : val
    end

    def conflict_field?(val_a, val_b)
      sa = val_a.to_s
      sb = val_b.to_s
      !sa.empty? && !sb.empty? && sa != sb
    end

    def normalize_diff_field(key, value)
      return nil if value.nil?

      str = value.to_s
      return nil if str.empty?
      return nil if %w[prism cruby].include?(key) && str == "ok"

      str
    end

    def generic_diff_error?(key, value)
      %w[prism cruby].include?(key) && GENERIC_DIFF_ERRORS.include?(value)
    end

    def diff_symptom_similarity(
      evidence,
      fields_a,
      fields_b,
      conflict_scale: DIFF_CONFLICT_SCALE,
      match_boost: DIFF_MATCH_BOOST
    )
      return evidence unless fields_a.is_a?(Hash) && fields_b.is_a?(Hash)

      if conflict_field?(fields_a["sub"], fields_b["sub"]) ||
         conflict_field?(fields_a["kind"], fields_b["kind"]) ||
         conflict_field?(fields_a["section"], fields_b["section"])
        return evidence * conflict_scale
      end

      mismatch = false
      specific_match = false
      %w[prism cruby node scope type ctx].each do |key|
        va = normalize_diff_field(key, fields_a[key])
        vb = normalize_diff_field(key, fields_b[key])
        next unless va && vb

        if va != vb
          mismatch = true
        elsif !generic_diff_error?(key, va)
          specific_match = true
        end
      end

      if specific_match && !mismatch
        [1.0, (1.0 - match_boost) * evidence + match_boost].min
      elsif mismatch
        evidence * conflict_scale
      else
        evidence
      end
    end

    def weighted_jaccard_and_cosine(va, sa, na2, vb, sb, nb2)
      return [0.0, 0.0] if va.empty? || vb.empty? || sa <= 0.0 || sb <= 0.0

      small, large = va.size <= vb.size ? [va, vb] : [vb, va]
      inter_w = 0.0
      inter_w2 = 0.0
      small.each do |k, w|
        next unless large.key?(k)

        inter_w += w
        inter_w2 += w * w
      end
      return [0.0, 0.0] if inter_w <= 0.0

      j_denom = sa + sb - inter_w
      j = j_denom > 0.0 ? [1.0, inter_w / j_denom].min : 0.0
      c_denom = Math.sqrt(na2 * nb2)
      cos = c_denom > 0.0 ? [1.0, inter_w2 / c_denom].min : 0.0
      [j, cos]
    end

    def diff_mismatch_class(fields)
      return "ast" unless fields.is_a?(Hash)

      kind = fields["kind"].to_s
      if kind == "syntax_mismatch"
        "syntax_mismatch:#{fields['sub']}"
      else
        "ast"
      end
    end

    def cruby_error_exception_class(val)
      s = val.to_s
      return nil if s.empty? || s == "ok"

      s.split(":", 2).first
    end

    def diff_parse_y_dual_similarity(
      a,
      b,
      locals_penalty: DIFF_LOCALS_MISMATCH_PENALTY,
      cruby_class_penalty: DIFF_CRUBY_CLASS_MISMATCH_PENALTY,
      diag_boost: DIFF_DIAGNOSTIC_MATCH_BOOST
    )
      fa = a[:diff_fields]
      fb = b[:diff_fields]
      cls_a = diff_mismatch_class(fa)
      cls_b = diff_mismatch_class(fb)
      return 0.0 if cls_a != cls_b

      sim =
        if a[:diff_has_domains] && b[:diff_has_domains]
          jp, cp = weighted_jaccard_and_cosine(
            a[:diff_prism_vec], a[:diff_prism_sum], a[:diff_prism_norm2],
            b[:diff_prism_vec], b[:diff_prism_sum], b[:diff_prism_norm2]
          )
          jy, cy = weighted_jaccard_and_cosine(
            a[:diff_parse_y_vec], a[:diff_parse_y_sum], a[:diff_parse_y_norm2],
            b[:diff_parse_y_vec], b[:diff_parse_y_sum], b[:diff_parse_y_norm2]
          )
          0.5 * Math.sqrt(jp * jy) + 0.5 * Math.sqrt(cp * cy)
        else
          jpool, cpool = weighted_jaccard_and_cosine(
            a[:diff_pooled_vec], a[:diff_pooled_sum], a[:diff_pooled_norm2],
            b[:diff_pooled_vec], b[:diff_pooled_sum], b[:diff_pooled_norm2]
          )
          0.5 * jpool + 0.5 * cpool
        end

      if cls_a == "ast"
        loc_a = fa.is_a?(Hash) && fa["kind"] == "locals_count_mismatch"
        loc_b = fb.is_a?(Hash) && fb["kind"] == "locals_count_mismatch"
        sim *= locals_penalty if loc_a != loc_b
        pre_a = fa.is_a?(Hash) && fa["kind"] == "ast_preexe_order_mismatch"
        pre_b = fb.is_a?(Hash) && fb["kind"] == "ast_preexe_order_mismatch"
        sim *= locals_penalty if pre_a != pre_b
      elsif fa.is_a?(Hash) && fb.is_a?(Hash)
        if fa["sub"] == "prism_ok_cruby_err"
          va = normalize_diff_field("cruby", fa["cruby"])
          vb = normalize_diff_field("cruby", fb["cruby"])
          if va && vb
            ca = cruby_error_exception_class(va)
            cb = cruby_error_exception_class(vb)
            if ca != cb
              sim *= cruby_class_penalty
            elsif va == vb && !generic_diff_error?("cruby", va) && sim > 0.05
              sim = [1.0, (1.0 - diag_boost) * sim + diag_boost].min
            end
          end
        elsif fa["sub"] == "prism_err_cruby_ok"
          va = normalize_diff_field("prism", fa["prism"])
          vb = normalize_diff_field("prism", fb["prism"])
          if va && vb && va == vb && !generic_diff_error?("prism", va) && sim > 0.05
            sim = [1.0, (1.0 - diag_boost) * sim + diag_boost].min
          end
        end
      end

      sim
    end

    def pair_similarity(
      a,
      b,
      reason_weight: DEFAULT_REASON_WEIGHT,
      frame_blend: FRAME_BLEND_WEIGHT,
      mismatch_penalty: FRAME_MISMATCH_PENALTY,
      diff_conflict_scale: DIFF_CONFLICT_SCALE,
      diff_match_boost: DIFF_MATCH_BOOST
    )
      # Never mix buckets from distinct verification oracles or distinct differential source pairs.
      return 0.0 if a[:oracle] && b[:oracle] && a[:oracle] != b[:oracle]
      return 0.0 if a[:diff_pair_key] && b[:diff_pair_key] && a[:diff_pair_key] != b[:diff_pair_key]

      if a[:oracle] == "diff_parse_y" && a[:diff_cov_available] && b[:diff_cov_available]
        return diff_parse_y_dual_similarity(a, b)
      end

      has_fa = a[:frame_norm2] > 0.0
      has_fb = b[:frame_norm2] > 0.0
      cov_both = a[:cov_available] && b[:cov_available]
      scov = cov_both ? coverage_similarity(a, b) : 0.0

      evidence =
        if has_fa && has_fb
          sfrm = frame_similarity(a, b)
          cov_both ? (frame_blend * sfrm + (1.0 - frame_blend) * scov) : sfrm
        elsif !has_fa && !has_fb
          diff_symptom_similarity(
            scov,
            a[:diff_fields],
            b[:diff_fields],
            conflict_scale: diff_conflict_scale,
            match_boost: diff_match_boost
          )
        else
          mismatch_penalty * scov
        end

      same_reason = !a[:reason].empty? && a[:reason] == b[:reason] ? 1.0 : 0.0
      ((1.0 - reason_weight) * evidence) + (reason_weight * same_reason)
    end

    def compute_similarity_matrix(features, **sim_opts)
      n = features.size
      mat = Array.new(n) { Array.new(n, 0.0) }
      (0...n).each do |i|
        mat[i][i] = 1.0
        (i + 1...n).each do |j|
          s = pair_similarity(features[i], features[j], **sim_opts)
          mat[i][j] = s
          mat[j][i] = s
        end
      end
      mat
    end

    def best_upgma_merge(active, pair_sum, _features, threshold: DEFAULT_THRESHOLD, diff_threshold: DIFF_DEFAULT_THRESHOLD)
      best = nil

      (0...active.size).each do |i|
        ci = active[i]
        uid_i = ci[:uid]
        size_i = ci[:members].size
        row_i = pair_sum[uid_i]

        (i + 1...active.size).each do |j|
          cj = active[j]
          next if ci[:oracle] && cj[:oracle] && ci[:oracle] != cj[:oracle]

          avg_sim = row_i[cj[:uid]] / (size_i * cj[:members].size).to_f
          pair_thresh = (ci[:diff_dual] && cj[:diff_dual]) ? diff_threshold : threshold
          next if avg_sim < pair_thresh

          pair_key = ci[:canon] <= cj[:canon] ? [ci[:canon], cj[:canon]] : [cj[:canon], ci[:canon]]

          if best.nil? ||
             avg_sim > best[:sim] + TIE_EPSILON ||
             ((avg_sim - best[:sim]).abs <= TIE_EPSILON && (pair_key <=> best[:pair_key]) < 0)
            best = { i: i, j: j, sim: avg_sim, pair_key: pair_key }
          end
        end
      end

      best
    end

    def cluster_mean_similarity(members, sim_matrix)
      return 1.0 if members.size <= 1

      total = 0.0
      pairs = 0
      members.each_with_index do |a, i|
        ((i + 1)...members.size).each do |j|
          total += sim_matrix[a][members[j]]
          pairs += 1
        end
      end
      total / pairs.to_f
    end

    def effective_thresholds(threshold: DEFAULT_THRESHOLD, diff_threshold: nil, reason_weight: DEFAULT_REASON_WEIGHT)
      raise ArgumentError, "threshold must be between 0.0 and 1.0" unless threshold >= 0.0 && threshold <= 1.0
      raise ArgumentError, "reason_weight must be between 0.0 and 1.0" unless reason_weight >= 0.0 && reason_weight <= 1.0

      effective_diff = if diff_threshold.nil?
                         (threshold - DEFAULT_THRESHOLD).abs <= TIE_EPSILON ? DIFF_DEFAULT_THRESHOLD : threshold
                       else
                         diff_threshold
                       end
      unless effective_diff >= 0.0 && effective_diff <= 1.0
        raise ArgumentError, "diff_threshold must be between 0.0 and 1.0"
      end

      [threshold, effective_diff]
    end

    def cluster_matches_pattern?(cluster, patterns)
      pats = Array(patterns).map { |p| p.to_s.strip }.reject(&:empty?)
      return true if pats.empty?

      cid = cluster["cluster_id"].to_s
      cid_num = cid[/\d+\z/]&.to_i
      members = cluster["buckets"] || []

      pats.any? do |pat|
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
  end
end
