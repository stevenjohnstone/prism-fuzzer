# frozen_string_literal: true

require "time"

module FuzzClustering
  # Builds IDF-weighted coverage vectors, stack-frame vectors, option/symptom
  # summaries, and timestamp features from metadata.json bucket records.
  module Features
    extend self

    def boilerplate_function?(func_name)
      name = func_name.to_s
      BOILERPLATE_FUNCTIONS.include?(name) ||
        BOILERPLATE_PREFIXES.any? { |prefix| name.start_with?(prefix) }
    end

    def prism_frame?(frame)
      frame.is_a?(Hash) &&
        frame["scope"] == "prism" &&
        !frame["func"].to_s.empty? &&
        !boilerplate_function?(frame["func"])
    end

    def external_crash_frame?(frame)
      frame.is_a?(Hash) &&
        frame["scope"] == "external" &&
        !frame["func"].to_s.empty? &&
        !boilerplate_function?(frame["func"]) &&
        !EXTERNAL_FRAME_BOILERPLATE.include?(frame["func"])
    end

    def function_weight_multiplier(
      func_name,
      setup_weight: SETUP_FUNCTION_WEIGHT,
      encoding_weight: ENCODING_HELPER_WEIGHT,
      recovery_weight: RECOVERY_FUNCTION_WEIGHT,
      dispatcher_weight: DISPATCHER_WEIGHT,
      fn_edge_count: 0,
      function_edge_cap: FUNCTION_EDGE_CAP
    )
      base =
        if boilerplate_function?(func_name)
          0.0
        elsif SETUP_FUNCTIONS.include?(func_name)
          setup_weight
        elsif ENCODING_HELPER_FUNCTIONS.include?(func_name)
          encoding_weight
        elsif RECOVERY_FUNCTIONS.include?(func_name)
          recovery_weight
        else
          1.0
        end
      return 0.0 if base <= 0.0

      mult = base
      mult *= dispatcher_weight if DISPATCHER_FUNCTIONS.include?(func_name)
      if function_edge_cap && function_edge_cap > 0.0 && fn_edge_count > function_edge_cap
        mult *= Math.sqrt(function_edge_cap / fn_edge_count.to_f)
      end
      mult
    end

    def diff_boilerplate_function?(func_name, domain: nil)
      return true if domain == "harness"

      name = func_name.to_s
      DIFF_BOILERPLATE_FUNCTIONS.include?(name) ||
        DIFF_BOILERPLATE_PREFIXES.any? { |prefix| name.start_with?(prefix) }
    end

    def diff_function_weight_multiplier(
      func_name,
      domain: nil,
      fn_edge_count: 0,
      function_edge_cap: DIFF_FUNCTION_EDGE_CAP
    )
      return 0.0 if diff_boilerplate_function?(func_name, domain: domain)

      name = func_name.to_s
      mult =
        if name.start_with?("pm_encoding_")
          DIFF_ENCODING_HELPER_WEIGHT
        elsif DIFF_IDENTIFIER_FUNCTIONS.include?(name)
          DIFF_IDENTIFIER_HELPER_WEIGHT
        elsif DIFF_LEXER_DISPATCHERS.include?(name)
          DIFF_LEXER_DISPATCHER_WEIGHT
        elsif DIFF_PRISM_DISPATCHERS.include?(name)
          DIFF_PRISM_DISPATCHER_WEIGHT
        else
          1.0
        end
      if function_edge_cap && function_edge_cap > 0.0 && fn_edge_count > function_edge_cap
        mult *= Math.sqrt(function_edge_cap / fn_edge_count.to_f)
      end
      mult
    end

    def build_diff_edge_idf(
      diff_corpus,
      smoothing: IDF_SMOOTHING,
      function_edge_cap: DIFF_FUNCTION_EDGE_CAP
    )
      unless diff_corpus.is_a?(Hash) && diff_corpus["available"] == true
        return { enabled: false, prism_idf: {}, parse_y_idf: {}, pooled_idf: {}, edge_domains: {}, edge_functions: {} }
      end

      corpus_count = diff_corpus["corpus_count"].to_f
      unless corpus_count > 0.0
        return { enabled: false, prism_idf: {}, parse_y_idf: {}, pooled_idf: {}, edge_domains: {}, edge_functions: {} }
      end

      edge_df = diff_corpus["edge_df"].is_a?(Hash) ? diff_corpus["edge_df"] : {}
      edge_functions = diff_corpus["edge_functions"].is_a?(Hash) ? diff_corpus["edge_functions"] : {}
      edge_domains = diff_corpus["edge_domains"].is_a?(Hash) ? diff_corpus["edge_domains"] : {}

      if edge_functions.empty?
        return {
          enabled: true,
          prism_idf: {},
          parse_y_idf: {},
          pooled_idf: {},
          edge_domains: edge_domains,
          edge_functions: edge_functions,
          unmapped_fallback: true,
          corpus_count: corpus_count,
          smoothing: smoothing
        }
      end

      fn_counts = Hash.new(0)
      edge_functions.each do |edge_id, fn|
        dom = edge_domains[edge_id]
        fn_counts[[dom, fn]] += 1
      end

      prism_idf = {}
      parse_y_idf = {}
      pooled_idf = {}
      has_domains = !edge_domains.empty?

      edge_functions.each do |edge_id, func_name|
        dom = edge_domains[edge_id]
        mult = diff_function_weight_multiplier(
          func_name,
          domain: dom,
          fn_edge_count: fn_counts[[dom, func_name]],
          function_edge_cap: function_edge_cap
        )
        next if mult <= 0.0

        df = edge_df[edge_id].to_f
        raw = Math.log((corpus_count + smoothing) / (df + smoothing))
        w = raw * mult
        next unless w > 0.0

        if has_domains
          if dom == "prism"
            prism_idf[edge_id] = w
          elsif dom == "parse_y" || dom == "cruby_compile"
            parse_y_idf[edge_id] = w
          end
        else
          pooled_idf[edge_id] = w
        end
      end

      {
        enabled: true,
        prism_idf: prism_idf,
        parse_y_idf: parse_y_idf,
        pooled_idf: pooled_idf,
        edge_domains: edge_domains,
        edge_functions: edge_functions,
        has_domains: has_domains,
        unmapped_fallback: false,
        corpus_count: corpus_count,
        smoothing: smoothing
      }
    end

    def build_edge_idf(
      corpus,
      smoothing: IDF_SMOOTHING,
      setup_weight: SETUP_FUNCTION_WEIGHT,
      encoding_weight: ENCODING_HELPER_WEIGHT,
      recovery_weight: RECOVERY_FUNCTION_WEIGHT,
      dispatcher_weight: DISPATCHER_WEIGHT,
      function_edge_cap: FUNCTION_EDGE_CAP
    )
      return { enabled: false, idf: {}, edge_functions: {} } unless corpus.is_a?(Hash) && corpus["available"] == true

      corpus_count = corpus["corpus_count"].to_f
      return { enabled: false, idf: {}, edge_functions: {} } unless corpus_count > 0.0

      edge_df = corpus["edge_df"].is_a?(Hash) ? corpus["edge_df"] : {}
      edge_functions = corpus["edge_functions"].is_a?(Hash) ? corpus["edge_functions"] : {}
      idf = {}

      if edge_functions.empty?
        return {
          enabled: true,
          idf: idf,
          edge_functions: edge_functions,
          unmapped_fallback: true,
          corpus_count: corpus_count,
          smoothing: smoothing
        }
      end

      fn_counts = Hash.new(0)
      edge_functions.each_value { |fn| fn_counts[fn] += 1 }

      edge_functions.each do |edge_id, func_name|
        mult = function_weight_multiplier(
          func_name,
          setup_weight: setup_weight,
          encoding_weight: encoding_weight,
          recovery_weight: recovery_weight,
          dispatcher_weight: dispatcher_weight,
          fn_edge_count: fn_counts[func_name],
          function_edge_cap: function_edge_cap
        )
        next if mult <= 0.0

        df = edge_df[edge_id].to_f
        raw = Math.log((corpus_count + smoothing) / (df + smoothing))
        idf[edge_id] = raw * mult if raw > 0.0
      end

      {
        enabled: true,
        idf: idf,
        edge_functions: edge_functions,
        unmapped_fallback: false,
        corpus_count: corpus_count,
        smoothing: smoothing
      }
    end

    def extract_frame_vector(frames, frame_decay: FRAME_DECAY, oracle: nil)
      raw_frames = Array(frames)
      prism_frames = raw_frames.select { |f| prism_frame?(f) }
      used_frames =
        if !prism_frames.empty?
          prism_frames
        elsif oracle == "cruby_crash"
          raw_frames.select { |f| external_crash_frame?(f) }
        else
          []
        end

      vec = {}
      used_frames.each_with_index do |frame, depth|
        file = frame["file"].to_s
        file = "" if file == "(null)"
        key = file.empty? ? frame["func"].to_s : "#{frame['func']}@#{file}"
        vec[key] ||= frame_decay**depth
      end

      top_frame = if prism_frames.empty?
        nil
      else
        top = prism_frames.first
        line_suffix = top["line"] ? ":#{top['line']}" : ""
        "#{top['func']}@#{top['file']}#{line_suffix}"
      end

      [vec, vec.values.sum { |w| w * w }, top_frame]
    end

    def extract_coverage_vector(bucket, cov_model, corpus_edge_df)
      cov = bucket["coverage"]
      available = cov_model[:enabled] && cov.is_a?(Hash) && cov["available"] == true && cov["edges"].is_a?(Hash)
      return [{}, 0.0, false] unless available

      edges = cov["edges"]
      vec = {}

      if cov_model[:unmapped_fallback]
        n = cov_model[:corpus_count]
        smoothing = cov_model[:smoothing] || IDF_SMOOTHING
        edges.each_key do |edge_id|
          df = corpus_edge_df[edge_id].to_f
          raw = Math.log((n + smoothing) / (df + smoothing))
          # Store sqrt(weight) so dot products and Tanimoto denominators stay linear in IDF weight.
          vec[edge_id] = Math.sqrt(raw) if raw > 0.0
        end
      else
        idf = cov_model[:idf]
        edges.each_key do |edge_id|
          w = idf[edge_id]
          vec[edge_id] = Math.sqrt(w) if w && w > 0.0
        end
      end

      [vec, vec.values.sum { |w| w * w }, true]
    end

    def extract_diff_coverage_vectors(bucket, diff_cov_model, diff_corpus_edge_df)
      empty = [{}, 0.0, 0.0, {}, 0.0, 0.0, {}, 0.0, 0.0, false]
      cov = bucket["diff_coverage"]
      available = diff_cov_model[:enabled] && cov.is_a?(Hash) && cov["available"] == true && cov["edges"].is_a?(Hash)
      return empty unless available

      edges = cov["edges"]
      prism_vec = {}
      parse_y_vec = {}
      pooled_vec = {}
      prism_sum = 0.0
      prism_norm2 = 0.0
      parse_y_sum = 0.0
      parse_y_norm2 = 0.0
      pooled_sum = 0.0
      pooled_norm2 = 0.0

      if diff_cov_model[:unmapped_fallback]
        n = diff_cov_model[:corpus_count]
        smoothing = diff_cov_model[:smoothing] || IDF_SMOOTHING
        edges.each_key do |edge_id|
          df = diff_corpus_edge_df[edge_id].to_f
          raw = Math.log((n + smoothing) / (df + smoothing))
          next unless raw > 0.0

          pooled_vec[edge_id] = raw
          pooled_sum += raw
          pooled_norm2 += raw * raw
        end
      elsif diff_cov_model[:has_domains]
        p_idf = diff_cov_model[:prism_idf]
        y_idf = diff_cov_model[:parse_y_idf]
        edges.each_key do |edge_id|
          if (pw = p_idf[edge_id]) && pw > 0.0
            prism_vec[edge_id] = pw
            prism_sum += pw
            prism_norm2 += pw * pw
          elsif (yw = y_idf[edge_id]) && yw > 0.0
            parse_y_vec[edge_id] = yw
            parse_y_sum += yw
            parse_y_norm2 += yw * yw
          end
        end
      else
        pool_idf = diff_cov_model[:pooled_idf]
        edges.each_key do |edge_id|
          w = pool_idf[edge_id]
          next unless w && w > 0.0

          pooled_vec[edge_id] = w
          pooled_sum += w
          pooled_norm2 += w * w
        end
      end

      [
        prism_vec, prism_sum, prism_norm2,
        parse_y_vec, parse_y_sum, parse_y_norm2,
        pooled_vec, pooled_sum, pooled_norm2,
        true
      ]
    end

    def prism_source_file?(path)
      s = path.to_s
      return false if s.empty?

      s.match?(%r{(?:\A|/prism/)(?:src|include|templates)/}) ||
        File.basename(s) == "prism.c"
    end

    def prism_symptom?(bucket)
      return true if prism_source_file?(bucket.dig("symptom", "assertion", "file"))
      return true if prism_source_file?(bucket.dig("symptom", "ubsan", "file"))

      text = ([bucket.dig("symptom", "headline")] + Array(bucket.dig("symptom", "preamble_lines"))).compact.join("\n")
      text.match?(%r{(?:/prism/|\b)(?:src|include|templates)/[A-Za-z0-9_./-]+\.[ch](?:\b|:)})
    end

    def oracle_family(bucket)
      ns = bucket.dig("symptom", "invariant", "namespace").to_s
      headline = bucket.dig("symptom", "headline").to_s
      if ns == "diff_parse_y" || headline.start_with?("INVARIANT[diff_parse_y]:")
        "diff_parse_y"
      elsif ns == "diff_prism" || headline.start_with?("INVARIANT[diff_prism]:")
        "diff_prism"
      elsif %w[oracle_arm32 oracle_ppc].include?(ns)
        ns
      elsif headline =~ /\AINVARIANT\[(oracle_(?:arm32|ppc))\]:/
        Regexp.last_match(1)
      elsif ns == "stream_diff" || headline.start_with?("INVARIANT[stream_diff]:")
        "stream_diff"
      elsif (ns == "cruby_pipeline" || headline.start_with?("INVARIANT[cruby_pipeline]:")) &&
            bucket.dig("symptom", "invariant", "fields", "kind").to_s != "internal_compile_error" &&
            !headline.include?("kind=internal_compile_error")
        "diff_parse_y"
      elsif %w[diff_parse_y cruby_compile cruby_pipeline].include?(bucket["verify_profile"].to_s) ||
            headline.start_with?("CRASH[diff_parse_y]:", "CRASH[cruby_compile]:", "CRASH[cruby_pipeline]:", "INVARIANT[cruby_compile]:", "INVARIANT[cruby_pipeline]:")
        has_prism = Array(bucket["frames"]).any? { |f| prism_frame?(f) } || prism_symptom?(bucket)
        has_prism ? "crash_or_inv" : "cruby_crash"
      else
        "crash_or_inv"
      end
    end

    def extract_diff_fields(bucket)
      inv = bucket.dig("symptom", "invariant")
      return nil unless inv.is_a?(Hash) && %w[diff_parse_y cruby_pipeline].include?(inv["namespace"])

      fields = inv["fields"]
      return nil unless fields.is_a?(Hash) && fields["kind"].to_s != "internal_compile_error"

      fields
    end

    def parse_afl_time_ms(name_or_path)
      return nil if name_or_path.nil?

      m = File.basename(name_or_path.to_s).match(/(?:\A|,)time:(\d+)(?:,|\z)/)
      m ? m[1].to_i : nil
    end

    def timestamp_sort_key(iso_str)
      return [1, Float::INFINITY, ""] if iso_str.nil? || iso_str.empty?

      [0, Time.iso8601(iso_str).to_f, iso_str]
    rescue ArgumentError
      [0, Float::INFINITY, iso_str]
    end

    # Returns non-negative elapsed milliseconds between two ISO-8601 timestamps,
    # or nil when either timestamp is missing or unparseable.
    def elapsed_ms_between(first_seen, baseline_seen)
      return nil if first_seen.to_s.empty? || baseline_seen.to_s.empty?

      [((Time.iso8601(first_seen) - Time.iso8601(baseline_seen)) * 1000.0).round, 0].max
    rescue ArgumentError
      nil
    end

    # Populates first_elapsed_ms from first_seen - baseline_seen when ,time:<ms>
    # is absent (e.g. crashes imported via AFL++ sync:main).
    def with_fallback_elapsed_ms(entry, baseline_seen)
      return entry unless entry["first_elapsed_ms"].nil?

      fallback_ms = elapsed_ms_between(entry["first_seen"], baseline_seen)
      return entry if fallback_ms.nil?

      entry.merge("first_elapsed_ms" => fallback_ms)
    end

    def extract_bucket_timestamps(bucket)
      occ = bucket["occurrences"].is_a?(Hash) ? bucket["occurrences"] : {}
      first_seen_str = occ["first_seen"].to_s.strip
      first_seen = first_seen_str.empty? ? nil : first_seen_str
      last_seen_str = occ["last_seen"].to_s.strip
      last_seen = last_seen_str.empty? ? nil : last_seen_str

      raw_elapsed = occ["first_elapsed_ms"]
      first_elapsed_ms = raw_elapsed.nil? ? nil : raw_elapsed.to_i
      if first_elapsed_ms.nil? && occ["sample_crashes"].is_a?(Array)
        candidates = occ["sample_crashes"].filter_map do |sample|
          next unless sample.is_a?(Hash)

          t_ms = sample["time_ms"] || parse_afl_time_ms(sample["filename"] || sample["path"])
          next unless t_ms

          [timestamp_sort_key(sample["mtime"].to_s.strip), t_ms.to_i]
        end
        best = candidates.min_by { |ts_key, ms| [ts_key, ms] }
        if best && (first_seen.nil? || best[0][0] == 1 || (best[0] <=> timestamp_sort_key(first_seen)) <= 0)
          first_elapsed_ms = best[1]
        end
      end

      [first_seen, last_seen, first_elapsed_ms]
    end

    def extract_bucket_options_meta(bucket)
      input = bucket["input"].is_a?(Hash) ? bucket["input"] : {}
      opts = bucket["options"].is_a?(Hash) ? bucket["options"] : {}

      header_hex = input["header_hex"].to_s.strip
      if header_hex.empty? && input["header_bytes"].is_a?(Array) && input["header_bytes"].size == 4
        header_hex = input["header_bytes"].map { |b| format("%02x", b.to_i & 0xff) }.join
      end
      header_hex = nil if header_hex.empty?

      non_default = {}
      opts.each do |k, v|
        if DEFAULT_BUCKET_OPTIONS.key?(k)
          non_default[k] = v if v != DEFAULT_BUCKET_OPTIONS[k]
        elsif !v.nil? && v != false && v != []
          non_default[k] = v
        end
      end

      labels = []
      if non_default.key?("ruby_version")
        labels << "ver=#{non_default['ruby_version']}"
      end
      labels << "stream_mode" if non_default["stream_mode"] == true
      labels << "encoding=#{non_default['encoding']}" if non_default["encoding"]
      labels << "encoding_locked" if non_default["encoding_locked"] == true
      if non_default.key?("frozen_string_literal")
        labels << "frozen_lit=#{non_default['frozen_string_literal']}"
      end
      if non_default["command_line_flags"].is_a?(Array) && !non_default["command_line_flags"].empty?
        labels << "cmd=-#{non_default['command_line_flags'].join}"
      end
      labels << "main_script" if non_default["main_script"] == true
      labels << "partial_script" if non_default["partial_script"] == true
      labels << "freeze" if non_default["freeze"] == true
      labels << "attach_comments" if non_default["attach_comments"] == true
      labels << "shebang_cb" if non_default["shebang_callback"] == true
      labels << "filepath=#{non_default['filepath']}" if non_default["filepath"]
      if non_default["start_line_expr"] || non_default.key?("start_line")
        labels << "line=#{non_default['start_line_expr'] || non_default['start_line']}"
      end
      labels << "stack_budget=#{non_default['stack_budget']}" if non_default["stack_budget"]
      if non_default["scopes_count"] && non_default["scopes_count"].to_i > 0
        fwd_chars = Array(non_default["forwarding_flags"]).join
        fwd_scope = non_default["forwarding_scope"]
        scope_tag = "scopes=#{non_default['scopes_count']}"
        if !fwd_chars.empty?
          scope_tag += "(fwd#{fwd_scope}=#{fwd_chars})"
        elsif !fwd_scope.nil?
          scope_tag += "(fwd=#{fwd_scope})"
        end
        labels << scope_tag
      end

      options_label = labels.empty? ? nil : labels.join(" ")
      {
        header_hex: header_hex,
        non_default_options: non_default.empty? ? nil : non_default,
        options_label: options_label,
        has_shebang_prefix: input["has_shebang_prefix"] == true,
        loupe_url: input["loupe_url"].to_s.empty? ? nil : input["loupe_url"].to_s,
        payload_sha256: input["payload_sha256"].to_s.empty? ? nil : input["payload_sha256"].to_s,
        source_preview: input.key?("source_preview") ? input["source_preview"] : nil
      }
    end

    def extract_prism_trace(frames, oracle: nil, limit: 4)
      raw_frames = Array(frames)
      prism_frames = raw_frames.select { |f| prism_frame?(f) }
      used = if !prism_frames.empty?
               prism_frames
             elsif oracle == "cruby_crash"
               raw_frames.select { |f| external_crash_frame?(f) }
             else
               []
             end

      out = []
      used.each do |f|
        line_suffix = f["line"] ? ":#{f['line']}" : ""
        label = "#{f['func']}@#{f['file']}#{line_suffix}"
        out << label if out.last != label
        break if out.size >= limit
      end
      out
    end

    def extract_bucket_digest(bucket)
      d = bucket["digest"]
      (d.is_a?(Hash) && !d.empty?) ? d : nil
    end

    def bucket_variant_label(bucket_data)
      oracle = bucket_data[:oracle]
      diff = bucket_data[:diff_fields]
      dg = bucket_data[:digest]
      sym = bucket_data[:symptom]

      if oracle == "diff_parse_y" && diff.is_a?(Hash)
        parts = []
        parts << (diff["sub"] || diff["kind"]) if diff["sub"] || diff["kind"]
        parts << "prism=#{diff['prism']}" if diff["prism"] && !diff["prism"].to_s.empty?
        parts << "cruby=#{diff['cruby']}" if diff["cruby"] && !diff["cruby"].to_s.empty?
        parts << "node=#{diff['node']}" if diff["node"] && !diff["node"].to_s.empty?
        parts << "iseq=#{dg['iseq_status']}" if dg.is_a?(Hash) && dg["iseq_status"]
        return parts.join(" ") unless parts.empty?
      end

      if sym.is_a?(Hash)
        if (inv = sym["invariant"]).is_a?(Hash)
          fields = inv["fields"].is_a?(Hash) ? inv["fields"] : {}
          ns = inv["namespace"].to_s
          parts = [ns.empty? ? nil : ns]
          target = fields["type"] || fields["parent"] || fields["list"]
          parts << target if target && !target.to_s.empty?
          parts << fields["field"] if fields["field"] && !fields["field"].to_s.empty?
          parts << fields["kind"] if fields["kind"] && !fields["kind"].to_s.empty?
          return parts.compact.join(":") unless parts.compact.empty?
        elsif (assn = sym["assertion"]).is_a?(Hash)
          file = File.basename(assn["file"].to_s)
          return "assert:#{file}:#{assn['line']}" unless file.empty?
        elsif (ub = sym["ubsan"]).is_a?(Hash)
          file = File.basename(ub["file"].to_s)
          return "ubsan:#{file}:#{ub['line']}" unless file.empty?
        elsif (san = sym["sanitizer"]).is_a?(Hash)
          return [san["tool"], san["kind"], san["access"]].compact.join(":")
        end
      end

      bucket_data[:top_prism_frame] || Array(bucket_data[:prism_trace]).first || bucket_data[:reason].to_s
    end

    def summarize_cluster_variants(member_feats, limit: 8)
      return nil if member_feats.size <= 1

      grouped = {}
      member_feats.each do |f|
        lbl = bucket_variant_label(f).to_s.strip
        next if lbl.empty?

        rec = (grouped[lbl] ||= { "label" => lbl, "buckets" => 0, "occurrences" => 0 })
        rec["buckets"] += 1
        rec["occurrences"] += f[:occurrences].to_i
      end
      return nil if grouped.size <= 1 && member_feats.size <= 1

      grouped.values
        .sort_by { |v| [-v["buckets"], -v["occurrences"], v["label"]] }
        .first(limit)
    end

    def summarize_cluster_digest(member_feats)
      syntax_counts = Hash.new(0)
      iseq_counts = Hash.new(0)
      anomaly_counts = Hash.new(0)
      sizes = []

      member_feats.each do |f|
        sz = f[:min_size_bytes]
        sizes << sz.to_i if !sz.nil? && sz.to_i >= 0

        dg = f[:digest]
        next unless dg.is_a?(Hash)

        syntax_counts[dg["syntax_status"].to_s] += 1 unless dg["syntax_status"].to_s.empty?
        iseq_counts[dg["iseq_status"].to_s] += 1 unless dg["iseq_status"].to_s.empty?
        seen_kinds = []
        Array(dg["anomalies"]).each do |a|
          next unless a.is_a?(Hash)

          k = a["kind"].to_s
          next if k.empty? || seen_kinds.include?(k)

          seen_kinds << k
          anomaly_counts[k] += 1
        end
      end

      out = {}
      out["size_range"] = [sizes.min, sizes.max] if sizes.size >= 2 && sizes.min != sizes.max
      out["syntax_statuses"] = syntax_counts.sort_by { |k, v| [-v, k] }.to_h unless syntax_counts.empty?
      out["iseq_statuses"] = iseq_counts.sort_by { |k, v| [-v, k] }.to_h unless iseq_counts.empty?
      out["anomaly_kinds"] = anomaly_counts.sort_by { |k, v| [-v, k] }.to_h unless anomaly_counts.empty?
      out.empty? ? nil : out
    end

    def extract_bucket_symptom_summary(bucket)
      sym = bucket["symptom"].is_a?(Hash) ? bucket["symptom"] : {}
      out = {}

      if sym["invariant"].is_a?(Hash)
        inv = {
          "namespace" => sym["invariant"]["namespace"],
          "fields" => sym["invariant"]["fields"]
        }.compact
        out["invariant"] = inv unless inv.empty?
      end
      if sym["assertion"].is_a?(Hash)
        assn = sym["assertion"].slice("file", "line", "func", "expr").compact
        out["assertion"] = assn unless assn.empty?
      end
      if sym["ubsan"].is_a?(Hash)
        ub = sym["ubsan"].slice("file", "line", "check").compact
        out["ubsan"] = ub unless ub.empty?
      end
      if sym["sanitizer"].is_a?(Hash)
        san = sym["sanitizer"].slice("tool", "kind", "access").compact
        out["sanitizer"] = san unless san.empty?
      end

      out.empty? ? nil : out
    end

    def build_bucket_feature(
      bucket,
      cov_model,
      corpus_edge_df,
      diff_cov_model = nil,
      diff_corpus_edge_df = {},
      frame_decay: FRAME_DECAY
    )
      oracle = oracle_family(bucket)
      cov_vec, cov_norm2, cov_available = extract_coverage_vector(bucket, cov_model, corpus_edge_df)
      diff_vecs = if oracle == "diff_parse_y" && diff_cov_model
                    extract_diff_coverage_vectors(bucket, diff_cov_model, diff_corpus_edge_df)
                  else
                    [{}, 0.0, 0.0, {}, 0.0, 0.0, {}, 0.0, 0.0, false]
                  end
      dp_vec, dp_sum, dp_norm2, dy_vec, dy_sum, dy_norm2, dpool_vec, dpool_sum, dpool_norm2, diff_cov_available = diff_vecs
      frame_vec, frame_norm2, top_frame = extract_frame_vector(
        bucket["frames"],
        frame_decay: frame_decay,
        oracle: oracle
      )
      prism_trace = extract_prism_trace(bucket["frames"], oracle: oracle)
      digest = extract_bucket_digest(bucket)
      occ = bucket.dig("occurrences", "count").to_i
      occ_by_worker = Hash.new(0)
      if (raw_bw = bucket.dig("occurrences", "by_worker")).is_a?(Hash)
        raw_bw.each { |w, cnt| occ_by_worker[w.to_s] += cnt.to_i if cnt.to_i > 0 }
      end
      first_seen, last_seen, first_elapsed_ms = extract_bucket_timestamps(bucket)
      min_size = bucket.dig("input", "min_size_bytes")
      versions = bucket["versions"].is_a?(Hash) && !bucket["versions"].empty? ? bucket["versions"] : nil
      opt_meta = extract_bucket_options_meta(bucket)
      symptom_summary = extract_bucket_symptom_summary(bucket)
      verify_profile = bucket["verify_profile"].to_s
      reproduced_by = bucket["reproduced_by"].to_s
      target_meta = bucket["target"].is_a?(Hash) ? bucket["target"] : nil
      target_id = target_meta&.dig("id")&.to_s
      target_sources = target_meta&.dig("sources").is_a?(Hash) ? target_meta["sources"] : nil
      diff_pair_key = if oracle.to_s.start_with?("diff_") && target_sources && !target_sources.empty?
                        target_sources.sort_by { |k, _| k.to_s }.map { |k, v| "#{k}=#{v}" }.join(",")
                      end

      {
        id: bucket["bucket_id"].to_s,
        reason: bucket["reason"].to_s,
        signature: bucket["signature"].to_s,
        oracle: oracle,
        target_id: target_id,
        diff_pair_key: diff_pair_key,
        verify_profile: verify_profile.empty? ? nil : verify_profile,
        reproduced_by: reproduced_by.empty? ? nil : reproduced_by,
        header_hex: opt_meta[:header_hex],
        options: opt_meta[:non_default_options],
        options_label: opt_meta[:options_label],
        has_shebang_prefix: opt_meta[:has_shebang_prefix],
        loupe_url: opt_meta[:loupe_url],
        payload_sha256: opt_meta[:payload_sha256],
        source_preview: opt_meta[:source_preview],
        symptom: symptom_summary,
        diff_fields: extract_diff_fields(bucket),
        digest: digest,
        occurrences: occ,
        by_worker: occ_by_worker,
        first_seen: first_seen,
        first_elapsed_ms: first_elapsed_ms,
        last_seen: last_seen,
        min_size_bytes: min_size,
        versions: versions,
        headline: bucket.dig("symptom", "headline").to_s,
        cov_vec: cov_vec,
        cov_norm2: cov_norm2,
        cov_available: cov_available,
        diff_cov_available: diff_cov_available,
        diff_has_domains: !!(diff_cov_model && diff_cov_model[:has_domains]),
        diff_prism_vec: dp_vec,
        diff_prism_sum: dp_sum,
        diff_prism_norm2: dp_norm2,
        diff_parse_y_vec: dy_vec,
        diff_parse_y_sum: dy_sum,
        diff_parse_y_norm2: dy_norm2,
        diff_pooled_vec: dpool_vec,
        diff_pooled_sum: dpool_sum,
        diff_pooled_norm2: dpool_norm2,
        frame_vec: frame_vec,
        frame_norm2: frame_norm2,
        top_prism_frame: top_frame,
        prism_trace: prism_trace
      }
    end

    def prepare_feature_context(
      metadata,
      idf_smoothing: IDF_SMOOTHING,
      frame_decay: FRAME_DECAY,
      setup_weight: SETUP_FUNCTION_WEIGHT,
      encoding_weight: ENCODING_HELPER_WEIGHT,
      recovery_weight: RECOVERY_FUNCTION_WEIGHT,
      dispatcher_weight: DISPATCHER_WEIGHT,
      function_edge_cap: FUNCTION_EDGE_CAP
    )
      corpus = metadata["corpus"].is_a?(Hash) ? metadata["corpus"] : {}
      corpus_edge_df = corpus["edge_df"].is_a?(Hash) ? corpus["edge_df"] : {}
      cov_model = build_edge_idf(
        corpus,
        smoothing: idf_smoothing,
        setup_weight: setup_weight,
        encoding_weight: encoding_weight,
        recovery_weight: recovery_weight,
        dispatcher_weight: dispatcher_weight,
        function_edge_cap: function_edge_cap
      )

      diff_corpus = metadata["diff_corpus"].is_a?(Hash) ? metadata["diff_corpus"] : {}
      diff_corpus_edge_df = diff_corpus["edge_df"].is_a?(Hash) ? diff_corpus["edge_df"] : {}
      diff_cov_model = build_diff_edge_idf(diff_corpus, smoothing: idf_smoothing)

      {
        corpus: corpus,
        corpus_edge_df: corpus_edge_df,
        cov_model: cov_model,
        diff_corpus: diff_corpus,
        diff_corpus_edge_df: diff_corpus_edge_df,
        diff_cov_model: diff_cov_model,
        frame_decay: frame_decay
      }
    end

    def feature_for_bucket(bucket, feature_ctx)
      build_bucket_feature(
        bucket,
        feature_ctx[:cov_model],
        feature_ctx[:corpus_edge_df],
        feature_ctx[:diff_cov_model],
        feature_ctx[:diff_corpus_edge_df],
        frame_decay: feature_ctx[:frame_decay]
      )
    end
  end
end
