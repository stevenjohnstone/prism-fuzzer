# frozen_string_literal: true

module FuzzTriage
  # Enriches bucket meta.json records with fuzz.explain --digest AST anomaly
  # summaries and CRuby parse.y differential disasm/syntax probes.
  module DigestEnricher
    include Config
    extend self

    def diff_parse_y_invariant_meta?(meta)
      return false unless meta.is_a?(Hash)

      ns = meta.dig("symptom", "invariant", "namespace").to_s
      headline = meta.dig("symptom", "headline").to_s
      ns == "diff_parse_y" || headline.start_with?("INVARIANT[diff_parse_y]:")
    end

    def summarize_first_disasm_diff(diff_text)
      return nil if diff_text.nil? || diff_text.empty?

      minus_line = nil
      plus_line = nil
      diff_text.each_line(chomp: true) do |ln|
        next if ln.start_with?("---", "+++", "@@")

        if ln.start_with?("-") && minus_line.nil?
          minus_line = ln[1..].to_s.strip.gsub(/\s+/, " ")
        elsif ln.start_with?("+") && plus_line.nil?
          plus_line = ln[1..].to_s.strip.gsub(/\s+/, " ")
        end
        break if minus_line && plus_line
      end
      return nil unless minus_line || plus_line

      preview = [minus_line ? "-#{minus_line}" : nil, plus_line ? "+#{plus_line}" : nil].compact.join(" => ")
      preview.length > 140 ? "#{preview[0, 137]}..." : preview
    end

    def run_explain_digest_probe(explain_bin, min_path, stream_diff:, serialize:)
      cmd = [explain_bin, "--digest", "--raw"]
      cmd << "--compare-stream" if stream_diff
      cmd << "--serialize" if serialize
      cmd << min_path

      out, _, status = Open3.capture3(*cmd)
      return { "c_explain_aborted" => true, "c_explain_exit" => status.exitstatus } unless status.success?

      parsed = JSON.parse(out.lines.first.to_s)
      return {} unless parsed.is_a?(Hash)

      out_hash = parsed.slice(
        "parsed_size", "encoding", "stream_mode", "continuable",
        "errors", "warnings", "top_errors", "anomaly_count",
        "serialize_bytes", "stream_compare"
      ).compact
      if parsed["anomalies"].is_a?(Array) && !parsed["anomalies"].empty?
        out_hash["anomalies"] = parsed["anomalies"].first(8)
      elsif parsed.key?("anomalies")
        out_hash["anomalies"] = []
      end
      out_hash
    rescue JSON::ParserError, SystemCallError, IOError, EncodingError => e
      warn "DigestEnricher: explain probe failed for #{min_path}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
      nil
    end

    def run_diff_digest_probe(ruby_bin, min_path)
      raw = File.binread(min_path)
      body = raw.bytesize >= 4 ? (raw.byteslice(4..) || "".b) : raw
      comp = FuzzExplain.compare_entry(
        { body: body, cmd_flags: [] },
        { ruby: ruby_bin, disasm: false, ignore_locations: true, eval: false, apply_cmd_flags: false, timeout: 5.0 }
      )

      out = {
        "syntax_status" => comp.dig("syntax", "status"),
        "iseq_status" => comp.dig("iseq", "status")
      }.compact

      if (pe = comp.dig("prism_parse", "errors"))
        out["prism_errors_count"] = pe.size
        if !pe.empty?
          first = pe.first
          msg = "#{first['type']}: #{first['message']}".strip
          out["prism_error"] = msg.length > 120 ? "#{msg[0, 117]}..." : msg
        end
      end

      unless comp.dig("syntax", "parse_y", "ok")
        err = comp.dig("syntax", "parse_y", "stderr").to_s.lines.first.to_s.strip
        out["parse_y_error"] = err.length > 120 ? "#{err[0, 117]}..." : err unless err.empty?
      end

      if out["iseq_status"] == "disasm_diff"
        preview = summarize_first_disasm_diff(comp.dig("iseq", "disasm_diff"))
        out["disasm_diff_preview"] = preview if preview
      end
      out
    rescue FuzzExplain::ConfigError, SystemCallError, IOError, JSON::ParserError, EncodingError => e
      warn "DigestEnricher: diff probe failed for #{min_path}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
      nil
    end

    def run_digest_work_pool(items, workers: env_triage_threads, &block)
      return if items.empty?

      effective_workers = [workers.to_i, items.size, 8].min
      if effective_workers <= 1 || !defined?(Concurrent)
        items.each(&block)
        return
      end

      pool = Concurrent::FixedThreadPool.new(effective_workers)
      futures = items.map { |item| Concurrent::Future.execute(executor: pool) { block.call(item) } }
      futures.each(&:wait!)
    ensure
      if pool
        pool.shutdown
        pool.wait_for_termination
      end
    end

    def enrich_bucket_digests!(metas_by_dir, triage_dir:, dirty_dirs:, workers: env_triage_threads, force: env_recount?)
      return if ENV["TRIAGE_DIGEST"] == "0" || metas_by_dir.empty?

      mutex = Mutex.new

      explain_bin = resolve_triage_explain_bin(triage_dir: triage_dir)
      if explain_bin
        explain_targets = metas_by_dir.select do |dir, meta|
          next false unless meta["reproducible"] == true
          next false if %w[hang allocation-size-too-big].include?(meta["reason"].to_s) || meta["timed_out"]
          next false unless File.file?(File.join(dir, "input.min"))

          dg = meta["digest"]
          force || !dg.is_a?(Hash) || (!dg.key?("anomalies") && !dg["c_explain_aborted"])
        end

        run_digest_work_pool(explain_targets.to_a, workers: workers) do |dir, meta|
          min_path = File.join(dir, "input.min")
          headline = meta.dig("symptom", "headline").to_s
          prof = meta["verify_profile"].to_s
          res = run_explain_digest_probe(
            explain_bin,
            min_path,
            stream_diff: headline.include?("INVARIANT[stream_diff]"),
            serialize: prof == "arm32_oracle" || prof == "ppc_oracle" || headline.include?("INVARIANT[oracle_")
          )
          next unless res.is_a?(Hash) && !res.empty?

          mutex.synchronize do
            merged = (meta["digest"].is_a?(Hash) ? meta["digest"].dup : {}).merge(res)
            if meta["digest"] != merged
              meta["digest"] = merged
              dirty_dirs.add(dir)
            end
          end
        end
      end

      if defined?(FuzzExplain)
        diff_ruby = ENV.fetch("TRIAGE_DIFF_RUBY", RbConfig.ruby)
        if FuzzExplain.ruby_supports_parse_y?(diff_ruby, timeout_sec: 5.0)
          diff_targets = metas_by_dir.select do |dir, meta|
            diff_parse_y_invariant_meta?(meta) &&
              File.file?(File.join(dir, "input.min")) &&
              (force || !meta.dig("digest", "iseq_status"))
          end

          run_digest_work_pool(diff_targets.to_a, workers: workers) do |dir, meta|
            res = run_diff_digest_probe(diff_ruby, File.join(dir, "input.min"))
            next unless res.is_a?(Hash) && !res.empty?

            mutex.synchronize do
              merged = (meta["digest"].is_a?(Hash) ? meta["digest"].dup : {}).merge(res)
              if meta["digest"] != merged
                meta["digest"] = merged
                dirty_dirs.add(dir)
              end
            end
          end
        end
      end
    end
  end
end
