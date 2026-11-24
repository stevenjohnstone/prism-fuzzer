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

    BATCH_DIFF_WORKER_SCRIPT = <<~'RUBY'.freeze
      require "base64"
      require "json"
      require "timeout"

      include_prism = ARGV[0] == "prism"
      if include_prism
        begin
          require "prism"
        rescue LoadError
          include_prism = false
        end
      end

      items = JSON.parse($stdin.read)
      items.each do |key, b64|
        code = Base64.strict_decode64(b64)
        rec = { "key" => key }
        begin
          Timeout.timeout(2.5) do
            if include_prism
              pr = Prism.parse(code)
              errs = pr.errors
              rec["prism_errors_count"] = errs.size
              if !errs.empty?
                e0 = errs.first
                rec["prism_first_error"] = { "type" => e0.type.to_s, "message" => e0.message.to_s }
              end
            end

            begin
              iseq = RubyVM::InstructionSequence.compile(code, "(compare)", "(compare)", 1)
              rec["ok"] = true
              rec["disasm"] = iseq.disasm
            rescue SyntaxError => e
              rec["ok"] = false
              rec["error_class"] = e.class.name
              rec["stderr"] = e.message.to_s
            rescue ScriptError, StandardError
              rec["fallback"] = true
            end
          end
        rescue Timeout::Error, SystemStackError, NoMemoryError
          rec["fallback"] = true
        end
        $stdout.puts(JSON.generate(rec))
        $stdout.flush
      end
    RUBY

    def parse_batch_worker_jsonl(stdout_text)
      out = {}
      stdout_text.to_s.each_line do |line|
        line = line.strip
        next if line.empty?

        rec = JSON.parse(line)
        out[rec["key"]] = rec if rec.is_a?(Hash) && rec["key"]
      rescue JSON::ParserError
        next
      end
      out
    end

    def run_diff_digest_batch(ruby_bin, target_pairs)
      return {} if target_pairs.empty?

      payload_items = target_pairs.filter_map do |dir, _meta|
        min_path = File.join(dir, "input.min")
        next nil unless File.file?(min_path)

        raw = File.binread(min_path)
        body = raw.bytesize >= 4 ? (raw.byteslice(4..) || "".b) : raw
        [dir, Base64.strict_encode64(body)]
      end
      return {} if payload_items.empty?

      stdin_json = JSON.generate(payload_items)
      batch_timeout = [payload_items.size * 2.5 + 10.0, 15.0].max

      y_thr = Thread.new do
        FuzzExplain.run_with_timeout([ruby_bin, "--parser=parse.y", "-e", BATCH_DIFF_WORKER_SCRIPT, "parse.y"], timeout_sec: batch_timeout, stdin_data: stdin_json)
      end
      p_thr = Thread.new do
        FuzzExplain.run_with_timeout([ruby_bin, "--parser=prism", "-e", BATCH_DIFF_WORKER_SCRIPT, "prism"], timeout_sec: batch_timeout, stdin_data: stdin_json)
      end
      y_res = y_thr.value
      p_res = p_thr.value

      y_map = parse_batch_worker_jsonl(y_res[:stdout])
      p_map = parse_batch_worker_jsonl(p_res[:stdout])
      results = {}

      target_pairs.each do |dir, _meta|
        yr = y_map[dir]
        pr = p_map[dir]
        if yr.nil? || pr.nil? || yr["fallback"] || pr["fallback"]
          fallback_res = run_diff_digest_probe(ruby_bin, File.join(dir, "input.min"))
          results[dir] = fallback_res if fallback_res
          next
        end

        y_ok = yr["ok"] == true
        p_ok = pr["ok"] == true
        syntax_status = if y_ok && p_ok
                          "both_ok"
                        elsif !y_ok && !p_ok
                          "both_error"
                        elsif y_ok && !p_ok
                          "parse_y_ok_prism_err"
                        else
                          "prism_ok_parse_y_err"
                        end

        iseq_status = if y_ok && p_ok
                        dy = FuzzExplain.normalize_disasm(yr["disasm"], ignore_locations: true)
                        dp = FuzzExplain.normalize_disasm(pr["disasm"], ignore_locations: true)
                        dy == dp ? "match" : "disasm_diff"
                      elsif !y_ok && !p_ok
                        yr["error_class"] == pr["error_class"] ? "both_compile_error" : "compile_error_class_mismatch"
                      elsif y_ok && !p_ok
                        "parse_y_ok_prism_compile_err"
                      else
                        "prism_ok_parse_y_compile_err"
                      end

        entry_out = {
          "syntax_status" => syntax_status,
          "iseq_status" => iseq_status
        }

        if pr.key?("prism_errors_count")
          entry_out["prism_errors_count"] = pr["prism_errors_count"]
          if (fe = pr["prism_first_error"])
            msg = "#{fe['type']}: #{fe['message']}".strip
            entry_out["prism_error"] = msg.length > 120 ? "#{msg[0, 117]}..." : msg
          end
        end

        unless y_ok
          err = yr["stderr"].to_s.lines.first.to_s.strip
          entry_out["parse_y_error"] = err.length > 120 ? "#{err[0, 117]}..." : err unless err.empty?
        end

        if iseq_status == "disasm_diff"
          diff_txt = FuzzExplain.simple_line_diff(
            FuzzExplain.normalize_disasm(yr["disasm"], ignore_locations: true),
            FuzzExplain.normalize_disasm(pr["disasm"], ignore_locations: true)
          )
          preview = summarize_first_disasm_diff(diff_txt)
          entry_out["disasm_diff_preview"] = preview if preview
        end

        results[dir] = entry_out
      end
      results
    rescue SystemCallError, IOError, JSON::ParserError, EncodingError => e
      warn "DigestEnricher: batched diff probe failed: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
      {}
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

          if diff_targets.size >= 2
            batch_results = run_diff_digest_batch(diff_ruby, diff_targets.to_a)
            batch_results.each do |dir, res|
              next unless res.is_a?(Hash) && !res.empty?

              meta = metas_by_dir[dir]
              next unless meta

              merged = (meta["digest"].is_a?(Hash) ? meta["digest"].dup : {}).merge(res)
              if meta["digest"] != merged
                meta["digest"] = merged
                dirty_dirs.add(dir)
              end
            end
          else
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
end
