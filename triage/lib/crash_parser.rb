# frozen_string_literal: true

module FuzzTriage
  # Executes crash inputs under timeout/sanitizer bounds and parses sanitizer,
  # invariant, UBSan, assertion, and backtrace metadata from output.
  module CrashParser
    include Config
    extend self

    def frame_scope(file)
      return "external" if file.nil? || file.empty?
      return "prism" if file.start_with?("src/", "include/", "templates/")
      return "harness" if file.start_with?("harnesses/prism/")

      "external"
    end

    def parse_kv_pairs(text)
      result = {}
      text.to_s.scan(/([A-Za-z0-9_]+)=([^\s\]]+)/) do |k, v|
        result[k] = v.match?(/\A-?\d+\z/) ? v.to_i : v
      end
      result
    end

    def parse_frame_location(loc)
      clean_loc = loc.sub(/\s+\(BuildId:[^)]*\)\z/, "").strip
      if clean_loc =~ /\A(.+?):(\d+):(\d+)\z/
        [normalize_repo_path(Regexp.last_match(1)), Regexp.last_match(2).to_i, Regexp.last_match(3).to_i, nil]
      elsif clean_loc =~ /\A(.+?):(\d+)\z/
        [normalize_repo_path(Regexp.last_match(1)), Regexp.last_match(2).to_i, nil, nil]
      elsif clean_loc =~ /\A\(([^)]+)\)\z/
        [nil, nil, nil, Regexp.last_match(1)]
      else
        [normalize_repo_path(clean_loc), nil, nil, nil]
      end
    end

    # Extracts structured symptom, invariant, sanitizer, assertion, and full stack
    # frames from raw sanitizer/abort output so downstream clustering never needs
    # to scrape raw bucket artifacts or re-run testcases.
    def parse_crash_output(crash_output)
      clean = utf8_safe(crash_output)
      lines = clean.lines.map(&:chomp)

      summary = nil
      invariant = nil
      ubsan = nil
      sanitizer = nil
      assertion = nil
      frames = []
      preamble_lines = []
      seen_frames = false

      lines.each do |line|
        next if line.match?(/\AReading \d+ bytes from /) || line == "Execution successful."

        if line =~ /\A\s*#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(.+?)\s+((?:\/|\(|<|[^\s]+\/|[^\s]+:\d+)\S*(?:\s+\(BuildId:[^)]*\))?)\s*\z/ ||
           line =~ /\A\s*#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(\S+)\s+(.+?)\s*\z/
          seen_frames = true
          next if frames.size >= 64

          depth = Regexp.last_match(1).to_i
          func = Regexp.last_match(2)
          file, line_no, col_no, mod = parse_frame_location(Regexp.last_match(3))
          frames << {
            "depth" => depth,
            "func" => func,
            "file" => file,
            "line" => line_no,
            "col" => col_no,
            "module" => mod,
            "scope" => frame_scope(file)
          }.compact
          next
        elsif line =~ /\A\s*#(\d+)\s+0x[0-9a-fA-F]+\s+\(([^)]+)\)(?:\s+\(BuildId:.*\))?\s*\z/
          seen_frames = true
          next if frames.size >= 64

          frames << {
            "depth" => Regexp.last_match(1).to_i,
            "module" => Regexp.last_match(2),
            "scope" => "external"
          }
          next
        elsif line =~ /\A\s*([^\s(]+)?\(([^)]*)\)\s+\[0x[0-9a-fA-F]+\](?:\s+(.+?))?\s*\z/ ||
              line =~ /\A\s*([^\s(]+)\(([^)\s]+)\)\s+((?:\/|[^\s]+:\d+)\S*)\s*\z/
          seen_frames = true
          next if frames.size >= 64

          mod_path = Regexp.last_match(1)
          sym_part = Regexp.last_match(2).to_s
          loc_part = Regexp.last_match(3)
          func = sym_part.sub(/\+0x[0-9a-fA-F]+\z/, "")
          func = nil if func.empty?
          file, line_no, col_no, loc_mod = loc_part && !loc_part.empty? ? parse_frame_location(loc_part) : [nil, nil, nil, nil]
          mod = file ? loc_mod : (mod_path && !mod_path.empty? ? "#{mod_path}(#{sym_part})" : loc_mod)
          frames << {
            "depth" => frames.size,
            "func" => func,
            "file" => file,
            "line" => line_no,
            "col" => col_no,
            "module" => mod,
            "scope" => frame_scope(file)
          }.compact
          next
        end

        if line.start_with?("SUMMARY: ")
          summary ||= line.delete_prefix("SUMMARY: ").strip
        elsif !seen_frames && preamble_lines.size < 20 && !line.strip.empty?
          preamble_lines << line
        end

        if invariant.nil? && line =~ /\AINVARIANT\[([^\]]+)\]:\s*(.+)\z/
          ns = Regexp.last_match(1)
          rest = Regexp.last_match(2)
          before_detail, detail_body = rest.split(/\s*\[detail:\s*(.*?)\]\s*\z/, 2)
          invariant = {
            "namespace" => ns,
            "fields" => parse_kv_pairs(before_detail),
            "detail" => detail_body ? parse_kv_pairs(detail_body) : {}
          }
        end

        if ubsan.nil? && line =~ /\A(.+?):(\d+):(\d+): runtime error: (.+?)\z/
          msg = Regexp.last_match(4).strip
          check, detail = msg.split(": ", 2)
          ubsan = {
            "file" => normalize_repo_path(Regexp.last_match(1)),
            "line" => Regexp.last_match(2).to_i,
            "col" => Regexp.last_match(3).to_i,
            "check" => check,
            "message" => detail
          }.compact
        end

        if line =~ /ERROR: (AddressSanitizer|MemorySanitizer|LeakSanitizer): (detected memory leaks|\S+)(.*)\z/
          sanitizer ||= {
            "tool" => Regexp.last_match(1),
            "kind" => Regexp.last_match(2).tr(" ", "-")
          }
        end

        if line =~ /\A(READ|WRITE) of size (\d+)\b/
          sanitizer ||= { "tool" => "AddressSanitizer" }
          sanitizer["access"] ||= {
            "op" => Regexp.last_match(1),
            "size" => Regexp.last_match(2).to_i
          }
        end

        if assertion.nil? && line =~ /(?:([^:\s]+):(\d+): (?:([^:]+): )?)?Assertion `(.+?)' failed\.\z/
          assertion = {
            "file" => Regexp.last_match(1) ? normalize_repo_path(Regexp.last_match(1)) : nil,
            "line" => Regexp.last_match(2)&.to_i,
            "func" => Regexp.last_match(3),
            "expr" => Regexp.last_match(4)
          }.compact
        end
      end

      headline = preamble_lines.find { |l| !l.start_with?("====") && l != "AddressSanitizer:DEADLYSIGNAL" } || summary || preamble_lines.first

      {
        "symptom" => {
          "headline" => headline,
          "summary" => summary,
          "preamble_lines" => preamble_lines,
          "invariant" => invariant,
          "ubsan" => ubsan,
          "sanitizer" => sanitizer,
          "assertion" => assertion
        },
        "frames" => frames
      }
    end

    def infer_crash_reason(clean_output, sig_name = nil, default_reason: "unknown")
      reason = default_reason == "hang" ? "unknown" : default_reason
      clean_output.match(/SUMMARY: (Memory|UndefinedBehavior|Address|Leak)Sanitizer: ([[:alpha:]-]*) .*/) do |m|
        reason = m.captures[1]
      end
      if reason == "unknown"
        if clean_output.match?(/ERROR: LeakSanitizer: detected memory leaks/) || clean_output.include?("Assertion `allocated == 0' failed")
          reason = "memory-leak"
        elsif clean_output.include?("FUZZ_MAX_ALLOCATED_BYTES")
          reason = "allocation-size-too-big"
        elsif clean_output.include?("Assertion `") || clean_output.include?("INVARIANT[")
          reason = "ABRT"
        elsif clean_output =~ /^CRASH\[[^\]]+\]:\s*signal=SIG([A-Z0-9_]+)/
          reason = Regexp.last_match(1)
        elsif sig_name && !sig_name.empty?
          reason = sig_name
        end
      end
      reason
    end

    def sig_lines_for_reason(reason)
      case reason
      when "undefined-behavior" then 3
      when "ABRT" then 15
      when "use-of-uninitialized-value" then 5
      when "heap-use-after-free" then 7
      when "stack-use-after-return" then 50
      else 10
      end
    end

    def testcase_output_signature(testcase_output, siglines = 10)
      o, = Open3.capture2({ "SIGLINES" => siglines.to_s }, triage_script_path("signature.sh"), stdin_data: testcase_output.to_s.b)
      o.strip
    end

    def with_testcase_timeout(seconds)
      prev = Thread.current[:testcase_timeout_sec]
      Thread.current[:testcase_timeout_sec] = seconds
      yield
    ensure
      Thread.current[:testcase_timeout_sec] = prev
    end

    def run_testcase(executable, input_file)
      Thread.current[:last_testcase_signal] = nil
      timeout_sec = Thread.current[:testcase_timeout_sec] || env_crash_timeout_seconds
      o, s = Open3.capture2e(env_sanitizer_env(executable: executable), "timeout", "-k", "1", timeout_sec.to_s, executable, input_file)
      timed_out = s.exitstatus == 124 || s.exitstatus == 137
      crashed = !s.success? && !timed_out
      sig = if crashed
              s.termsig || (s.exitstatus && s.exitstatus > 128 ? s.exitstatus - 128 : nil)
            end
      Thread.current[:last_testcase_signal] = sig && (1..64).include?(sig) ? Signal.signame(sig) : nil
      [o.b, crashed, timed_out]
    end

    def run_crash_testcase(executable, input_file)
      crash_timeout = env_crash_timeout_seconds
      out, crashed, timed_out = with_testcase_timeout(crash_timeout) { run_testcase(executable, input_file) }
      return [out, crashed, timed_out] unless !crashed && timed_out

      # Retry once on transient wall-clock timeouts (e.g. parallel fuzz.diff DWARF backtrace contention)
      retry_timeout = [crash_timeout * 2, 30].max
      with_testcase_timeout(retry_timeout) { run_testcase(executable, input_file) }
    end

    def classify_crash_execution(crash_dir, crash_input, executable, triage_dir: TESTCASES_DIR)
      reason = File.basename(crash_dir) == "hangs" ? "hang" : "unknown"
      timed_out = false
      Thread.current[:last_testcase_signal] = nil
      fspec = resolve_topology_fuzzer(executable: executable, triage_dir: triage_dir)
      repro_name = fspec && fspec["repro"] ? File.basename(fspec["repro"]) : nil
      fast_exe = companion_executable(executable, "fuzz", triage_dir: triage_dir)
      lsan_exe = companion_executable(executable, "fuzz.lsan", triage_dir: triage_dir)
      replay_exe = if repro_name
                     companion_executable(executable, repro_name, triage_dir: triage_dir)
                   elsif (oracle_kind = cross_oracle_kind(executable: executable, triage_dir: triage_dir))
                     companion_executable(executable, CROSS_ORACLE_TARGETS.fetch(oracle_kind)[:repro_exe], triage_dir: triage_dir)
                   else
                     executable
                   end

      if reason == "hang"
        executable = replay_exe
        testcase_output, crashed, timed_out = with_testcase_timeout(env_hang_timeout_seconds) { run_testcase(executable, crash_input) }
        return { transient_timeout: true } if !crashed && !timed_out
      elsif (fspec ? (fspec["shape"] == "prism_parse" && Array(fspec["sanitizers"]).empty?) : executable.end_with?("ijon", "native"))
        # Sanitizer-less binaries (e.g. fuzz.ijon, fuzz.native) defer classification to fast ASAN/UBSAN
        # (when available) so bugs deduplicate with main, then LSAN, then the raw binary.
        if File.executable?(fast_exe) && File.basename(fast_exe) != File.basename(executable)
          testcase_output, crashed, timed_out = run_crash_testcase(fast_exe, crash_input)
          executable = fast_exe if crashed
        else
          crashed = false
        end
        unless crashed
          Thread.current[:last_testcase_signal] = nil
          if File.executable?(lsan_exe) && File.basename(lsan_exe) != File.basename(executable)
            testcase_output, crashed, timed_out = run_crash_testcase(lsan_exe, crash_input)
            executable = lsan_exe if crashed
          end
          unless crashed
            Thread.current[:last_testcase_signal] = nil
            testcase_output, crashed, timed_out = run_crash_testcase(executable, crash_input)
          end
        end
      elsif executable.end_with?("msan", "slow", "diff", "arm32", "arm32.repro", "ppc", "ppc.repro") ||
            (fspec && %w[prism_diff_ruby prism_cross_oracle].include?(fspec["shape"])) ||
            (fspec && fspec["shape"] == "prism_parse" && (fspec["mode"].to_s == "slow" || Array(fspec["sanitizers"]).include?("msan")))
        if File.executable?(fast_exe) && File.basename(fast_exe) != File.basename(executable)
          testcase_output, crashed, timed_out = run_crash_testcase(fast_exe, crash_input)
          executable = fast_exe if crashed
        else
          crashed = false
        end
        unless crashed
          executable = replay_exe
          Thread.current[:last_testcase_signal] = nil
          testcase_output, crashed, timed_out = run_crash_testcase(executable, crash_input)
        end
      else
        testcase_output, crashed, timed_out = run_crash_testcase(executable, crash_input)
      end

      sig_name = crashed ? Thread.current[:last_testcase_signal] : nil
      unreproducible = !crashed && !(reason == "hang" && timed_out)

      clean_output = utf8_safe(testcase_output)
      reason = infer_crash_reason(clean_output, sig_name, default_reason: reason) if crashed
      sig_lines = sig_lines_for_reason(reason)

      {
        transient_timeout: false,
        reason: reason,
        executable: executable,
        testcase_output: testcase_output,
        crashed: crashed,
        timed_out: timed_out,
        unreproducible: unreproducible,
        sig_lines: sig_lines
      }
    end
  end
end
