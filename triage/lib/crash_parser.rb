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
      FuzzTriage::Signature.compute(testcase_output, siglines)
    end

    def invariant_line_present?(raw_output)
      b = raw_output.to_s.b
      b.include?("INVARIANT[".b) && b.match?(/^INVARIANT\[/n)
    end

    def differential_invariant_present?(raw_output)
      b = raw_output.to_s.b
      b.include?("INVARIANT[".b) && b.match?(/^INVARIANT\[(?:diff_parse_y|diff_prism|oracle_[A-Za-z0-9_]+)\]:/n)
    end

    def with_testcase_timeout(seconds)
      prev = Thread.current[:testcase_timeout_sec]
      Thread.current[:testcase_timeout_sec] = seconds
      yield
    ensure
      Thread.current[:testcase_timeout_sec] = prev
    end

    def spawn_testcase_with_timeout(env, executable, input_file, timeout_sec)
      r, w = IO.pipe
      r.binmode
      out = +"".b
      timed_out = false
      pid = Process.spawn(env, executable, input_file, in: File::NULL, out: w, err: w, pgroup: true)
      w.close

      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout_sec
      loop do
        remain = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
        if remain <= 0
          timed_out = true
          begin
            Process.kill("TERM", -pid)
          rescue Errno::ESRCH, Errno::EPERM
            begin
              Process.kill("TERM", pid)
            rescue Errno::ESRCH
              nil
            end
          end
          kill_deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 0.2
          while Process.clock_gettime(Process::CLOCK_MONOTONIC) < kill_deadline
            break if Process.waitpid(pid, Process::WNOHANG)

            sleep 0.01
          end
          begin
            Process.kill("KILL", -pid)
          rescue Errno::ESRCH, Errno::EPERM
            begin
              Process.kill("KILL", pid)
            rescue Errno::ESRCH
              nil
            end
          end
          break
        end

        ready = IO.select([r], nil, nil, [remain, 0.25].min)
        next unless ready

        begin
          out << r.read_nonblock(65_536)
        rescue IO::WaitReadable
          nil
        rescue EOFError
          break
        end
      end

      unless timed_out
        begin
          while (chunk = r.read_nonblock(65_536))
            out << chunk
          end
        rescue IO::WaitReadable, EOFError
          nil
        end
      end

      r.close unless r.closed?
      _, status = begin
        Process.waitpid2(pid)
      rescue Errno::ECHILD
        [pid, nil]
      end
      [out, status, timed_out]
    ensure
      w.close if w && !w.closed?
      r.close if r && !r.closed?
    end

    def run_testcase(executable, input_file, symbolize: true)
      Thread.current[:last_testcase_signal] = nil
      timeout_sec = Thread.current[:testcase_timeout_sec] || env_crash_timeout_seconds
      env = env_sanitizer_env(executable: executable, symbolize: symbolize)
      o, s, timed_out = spawn_testcase_with_timeout(env, executable, input_file, timeout_sec)
      timed_out ||= (s && (s.exitstatus == 124 || s.exitstatus == 137))
      crashed = !timed_out && (s.nil? || !s.success?)
      sig = if crashed && s
              s.termsig || (s.exitstatus && s.exitstatus > 128 ? s.exitstatus - 128 : nil)
            end
      Thread.current[:last_testcase_signal] = sig && (1..64).include?(sig) ? Signal.signame(sig) : nil
      [o.b, crashed, timed_out]
    end

    def run_crash_testcase(executable, input_file, symbolize: true)
      crash_timeout = env_crash_timeout_seconds
      out, crashed, timed_out = with_testcase_timeout(crash_timeout) { run_testcase(executable, input_file, symbolize: symbolize) }
      return [out, crashed, timed_out] unless !crashed && timed_out

      # Retry once on transient wall-clock timeouts (e.g. parallel fuzz.diff DWARF backtrace contention)
      retry_timeout = [crash_timeout * 2, 30].max
      with_testcase_timeout(retry_timeout) { run_testcase(executable, input_file, symbolize: symbolize) }
    end

    def classify_crash_execution(crash_dir, crash_input, executable, triage_dir: TESTCASES_DIR)
      reason = File.basename(crash_dir) == "hangs" ? "hang" : "unknown"
      timed_out = false
      symbolized = false
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

      is_diff_or_oracle = executable.end_with?("diff", "prism_diff", "arm32", "arm32.repro", "ppc", "ppc.repro") ||
                          (fspec && %w[prism_diff_ruby prism_diff_prism prism_cross_oracle].include?(fspec["shape"]))

      if reason == "hang"
        executable = replay_exe
        testcase_output, crashed, timed_out = with_testcase_timeout(env_hang_timeout_seconds) { run_testcase(executable, crash_input, symbolize: false) }
        return { transient_timeout: true } if !crashed && !timed_out
      elsif is_diff_or_oracle
        # Differential and cross-oracle queues overwhelmingly hit differential invariants
        # (`INVARIANT[diff_parse_y]`, `INVARIANT[oracle_*]`), which `fast_exe` (`fuzz`) can
        # never reproduce. Probe `replay_exe` unsymbolized first; only consult `fast_exe`
        # when the crash is NOT a differential invariant so shared 64-bit Prism crashes
        # still promote to `fuzz` and deduplicate with `main`.
        executable = replay_exe
        testcase_output, crashed, timed_out = run_crash_testcase(executable, crash_input, symbolize: false)
        if (!crashed || !differential_invariant_present?(testcase_output)) &&
           File.executable?(fast_exe) && File.basename(fast_exe) != File.basename(executable)
          saved_out = testcase_output
          saved_crashed = crashed
          saved_timed_out = timed_out
          saved_sig = Thread.current[:last_testcase_signal]
          fast_out, fast_crashed, fast_timed_out = run_crash_testcase(fast_exe, crash_input, symbolize: false)
          if fast_crashed
            executable = fast_exe
            testcase_output = fast_out
            crashed = true
            timed_out = fast_timed_out
          else
            testcase_output = saved_out
            crashed = saved_crashed
            timed_out = saved_timed_out
            Thread.current[:last_testcase_signal] = saved_sig
          end
        end
      elsif (fspec ? (fspec["shape"] == "prism_parse" && Array(fspec["sanitizers"]).empty?) : executable.end_with?("ijon", "native"))
        # Sanitizer-less binaries (e.g. fuzz.ijon, fuzz.native) defer classification to fast ASAN/UBSAN
        # (when available) so bugs deduplicate with main, then LSAN, then the raw binary.
        if File.executable?(fast_exe) && File.basename(fast_exe) != File.basename(executable)
          testcase_output, crashed, timed_out = run_crash_testcase(fast_exe, crash_input, symbolize: false)
          executable = fast_exe if crashed
        else
          crashed = false
        end
        unless crashed
          Thread.current[:last_testcase_signal] = nil
          if File.executable?(lsan_exe) && File.basename(lsan_exe) != File.basename(executable)
            testcase_output, crashed, timed_out = run_crash_testcase(lsan_exe, crash_input, symbolize: false)
            executable = lsan_exe if crashed
          end
          unless crashed
            Thread.current[:last_testcase_signal] = nil
            testcase_output, crashed, timed_out = run_crash_testcase(executable, crash_input, symbolize: false)
          end
        end
      elsif executable.end_with?("msan", "slow") ||
            (fspec && fspec["shape"] == "prism_parse" && (fspec["mode"].to_s == "slow" || Array(fspec["sanitizers"]).include?("msan")))
        if File.executable?(fast_exe) && File.basename(fast_exe) != File.basename(executable)
          testcase_output, crashed, timed_out = run_crash_testcase(fast_exe, crash_input, symbolize: false)
          executable = fast_exe if crashed
        else
          crashed = false
        end
        unless crashed
          executable = replay_exe
          Thread.current[:last_testcase_signal] = nil
          testcase_output, crashed, timed_out = run_crash_testcase(executable, crash_input, symbolize: false)
        end
      else
        testcase_output, crashed, timed_out = run_crash_testcase(executable, crash_input, symbolize: false)
      end

      # Non-INVARIANT crashes rely on symbolized frame names for signature hashing;
      # INVARIANT[...] signatures use only the INVARIANT line, deferring symbolization
      # until the single winning leader input per new bucket is published.
      if crashed && !invariant_line_present?(testcase_output)
        sym_out, sym_crashed, sym_timed_out = run_crash_testcase(executable, crash_input, symbolize: true)
        if sym_crashed
          testcase_output = sym_out
          timed_out = sym_timed_out
          symbolized = true
        end
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
        sig_lines: sig_lines,
        symbolized: symbolized
      }
    end
  end
end
