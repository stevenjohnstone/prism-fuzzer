# frozen_string_literal: true

module FuzzTriage
  # Minimizes crash and hang testcases (halfempty / afl-tmin) and normalizes
  # 4-byte fuzzer option headers and IJON stream-mode bits.
  module Minimizer
    include Config
    include CrashParser
    extend self

    def signal_pgroup_or_pid(sig, pid)
      Process.kill(sig, -pid)
    rescue Errno::ESRCH, Errno::EPERM
      begin
        Process.kill(sig, pid)
      rescue Errno::ESRCH
        nil
      end
    end

    def drain_pipe_nonblock!(io, buf)
      while (chunk = io.read_nonblock(65_536))
        buf << chunk
      end
    rescue IO::WaitReadable, EOFError
      nil
    end

    def run_bounded_pgroup(env, *cmd, max_time_sec:, stop_signal: "INT", grace_sec: 2.0)
      r, w = IO.pipe
      r.binmode
      out = +"".b
      timed_out = false
      reaped_status = nil
      pid = Process.spawn(env, *cmd, in: File::NULL, out: w, err: w, pgroup: true)
      w.close

      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + max_time_sec
      loop do
        remain = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
        if remain <= 0
          timed_out = true
          signal_pgroup_or_pid(stop_signal, pid)
          grace_deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + grace_sec
          while (g_rem = grace_deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)) > 0
            _, st = Process.waitpid2(pid, Process::WNOHANG)
            if st
              reaped_status = st
              break
            end
            ready = IO.select([r], nil, nil, [g_rem, 0.05].min)
            drain_pipe_nonblock!(r, out) if ready
          end
          signal_pgroup_or_pid("KILL", pid) unless reaped_status
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

      drain_pipe_nonblock!(r, out)
      r.close unless r.closed?
      status = reaped_status || begin
        Process.waitpid2(pid).last
      rescue Errno::ECHILD
        nil
      end
      [out, status, timed_out]
    ensure
      w.close if w && !w.closed?
      r.close if r && !r.closed?
    end

    def run_afl_tmin_hang(crash, minimized_input, executable, max_time_sec: env_hang_minimize_max_time_seconds)
      max_mb = env_max_allocated_mb
      hard_mb = env_hard_rss_limit_mb
      asan_opts = env_sanitizer_env(executable: executable)
                    .fetch("ASAN_OPTIONS")
                    .sub(":handle_abort=1", ":handle_abort=0")
      env = {
        "AFL_NO_IJON" => "1",
        "AFL_TMIN_EXACT" => "1",
        "ASAN_OPTIONS" => "#{asan_opts}:symbolize=0",
        "UBSAN_OPTIONS" => "abort_on_error=1:symbolize=0",
        "MSAN_OPTIONS" => "exit_code=86:abort_on_error=1:max_allocation_size_mb=#{max_mb}:hard_rss_limit_mb=#{hard_mb}:symbolize=0"
      }
      run_bounded_pgroup(
        env,
        "afl-tmin", "-H", "-t", "500", "-i", crash, "-o", minimized_input, "--", executable,
        max_time_sec: max_time_sec
      )
    end

    def minimize_options_header(minimized_input, executable, sig_lines)
      return unless File.exist?(minimized_input) && File.size(minimized_input) >= 4

      raw = File.binread(minimized_input)
      orig_hdr = raw.bytes[0, 4]
      hdr = orig_hdr.dup
      return if hdr == DEFAULT_HEADER_BYTES

      orig_out, orig_crashed, = run_testcase(executable, minimized_input, symbolize: false)
      if orig_crashed && !invariant_line_present?(orig_out)
        orig_out, orig_crashed, = run_testcase(executable, minimized_input, symbolize: true)
      end
      return unless orig_crashed

      fast_inv = invariant_line_present?(orig_out)
      orig_sig = testcase_output_signature(orig_out, sig_lines)
      body = raw.bytesize > 4 ? raw.byteslice(4..) : "".b
      tmp_file = "#{minimized_input}.hdrtmp"
      tested = Set.new([hdr.dup])

      try_hdr = lambda do |cand|
        return true if cand == hdr
        return false unless tested.add?(cand.dup)

        File.binwrite(tmp_file, cand.pack("C4") + body)
        out, crashed, = run_testcase(executable, tmp_file, symbolize: !fast_inv)
        if crashed && testcase_output_signature(out, sig_lines) == orig_sig
          hdr = cand.dup
          true
        else
          false
        end
      end

      begin
        unless try_hdr.call(DEFAULT_HEADER_BYTES)
          loop do
            prev_hdr = hdr.dup

            # b0: stream_mode, has_encoding_opts, frozen_string_literal, and boolean flags
            try_hdr.call([hdr[0] & ~0x40, hdr[1], hdr[2], hdr[3]]) if (hdr[0] & 0x40) != 0
            if (hdr[0] & 0x80) != 0
              unless try_hdr.call([hdr[0] & ~0x80, hdr[1], hdr[2], hdr[3]])
                try_hdr.call([hdr[0] & ~0x80, hdr[1], hdr[2], 0x01]) if (hdr[1] & 0x80) == 0 && hdr[3] != 0x01
              end
            end
            try_hdr.call([hdr[0] & ~0x30, hdr[1], hdr[2], hdr[3]]) if (hdr[0] & 0x30) != 0
            try_hdr.call([hdr[0] & ~0x20, hdr[1], hdr[2], hdr[3]]) if (hdr[0] & 0x10) == 0 && (hdr[0] & 0x20) != 0
            [0x08, 0x04, 0x02, 0x01].each do |bit|
              try_hdr.call([hdr[0] & ~bit, hdr[1], hdr[2], hdr[3]]) if (hdr[0] & bit) != 0
            end

            # b1: has_limit_opts, main_script, and command_line flags
            if (hdr[1] & 0x80) != 0
              alt_b3 = (hdr[0] & 0x80) != 0 ? (hdr[3] & 0x1f) : 0x01
              unless try_hdr.call([hdr[0], hdr[1] & ~0x80, hdr[2], alt_b3])
                try_hdr.call([hdr[0], hdr[1] & ~0x80, hdr[2], hdr[3]])
              end
            end
            try_hdr.call([hdr[0], hdr[1] & ~0x40, hdr[2], hdr[3]]) if (hdr[1] & 0x40) != 0
            if (hdr[1] & 0x3f) != 0 && !try_hdr.call([hdr[0], hdr[1] & ~0x3f, hdr[2], hdr[3]])
              [0x20, 0x10, 0x08, 0x04, 0x02, 0x01].each do |bit|
                try_hdr.call([hdr[0], hdr[1] & ~bit, hdr[2], hdr[3]]) if (hdr[1] & bit) != 0
              end
            end

            # b2: version (prefer latest "4.1" = 3), scopes_count, and forwarding
            try_hdr.call([hdr[0], hdr[1], (hdr[2] & ~0x03) | 0x03, hdr[3]]) if (hdr[2] & 0x03) != 0x03
            if (hdr[2] & 0xfc) != 0 && !try_hdr.call([hdr[0], hdr[1], hdr[2] & 0x03, hdr[3]])
              scopes = (hdr[2] >> 2) & 0x03
              if scopes > 1 && !try_hdr.call([hdr[0], hdr[1], (hdr[2] & ~0x0c) | 0x04, hdr[3]])
                try_hdr.call([hdr[0], hdr[1], (hdr[2] & ~0x0c) | 0x08, hdr[3]]) if scopes > 2
              end
              if ((hdr[2] >> 2) & 0x03) == 0
                try_hdr.call([hdr[0], hdr[1], hdr[2] & 0x03, hdr[3]])
              elsif (hdr[2] & 0xf0) != 0 && !try_hdr.call([hdr[0], hdr[1], hdr[2] & ~0xf0, hdr[3]])
                [0x80, 0x40, 0x20, 0x10].each do |bit|
                  try_hdr.call([hdr[0], hdr[1], hdr[2] & ~bit, hdr[3]]) if (hdr[2] & bit) != 0
                end
              end
            end

            # b3: start_line (default 1) and aux_byte subfields
            if hdr[3] != 0x01 && !try_hdr.call([hdr[0], hdr[1], hdr[2], 0x01])
              if (hdr[0] & 0x80) != 0
                try_hdr.call([hdr[0], hdr[1], hdr[2], hdr[3] & ~0x08]) if (hdr[3] & 0x08) != 0
                try_hdr.call([hdr[0], hdr[1], hdr[2], hdr[3] & ~0x10]) if (hdr[1] & 0x80) == 0 && (hdr[3] & 0x10) != 0
                try_hdr.call([hdr[0], hdr[1], hdr[2], hdr[3] & 0x1f]) if (hdr[1] & 0x80) == 0 && (hdr[3] & 0xe0) != 0
                try_hdr.call([hdr[0], hdr[1], hdr[2], hdr[3] & ~0x07]) if (hdr[3] & 0x07) != 0
              end
              if (hdr[1] & 0x80) != 0
                try_hdr.call([hdr[0], hdr[1], hdr[2], hdr[3] & ~0xc0]) if (hdr[3] & 0xc0) != 0
                try_hdr.call([hdr[0], hdr[1], hdr[2], hdr[3] | 0x30]) if (hdr[3] & 0x30) != 0x30
                try_hdr.call([hdr[0], hdr[1], hdr[2], hdr[3] & 0xf0]) if (hdr[0] & 0x80) == 0 && (hdr[3] & 0x0f) != 0
              end
            end

            break if hdr == prev_hdr
          end
        end

        File.binwrite(minimized_input, hdr.pack("C4") + body) if hdr != orig_hdr
      ensure
        FileUtils.rm_f(tmp_file)
      end
    end

    COARSE_ONLY_REASONS = %w[stack-overflow allocation-size-too-big out-of-memory].freeze

    def minimize(crash, reason, minimized_input, executable, sig_lines)
      puts "minimizing #{crash}"
      t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      pre_min_size = File.size(crash)
      if reason == "hang"
        run_afl_tmin_hang(crash, minimized_input, executable)
      else
        extra_he_env = {
          "SIGLINES" => sig_lines.to_s,
          "HALFEMPTY_THREADS" => env_halfempty_threads.to_s
        }
        if COARSE_ONLY_REASONS.include?(reason.to_s)
          extra_he_env["HALFEMPTY_SKIP_FINE"] = "1"
          extra_he_env["HALFEMPTY_MAX_TIME"] = ENV.fetch("HALFEMPTY_MAX_TIME", "20")
        end
        Open3.capture2e(
          env_sanitizer_env(executable: executable).merge(extra_he_env),
          triage_script_path("halfempty.sh"), executable, crash, minimized_input
        )
      end
      FileUtils.cp(crash, minimized_input) unless File.exist?(minimized_input) && File.size(minimized_input) >= 4
      if reason != "hang" && !COARSE_ONLY_REASONS.include?(reason.to_s)
        minimize_options_header(minimized_input, executable, sig_lines)
      end
      post_min_size = File.size(minimized_input)
      elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0
      puts "#{crash} minimized #{pre_min_size} => #{post_min_size} (#{format('%.1fs', elapsed)})"
    end

    def normalize_ijon_crash_bytes(raw)
      return nil unless raw.bytesize >= 4 && (raw.getbyte(0) & 0x40) != 0

      out = raw.b.dup
      out.setbyte(0, out.getbyte(0) & ~0x40)
      out
    end
  end
end
