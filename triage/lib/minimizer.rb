# frozen_string_literal: true

module FuzzTriage
  # Minimizes crash and hang testcases (halfempty / afl-tmin) and normalizes
  # 4-byte fuzzer option headers and IJON stream-mode bits.
  module Minimizer
    include Config
    include CrashParser
    extend self

    def run_afl_tmin_hang(crash, minimized_input, executable)
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
      Open3.capture2e(env, "afl-tmin", "-H", "-t", "500", "-i", crash, "-o", minimized_input, "--", executable)
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

    def minimize(crash, reason, minimized_input, executable, sig_lines)
      puts "minimizing #{crash}"
      pre_min_size = File.size(crash)
      if reason == "hang"
        run_afl_tmin_hang(crash, minimized_input, executable)
      else
        Open3.capture2e(
          env_sanitizer_env(executable: executable).merge({
            "SIGLINES" => sig_lines.to_s,
            "HALFEMPTY_THREADS" => env_halfempty_threads.to_s
          }),
          triage_script_path("halfempty.sh"), executable, crash, minimized_input
        )
      end
      FileUtils.cp(crash, minimized_input) unless File.exist?(minimized_input) && File.size(minimized_input) >= 4
      minimize_options_header(minimized_input, executable, sig_lines) if reason != "hang"
      post_min_size = File.size(minimized_input)
      puts "#{crash} minimized #{pre_min_size} => #{post_min_size}"
    end

    def normalize_ijon_crash_bytes(raw)
      return nil unless raw.bytesize >= 4 && (raw.getbyte(0) & 0x40) != 0

      out = raw.b.dup
      out.setbyte(0, out.getbyte(0) & ~0x40)
      out
    end
  end
end
