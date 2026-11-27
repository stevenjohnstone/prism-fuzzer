# frozen_string_literal: true

module FuzzTriage
  # In-process crash output normalizer and XXH64 (seed 0) digest implementation
  # maintaining byte-for-byte parity with `triage/signature.sh` without spawning
  # external `bash | sed | awk | xxh64sum | cut` pipelines on every crash/probe.
  module Signature
    MASK64 = 0xffffffffffffffff
    PRIME64_1 = 0x9e3779b185ebca87
    PRIME64_2 = 0xc2b2ae3d27d4eb4f
    PRIME64_3 = 0x165667b19e3779f9
    PRIME64_4 = 0x85ebca77c2b2ae63
    PRIME64_5 = 0x27d4eb2f165667c5

    INV_PREFIX = "INVARIANT[".b.freeze
    HANG_PREFIX = "HANG[stack]: ".b.freeze
    EXEC_SUCCESS = "Execution successful.".b.freeze
    RT_ERR_MARKER = ": runtime error: ".b.freeze
    DIFF_HANDLER = "diff_fatal_signal_handler".b.freeze
    COMPILE_HANDLER = "compile_fatal_signal_handler".b.freeze
    SIGRETURN_1 = "__kernel_rt_sigreturn".b.freeze
    SIGRETURN_2 = "__restore_rt".b.freeze

    module_function

    def rotl64(val, bits)
      (((val << bits) & MASK64) | (val >> (64 - bits)))
    end

    def round64(acc, input)
      acc = (acc + ((input * PRIME64_2) & MASK64)) & MASK64
      acc = rotl64(acc, 31)
      (acc * PRIME64_1) & MASK64
    end

    def merge_round64(acc, val)
      val = round64(0, val)
      acc ^= val
      (((acc * PRIME64_1) & MASK64) + PRIME64_4) & MASK64
    end

    def xxh64(data, seed = 0)
      bytes = data.b
      len = bytes.bytesize
      pos = 0

      if len >= 32
        v1 = (seed + PRIME64_1 + PRIME64_2) & MASK64
        v2 = (seed + PRIME64_2) & MASK64
        v3 = seed & MASK64
        v4 = (seed - PRIME64_1) & MASK64
        limit = len - 32
        while pos <= limit
          v1 = round64(v1, bytes.unpack1("Q<", offset: pos))
          v2 = round64(v2, bytes.unpack1("Q<", offset: pos + 8))
          v3 = round64(v3, bytes.unpack1("Q<", offset: pos + 16))
          v4 = round64(v4, bytes.unpack1("Q<", offset: pos + 24))
          pos += 32
        end
        h64 = (rotl64(v1, 1) + rotl64(v2, 7) + rotl64(v3, 12) + rotl64(v4, 18)) & MASK64
        h64 = merge_round64(h64, v1)
        h64 = merge_round64(h64, v2)
        h64 = merge_round64(h64, v3)
        h64 = merge_round64(h64, v4)
      else
        h64 = (seed + PRIME64_5) & MASK64
      end

      h64 = (h64 + len) & MASK64

      while pos + 8 <= len
        k1 = round64(0, bytes.unpack1("Q<", offset: pos))
        h64 ^= k1
        h64 = (((rotl64(h64, 27) * PRIME64_1) & MASK64) + PRIME64_4) & MASK64
        pos += 8
      end

      if pos + 4 <= len
        u32 = bytes.unpack1("V", offset: pos)
        h64 ^= (u32 * PRIME64_1) & MASK64
        h64 = (((rotl64(h64, 23) * PRIME64_2) & MASK64) + PRIME64_3) & MASK64
        pos += 4
      end

      while pos < len
        b = bytes.getbyte(pos)
        h64 ^= (b * PRIME64_5) & MASK64
        h64 = (rotl64(h64, 11) * PRIME64_1) & MASK64
        pos += 1
      end

      h64 ^= h64 >> 33
      h64 = (h64 * PRIME64_2) & MASK64
      h64 ^= h64 >> 29
      h64 = (h64 * PRIME64_3) & MASK64
      h64 ^= h64 >> 32
      h64
    end

    def xxh64_hex(data, seed = 0)
      format("%016x", xxh64(data, seed))
    end

    def normalize_line(raw_line)
      line = raw_line.dup
      line.delete_suffix!("\n".b)

      return nil if line == EXEC_SUCCESS
      return nil if line.start_with?("Reading ".b) && line.match?(/\AReading [0-9]+ bytes from /n)
      return nil if line.include?(DIFF_HANDLER) || line.include?(COMPILE_HANDLER)
      return nil if line.include?(SIGRETURN_1) || line.include?(SIGRETURN_2)
      if line.include?("rb_".b) &&
         line.match?(/\((?:rb_print_backtrace|rb_vm_bugreport|rb_bug_without_die_internal|rb_bug_context|rb_bug_for_fatal_signal|rb_bug)(?:\+0x[0-9a-fA-F]+)?\)/n)
        return nil
      end
      return nil if line.start_with?("ruby ".b) && line.match?(/\Aruby [0-9]+\.[0-9]+.* \[[^\]]+\]\z/n)
      if line.start_with?("-- ".b) &&
         line.match?(/\A-- (?:Control frame|Ruby level backtrace|Threading|C level backtrace|Machine register|Other runtime) information -+\z/n)
        return nil
      end
      return nil if line.start_with?("c:".b) && line.match?(/\Ac:[0-9]{4} p:/n)
      if (line.start_with?("-e:".b) || line.start_with?("<compiled>:".b)) && line.match?(/\A(?:-e|<compiled>):[0-9]+:in /n)
        return nil
      end
      if (line.start_with?("Total ractor count: ".b) || line.start_with?("Ruby thread count for this ractor: ".b)) &&
         line.match?(/\A(?:Total ractor count|Ruby thread count for this ractor): [0-9]+\z/n)
        return nil
      end

      line.sub!(/\A(-e|<compiled>):[0-9]+: \[BUG\] /n, '\1: [BUG] ') if line.include?(": [BUG] ".b)

      line.sub!(/\A(?:[^ :]+\/)?fuzz(?:\.[A-Za-z0-9_.-]+)*:/n, "fuzz_bin:")
      line.gsub!(/(?:\/?[^ ("']+\/)?(?:build|bin)\/fuzz(?:\.[A-Za-z0-9_.-]+)*/n, "fuzz_bin")
      line.gsub!(/(?:\/?[^ ("']+\/)?build\/[A-Za-z0-9_.-]+/n, "fuzz_bin")
      line.sub!(/ \[detail: .*\]\z/n, "")
      line.gsub!(/0x[0-9a-fA-F]+/n, "")

      if line.include?(RT_ERR_MARKER)
        nil while line.sub!(/(: runtime error: .*[^A-Za-z0-9_])-?[0-9]+/n, '\1')
      end

      line.gsub!(/(READ|WRITE) of size [0-9]+/n, '\1 of size N')
      line.gsub!(/==[0-9]+==/n, "")
      line.gsub!(/T[0-9]+/n, "")
      line.gsub!(/[0-9]+ byte\(s\)/n, "")
      line.gsub!(/[0-9]+ object\(s\)/n, "")
      line.gsub!(/[0-9]+ bytes/n, "")
      line.gsub!(/[0-9]+-byte/n, "")
      line
    end

    def normalized_payload(raw_output, siglines = 10)
      raw = raw_output.to_s.b
      return "".b if raw.empty?

      max_lines = siglines.to_i
      may_have_invariant = raw.include?(INV_PREFIX) || raw.include?(HANG_PREFIX)
      kept = []
      nr = 0

      raw.each_line("\n".b) do |raw_line|
        norm = normalize_line(raw_line)
        next if norm.nil?

        nr += 1
        if may_have_invariant && (norm.start_with?(INV_PREFIX) || norm.start_with?(HANG_PREFIX))
          return "#{norm}\n".b
        end

        kept << norm if nr <= max_lines
        break if !may_have_invariant && nr >= max_lines
      end

      return "".b if kept.empty?

      kept << "".b
      kept.join("\n".b)
    end

    def compute(raw_output, siglines = 10)
      xxh64_hex(normalized_payload(raw_output, siglines))
    end
  end
end
