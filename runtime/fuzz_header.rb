# frozen_string_literal: true

require "base64"
require "cgi/escape"

require_relative "common"

module PrismFuzzer
  # Single source of truth in Ruby for the 4-byte fuzzer option header consumed by
  # `fuzz_options_decode` / `fuzz_options_populate` in `harnesses/prism/include/fuzz_options.h`.
  module FuzzHeader
    VERSIONS = %w[3.3 3.4 3.5 4.1].freeze
    ENCODINGS = %w[UTF-8 ASCII-8BIT US-ASCII Windows-31J EUC-JP UTF-8-MAC ISO-8859-1 Shift_JIS].freeze
    EXTREME_LINES = [2_147_483_647, 2_147_483_643, -2_147_483_648, 0].freeze
    EXTREME_LINES_C = ["INT32_MAX", "INT32_MAX - 4", "INT32_MIN", "0"].freeze
    STACK_BUDGETS = %w[SIZE_MAX 0 512 4096].freeze
    SCOPE_BASE_LOCALS = [%w[a foo], %w[b it], %w[c _1]].freeze
    DEFAULT_HEADER_BYTES = [0x00, 0x00, 0x03, 0x01].freeze

    COMMAND_LINE_CHARS = [
      [0x01, "a"],
      [0x02, "e"],
      [0x04, "l"],
      [0x08, "n"],
      [0x10, "p"],
      [0x20, "x"]
    ].freeze

    FORWARDING_CHARS = [
      [0x01, "p"],
      [0x02, "k"],
      [0x04, "b"],
      [0x08, "a"]
    ].freeze

    module_function

    # Decodes the 4-byte fuzzer option header into structured fields.
    # When `pad_short` is true (default), `<4`-byte inputs are NUL-padded on the right;
    # when false, `<4`-byte or nil inputs return nil.
    def decode(raw, pad_short: true)
      return nil if raw.nil? && !pad_short

      raw = (raw || "").b
      valid_header = raw.bytesize >= 4
      return nil if !valid_header && !pad_short

      padded_raw = valid_header ? raw : (raw + ("\x00".b * (4 - raw.bytesize)))
      b0, b1, b2, b3 = padded_raw.bytes[0, 4]
      source = raw.bytesize > 4 ? raw.byteslice(4..) : "".b

      freeze = (b0 & 0x01) != 0
      partial_script = (b0 & 0x02) != 0
      attach_comments = (b0 & 0x04) != 0
      encoding_locked = (b0 & 0x08) != 0
      has_frozen_string_literal = (b0 & 0x10) != 0
      frozen_string_literal = (b0 & 0x20) != 0
      stream_mode = (b0 & 0x40) != 0
      has_encoding_opts = (b0 & 0x80) != 0

      cmd_flags = b1 & 0x3f
      main_script = (b1 & 0x40) != 0
      has_limit_opts = (b1 & 0x80) != 0

      version = VERSIONS[b2 & 0x03]
      scopes_count = (b2 >> 2) & 0x03
      forwarding_bits = (b2 >> 4) & 0x0f

      extreme_idx = has_limit_opts ? ((b3 >> 4) & 0x03) : nil
      start_line = has_limit_opts ? EXTREME_LINES[extreme_idx] : [b3].pack("C").unpack1("c")
      start_line_c = has_limit_opts ? EXTREME_LINES_C[extreme_idx] : start_line.to_s
      need_limits = has_limit_opts && extreme_idx != 3
      stack_budget = has_limit_opts ? STACK_BUDGETS[(b3 >> 6) & 0x03] : "SIZE_MAX"

      encoding = has_encoding_opts ? ENCODINGS[b3 & 0x07] : nil
      filepath = has_encoding_opts ? "fuzz.rb" : nil
      shebang_callback = has_encoding_opts && (b3 & 0x08) != 0

      forwarding_scope = scopes_count > 0 ? (has_encoding_opts ? (b3 % scopes_count) : (scopes_count - 1)) : nil
      cmd_chars = COMMAND_LINE_CHARS.filter_map { |bit, ch| ch if (cmd_flags & bit) != 0 }
      fwd_chars = FORWARDING_CHARS.filter_map { |bit, ch| ch if (forwarding_bits & bit) != 0 }
      has_shebang_prefix = source.start_with?("#!".b) || source.start_with?("\xef\xbb\xbf#!".b)

      {
        raw: raw,
        valid_header: valid_header,
        padded_raw: padded_raw,
        header_bytes: [b0, b1, b2, b3],
        b3: b3,
        source: source,
        freeze: freeze,
        partial_script: partial_script,
        attach_comments: attach_comments,
        encoding_locked: encoding_locked,
        has_frozen_string_literal: has_frozen_string_literal,
        frozen_string_literal: frozen_string_literal,
        stream_mode: stream_mode,
        has_encoding_opts: has_encoding_opts,
        cmd_flags: cmd_flags,
        command_line_chars: cmd_chars,
        main_script: main_script,
        has_limit_opts: has_limit_opts,
        extreme_idx: extreme_idx,
        need_limits: need_limits,
        start_line: start_line,
        start_line_c: start_line_c,
        stack_budget: stack_budget,
        version: version,
        scopes_count: scopes_count,
        forwarding_bits: forwarding_bits,
        forwarding_chars: fwd_chars,
        forwarding_scope: forwarding_scope,
        encoding: encoding,
        filepath: filepath,
        shebang_callback: shebang_callback,
        has_shebang_prefix: has_shebang_prefix
      }
    end

    # Encodes human-readable option fields into a 4-byte binary fuzzer header.
    def encode(
      ruby_version: "4.1",
      encoding: nil,
      frozen_string_literal: nil,
      partial_script: false,
      freeze: false,
      attach_comments: false,
      encoding_locked: false,
      stream_mode: false,
      main_script: false,
      command_line: nil,
      scopes_count: 0,
      forwarding: nil,
      start_line: 1
    )
      ver_idx = VERSIONS.index(ruby_version.to_s)
      raise ArgumentError, "Unknown ruby_version '#{ruby_version}' (expected #{VERSIONS.join(', ')})" unless ver_idx

      b0 = 0
      b0 |= 0x01 if freeze
      b0 |= 0x02 if partial_script
      b0 |= 0x04 if attach_comments
      b0 |= 0x08 if encoding_locked
      unless frozen_string_literal.nil?
        b0 |= 0x10
        b0 |= 0x20 if frozen_string_literal
      end
      b0 |= 0x40 if stream_mode

      b1 = 0
      unless command_line.nil? || command_line.to_s.empty?
        command_line.to_s.each_char do |ch|
          pair = COMMAND_LINE_CHARS.find { |_, c| c == ch }
          raise ArgumentError, "Unknown command_line flag '#{ch}'" unless pair

          b1 |= pair[0]
        end
      end
      b1 |= 0x40 if main_script

      fwd_bits = 0
      unless forwarding.nil? || forwarding.to_s.empty?
        forwarding.to_s.each_char do |ch|
          pair = FORWARDING_CHARS.find { |_, c| c == ch }
          raise ArgumentError, "Unknown forwarding flag '#{ch}'" unless pair

          fwd_bits |= pair[0]
        end
      end
      unless (0..3).cover?(scopes_count.to_i)
        raise ArgumentError, "scopes_count must be between 0 and 3"
      end

      b2 = (ver_idx & 0x03) | ((scopes_count.to_i & 0x03) << 2) | ((fwd_bits & 0x0f) << 4)

      if encoding && !encoding.to_s.empty?
        enc_idx = ENCODINGS.index { |e| e.casecmp?(encoding.to_s) }
        raise ArgumentError, "Unknown encoding '#{encoding}' (expected #{ENCODINGS.join(', ')})" unless enc_idx

        b0 |= 0x80
        b3 = enc_idx & 0x07
      else
        raise ArgumentError, "start_line must be in -128..127" unless (-128..127).cover?(start_line.to_i)

        b3 = [start_line.to_i].pack("c").unpack1("C")
      end

      [b0, b1, b2, b3].pack("C4")
    end

    # Extracts `[payload_bytes, cmd_flags]` from raw fuzzer input.
    def strip_header(raw_bytes)
      h = decode(raw_bytes, pad_short: false)
      return [(raw_bytes || "".b).b, []] unless h

      [h[:source], h[:command_line_chars]]
    end

    # Formats a concise human-readable summary of a 4-byte option header, or returns nil
    # when fewer than 4 bytes are present.
    def format_summary(raw)
      h = raw.is_a?(Hash) ? raw : decode(raw, pad_short: false)
      return nil unless h

      flags = ["v#{h[:version]}"]
      flags << "stream" if h[:stream_mode]
      flags << "line=#{h[:start_line]}" if h[:start_line] != 1
      if h[:has_encoding_opts]
        flags << "enc=#{h[:encoding]}"
        flags << "shebang_cb" if h[:shebang_callback]
        flags << "scope0_empty" if h[:scopes_count] > 0 && (h[:b3] & 0x10) != 0
      end
      flags << "stack_budget=#{h[:stack_budget]}" if h[:has_limit_opts]
      flags << "scopes=#{h[:scopes_count]}" if h[:scopes_count] > 0
      if h[:forwarding_bits] > 0
        flags << if h[:forwarding_scope]
                   "fwd[#{h[:forwarding_scope]}]=0x#{h[:forwarding_bits].to_s(16)}"
                 else
                   "fwd=0x#{h[:forwarding_bits].to_s(16)}"
                 end
      end
      flags << "freeze" if h[:freeze]
      flags << "partial" if h[:partial_script]
      flags << "comments" if h[:attach_comments]
      flags << "enc_lock" if h[:encoding_locked]
      flags << (h[:frozen_string_literal] ? "frozen_lit=true" : "frozen_lit=false") if h[:has_frozen_string_literal]
      cmd = h[:command_line_chars].map { |ch| "-#{ch}" }
      flags << cmd.join if cmd.any?
      flags << "main" if h[:main_script]
      flags.join(", ")
    end
  end

  # Builds Prism Loupe playback URLs with exact 4-byte header options and sanitizer toggles.
  module LoupeUrl
    BASE_URL = "https://stevenjohnstone.github.io/prism-loupe/"

    module_function

    def encode_scope_local(bytes)
      if bytes.match?(/\A[A-Za-z0-9_]+\z/n)
        bytes
      else
        "~#{Base64.urlsafe_encode64(bytes, padding: false)}"
      end
    end

    def sanitizer_crash?(reason, crash_output = "")
      co = PrismFuzzer::Common.utf8_safe(crash_output)
      return false if co.include?("INVARIANT[") || co.include?("Assertion `")
      return true if reason.to_s == "undefined-behavior"
      return true if co.match?(/(?:Address|UndefinedBehavior)Sanitizer|\b(?:ASAN|UBSAN)\b/)
      return true if co.match?(/:\d+:\d+: runtime error: |fuzz_(?:free|realloc)_sized/)

      %w[
        heap-buffer-overflow stack-buffer-overflow global-buffer-overflow
        heap-use-after-free stack-use-after-return stack-use-after-scope
        attempting-double-free bad-free alloc-dealloc-mismatch SEGV
      ].include?(reason.to_s)
    end

    def diff_url(source)
      "#{BASE_URL}?code=#{CGI.escape(Base64.strict_encode64(source.b))}&ruby_ver=4.1"
    end

    def prism_url(raw, sanitize: false)
      return nil if raw.nil? || raw.empty?

      if raw.bytesize < 4
        san_part = sanitize ? "&san=1" : ""
        return "#{BASE_URL}?code=#{CGI.escape(Base64.strict_encode64(raw))}#{san_part}"
      end

      h = FuzzHeader.decode(raw)
      source = h[:source]

      params = [["code", Base64.strict_encode64(source)]]
      params << ["san", "1"] if sanitize
      params << ["enc", h[:encoding]] if h[:has_encoding_opts]
      params << ["ruby_ver", h[:version]]
      params << ["line", h[:start_line].to_s] if h[:start_line] != 1

      cmd = h[:command_line_chars].join
      params << ["cmd", cmd] unless cmd.empty?

      params << ["main", "1"] if h[:main_script]
      params << ["partial", "1"] if h[:partial_script]
      params << ["freeze", "1"] if h[:freeze]
      params << ["comments", "1"] if h[:attach_comments]
      params << ["enc_lock", "1"] if h[:encoding_locked]
      params << ["frozen_lit", h[:frozen_string_literal] ? "1" : "0"] if h[:has_frozen_string_literal]
      params << ["stream", "1"] if h[:stream_mode]

      if h[:has_encoding_opts]
        params << ["filepath", h[:filepath]]
        params << ["shebang_cb", "1"] if h[:shebang_callback]
      end

      params << ["budget", h[:stack_budget]] unless h[:stack_budget] == "SIZE_MAX"

      scopes_count = h[:scopes_count]
      if scopes_count > 0
        fwd_chars = h[:forwarding_chars].join
        forwarding_scope = h[:forwarding_scope]

        scope_segments = (0...scopes_count).map do |i|
          locals_count = (i == 0 && source.bytesize > 0) ? 3 : 2
          locals_count = 0 if i == 0 && h[:has_encoding_opts] && (h[:b3] & 0x10) != 0
          locals = (0...[2, locals_count].min).map { |j| FuzzHeader::SCOPE_BASE_LOCALS[i][j].b }
          locals << source.byteslice(0, [source.bytesize, 4].min) if locals_count == 3
          encoded_locals = locals.map { |loc| encode_scope_local(loc) }
          fwd = (i == forwarding_scope) ? fwd_chars : ""
          if encoded_locals.empty?
            fwd.empty? ? ":" : "#{fwd}:"
          else
            fwd.empty? ? encoded_locals.join(",") : "#{fwd}:#{encoded_locals.join(",")}"
          end
        end
        params << ["scopes", scope_segments.join(";")]
      end

      query = params.map { |k, v| "#{k}=#{CGI.escape(v)}" }.join("&")
      "#{BASE_URL}?#{query}"
    end
  end
end
