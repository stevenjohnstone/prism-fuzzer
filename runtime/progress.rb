# frozen_string_literal: true

require "fileutils"
require "open3"
require "shellwords"
require "time"

begin
  require "io/console"
rescue LoadError
  nil
end

module PrismFuzzer
  # BuildKit-style terminal stage progress UI backed by persistent log files.
  # Writes scrolling stage output to $stderr on interactive TTYs and collapses
  # completed stages into a single summary line while keeping $stdout clean.
  module Progress
    ANSI_ESCAPE_RE = /\e\[[0-9;?]*[ -\/]*[@-~]/
    DEFAULT_BOX_LINES = Integer(ENV.fetch("FUZZ_PROGRESS_LINES", "6"))
    REDRAW_INTERVAL = 0.08
    FAILURE_TAIL_LINES = 25

    class StageCommandError < StandardError
      attr_reader :exit_status, :log_path

      def initialize(message, exit_status: nil, log_path: nil)
        @exit_status = exit_status
        @log_path = log_path
        super(message)
      end
    end

    module_function

    def mode(io = $stderr)
      raw = ENV["FUZZ_PROGRESS"].to_s.strip.downcase
      return "inner" if raw == "inner"
      return "plain" if raw == "plain"
      return "tty" if raw == "tty"
      return "plain" if ENV["CI"].to_s == "true" || ENV["TERM"].to_s == "dumb"
      return "tty" if io.respond_to?(:tty?) && io.tty?

      "plain"
    end

    def color?(io = $stderr)
      return false unless ENV["NO_COLOR"].to_s.empty?

      mode(io) == "tty"
    end

    def terminal_width(io = $stderr)
      cols = nil
      if io.respond_to?(:winsize)
        _, cols = io.winsize
      end
      cols = Integer(ENV["COLUMNS"]) if (cols.nil? || cols <= 0) && ENV["COLUMNS"].to_s.match?(/\A\d+\z/)
      cols = 100 if cols.nil? || cols <= 0
      [cols, 40].max
    rescue SystemCallError, IOError
      100
    end

    def strip_ansi(str)
      str.to_s.gsub(ANSI_ESCAPE_RE, "").gsub(/[\x00-\x08\x0b-\x1f\x7f]/, "")
    end

    def clean_utf8(str)
      s = str.to_s.dup
      s.force_encoding("UTF-8")
      s.valid_encoding? ? s : s.encode("UTF-8", "BINARY", invalid: :replace, undef: :replace, replace: "?")
    rescue EncodingError
      str.to_s.b.gsub(/[^\x09\x20-\x7e]/, "?")
    end

    def truncate_line(str, max_width)
      return "" if max_width <= 0
      return str if str.length <= max_width
      return str[0, max_width] if max_width <= 3

      "#{str[0, max_width - 3]}..."
    end

    def drain_stream(io, buf: nil, &on_line)
      partial = +""
      while (chunk = io.readpartial(4096))
        buf << chunk if buf
        pos = 0
        len = chunk.bytesize
        while pos < len
          nl_idx = chunk.byteindex("\n", pos)
          cr_idx = chunk.byteindex("\r", pos)
          sep_idx = if nl_idx && cr_idx
                      nl_idx < cr_idx ? nl_idx : cr_idx
                    else
                      nl_idx || cr_idx
                    end
          unless sep_idx
            partial << (pos == 0 ? chunk : chunk.byteslice(pos, len - pos))
            break
          end

          partial << chunk.byteslice(pos, sep_idx - pos) if sep_idx > pos
          on_line&.call(partial, sep_idx == nl_idx)
          partial.clear
          pos = sep_idx + 1
        end
      end
    rescue EOFError
      on_line&.call(partial, true) unless partial.empty?
    end

    def current_stage
      Thread.current[:prism_fuzzer_progress_stage]
    end

    def cached(message, io: $stderr)
      return if mode(io) == "inner"

      tag = color?(io) ? "\e[36m[=]\e[0m" : "[=]"
      io.puts "#{tag} #{message}"
      io.flush
    end

    def stage(title, log_path: nil, display_log: nil, done_message: nil, io: $stderr, &block)
      raise ArgumentError, "block required" unless block

      if mode(io) == "inner"
        s = Stage.new(title, log_path: log_path, display_log: display_log, io: io, inner: true)
        prev = Thread.current[:prism_fuzzer_progress_stage]
        Thread.current[:prism_fuzzer_progress_stage] = s
        begin
          io.puts "==> #{title}"
          io.flush
          result = yield s
          return result
        ensure
          Thread.current[:prism_fuzzer_progress_stage] = prev
        end
      end

      s = Stage.new(title, log_path: log_path, display_log: display_log, io: io)
      prev = Thread.current[:prism_fuzzer_progress_stage]
      Thread.current[:prism_fuzzer_progress_stage] = s
      s.start!
      begin
        result = yield s
        s.finish_ok!(s.custom_done || done_message)
        result
      rescue StandardError => e
        s.finish_error!(e)
        raise
      ensure
        s.cleanup_tty!
        s.close_log!
        Thread.current[:prism_fuzzer_progress_stage] = prev
      end
    end

    # Represents a single scrolling progress stage writing to $stderr and an
    # optional persistent log file.
    class Stage
      attr_reader :title, :log_path, :display_log
      attr_accessor :custom_done

      def initialize(title, log_path: nil, display_log: nil, io: $stderr, inner: false)
        @title = title.to_s
        @log_path = log_path
        @display_log = display_log || log_path
        @io = io
        @inner = inner
        @mode = inner ? "inner" : Progress.mode(io)
        @color = !inner && Progress.color?(io)
        @lock = Mutex.new
        @tail = []
        @error_tail = []
        @drawn_lines = 0
        @cursor_hidden = false
        @finished = false
        @last_render = Process.clock_gettime(Process::CLOCK_MONOTONIC) - 1.0
        @start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        @log_file = nil
      end

      def elapsed
        Process.clock_gettime(Process::CLOCK_MONOTONIC) - @start_time
      end

      def start!
        if @log_path
          FileUtils.mkdir_p(File.dirname(@log_path))
          @log_file = File.open(@log_path, "w", encoding: "UTF-8")
          @log_file.puts("# [#{Time.now.utc.iso8601}] STAGE: #{@title}")
          @log_file.flush
        end

        @lock.synchronize do
          if @mode == "tty"
            render_locked!(force: true)
          else
            suffix = @display_log ? " (log: #{@display_log})" : ""
            @io.puts "[+] #{@title}#{suffix}"
            @io.flush
          end
        end
      end

      def log_command(cmd)
        str = cmd.is_a?(Array) ? cmd.map { |t| Shellwords.escape(t.to_s) }.join(" ") : cmd.to_s
        @lock.synchronize do
          if @log_file
            @log_file.puts("# [#{Time.now.utc.iso8601}] $ #{str}")
            @log_file.flush
          end
        end
      end

      def note(message)
        clean = Progress.clean_utf8(message.to_s).strip
        return if clean.empty?

        if @inner
          @lock.synchronize do
            @io.puts(clean)
            @io.flush
          end
          return
        end

        @lock.synchronize do
          if @log_file
            @log_file.puts("# [#{Time.now.utc.iso8601}] #{clean}")
            @log_file.flush
          end
          push_preview_locked(clean, record_error: true)
          if @mode == "tty"
            render_locked!(force: true)
          else
            @io.puts "  | #{clean}"
            @io.flush
          end
        end
      end

      def feed_line(raw_line, persist: true, preview: true)
        clean = Progress.clean_utf8(raw_line.to_s)
        stripped = clean.rstrip
        return if stripped.empty? && persist == false

        if @inner
          if preview
            @lock.synchronize do
              @io.puts(stripped)
              @io.flush
            end
          end
          return
        end

        @lock.synchronize do
          @log_file&.puts(stripped) if persist
          plain = Progress.strip_ansi(stripped).gsub("\t", "  ").strip
          return if plain.empty?

          push_preview_locked(plain, record_error: persist)
          if preview
            if @mode == "tty"
              render_locked!(force: @drawn_lines <= 1)
            elsif persist
              @io.puts "  | #{plain}"
              @io.flush
            end
          end
        end
      end

      def exec_stream(*cmd, env: {}, chdir: nil, raise_on_fail: true, fail_message: nil)
        log_command(cmd)
        opts = {}
        opts[:chdir] = chdir if chdir
        args = env && !env.empty? ? [env.transform_keys(&:to_s).transform_values(&:to_s), *cmd] : cmd
        status = nil
        Open3.popen2e(*args, **opts) do |stdin, out_err, wait_thr|
          stdin.close
          Progress.drain_stream(out_err) do |line, is_newline|
            feed_line(line, persist: is_newline, preview: true)
          end
          status = wait_thr.value
        end

        @lock.synchronize do
          @log_file&.puts("# [#{Time.now.utc.iso8601}] exit=#{status&.exitstatus}")
        end

        if raise_on_fail && !status&.success?
          msg = fail_message || "Command failed (exit #{status&.exitstatus}): #{cmd.join(' ')}"
          raise StageCommandError.new(msg, exit_status: status&.exitstatus, log_path: @log_path)
        end

        status
      end

      def finish_ok!(message = nil)
        dt = format("%.1fs", elapsed)
        @lock.synchronize do
          @finished = true
          buf = +""
          if @mode == "tty"
            buf << "\e[?2026h"
            buf << clear_box_seq_locked
          end
          @log_file&.puts("# [#{Time.now.utc.iso8601}] DONE (#{dt})")
          label = message || @title
          prefix = @color ? "\e[32m[+]\e[0m" : "[ok]"
          log_hint = if @display_log
                       @color ? " \e[2m-> #{@display_log}\e[0m" : " -> #{@display_log}"
                     else
                       ""
                     end
          buf << "#{prefix} #{label} (#{dt})#{log_hint}\n"
          if @mode == "tty"
            if @cursor_hidden
              buf << "\e[?25h"
              @cursor_hidden = false
            end
            buf << "\e[?2026l"
          end
          @io.write(buf)
          @io.flush
        end
      end

      def finish_error!(error)
        error.instance_variable_set(:@logged_by_progress, true)
        dt = format("%.1fs", elapsed)
        @lock.synchronize do
          @finished = true
          buf = +""
          if @mode == "tty"
            buf << "\e[?2026h"
            buf << clear_box_seq_locked
          end
          @log_file&.puts("# [#{Time.now.utc.iso8601}] FAILED (#{dt}): #{error.class}: #{error.message}")
          prefix = @color ? "\e[31m[!]\e[0m" : "[!]"
          buf << "#{prefix} #{@title} FAILED (#{dt})\n"
          tail = @error_tail.last(FAILURE_TAIL_LINES)
          if tail.any?
            tail.each { |ln| buf << "    #{ln}\n" }
          elsif error.message && !error.message.empty?
            error.message.lines.first(15).each { |ln| buf << "    #{ln.rstrip}\n" }
          end
          buf << "    Full log: #{@log_path}\n" if @log_path
          if @mode == "tty"
            if @cursor_hidden
              buf << "\e[?25h"
              @cursor_hidden = false
            end
            buf << "\e[?2026l"
          end
          @io.write(buf)
          @io.flush
        end
      end

      def cleanup_tty!
        @lock.synchronize do
          return unless @mode == "tty" && (@cursor_hidden || (@drawn_lines > 0 && !@finished))

          buf = +"\e[?2026h"
          buf << clear_box_seq_locked if !@finished && @drawn_lines > 0
          if @cursor_hidden
            buf << "\e[?25h"
            @cursor_hidden = false
          end
          buf << "\e[?2026l"
          @io.write(buf)
          @io.flush
        end
      rescue SystemCallError, IOError
        nil
      end

      def close_log!
        @lock.synchronize do
          @log_file&.close unless @log_file&.closed?
          @log_file = nil
        end
      end

      private

      def push_preview_locked(line, record_error: true)
        if record_error
          @error_tail << line
          @error_tail.shift while @error_tail.size > 100
        end
        @tail << line
        @tail.shift while @tail.size > DEFAULT_BOX_LINES
      end

      def clear_box_seq_locked
        return "" if @drawn_lines <= 0

        seq = +"\e[#{@drawn_lines}A\r"
        @drawn_lines.times { seq << "\e[2K\n" }
        seq << "\e[#{@drawn_lines}A\r"
        @drawn_lines = 0
        seq
      end

      def render_locked!(force:)
        now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        return if !force && (now - @last_render) < REDRAW_INTERVAL

        @last_render = now
        @log_file&.flush
        cols = Progress.terminal_width(@io)
        max_w = [cols - 1, 20].max

        dt = format("%.1fs", elapsed)
        log_note = @display_log ? " (#{@display_log})" : ""
        header_plain = Progress.truncate_line("[+] #{@title} [#{dt}]#{log_note}", max_w)
        header = if @color
                   head_prefix = "\e[36m[+]\e[0m "
                   body_len = [max_w - 4, 16].max
                   rest = Progress.truncate_line("#{@title} [#{dt}]#{log_note}", body_len)
                   "#{head_prefix}#{rest}"
                 else
                   header_plain
                 end

        body_max = [max_w - 3, 12].max
        lines = [header]
        @tail.each do |ln|
          truncated = Progress.truncate_line(ln, body_max)
          lines << (@color ? " \e[2m|\e[0m #{truncated}" : " | #{truncated}")
        end

        buf = +"\e[?2026h"
        unless @cursor_hidden
          buf << "\e[?25l"
          @cursor_hidden = true
        end
        buf << "\e[#{@drawn_lines}A\r" if @drawn_lines > 0
        lines.each { |ln| buf << "\e[2K#{ln}\n" }
        if @drawn_lines > lines.size
          extra = @drawn_lines - lines.size
          extra.times { buf << "\e[2K\n" }
          buf << "\e[#{extra}A"
        end
        buf << "\e[?2026l"
        @io.write(buf)
        @io.flush
        @drawn_lines = lines.size
      end
    end
  end
end
