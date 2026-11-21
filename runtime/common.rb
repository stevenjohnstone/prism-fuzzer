# frozen_string_literal: true

require "fileutils"
require "json"

module PrismFuzzer
  # Shared filesystem, root-discovery, and UTF-8 sanitization helpers used across
  # runtime, triage, and reporting tools.
  module Common
    module_function

    # Parses JSON from `path`, returning `default` silently when the file is missing
    # and logging a diagnostic warning on malformed JSON or unexpected read failures.
    def read_json(path, default: nil, warn_on_error: true, context: nil)
      return default if path.nil? || path.to_s.empty?

      JSON.parse(File.read(path, encoding: "UTF-8"))
    rescue Errno::ENOENT, Errno::ENOTDIR
      default
    rescue JSON::ParserError, EncodingError => e
      if warn_on_error && ENV["FUZZ_QUIET"] != "1"
        prefix = context && !context.to_s.empty? ? "#{context}: " : "PrismFuzzer: "
        warn "#{prefix}failed to parse JSON #{path}: #{e.message}"
      end
      default
    rescue SystemCallError, IOError => e
      if warn_on_error && ENV["FUZZ_QUIET"] != "1"
        prefix = context && !context.to_s.empty? ? "#{context}: " : "PrismFuzzer: "
        warn "#{prefix}failed to read JSON #{path}: #{e.class}: #{e.message}"
      end
      default
    end

    # Atomically writes pretty-printed JSON to `path` with umask-respecting mode,
    # returning `data`.
    def write_json_atomic(path, data)
      dir = File.dirname(path)
      FileUtils.mkdir_p(dir)
      tmp_path = File.join(dir, ".#{File.basename(path)}.tmp.#{Process.pid}.#{Thread.current.object_id}")
      File.write(tmp_path, "#{JSON.pretty_generate(data)}\n")
      File.chmod(0o666 & ~File.umask, tmp_path)
      File.rename(tmp_path, path)
      data
    ensure
      FileUtils.rm_f(tmp_path) if tmp_path && File.exist?(tmp_path)
    end

    # Converts arbitrary bytes or malformed text into valid UTF-8, replacing invalid sequences.
    def utf8_safe(text)
      return "" if text.nil?

      s = text.to_s
      if s.encoding == Encoding::BINARY
        s = s.dup.force_encoding(Encoding::UTF_8)
      elsif s.encoding != Encoding::UTF_8
        return s.encode(Encoding::UTF_8, invalid: :replace, undef: :replace, replace: "?")
      end
      s.valid_encoding? ? s : s.scrub("?")
    end

    # Walks upward from candidate directories to locate the prism-fuzzer repository root.
    def locate_fuzz_root(start_dir = nil, fallback: nil)
      candidates = [
        start_dir,
        (__dir__ ? File.expand_path("..", __dir__) : nil),
        Dir.pwd
      ].compact.uniq

      candidates.each do |dir|
        cur = File.expand_path(dir)
        loop do
          if File.file?(File.join(cur, "harnesses/prism/parse.c")) &&
             (File.file?(File.join(cur, "runtime/topology.rb")) ||
              File.file?(File.join(cur, "runtime/provenance.rb")) ||
              File.file?(File.join(cur, "runtime/common.rb")))
            return cur
          end

          parent = File.dirname(cur)
          break if parent == cur

          cur = parent
        end
      end
      fallback
    end

    # Locates the target Prism source tree using explicit/env/topology/workspace candidates.
    def locate_prism_root(start_dir = nil, fuzz_root: locate_fuzz_root(start_dir), topo: nil, require_src: false)
      topo_path = nil
      ws_build = fuzz_root ? File.join(fuzz_root, "tmp/fuzz/build") : nil
      if fuzz_root && defined?(PrismFuzzer::Topology)
        topo ||= PrismFuzzer::Topology.discover(start_dir: fuzz_root)
        cov_id = topo&.dig("coverage", "source") ||
                 topo&.dig("sources")&.find { |_, v| v.is_a?(Hash) && v["kind"] == "prism" }&.first
        topo_path = topo&.dig("sources", cov_id, "path") if cov_id
        ws_build = PrismFuzzer::Topology.workspace_paths(topo, fuzz_root: fuzz_root)[:build_dir] if topo
      end

      candidates = [
        start_dir,
        ENV["PRISM_A_DIR"],
        ENV["PRISM_DIR"],
        ENV["PRISM_ROOT"],
        topo_path,
        ws_build ? File.join(ws_build, "targets/prism_a") : nil,
        fuzz_root ? File.join(fuzz_root, "tmp/fuzz/build/targets/prism_a") : nil,
        Dir.pwd
      ].compact.reject { |c| c.to_s.strip.empty? }.uniq

      candidates.each do |dir|
        cur = File.expand_path(dir)
        loop do
          if require_src
            return cur if File.file?(File.join(cur, "include/prism.h")) && File.directory?(File.join(cur, "src"))
          elsif File.file?(File.join(cur, "include/prism/version.h"))
            return cur
          end

          parent = File.dirname(cur)
          break if parent == cur

          cur = parent
        end
      end
      nil
    end

    # Locates the active Prism source root, falling back to the prism-fuzzer root.
    def locate_repo_root(start_dir = nil)
      locate_prism_root(start_dir) || locate_fuzz_root(start_dir)
    end
  end
end
