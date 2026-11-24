# frozen_string_literal: true

require "base64"
begin
  require "concurrent"
rescue LoadError
  # Optional when using library helpers or sequential fallback without concurrent-ruby.
end
require "digest"
require "etc"
require "fileutils"
require "json"
require "open3"
require "rubygems/package"
require "set"
require "tempfile"
require "time"
require "tmpdir"
require "zlib"

triage_root_dir = File.expand_path("..", __dir__)
repo_root_dir = File.expand_path("..", triage_root_dir)

[
  File.join(repo_root_dir, "runtime/common.rb"),
  File.join(repo_root_dir, "runtime/fuzz_header.rb"),
  File.join(triage_root_dir, "lib/verify_profile.rb"),
  File.join(triage_root_dir, "cluster.rb"),
  File.join(repo_root_dir, "runtime/provenance.rb"),
  File.join(repo_root_dir, "runtime/topology.rb"),
  File.join(triage_root_dir, "explain.rb")
].each do |lib_path|
  require lib_path if File.file?(lib_path)
end

module FuzzTriage
  # Shared triage configuration defaults, workspace/topology path discovery,
  # verify-profile wrappers, and header/Loupe delegators.
  module Config
    extend self

    TRIAGE_FILE_DIR = File.expand_path("..", __dir__)
    PRISM_LOUPE_BASE_URL = PrismFuzzer::LoupeUrl::BASE_URL

    OUTPUT_DIRS = ["tmp/fuzz/afl", "tmp/fuzz/afl-ijon"].freeze
    TESTCASES_DIR = "tmp/fuzz/report/triage"
    TESTCASES_PROCESSED_DIR = File.join(TESTCASES_DIR, ".processed")
    DEFAULT_CORPUS_DIR = "tmp/fuzz/corpus"
    DEFAULT_COVERAGE_BIN = "./tmp/fuzz/build/fuzz"
    DEFAULT_DIFF_COVERAGE_BIN = "./tmp/fuzz/build/fuzz.diff"

    MAX_ALLOCATED_MB = Integer(ENV.fetch("FUZZ_MAX_ALLOCATED", "128"))
    HARD_RSS_LIMIT_MB = MAX_ALLOCATED_MB * 16
    HALFEMPTY_THREADS = Integer(ENV.fetch("HALFEMPTY_THREADS", "2"))
    TRIAGE_THREADS = Integer(ENV.fetch("TRIAGE_THREADS", [(defined?(Concurrent) ? Concurrent.processor_count : Etc.nprocessors) / 2, 1].max.to_s))
    HANG_TIMEOUT_SECONDS = Integer(ENV.fetch("TRIAGE_HANG_TIMEOUT", "5"))
    CRASH_TIMEOUT_SECONDS = Integer(ENV.fetch("TRIAGE_CRASH_TIMEOUT", "15"))
    COVERAGE_BIN = ENV.fetch("TRIAGE_COVERAGE_BIN", DEFAULT_COVERAGE_BIN)
    COVERAGE_IDS_PATH = ENV.fetch("TRIAGE_COVERAGE_IDS", COVERAGE_BIN.empty? ? "" : "#{COVERAGE_BIN}.ids")
    DIFF_COVERAGE_BIN = ENV.fetch("TRIAGE_DIFF_COVERAGE_BIN", DEFAULT_DIFF_COVERAGE_BIN)
    DIFF_COVERAGE_IDS_PATH = ENV.fetch("TRIAGE_DIFF_COVERAGE_IDS", DIFF_COVERAGE_BIN.empty? ? "" : "#{DIFF_COVERAGE_BIN}.ids")
    CORPUS_DIR = ENV.fetch("TRIAGE_CORPUS_DIR", DEFAULT_CORPUS_DIR)
    AFL_SHOWMAP_BIN = ENV.fetch("AFL_SHOWMAP", "afl-showmap")
    SHOWMAP_TIMEOUT_MS = Integer(ENV.fetch("TRIAGE_SHOWMAP_TIMEOUT_MS", "1000"))
    TRIAGE_RECOUNT = ENV["TRIAGE_RECOUNT"] == "1"
    INPUTS_ARCHIVE_FILE = "inputs.tar.gz"
    PENDING_INPUTS_FILE = ".inputs.pending"
    META_SCHEMA_VERSION = 1

    SANITIZER_ENV = {
      "ASAN_OPTIONS" => "abort_on_error=1:handle_abort=1:max_allocation_size_mb=#{MAX_ALLOCATED_MB}:hard_rss_limit_mb=#{HARD_RSS_LIMIT_MB}",
      "UBSAN_OPTIONS" => "abort_on_error=1:print_stacktrace=1",
      "MSAN_OPTIONS" => "abort_on_error=1:handle_abort=1:max_allocation_size_mb=#{MAX_ALLOCATED_MB}:hard_rss_limit_mb=#{HARD_RSS_LIMIT_MB}",
      "LSAN_OPTIONS" => "handle_abort=1:max_allocation_size_mb=#{MAX_ALLOCATED_MB}:hard_rss_limit_mb=#{HARD_RSS_LIMIT_MB}"
    }.freeze

    VERSIONS = PrismFuzzer::FuzzHeader::VERSIONS
    ENCODINGS = PrismFuzzer::FuzzHeader::ENCODINGS
    EXTREME_LINES = PrismFuzzer::FuzzHeader::EXTREME_LINES
    EXTREME_LINES_C = PrismFuzzer::FuzzHeader::EXTREME_LINES_C
    STACK_BUDGETS = PrismFuzzer::FuzzHeader::STACK_BUDGETS
    SCOPE_BASE_LOCALS = PrismFuzzer::FuzzHeader::SCOPE_BASE_LOCALS
    DEFAULT_HEADER_BYTES = PrismFuzzer::FuzzHeader::DEFAULT_HEADER_BYTES
    COMMAND_LINE_CHARS = PrismFuzzer::FuzzHeader::COMMAND_LINE_CHARS
    FORWARDING_CHARS = PrismFuzzer::FuzzHeader::FORWARDING_CHARS
    CROSS_ORACLE_TARGETS = FuzzVerifyProfile::CROSS_ORACLE_TARGETS

    def env_max_allocated_mb
      Integer(ENV.fetch("FUZZ_MAX_ALLOCATED", "128"))
    end

    def env_hard_rss_limit_mb
      env_max_allocated_mb * 16
    end

    def env_sanitizer_env(executable: nil, triage_dir: nil, detect_leaks: nil)
      max_mb = env_max_allocated_mb
      disable_leaks = if !detect_leaks.nil?
                        !detect_leaks
                      elsif executable
                        FuzzVerifyProfile.diff_bucket?(executable: executable, triage_dir: triage_dir)
                      else
                        false
                      end
      return SANITIZER_ENV if max_mb == MAX_ALLOCATED_MB && !disable_leaks

      hard_mb = max_mb * 16
      diff_opts = disable_leaks ? ":detect_leaks=0:detect_stack_use_after_return=0" : ""
      {
        "ASAN_OPTIONS" => "abort_on_error=1:handle_abort=1#{diff_opts}:max_allocation_size_mb=#{max_mb}:hard_rss_limit_mb=#{hard_mb}",
        "UBSAN_OPTIONS" => "abort_on_error=1:print_stacktrace=1",
        "MSAN_OPTIONS" => "abort_on_error=1:handle_abort=1:max_allocation_size_mb=#{max_mb}:hard_rss_limit_mb=#{hard_mb}",
        "LSAN_OPTIONS" => "handle_abort=1:max_allocation_size_mb=#{max_mb}:hard_rss_limit_mb=#{hard_mb}"
      }
    end

    def env_halfempty_threads
      Integer(ENV.fetch("HALFEMPTY_THREADS", "2"))
    end

    def env_triage_threads
      Integer(ENV.fetch("TRIAGE_THREADS", [(defined?(Concurrent) ? Concurrent.processor_count : Etc.nprocessors) / 2, 1].max.to_s))
    end

    def env_hang_timeout_seconds
      Integer(ENV.fetch("TRIAGE_HANG_TIMEOUT", "5"))
    end

    def env_crash_timeout_seconds
      Integer(ENV.fetch("TRIAGE_CRASH_TIMEOUT", "15"))
    end

    def env_showmap_bin
      ENV.fetch("AFL_SHOWMAP", "afl-showmap")
    end

    def env_showmap_timeout_ms
      Integer(ENV.fetch("TRIAGE_SHOWMAP_TIMEOUT_MS", "1000"))
    end

    def env_recount?
      ENV["TRIAGE_RECOUNT"] == "1"
    end

    def env_minimize?
      ENV["TRIAGE_MINIMIZE"] != "0"
    end

    def env_corpus_dir
      ENV.fetch("TRIAGE_CORPUS_DIR", DEFAULT_CORPUS_DIR)
    end

    def triage_ws_roots(triage_dir)
      return [] if triage_dir.nil? || triage_dir.to_s.empty?

      if defined?(PrismFuzzer::Topology) && PrismFuzzer::Topology.respond_to?(:triage_workspace_candidates)
        PrismFuzzer::Topology.triage_workspace_candidates(triage_dir)
      else
        abs_t = File.expand_path(triage_dir)
        p1 = File.dirname(abs_t)
        p2 = File.dirname(p1)
        File.basename(p1) == "report" ? [p2, p1].uniq : [p1, p2].uniq
      end
    end

    TOPOLOGY_CACHE_MUTEX = Mutex.new

    def with_cached_topology
      prev = TOPOLOGY_CACHE_MUTEX.synchronize do
        old = @topology_lookup_cache
        @topology_lookup_cache = {}
        old
      end
      yield
    ensure
      TOPOLOGY_CACHE_MUTEX.synchronize { @topology_lookup_cache = prev }
    end

    def resolve_topology(triage_dir: TESTCASES_DIR, output_dirs: nil)
      return nil unless defined?(PrismFuzzer::Topology)

      cache_key = [File.expand_path(triage_dir.to_s), Array(output_dirs).map(&:to_s)]
      cached = TOPOLOGY_CACHE_MUTEX.synchronize do
        @topology_lookup_cache && @topology_lookup_cache[cache_key]
      end
      return PrismFuzzer::Topology.deep_dup(cached) if cached

      bin_dir = triage_ws_roots(triage_dir).map { |r| File.join(r, "bin") }.find { |d| File.directory?(d) }
      afl_cand = Array(output_dirs).first
      resolved = PrismFuzzer::Topology.discover(triage_dir: triage_dir, afl_dir: afl_cand, bin_dir: bin_dir)

      if resolved
        TOPOLOGY_CACHE_MUTEX.synchronize do
          @topology_lookup_cache[cache_key] = resolved if @topology_lookup_cache
        end
      end
      resolved
    end

    def resolve_triage_output_dirs(output_dirs:, testcases_dir: TESTCASES_DIR)
      default_dirs = ["tmp/fuzz/afl", "tmp/fuzz/afl-ijon"]
      return output_dirs unless output_dirs == default_dirs

      env_dirs = ENV.fetch("TRIAGE_OUTPUT_DIRS", "").split(",").map(&:strip).reject(&:empty?)
      return env_dirs unless env_dirs.empty?

      parent_dir = nil
      local_topo = nil
      triage_ws_roots(testcases_dir).each do |r|
        cand = [File.join(r, "bin", "topology.json"), File.join(r, "topology.json")].find { |p| File.file?(p) }
        if cand
          local_topo = cand
          parent_dir = r
          break
        end
      end
      parent_dir ||= triage_ws_roots(testcases_dir).first || File.dirname(File.expand_path(testcases_dir))
      topo = if local_topo && defined?(PrismFuzzer::Topology)
               PrismFuzzer::Topology.read_json(local_topo)
             elsif testcases_dir != "tmp/fuzz/report/triage" || ENV["TOPOLOGY"] || ENV["FUZZ_DIR"]
               resolve_topology(triage_dir: testcases_dir)
             elsif testcases_dir == "tmp/fuzz/report/triage"
               resolve_topology(triage_dir: testcases_dir)
             end
      if topo
        dirs = PrismFuzzer::Topology.sync_group_dirs(topo, base_dir: parent_dir)
        return dirs unless dirs.empty?
      end
      output_dirs
    end

    def workspace_default_triage_dir
      return ENV["TRIAGE_DIR"] if ENV["TRIAGE_DIR"] && !ENV["TRIAGE_DIR"].empty?
      return TESTCASES_DIR unless defined?(PrismFuzzer::Topology)

      topo = PrismFuzzer::Topology.discover(start_dir: Dir.pwd)
      return TESTCASES_DIR unless topo

      PrismFuzzer::Topology.path_relative_or_abs(PrismFuzzer::Topology.workspace_paths(topo)[:triage_dir], Dir.pwd)
    end

    def workspace_default_corpus_dir(triage_dir = TESTCASES_DIR)
      return ENV["TRIAGE_CORPUS_DIR"] if ENV["TRIAGE_CORPUS_DIR"] && !ENV["TRIAGE_CORPUS_DIR"].empty?

      topo = resolve_topology(triage_dir: triage_dir)
      return env_corpus_dir unless topo && defined?(PrismFuzzer::Topology)

      PrismFuzzer::Topology.path_relative_or_abs(PrismFuzzer::Topology.workspace_paths(topo)[:corpus_dir], Dir.pwd)
    end

    def resolve_topology_fuzzer(executable: "", triage_dir: TESTCASES_DIR)
      topo = resolve_topology(triage_dir: triage_dir)
      return nil unless topo && !executable.to_s.empty?

      PrismFuzzer::Topology.fuzzer_spec(topo, executable.to_s)
    end

    def fuzzer_allows_stream_with_ijon?(fspec)
      return false unless fspec.is_a?(Hash)

      defs = fspec["defines"]
      if defs.is_a?(Hash)
        val = defs["PRISM_FUZZ_ALLOW_STREAM_WITH_IJON"]
        return true if val && val != false && val != 0 && val.to_s != "0"
      end
      Array(fspec["cflags"]).any? { |f| f.to_s.match?(/\A-DPRISM_FUZZ_ALLOW_STREAM_WITH_IJON(?:=(?!0\z).+)?\z/) }
    end

    def fuzzer_suppresses_stream?(fspec, executable: "")
      if fspec
        fspec["shape"].to_s == "prism_parse" &&
          (fspec["ijon"] || fspec["afl"].to_s == "ijon") &&
          !fuzzer_allows_stream_with_ijon?(fspec)
      else
        executable.to_s.end_with?("ijon")
      end
    end

    def resolve_ids_path(bin_path, env_ids_key)
      return ENV[env_ids_key] if ENV.key?(env_ids_key)

      bin_path.empty? ? "" : "#{bin_path}.ids"
    end

    def resolve_coverage_target(triage_dir: TESTCASES_DIR, output_dirs: nil, coverage_bin: nil, coverage_ids: nil)
      unless coverage_bin.nil?
        ids = coverage_ids.nil? ? resolve_ids_path(coverage_bin, "TRIAGE_COVERAGE_IDS") : coverage_ids
        return [coverage_bin, ids]
      end

      if ENV.key?("TRIAGE_COVERAGE_BIN")
        bin = ENV["TRIAGE_COVERAGE_BIN"].to_s
        ids = coverage_ids.nil? ? resolve_ids_path(bin, "TRIAGE_COVERAGE_IDS") : coverage_ids
        return [bin, ids]
      end

      topo = resolve_topology(triage_dir: triage_dir, output_dirs: output_dirs)
      cov_fuzzer_id = topo&.dig("coverage", "fuzzer") || "fuzz"
      cov_bin_name = File.basename(topo&.dig("fuzzers", cov_fuzzer_id, "binary") || cov_fuzzer_id)
      cov_rel_bin = topo&.dig("fuzzers", cov_fuzzer_id, "binary") || DEFAULT_COVERAGE_BIN

      candidates = []
      triage_ws_roots(triage_dir).each { |r| candidates << File.join(r, "bin", cov_bin_name) }
      Array(output_dirs).each do |d|
        candidates << File.join(File.dirname(d), "bin", cov_bin_name) if d && !d.empty?
      end
      snap_bin = candidates.uniq.find { |p| File.file?(p) && File.executable?(p) }

      bin = snap_bin || (File.file?(cov_rel_bin) ? cov_rel_bin : DEFAULT_COVERAGE_BIN)
      ids = coverage_ids.nil? ? resolve_ids_path(bin, "TRIAGE_COVERAGE_IDS") : coverage_ids
      [bin, ids]
    end

    def resolve_diff_coverage_target(triage_dir: TESTCASES_DIR, output_dirs: nil, diff_coverage_bin: nil, diff_coverage_ids: nil, coverage_bin: nil)
      unless diff_coverage_bin.nil?
        ids = diff_coverage_ids.nil? ? resolve_ids_path(diff_coverage_bin, "TRIAGE_DIFF_COVERAGE_IDS") : diff_coverage_ids
        return [diff_coverage_bin, ids]
      end

      if ENV.key?("TRIAGE_DIFF_COVERAGE_BIN")
        bin = ENV["TRIAGE_DIFF_COVERAGE_BIN"].to_s
        ids = diff_coverage_ids.nil? ? resolve_ids_path(bin, "TRIAGE_DIFF_COVERAGE_IDS") : diff_coverage_ids
        return [bin, ids]
      end

      topo = resolve_topology(triage_dir: triage_dir, output_dirs: output_dirs)
      if topo && topo["coverage"].is_a?(Hash) && !topo["coverage"].key?("diff_fuzzer")
        return ["", ""]
      end
      diff_fuzzer_id = topo&.dig("coverage", "diff_fuzzer") || "fuzz.diff"
      diff_bin_name = File.basename(topo&.dig("fuzzers", diff_fuzzer_id, "binary") || diff_fuzzer_id)
      diff_rel_bin = topo&.dig("fuzzers", diff_fuzzer_id, "binary") || DEFAULT_DIFF_COVERAGE_BIN

      eff_cov_bin = coverage_bin.nil? ? ENV["TRIAGE_COVERAGE_BIN"] : coverage_bin
      if !eff_cov_bin.nil?
        return ["", ""] if eff_cov_bin.empty?

        if eff_cov_bin != DEFAULT_COVERAGE_BIN
          sibling = File.join(File.dirname(eff_cov_bin), diff_bin_name)
          ids = diff_coverage_ids.nil? ? resolve_ids_path(sibling, "TRIAGE_DIFF_COVERAGE_IDS") : diff_coverage_ids
          return [sibling, ids]
        end
      end

      candidates = []
      triage_ws_roots(triage_dir).each { |r| candidates << File.join(r, "bin", diff_bin_name) }
      Array(output_dirs).each do |d|
        candidates << File.join(File.dirname(d), "bin", diff_bin_name) if d && !d.empty?
      end
      exec_cands = candidates.uniq.select { |p| File.file?(p) && File.executable?(p) }
      snap_with_ids = exec_cands.find { |p| File.file?("#{p}.ids") }
      snap_bin = snap_with_ids || exec_cands.first

      # If an older snapshot binary predates fuzz.diff.ids while the live build has both,
      # prefer the snapshot if no live build .ids exists, otherwise use the live .ids binary.
      bin = if snap_with_ids
              snap_with_ids
            elsif snap_bin && !(File.file?(diff_rel_bin) && File.executable?(diff_rel_bin) && File.file?("#{diff_rel_bin}.ids"))
              snap_bin
            else
              File.file?(diff_rel_bin) ? diff_rel_bin : DEFAULT_DIFF_COVERAGE_BIN
            end
      ids = diff_coverage_ids.nil? ? resolve_ids_path(bin, "TRIAGE_DIFF_COVERAGE_IDS") : diff_coverage_ids
      [bin, ids]
    end

    def workspace_build_rel(triage_dir: nil)
      if defined?(PrismFuzzer::Topology)
        t = resolve_topology(triage_dir: triage_dir || TESTCASES_DIR)
        return PrismFuzzer::Topology.workspace_paths(t)[:build_rel] if t
      end
      "./tmp/fuzz/build"
    end

    def companion_executable(executable, name, triage_dir: TESTCASES_DIR)
      exe_dir = File.dirname(executable.to_s)
      if !exe_dir.empty? && exe_dir != "."
        cand = File.join(exe_dir, name)
        return cand if File.executable?(cand) && !File.directory?(cand)
      end
      File.join(workspace_build_rel(triage_dir: triage_dir), name)
    end

    def find_executable_in_path(cmd)
      return nil if cmd.nil? || cmd.empty?
      return cmd if cmd.include?("/") && File.executable?(cmd) && !File.directory?(cmd)

      ENV.fetch("PATH", "").split(File::PATH_SEPARATOR).each do |dir|
        cand = File.join(dir, cmd)
        return cand if File.executable?(cand) && !File.directory?(cand)
      end
      nil
    end

    def triage_script_path(filename)
      dir = (TRIAGE_FILE_DIR && File.directory?(TRIAGE_FILE_DIR)) ? TRIAGE_FILE_DIR : File.expand_path("triage")
      File.join(dir, filename)
    end

    def resolve_triage_explain_bin(triage_dir:)
      candidates = []
      env_bin = ENV["TRIAGE_EXPLAIN_BIN"].to_s.strip
      candidates << env_bin unless env_bin.empty?
      triage_ws_roots(triage_dir).each { |r| candidates << File.join(r, "bin", "fuzz.explain") }
      candidates << File.join(workspace_build_rel(triage_dir: triage_dir), "fuzz.explain")
      candidates.uniq.find do |p|
        File.file?(p) && File.executable?(p) && system(p, "--help", out: File::NULL, err: File::NULL)
      end
    end

    # Convert arbitrary bytes or malformed text into valid UTF-8 while replacing invalid sequences.
    def utf8_safe(text)
      PrismFuzzer::Common.utf8_safe(text)
    end

    def write_json_atomic(path, data)
      PrismFuzzer::Common.write_json_atomic(path, data)
    end

    def binary_build_id(bin_path)
      Digest::SHA256.file(bin_path).hexdigest
    end

    def normalize_repo_path(path)
      clean = utf8_safe(path).strip
      pwd_prefix = "#{Dir.pwd}/"
      clean = if clean.start_with?(pwd_prefix)
                clean.delete_prefix(pwd_prefix)
              elsif clean.start_with?("/prism-fuzzer/")
                clean.delete_prefix("/prism-fuzzer/")
              elsif clean.start_with?("/ruby-fuzz/")
                clean.delete_prefix("/ruby-fuzz/")
              elsif clean.start_with?("/prism/")
                clean.delete_prefix("/prism/")
              else
                clean
              end
      clean = clean.sub(%r{\A(?:\./)?(?:.*/)?build/targets/[^/]+/}, "")
      clean.start_with?("prism/src/", "prism/include/", "prism/templates/") ? clean.delete_prefix("prism/") : clean
    end

    def resolve_cmdline_executable(raw_cmdline)
      tokens = raw_cmdline.to_s.split(/[\0\r\n]+/).map(&:strip).reject(&:empty?)
      return "" if tokens.empty?

      if File.basename(tokens.first).start_with?("qemu-")
        tokens.reverse_each.find { |t| File.basename(t).start_with?("fuzz") } || tokens.last
      else
        tokens.first
      end
    end

    def encode_loupe_scope_local(bytes)
      PrismFuzzer::LoupeUrl.encode_scope_local(bytes)
    end

    def sanitizer_loupe_crash?(reason, crash_output)
      PrismFuzzer::LoupeUrl.sanitizer_crash?(reason, crash_output)
    end

    def prism_diff_bucket?(executable: "", crash_output: "", triage_dir: TESTCASES_DIR)
      FuzzVerifyProfile.prism_diff_bucket?(executable: executable, crash_output: crash_output, triage_dir: triage_dir)
    end

    def diff_bucket?(executable: "", crash_output: "", triage_dir: TESTCASES_DIR)
      FuzzVerifyProfile.diff_bucket?(executable: executable, crash_output: crash_output, triage_dir: triage_dir)
    end

    def cross_oracle_kind(executable: "", crash_output: "", triage_dir: TESTCASES_DIR)
      FuzzVerifyProfile.cross_oracle_kind(executable: executable, crash_output: crash_output, triage_dir: triage_dir)
    end

    def arm32_bucket?(executable: "", crash_output: "", triage_dir: TESTCASES_DIR)
      cross_oracle_kind(executable: executable, crash_output: crash_output, triage_dir: triage_dir) == "arm32"
    end

    def ppc_bucket?(executable: "", crash_output: "", triage_dir: TESTCASES_DIR)
      cross_oracle_kind(executable: executable, crash_output: crash_output, triage_dir: triage_dir) == "ppc"
    end

    def cross_oracle_bucket?(executable: "", crash_output: "", triage_dir: TESTCASES_DIR)
      !cross_oracle_kind(executable: executable, crash_output: crash_output, triage_dir: triage_dir).nil?
    end

    def build_diff_loupe_url(source)
      PrismFuzzer::LoupeUrl.diff_url(source)
    end

    # Decodes the 4-byte fuzzer option header consumed by harness() in
    # harnesses/prism/parse.c into structured fields shared by Loupe URLs and
    # bucket metadata JSON.
    def decode_fuzz_header(raw)
      PrismFuzzer::FuzzHeader.decode(raw)
    end

    def encode_fuzz_header(
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
      PrismFuzzer::FuzzHeader.encode(
        ruby_version: ruby_version,
        encoding: encoding,
        frozen_string_literal: frozen_string_literal,
        partial_script: partial_script,
        freeze: freeze,
        attach_comments: attach_comments,
        encoding_locked: encoding_locked,
        stream_mode: stream_mode,
        main_script: main_script,
        command_line: command_line,
        scopes_count: scopes_count,
        forwarding: forwarding,
        start_line: start_line
      )
    end

    def build_prism_loupe_url(raw, sanitize: false)
      PrismFuzzer::LoupeUrl.prism_url(raw, sanitize: sanitize)
    end

    def fuzz_root_lookup_bash
      <<~'SH'.chomp
        SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
        FUZZ_ROOT="${FUZZ_ROOT:-}"
        if [ -z "$FUZZ_ROOT" ]; then
          dir="$SCRIPT_DIR"
          while [ "$dir" != "/" ]; do
            if [ -f "$dir/triage/verify_bucket.sh" ] && [ -d "$dir/harnesses/prism" ]; then
              FUZZ_ROOT="$dir"
              break
            fi
            dir="$(dirname "$dir")"
          done
        fi
        if [ -z "$FUZZ_ROOT" ]; then
          echo "Error: could not locate prism-fuzzer root (set FUZZ_ROOT=/path/to/prism-fuzzer)" >&2
          exit 1
        fi
      SH
    end

    def repo_root_lookup_bash
      "#{fuzz_root_lookup_bash}\n" + <<~'SH'.chomp
        REPO_ROOT="${PRISM_ROOT:-${PRISM_A_DIR:-${PRISM_DIR:-}}}"
        ws_build="${FUZZ_BUILD_DIR:-}"
        if [ -z "$ws_build" ] && [ -f "$FUZZ_ROOT/bin/topology.rb" ]; then
          ws_build="$(ruby -r"$FUZZ_ROOT/runtime/topology" -e 't=PrismFuzzer::Topology.discover(triage_dir: ARGV[0], start_dir: ARGV[1]); puts PrismFuzzer::Topology.workspace_paths(t, fuzz_root: ARGV[1])[:build_dir] if t' "$SCRIPT_DIR" "$FUZZ_ROOT" 2>/dev/null || true)"
        fi
        ws_build="${ws_build:-$FUZZ_ROOT/tmp/fuzz/build}"
        if [ -z "$REPO_ROOT" ] && [ -f "$ws_build/targets/prism_a/include/prism.h" ] && [ -d "$ws_build/targets/prism_a/src" ]; then
          REPO_ROOT="$ws_build/targets/prism_a"
        fi
        if [ -z "$REPO_ROOT" ]; then
          dir="$SCRIPT_DIR"
          while [ "$dir" != "/" ]; do
            if [ -f "$dir/include/prism.h" ] && [ -d "$dir/src" ]; then
              REPO_ROOT="$dir"
              break
            fi
            dir="$(dirname "$dir")"
          done
        fi
        if [ -z "$REPO_ROOT" ]; then
          echo "Error: could not locate Prism target root (run 'make targets-sync' or set PRISM_A_DIR=/path/to/prism)" >&2
          exit 1
        fi
      SH
    end

    def bucket_verify_profile(reason:, executable: "", crash_output: "", triage_dir: TESTCASES_DIR)
      FuzzVerifyProfile.bucket_verify_profile(reason: reason, executable: executable, crash_output: crash_output, triage_dir: triage_dir)
    end

    def verify_script(reason:, executable: "", crash_output: "", triage_dir: TESTCASES_DIR)
      profile = bucket_verify_profile(reason: reason, executable: executable, crash_output: crash_output, triage_dir: triage_dir)
      <<~SH
        #!/usr/bin/env bash
        set -euo pipefail

        #{repo_root_lookup_bash}

        exec "$FUZZ_ROOT/triage/verify_bucket.sh" \\
          --repo-root "$REPO_ROOT" \\
          --fuzz-root "$FUZZ_ROOT" \\
          --bucket-dir "$SCRIPT_DIR" \\
          --profile "#{profile}" \\
          "$@"
      SH
    end

    def ensure_bucket_verify_script(bucket_dir, reason:, executable:, crash_output: "", triage_dir: TESTCASES_DIR)
      verify_path = File.join(bucket_dir, "verify.sh")
      content = verify_script(reason: reason, executable: executable, crash_output: crash_output, triage_dir: triage_dir)
      return if File.file?(verify_path) && File.read(verify_path) == content

      File.write(verify_path, content)
      File.chmod(0o755, verify_path)
    end
  end
end
