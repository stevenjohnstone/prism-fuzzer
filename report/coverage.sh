#!/usr/bin/env bash
# Collects LLVM source-based code coverage across (source, target) pairs from the
# active campaign topology and emits LCOV, text summaries, llvm-cov HTML, and
# unified coverage.json under <ws>/report/coverage/.
#
# Incremental per-pair caching (<ws>/.coverage-cache/<pair_id>/):
#   - Captures a filesystem mtime cutoff (cutoff_ns) on <ws>/ before scanning queues
#     (with a 50ms settle margin when FUZZ_COVERAGE_LIVE=1).
#   - On mid-run reports, ignores queue/crash/hang/seed files with mtime > cutoff_ns
#     (deferring them to the next pass), skips files with mtime <= last_cutoff_ns via
#     lstat without reading/hashing them, deduplicates cross-worker synced inputs
#     within each (source, target) pair via seen.sha256, replays only new inputs,
#     and merges new .profraw counters into cached.profdata.
#   - Because state, seen.sha256, and cached.profdata are scoped per (source, target)
#     pair (e.g. prism_a__native vs prism_a__swar vs prism_b__native), an input
#     synced across pairs is still replayed against each pair's own coverage binary.
#   - Automatically invalidates a pair's cache if its coverage binary/flags change or
#     worker queues reset, and deletes <ws>/.coverage-cache/ on final post-run sweeps
#     (FUZZ_COVERAGE_FINAL=1) or when FUZZ_COVERAGE_NO_CACHE=1 is set.
set -euo pipefail

if [ -n "${LLVM_VERSION:-}" ] && [ -d "/usr/lib/llvm-${LLVM_VERSION}/bin" ]; then
  export PATH="/usr/lib/llvm-${LLVM_VERSION}/bin:${PATH}"
fi

REPO_ROOT="$(pwd)"
if [ -f "$REPO_ROOT/bin/topology.rb" ]; then
  paths_env="$(ruby "$REPO_ROOT/bin/topology.rb" paths --relative --shell 2>/dev/null || true)"
  if [ -n "$paths_env" ]; then
    while IFS= read -r -d '' k && IFS= read -r -d '' v; do
      if [[ "$k" =~ ^WORKSPACE_[A-Z0-9_]+$ ]]; then
        printf -v "$k" '%s' "$v"
      fi
    done < <(ruby -rshellwords -e '
      ARGV[0].to_s.each_line do |line|
        line = line.chomp
        next if line.empty?
        key, raw_val = line.split("=", 2)
        next unless key&.match?(/\AWORKSPACE_[A-Z0-9_]+\z/)
        tokens = begin
          Shellwords.split(raw_val.to_s)
        rescue ArgumentError
          next
        end
        next if tokens.size > 1
        $stdout.write("#{key}\0#{tokens.empty? ? "" : tokens[0]}\0")
      end
    ' "$paths_env" 2>/dev/null || true)
  fi
fi

WS_DIR="${WORKSPACE_DIR:-tmp/fuzz}"
REPORT_DIR="${WORKSPACE_REPORT_DIR:-$WS_DIR/report}"
BUILD_ROOT="${WORKSPACE_BUILD_DIR:-tmp/fuzz/build}"
FINAL_COVERAGE_DIR="${WORKSPACE_COVERAGE_DIR:-$REPORT_DIR/coverage}"
CACHE_ROOT="${FUZZ_COVERAGE_CACHE_DIR:-$WS_DIR/.coverage-cache}"
COVERAGE_NO_CACHE="${FUZZ_COVERAGE_NO_CACHE:-0}"
COVERAGE_FINAL="${FUZZ_COVERAGE_FINAL:-0}"
COVERAGE_LIVE="${FUZZ_COVERAGE_LIVE:-0}"
mkdir -p "$BUILD_ROOT" "$WS_DIR" "$REPORT_DIR"

WORK_DIR=$(mktemp -d)
PAIRS_META="$WORK_DIR/pairs_meta.json"
LIVE_SEEDS_DIR="$WORK_DIR/live_seeds"
COLLECT_RB="$WORK_DIR/collect_inputs.rb"
COMMIT_CACHE_RB="$WORK_DIR/commit_cache.rb"
EMIT_COV_RB="$WORK_DIR/emit_coverage_payload.rb"
COVERAGE_TMP_BIN="$BUILD_ROOT/.fuzz.coverage.tmp.$$"
CLOCK_PROBE="$WS_DIR/.cov_clock_probe.$$"
COVERAGE_DIR="$WS_DIR/.coverage.tmp.$$"
OLD_COVERAGE_DIR="$WS_DIR/.coverage.old.$$"
CLANG_VER_LINE="$(clang --version | awk 'NR==1{print}')"
LLVM_COV_BIN_PATH="$(command -v llvm-cov || true)"
export REPO_ROOT WS_DIR BUILD_ROOT FINAL_COVERAGE_DIR REPORT_DIR CACHE_ROOT
export COVERAGE_NO_CACHE COVERAGE_FINAL COVERAGE_LIVE CLANG_VER_LINE LLVM_COV_BIN_PATH

cleanup_coverage() {
  local rc=$?
  if [ ! -e "$FINAL_COVERAGE_DIR" ] && [ -d "$OLD_COVERAGE_DIR" ]; then
    mv "$OLD_COVERAGE_DIR" "$FINAL_COVERAGE_DIR" 2>/dev/null || true
  fi
  if [ "$rc" -ne 0 ]; then
    if [ -f "$FINAL_COVERAGE_DIR/coverage.json" ]; then
      ruby -rjson -e '
        raw = File.read(ARGV[0], encoding: "UTF-8")
        doc = JSON.parse(raw)
        doc["status"] ||= "complete"
        js = JSON.generate(doc).gsub("<", "\\u003c").gsub(">", "\\u003e").gsub("\u2028", "\\u2028").gsub("\u2029", "\\u2029")
        tmp = "#{ARGV[1]}.tmp.#{Process.pid}"
        File.write(tmp, "if (typeof window !== \"undefined\" && typeof window.__PRISM_FUZZER_ON_COVERAGE__ === \"function\") {\n  window.__PRISM_FUZZER_ON_COVERAGE__(#{js});\n} else if (typeof window !== \"undefined\") {\n  window.__PRISM_FUZZER_PENDING_COVERAGE__ = #{js};\n}\n")
        File.rename(tmp, ARGV[1])
      ' "$FINAL_COVERAGE_DIR/coverage.json" "$FINAL_COVERAGE_DIR/coverage.js" 2>/dev/null || true
    else
      rm -f "$FINAL_COVERAGE_DIR/coverage.js" "$FINAL_COVERAGE_DIR"/.coverage.js.tmp.* 2>/dev/null || true
    fi
  fi
  rm -rf "$WORK_DIR" "$COVERAGE_TMP_BIN" "$CLOCK_PROBE" "$COVERAGE_DIR" "$OLD_COVERAGE_DIR"
  exit "$rc"
}
trap cleanup_coverage EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [ -n "${FUZZ_LIVE_SEEDS_TAR:-}" ]; then
  if [ -s "$FUZZ_LIVE_SEEDS_TAR" ]; then
    mkdir -p "$LIVE_SEEDS_DIR"
    tar -C "$LIVE_SEEDS_DIR" -xf "$FUZZ_LIVE_SEEDS_TAR" 2>/dev/null || rm -rf "$LIVE_SEEDS_DIR"
  fi
  rm -f "$FUZZ_LIVE_SEEDS_TAR"
fi

# Probe the workspace filesystem's current mtime clock before scanning any queues
# so host/container mount clocks and coarse kernel ticks align with queue mtimes.
NOW_FS_NS=$(ruby -e '
  probe = ARGV[0]
  begin
    File.binwrite(probe, "")
    st = File.lstat(probe)
    puts(st.mtime.tv_sec * 1_000_000_000 + st.mtime.tv_nsec)
  rescue SystemCallError, IOError
    t = Time.now
    puts(t.tv_sec * 1_000_000_000 + t.tv_nsec)
  ensure
    begin
      File.unlink(probe) if File.exist?(probe)
    rescue SystemCallError
      nil
    end
  end
' "$CLOCK_PROBE")
export NOW_FS_NS

# Verify that a coverage binary is non-empty, runnable on /dev/null, and emits
# profile data (rejecting 0-byte truncated files and un-instrumented binaries).
smoke_check_coverage_bin() {
  local bin="$1"
  local smoke_prof="$WORK_DIR/smoke.profraw"
  rm -f "$smoke_prof"
  if [ -s "$bin" ] && LLVM_PROFILE_FILE="$smoke_prof" "$bin" /dev/null >/dev/null 2>&1 && [ -s "$smoke_prof" ]; then
    rm -f "$smoke_prof"
    return 0
  fi
  rm -f "$smoke_prof"
  return 1
}

cat << 'RUBY' > "$COLLECT_RB"
  require "digest"
  require "fileutils"
  require "json"
  require "shellwords"

  work_dir = ARGV[0]
  pairs_meta_path = ARGV[1]
  live_seeds_dir = ARGV[2]
  recollect_pair_id = nil
  if ARGV[3] == "--recollect-pair"
    recollect_pair_id = ARGV[4].to_s
  end

  repo_root = ENV.fetch("REPO_ROOT", Dir.pwd)
  ws_dir = ENV.fetch("WS_DIR", "tmp/fuzz")
  build_root = ENV.fetch("BUILD_ROOT", File.join(ws_dir, "build"))
  cache_root = ENV.fetch("CACHE_ROOT", File.join(ws_dir, ".coverage-cache"))
  ws_afl = ENV.fetch("WORKSPACE_AFL_DIR", File.join(ws_dir, "afl"))
  ws_corpus = ENV.fetch("WORKSPACE_CORPUS_DIR", File.join(ws_dir, "corpus"))
  no_cache = ENV["COVERAGE_NO_CACHE"] == "1"
  is_final = ENV["COVERAGE_FINAL"] == "1"
  is_live = ENV["COVERAGE_LIVE"] == "1"
  now_fs_ns = ENV.fetch("NOW_FS_NS").to_i
  clang_ver_line = ENV.fetch("CLANG_VER_LINE", "")
  llvm_cov_bin_path = ENV.fetch("LLVM_COV_BIN_PATH", "")

  # Settle margin of 50ms when fuzzers are actively writing so no concurrently
  # created file within the current kernel coarse tick falls behind cutoff_ns.
  live_margin_ns = 50_000_000
  base_cutoff_ns = if is_final || no_cache
                     nil
                   elsif is_live
                     now_fs_ns - live_margin_ns
                   else
                     now_fs_ns
                   end

  topo_rb = File.join(repo_root, "runtime", "topology.rb")
  require topo_rb if File.file?(topo_rb)
  topo = defined?(PrismFuzzer::Topology) ? PrismFuzzer::Topology.discover(start_dir: repo_root, afl_dir: ws_afl) : nil

  user_flags = Shellwords.split(ENV.fetch("FUZZ_FLAGS", ""))
  default_defines = if topo && defined?(PrismFuzzer::Topology)
                      PrismFuzzer::Topology.default_coverage_define_flags(topo)
                    else
                      %w[-DPRISM_EXCLUDE_JSON -DPRISM_EXCLUDE_PRETTYPRINT -DPM_INTEGER_DIVIDE_THRESHOLD=8 -DPRISM_DEPTH_MAXIMUM=128 -DFUZZ_MAX_INPUT_SIZE=1024 -DFUZZ_MAX_ALLOCATED=128 -DFUZZ_HARD_RSS_LIMIT=2048]
                    end

  pairs = if topo && defined?(PrismFuzzer::Topology)
            PrismFuzzer::Topology.coverage_pairs(topo, fuzz_root: repo_root)
          else
            []
          end

  if pairs.empty?
    abs_build_root = File.expand_path(build_root, repo_root)
    fallback_dir = ENV["PRISM_A_DIR"] || ENV["PRISM_DIR"] || File.join(abs_build_root, "targets", "prism_a")
    fallback_gen = ENV["PRISM_A_GEN_DIR"] || File.join(abs_build_root, "targets", "gen", "prism_a")
    pairs << {
      "id" => "prism_a__native",
      "label" => "prism_a (native)",
      "source" => "prism_a",
      "source_path" => fallback_dir,
      "gen_dir" => fallback_gen,
      "target" => "native",
      "target_label" => "native",
      "cflags" => [],
      "fuzzers" => [],
      "workers" => [],
      "generators" => [],
      "cross_oracle_workers" => []
    }
  end

  worker_pairs = if topo && defined?(PrismFuzzer::Topology)
                   PrismFuzzer::Topology.worker_coverage_pairs(topo, fuzz_root: repo_root)
                 else
                   {}
                 end

  pairs.each do |p|
    sid = p["source"].to_s
    abs_build_root = File.expand_path(build_root, repo_root)
    if p["source_path"].nil? || p["source_path"].to_s.empty?
      env_dir = sid == "prism_a" ? (ENV["PRISM_A_DIR"] || ENV["PRISM_DIR"]) : (sid == "prism_b" ? ENV["PRISM_B_DIR"] : nil)
      p["source_path"] = env_dir || File.join(abs_build_root, "targets", sid)
    end
    if p["gen_dir"].nil? || p["gen_dir"].to_s.empty?
      env_gen = sid == "prism_a" ? ENV["PRISM_A_GEN_DIR"] : (sid == "prism_b" ? ENV["PRISM_B_GEN_DIR"] : nil)
      cand_gen = File.join(abs_build_root, "targets", "gen", sid)
      p["gen_dir"] = File.file?(File.join(cand_gen, "node_locations.inc")) ? cand_gen : (env_gen || cand_gen)
    end
    prism_root = p["source_path"].to_s
    unless File.file?(File.join(prism_root, "include", "prism.h")) && File.directory?(File.join(prism_root, "src"))
      abort "Error: invalid Prism target directory '#{prism_root}' for coverage pair '#{p["id"]}' (run make targets-sync first)."
    end
    if defined?(PrismFuzzer::Topology) && (!File.file?(File.join(p["gen_dir"].to_s, "node_locations.inc")) || !File.file?(File.join(p["gen_dir"].to_s, "prism_fuzz_compat.h")))
      PrismFuzzer::Topology.ensure_harness_generated_inc!(prism_root, p["gen_dir"].to_s, fuzz_root: repo_root)
    end
  end

  topo_roots = if topo && defined?(PrismFuzzer::Topology)
                 PrismFuzzer::Topology.sync_group_dirs(topo, base_dir: ws_dir)
               else
                 []
               end
  sync_roots = (topo_roots + [ws_afl, File.join(ws_dir, "afl-ijon")]).map { |p| File.expand_path(p) }.uniq
  worker_dirs = {}
  sync_roots.each do |root|
    next unless Dir.exist?(root)

    Dir.children(root).sort.each do |w|
      next if w.start_with?(".")
      d = File.join(root, w)
      next unless File.directory?(d) && !File.symlink?(File.join(d, "queue"))
      worker_dirs[w] ||= d
    end
  end

  # When cross-oracle queues contain PM64 oracle envelopes ("PM64" LE uint32 magic + olen + AST + raw payload),
  # unwrap the raw 4-byte-header + Ruby payload into a staged file before deduplication and replay.
  oracle32_magic = 0x504D3634
  unwrap_pm64_if_present = lambda do |data|
    return data if data.bytesize < 17

    magic, olen = data.byteslice(0, 8).unpack("V2")
    return data unless magic == oracle32_magic
    return data if olen < 9 || olen > data.bytesize - 8
    return data unless data.byteslice(8, 5) == "PRISM"

    data.byteslice(8 + olen, data.bytesize - 8 - olen)
  end

  defined_macro_names = lambda do |flags|
    names = {}
    i = 0
    while i < flags.size
      tok = flags[i].to_s
      if tok == "-D" && i + 1 < flags.size
        names[flags[i + 1].to_s.split("=", 2).first] = true
        i += 2
        next
      elsif tok.start_with?("-D")
        names[tok.delete_prefix("-D").split("=", 2).first] = true
      end
      i += 1
    end
    names
  end

  stat_mtime_ns = lambda do |full|
    lst = File.lstat(full)
    if lst.symlink?
      st = File.stat(full)
      return nil unless st.file?

      l_ns = lst.mtime.tv_sec * 1_000_000_000 + lst.mtime.tv_nsec
      s_ns = st.mtime.tv_sec * 1_000_000_000 + st.mtime.tv_nsec
      l_ns > s_ns ? l_ns : s_ns
    elsif lst.file?
      lst.mtime.tv_sec * 1_000_000_000 + lst.mtime.tv_nsec
    end
  rescue SystemCallError
    nil
  end

  sources_newer_than = lambda do |bin_mtime_ns, dirs|
    dirs.any? do |d|
      next false unless d && !d.to_s.empty? && Dir.exist?(d)

      Dir.glob(File.join(d, "**", "*")).any? do |f|
        begin
          st = File.lstat(f)
          st.file? && (st.mtime.tv_sec * 1_000_000_000 + st.mtime.tv_nsec) > bin_mtime_ns
        rescue SystemCallError
          false
        end
      end
    end
  end

  read_worker_start_time = lambda do |wdir|
    sf = File.join(wdir, "fuzzer_stats")
    return nil unless File.file?(sf)

    File.foreach(sf, encoding: "UTF-8", invalid: :replace) do |ln|
      k, v = ln.split(":", 2)
      return v.strip if k && v && k.strip == "start_time" && !v.strip.empty?
    end
    nil
  rescue SystemCallError, IOError
    nil
  end

  rd_flags = File::RDONLY | (defined?(File::NOATIME) ? File::NOATIME : 0)
  generators_cfg = topo && topo["generators"].is_a?(Hash) ? topo["generators"] : {}

  collect_for_pair = lambda do |pair, idx, force_uncached: false|
    pid = pair["id"].to_s
    pwork = File.join(work_dir, "pairs", pid)
    staged_dir = File.join(pwork, "staged")
    FileUtils.rm_rf(staged_dir)
    FileUtils.mkdir_p(staged_dir)

    pair_workers = Array(pair["workers"]).map(&:to_s)
    if pair_workers.empty? && topo.nil? && idx == 0
      pair_workers = worker_dirs.keys.sort
    end

    pair_flags = Array(pair["cflags"]).map(&:to_s)
    explicit_macros = defined_macro_names.call(pair_flags + user_flags)
    effective_defaults = default_defines.reject do |tok|
      macro = tok.sub(/\A-D/, "").split("=", 2).first
      explicit_macros[macro]
    end
    compile_flags = effective_defaults + pair_flags + user_flags

    prism_root = pair["source_path"].to_s
    prism_gen = pair["gen_dir"].to_s
    build_key = Digest::SHA256.hexdigest(JSON.generate([
      prism_root,
      prism_gen,
      compile_flags.join(" "),
      clang_ver_line,
      ENV["LLVM_VERSION"].to_s,
      llvm_cov_bin_path
    ]))

    # Compute current persistent queue/crash/hang/corpus inventory and worker start_time markers
    worker_start_times = {}
    persistent_file_count = 0
    pair_workers.each do |w|
      d = worker_dirs[w]
      next unless d

      st_val = read_worker_start_time.call(d)
      worker_start_times[w] = st_val if st_val

      q_dir = File.join(d, "queue")
      if Dir.exist?(q_dir)
        Dir.children(q_dir).each do |fname|
          next if fname.start_with?(".")
          persistent_file_count += 1 if stat_mtime_ns.call(File.join(q_dir, fname))
        end
      end
      %w[crashes hangs].each do |sub|
        s_dir = File.join(d, sub)
        next unless Dir.exist?(s_dir)

        Dir.children(s_dir).each do |fname|
          next unless fname.start_with?("id")
          next if fname.end_with?(".bt", ".min", ".md")
          persistent_file_count += 1 if stat_mtime_ns.call(File.join(s_dir, fname))
        end
      end
    end

    corpus_dirs = []
    Array(pair["generators"]).each do |gid|
      g = generators_cfg[gid]
      next unless g.is_a?(Hash) && g["kind"].to_s == "corpus"

      c_dir = if defined?(PrismFuzzer::Topology)
                PrismFuzzer::Topology.resolve_corpus_generator_dir(
                  g["dir"],
                  fuzz_dir: File.expand_path(ws_dir, repo_root),
                  fuzz_root: repo_root,
                  ws_raw_dir: topo&.dig("workspace", "dir"),
                  default_corpus_dir: File.expand_path(ws_corpus, repo_root)
                )
              else
                g["dir"] ? File.expand_path(g["dir"], repo_root) : File.expand_path(ws_corpus, repo_root)
              end
      corpus_dirs << c_dir if Dir.exist?(c_dir)
    end
    if topo.nil? && idx == 0 && Dir.exist?(ws_corpus)
      corpus_dirs << ws_corpus
    end
    corpus_dirs.each do |c_dir|
      Dir.children(c_dir).each do |fname|
        next if fname.start_with?(".") || fname.start_with?("README")
        persistent_file_count += 1 if stat_mtime_ns.call(File.join(c_dir, fname))
      end
    end

    # Validate existing per-pair incremental cache
    pcache = File.join(cache_root, pid)
    state_path = File.join(pcache, "state.json")
    prof_path = File.join(pcache, "cached.profdata")
    seen_path = File.join(pcache, "seen.sha256")
    cov_bin = File.join(build_root, "fuzz.coverage.#{pid}")
    stamp_file = File.join(build_root, ".fuzz.coverage.#{pid}.stamp")

    prev_state = nil
    if !no_cache && !force_uncached && persistent_file_count > 0 && File.file?(state_path) && File.size?(prof_path) && File.file?(seen_path) && File.size?(cov_bin) && File.file?(stamp_file)
      loaded_state = begin
        JSON.parse(File.read(state_path, encoding: "UTF-8"))
      rescue SystemCallError, IOError, JSON::ParserError
        nil
      end
      stamp_val = begin
        File.read(stamp_file, encoding: "UTF-8")
      rescue SystemCallError, IOError
        nil
      end
      bin_mtime_ns = stat_mtime_ns.call(cov_bin)
      if loaded_state.is_a?(Hash) &&
         loaded_state["schema_version"] == 1 &&
         loaded_state["pair_id"] == pid &&
         loaded_state["build_key"] == build_key &&
         stamp_val == build_key &&
         loaded_state["persistent_file_count"].to_i > 0 &&
         persistent_file_count >= loaded_state["persistent_file_count"].to_i &&
         bin_mtime_ns &&
         !sources_newer_than.call(bin_mtime_ns, [File.join(prism_root, "src"), File.join(prism_root, "include"), prism_gen, File.join(repo_root, "harnesses/prism")])
        prev_starts = loaded_state["worker_start_times"].is_a?(Hash) ? loaded_state["worker_start_times"] : {}
        restarted = prev_starts.any? { |w, prev_t| worker_start_times.key?(w) && worker_start_times[w] != prev_t }
        seen_bytes = loaded_state["seen_bytes"].to_i
        seen_size_ok = seen_bytes >= 0 && (seen_bytes % 32).zero? && File.size(seen_path) >= seen_bytes
        if !restarted && seen_size_ok
          bin_sha = begin
            Digest::SHA256.file(cov_bin).hexdigest
          rescue SystemCallError, IOError
            nil
          end
          prev_state = loaded_state if bin_sha && bin_sha == loaded_state["bin_sha256"]
        end
      end
    end

    use_cache = !prev_state.nil?
    last_cutoff_ns = use_cache ? prev_state["last_cutoff_ns"].to_i : nil
    prev_queue_count = use_cache ? prev_state["cumulative_queue_count"].to_i : 0
    prev_crash_count = use_cache ? prev_state["cumulative_crash_count"].to_i : 0
    prev_seen_bytes = use_cache ? prev_state["seen_bytes"].to_i : 0

    base_seen = {}
    if use_cache && prev_seen_bytes > 0
      raw_seen = File.binread(seen_path, prev_seen_bytes)
      pos = 0
      while pos < prev_seen_bytes
        base_seen[raw_seen.byteslice(pos, 32)] = true
        pos += 32
      end
    end

    cross_set = Array(pair["cross_oracle_workers"]).each_with_object({}) { |w, h| h[w.to_s] = true }

    scan_window = lambda do |upper_cutoff_ns|
      FileUtils.rm_rf(staged_dir)
      FileUtils.mkdir_p(staged_dir)
      seen = base_seen.dup
      new_digests = []
      queue_files = []
      crash_files = []
      staged_seq = 0
      deferred_after = 0

      add_raw_file = lambda do |full, target_list, unwrap_cross: false, copy_always: false|
        mtime_ns = stat_mtime_ns.call(full)
        return if mtime_ns.nil?
        return if last_cutoff_ns && mtime_ns <= last_cutoff_ns

        if upper_cutoff_ns && mtime_ns > upper_cutoff_ns
          deferred_after += 1
          return
        end

        data = begin
          begin
            File.open(full, rd_flags, &:read)
          rescue Errno::EPERM, Errno::EINVAL, Errno::EOPNOTSUPP
            File.binread(full)
          end
        rescue Errno::ENOENT
          nil
        rescue Errno::EACCES, SystemCallError => e
          warn "coverage.sh: failed to read '#{full}': #{e.class}: #{e.message}"
          nil
        end
        return if data.nil?

        rewrapped = false
        if unwrap_cross
          unwrapped = unwrap_pm64_if_present.call(data)
          if unwrapped.object_id != data.object_id
            data = unwrapped
            rewrapped = true
          end
        end

        digest = Digest::SHA256.digest(data)
        return if seen[digest]

        seen[digest] = true
        new_digests << digest
        if rewrapped || copy_always
          staged_path = File.join(staged_dir, "#{staged_seq}_#{File.basename(full)}")
          staged_seq += 1
          File.binwrite(staged_path, data)
          target_list << staged_path
        else
          target_list << full
        end
      end

      # 1. Worker queues and crashes/hangs
      pair_workers.each do |w|
        d = worker_dirs[w]
        next unless d

        unwrap = cross_set[w]
        q_dir = File.join(d, "queue")
        if Dir.exist?(q_dir)
          Dir.children(q_dir).sort.each do |fname|
            next if fname.start_with?(".")
            add_raw_file.call(File.join(q_dir, fname), queue_files, unwrap_cross: unwrap)
          end
        end

        %w[crashes hangs].each do |sub|
          s_dir = File.join(d, sub)
          next unless Dir.exist?(s_dir)

          Dir.children(s_dir).sort.each do |fname|
            next unless fname.start_with?("id")
            next if fname.end_with?(".bt", ".min", ".md")
            add_raw_file.call(File.join(s_dir, fname), crash_files, unwrap_cross: unwrap)
          end
        end
      end

      # 2. Generators targeting this pair source (initial corpus seeds)
      Array(pair["generators"]).each do |gid|
        g = generators_cfg[gid]
        next unless g.is_a?(Hash)

        if g["kind"].to_s == "corpus"
          c_dir = if defined?(PrismFuzzer::Topology)
                    PrismFuzzer::Topology.resolve_corpus_generator_dir(
                      g["dir"],
                      fuzz_dir: File.expand_path(ws_dir, repo_root),
                      fuzz_root: repo_root,
                      ws_raw_dir: topo&.dig("workspace", "dir"),
                      default_corpus_dir: File.expand_path(ws_corpus, repo_root)
                    )
                  else
                    g["dir"] ? File.expand_path(g["dir"], repo_root) : File.expand_path(ws_corpus, repo_root)
                  end
          if Dir.exist?(c_dir)
            Dir.children(c_dir).sort.each do |fname|
              next if fname.start_with?(".") || fname.start_with?("README")
              add_raw_file.call(File.join(c_dir, fname), queue_files)
            end
          end
        end
      end

      # Standalone fallback corpus when no topology exists
      if topo.nil? && idx == 0 && Dir.exist?(ws_corpus)
        Dir.children(ws_corpus).sort.each do |fname|
          next if fname.start_with?(".") || fname.start_with?("README")
          add_raw_file.call(File.join(ws_corpus, fname), queue_files)
        end
      end

      [queue_files, crash_files, new_digests, seen.size, deferred_after]
    end

    eff_cutoff_ns = if base_cutoff_ns && last_cutoff_ns && base_cutoff_ns < last_cutoff_ns
                      last_cutoff_ns
                    else
                      base_cutoff_ns
                    end

    queue_files, crash_files, new_digests, total_seen_count, deferred_after = scan_window.call(eff_cutoff_ns)

    # If a live report ran <50ms after campaign launch so every initial seed fell inside the
    # 50ms settle margin with an empty prior cache, widen cutoff to now_fs_ns so initial report succeeds.
    if is_live && !use_cache && queue_files.empty? && crash_files.empty? && deferred_after > 0
      eff_cutoff_ns = now_fs_ns
      queue_files, crash_files, new_digests, total_seen_count, deferred_after = scan_window.call(eff_cutoff_ns)
    end

    File.open(File.join(pwork, "queue.list"), "wb") { |f| queue_files.each { |p| f.write(p); f.write("\0") } }
    File.open(File.join(pwork, "crash.list"), "wb") { |f| crash_files.each { |p| f.write(p); f.write("\0") } }
    File.binwrite(File.join(pwork, "new_digests.sha256"), new_digests.join)

    cum_queue = prev_queue_count + queue_files.size
    cum_crash = prev_crash_count + crash_files.size
    cum_total = cum_queue + cum_crash
    delta_total = queue_files.size + crash_files.size

    next_state = {
      "schema_version" => 1,
      "pair_id" => pid,
      "build_key" => build_key,
      "last_cutoff_ns" => eff_cutoff_ns || now_fs_ns,
      "cumulative_queue_count" => cum_queue,
      "cumulative_crash_count" => cum_crash,
      "cumulative_input_count" => cum_total,
      "seen_bytes" => total_seen_count * 32,
      "prev_seen_bytes" => prev_seen_bytes,
      "worker_start_times" => worker_start_times,
      "persistent_file_count" => persistent_file_count,
      "cache_hit" => use_cache,
      "cacheable" => (!no_cache && !is_final && persistent_file_count > 0)
    }
    File.write(File.join(pwork, "next_state.json"), "#{JSON.pretty_generate(next_state)}\n")

    pair.merge(
      "primary" => (idx == 0),
      "compile_flags" => compile_flags,
      "build_key" => build_key,
      "cache_hit" => use_cache,
      "cached_input_count" => prev_queue_count + prev_crash_count,
      "delta_queue_count" => queue_files.size,
      "delta_crash_count" => crash_files.size,
      "delta_input_count" => delta_total,
      "deferred_after_cutoff" => deferred_after,
      "queue_count" => cum_queue,
      "crash_count" => cum_crash,
      "input_count" => cum_total
    )
  end

  if recollect_pair_id && !recollect_pair_id.empty?
    doc = JSON.parse(File.read(pairs_meta_path, encoding: "UTF-8"))
    idx = pairs.index { |p| p["id"].to_s == recollect_pair_id }
    abort "Error: unknown coverage pair '#{recollect_pair_id}'" unless idx
    updated = collect_for_pair.call(pairs[idx], idx, force_uncached: true)
    doc["pairs"] = doc.fetch("pairs").map { |p| p["id"].to_s == recollect_pair_id ? updated : p }
    File.write(pairs_meta_path, JSON.pretty_generate(doc))
  else
    pairs_out = pairs.each_with_index.map { |pair, idx| collect_for_pair.call(pair, idx) }
    File.write(pairs_meta_path, JSON.pretty_generate({
      "pairs" => pairs_out,
      "worker_pairs" => worker_pairs
    }))
    summary_parts = pairs_out.map do |p|
      if p["cache_hit"]
        "#{p["label"]}=#{p["input_count"]} inputs (#{p["delta_input_count"]} new, #{p["cached_input_count"]} cached)"
      else
        "#{p["label"]}=#{p["input_count"]} inputs"
      end
    end
    puts "Prepared #{pairs_out.size} coverage pair(s): #{summary_parts.join(', ')}"
  end
RUBY

cat << 'RUBY' > "$COMMIT_CACHE_RB"
  require "digest"
  require "fileutils"
  require "json"

  cache_root, pid, cov_bin, p_work, profdata_src, summary_json_src = ARGV
  next_state_path = File.join(p_work, "next_state.json")
  exit 0 unless File.file?(next_state_path)

  next_state = JSON.parse(File.read(next_state_path, encoding: "UTF-8"))
  exit 0 unless next_state["cacheable"]

  pcache = File.join(cache_root, pid)
  FileUtils.mkdir_p(pcache)
  next_state["bin_sha256"] = Digest::SHA256.file(cov_bin).hexdigest

  prof_dst = File.join(pcache, "cached.profdata")
  if File.expand_path(profdata_src) != File.expand_path(prof_dst)
    prof_tmp = "#{prof_dst}.tmp.#{Process.pid}"
    FileUtils.cp(profdata_src, prof_tmp)
    File.rename(prof_tmp, prof_dst)
  end

  sum_dst = File.join(pcache, "summary.json")
  if File.expand_path(summary_json_src) != File.expand_path(sum_dst)
    sum_tmp = "#{sum_dst}.tmp.#{Process.pid}"
    FileUtils.cp(summary_json_src, sum_tmp)
    File.rename(sum_tmp, sum_dst)
  end

  seen_dst = File.join(pcache, "seen.sha256")
  new_digests_path = File.join(p_work, "new_digests.sha256")
  new_bytes = File.file?(new_digests_path) ? File.binread(new_digests_path) : "".b
  prev_seen_bytes = next_state.delete("prev_seen_bytes").to_i
  if next_state["cache_hit"] && File.file?(seen_dst)
    File.open(seen_dst, File::RDWR | File::BINARY) do |f|
      f.truncate(prev_seen_bytes)
      f.seek(0, IO::SEEK_END)
      f.write(new_bytes) unless new_bytes.empty?
    end
  else
    seen_tmp = "#{seen_dst}.tmp.#{Process.pid}"
    File.binwrite(seen_tmp, new_bytes)
    File.rename(seen_tmp, seen_dst)
  end
  next_state.delete("cache_hit")
  next_state.delete("cacheable")

  state_dst = File.join(pcache, "state.json")
  state_tmp = "#{state_dst}.tmp.#{Process.pid}"
  File.write(state_tmp, "#{JSON.pretty_generate(next_state)}\n")
  File.rename(state_tmp, state_dst)
RUBY

cat << 'RUBY' > "$EMIT_COV_RB"
  require "fileutils"
  require "json"
  require "pathname"
  require "time"

  work_dir = ARGV[0]
  pairs_meta_path = ARGV[1]
  coverage_dir = ARGV[2]
  out_json_path = ARGV[3]
  mode = "complete"
  stage = nil
  i = 4
  while i < ARGV.size
    case ARGV[i]
    when "--mode"
      mode = ARGV[i + 1].to_s
      i += 2
    when "--stage"
      stage = ARGV[i + 1].to_s
      i += 2
    else
      i += 1
    end
  end

  repo_root = ENV.fetch("REPO_ROOT", Dir.pwd)
  ws_dir = ENV.fetch("WS_DIR", "tmp/fuzz")
  report_abs = File.expand_path(ENV.fetch("REPORT_DIR", File.join(ws_dir, "report")), repo_root)
  final_cov_abs = File.expand_path(ENV.fetch("FINAL_COVERAGE_DIR", File.join(report_abs, "coverage")), repo_root)
  cov_rel_prefix = begin
    Pathname.new(final_cov_abs).relative_path_from(Pathname.new(report_abs)).to_s
  rescue ArgumentError
    "coverage"
  end
  cov_rel_prefix = "." if cov_rel_prefix.empty?
  meta_doc = JSON.parse(File.read(pairs_meta_path, encoding: "UTF-8"))
  pairs_meta = meta_doc.fetch("pairs")
  worker_pairs = meta_doc.fetch("worker_pairs", {})

  prev_pairs_by_id = {}
  if mode == "running"
    prev_json_path = File.join(final_cov_abs, "coverage.json")
    if File.file?(prev_json_path)
      prev_doc = begin
        JSON.parse(File.read(prev_json_path, encoding: "UTF-8"))
      rescue SystemCallError, IOError, JSON::ParserError
        nil
      end
      if prev_doc.is_a?(Hash) && prev_doc["pairs"].is_a?(Array)
        prev_doc["pairs"].each { |pp| prev_pairs_by_id[pp["id"].to_s] = pp if pp.is_a?(Hash) && pp["id"] }
      end
    end
  end

  metrics = %w[lines functions instantiations regions branches].freeze
  extract_summary = lambda do |summary_hash|
    next {} unless summary_hash

    out = {}
    metrics.each do |m|
      next unless summary_hash[m]

      out[m] = {
        "count" => summary_hash[m]["count"].to_i,
        "covered" => summary_hash[m]["covered"].to_i,
        "percent" => summary_hash[m]["percent"].to_f.round(2)
      }
    end
    out
  end

  pairs_out = pairs_meta.map do |p|
    pid = p["id"].to_s
    sum_path = File.join(work_dir, "pairs", pid, "summary.json")
    prof_path = File.join(coverage_dir, "pairs", pid, "coverage.profdata")
    reused_prev_marker = File.join(work_dir, "pairs", pid, "reused_prev_html")
    has_cov = File.exist?(sum_path) && File.exist?(prof_path)

    if has_cov
      raw = JSON.parse(File.read(sum_path, encoding: "UTF-8")).dig("data", 0) || {}
      totals = extract_summary.call(raw["totals"])
      src_prefix = File.expand_path(p["source_path"].to_s).sub(%r{/\z}, "") + "/"
      files = (raw["files"] || []).filter_map do |f|
        raw_fname = f["filename"].to_s
        fname = raw_fname.delete_prefix(src_prefix).sub(%r{\A\./}, "")
        fsum = extract_summary.call(f["summary"])
        next if fsum.dig("lines", "count").to_i.zero? && fsum.dig("functions", "count").to_i.zero?

        html_sub = raw_fname.sub(%r{\A\./}, "").sub(%r{\A/}, "")
        {
          "filename" => fname,
          "report_rel_path" => "#{cov_rel_prefix}/pairs/#{pid}/report/coverage/#{html_sub}.html",
          "summary" => fsum
        }
      end.sort_by { |f| f["filename"] }

      html_ready = if mode == "complete"
                     File.file?(File.join(coverage_dir, "pairs", pid, "report", "index.html"))
                   else
                     File.file?(reused_prev_marker) && File.file?(File.join(final_cov_abs, "pairs", pid, "report", "index.html"))
                   end

      {
        "id" => pid,
        "label" => p["label"],
        "source" => p["source"],
        "source_commit" => p["commit"],
        "source_ref" => p["requested_ref"],
        "target" => p["target"],
        "target_label" => p["target_label"],
        "cflags" => p["cflags"],
        "input_count" => p["input_count"],
        "queue_count" => p["queue_count"],
        "crash_count" => p["crash_count"],
        "fuzzers" => p["fuzzers"],
        "workers" => p["workers"],
        "generators" => p["generators"],
        "has_coverage" => true,
        "html_ready" => html_ready,
        "report_rel_path" => "#{cov_rel_prefix}/pairs/#{pid}/report/index.html",
        "lcov_rel_path" => "#{cov_rel_prefix}/pairs/#{pid}/lcov.info",
        "summary_rel_path" => "#{cov_rel_prefix}/pairs/#{pid}/summary.txt",
        "file_report_prefix" => "#{cov_rel_prefix}/pairs/#{pid}/report/coverage/",
        "totals" => totals,
        "files" => files
      }.compact
    elsif mode == "running" && (prev_p = prev_pairs_by_id[pid]) && prev_p["has_coverage"]
      prev_html = File.file?(File.join(final_cov_abs, "pairs", pid, "report", "index.html"))
      prev_p.merge("updating" => true, "html_ready" => prev_html)
    else
      {
        "id" => pid,
        "label" => p["label"],
        "source" => p["source"],
        "source_commit" => p["commit"],
        "source_ref" => p["requested_ref"],
        "target" => p["target"],
        "target_label" => p["target_label"],
        "cflags" => p["cflags"],
        "input_count" => p["input_count"],
        "queue_count" => p["queue_count"],
        "crash_count" => p["crash_count"],
        "fuzzers" => p["fuzzers"],
        "workers" => p["workers"],
        "generators" => p["generators"],
        "has_coverage" => false,
        "html_ready" => false,
        "report_rel_path" => nil,
        "lcov_rel_path" => nil,
        "summary_rel_path" => nil,
        "file_report_prefix" => nil,
        "totals" => {},
        "files" => []
      }.compact
    end
  end

  primary_pair = pairs_out.find { |p| p["has_coverage"] } || pairs_out.first
  if mode == "complete" && !pairs_out.any? { |p| p["has_coverage"] }
    abort "Error: no coverage profile data was produced for any (source, target) pair."
  end

  payload = {
    "generated_at" => Time.now.utc.iso8601(3),
    "sequence" => Process.clock_gettime(Process::CLOCK_REALTIME, :millisecond),
    "status" => mode,
    "stage" => (mode == "running" ? stage : nil),
    "primary_pair_id" => primary_pair && primary_pair["id"],
    "totals" => primary_pair ? (primary_pair["totals"] || {}) : {},
    "pairs" => pairs_out,
    "worker_pairs" => worker_pairs
  }.compact

  json_js = JSON.generate(payload).gsub("<", "\\u003c").gsub(">", "\\u003e").gsub("\u2028", "\\u2028").gsub("\u2029", "\\u2029")
  js_body = <<~JS
    if (typeof window !== "undefined" && typeof window.__PRISM_FUZZER_ON_COVERAGE__ === "function") {
      window.__PRISM_FUZZER_ON_COVERAGE__(#{json_js});
    } else if (typeof window !== "undefined") {
      window.__PRISM_FUZZER_PENDING_COVERAGE__ = #{json_js};
    }
  JS

  if mode == "running"
    FileUtils.mkdir_p(final_cov_abs)
    live_js_dst = File.join(final_cov_abs, "coverage.js")
    live_js_tmp = File.join(final_cov_abs, ".coverage.js.tmp.#{Process.pid}")
    File.write(live_js_tmp, js_body)
    File.rename(live_js_tmp, live_js_dst)
  else
    File.write(out_json_path, JSON.pretty_generate(payload))
    File.write(File.join(coverage_dir, "coverage.js"), js_body)
  end
RUBY

# 1. Resolve (source, target) pairs from the topology and collect deduplicated
#    queue, crash, hang, and corpus inputs per pair.
ruby "$COLLECT_RB" "$WORK_DIR" "$PAIRS_META" "$LIVE_SEEDS_DIR"

TOTAL_INPUTS=$(ruby -rjson -e 'puts JSON.parse(File.read(ARGV[0]))["pairs"].sum { |p| p["input_count"].to_i }' "$PAIRS_META")
if [ "$TOTAL_INPUTS" -eq 0 ]; then
  echo "No fuzz inputs found in ${WORKSPACE_AFL_DIR:-$WS_DIR/afl}. Run fuzzing first." >&2
  exit 1
fi

DETECTED_CPUS=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
EXPLICIT_JOBS="${JOBS:-${FUZZ_BUILD_JOBS:-}}"
JOBS="${EXPLICIT_JOBS:-$DETECTED_CPUS}"
if [ -n "$EXPLICIT_JOBS" ]; then
  BUILD_JOBS="$EXPLICIT_JOBS"
elif [ "$DETECTED_CPUS" -gt 16 ]; then
  BUILD_JOBS=16
else
  BUILD_JOBS="$DETECTED_CPUS"
fi
rm -rf "$COVERAGE_DIR"
mkdir -p "$COVERAGE_DIR/pairs"

run_queue_batch() {
  if ! timeout -k 1s 15s "$COVERAGE_BIN" "$@" 2>/dev/null; then
    for f in "$@"; do
      timeout -k 1s 0.2s "$COVERAGE_BIN" "$f" 2>/dev/null || true
    done
  fi
}
export -f run_queue_batch

read_pair_meta() {
  local target_pid="$1"
  P_FLAGS=()
  {
    IFS='' read -r -d '' P_LABEL
    IFS='' read -r -d '' P_PRISM_ROOT
    IFS='' read -r -d '' P_PRISM_GEN
    IFS='' read -r -d '' P_BUILD_KEY
    IFS='' read -r -d '' P_INPUT_COUNT
    IFS='' read -r -d '' P_DELTA_COUNT
    IFS='' read -r -d '' P_CACHED_COUNT
    IFS='' read -r -d '' P_CACHE_HIT
    IFS='' read -r -d '' P_PRIMARY
    while IFS='' read -r -d '' p_flag; do
      P_FLAGS+=("$p_flag")
    done
  } < <(ruby -rjson -e '
    doc = JSON.parse(File.read(ARGV[0]))
    p = doc["pairs"].find { |x| x["id"] == ARGV[1] } or abort "missing pair #{ARGV[1]}"
    [
      p["label"].to_s,
      p["source_path"].to_s,
      p["gen_dir"].to_s,
      p["build_key"].to_s,
      p["input_count"].to_i,
      p["delta_input_count"].to_i,
      p["cached_input_count"].to_i,
      p["cache_hit"] ? 1 : 0,
      p["primary"] ? 1 : 0,
      *Array(p["compile_flags"]).map(&:to_s)
    ].each { |v| $stdout.write("#{v}\0") }
  ' "$PAIRS_META" "$target_pid")
}

# 2. Build (if stale) and run coverage for each (source, target) pair.
PAIR_IDS=$(ruby -rjson -e 'JSON.parse(File.read(ARGV[0]))["pairs"].each { |p| puts p["id"] }' "$PAIRS_META")
ruby "$EMIT_COV_RB" "$WORK_DIR" "$PAIRS_META" "$COVERAGE_DIR" "$COVERAGE_DIR/coverage.json" --mode running --stage "replaying"

for pid in $PAIR_IDS; do
  P_WORK="$WORK_DIR/pairs/$pid"
  P_OUT="$COVERAGE_DIR/pairs/$pid"
  P_REPORT="$P_OUT/report"
  P_PROFRAW="$P_WORK/profraw"
  P_CACHE="$CACHE_ROOT/$pid"
  mkdir -p "$P_OUT" "$P_PROFRAW"

  read_pair_meta "$pid"

  if [ "$P_INPUT_COUNT" -eq 0 ]; then
    echo "Skipping coverage replay for pair '${P_LABEL}' (0 inputs)."
    continue
  fi

  COVERAGE_BIN="$BUILD_ROOT/fuzz.coverage.${pid}"
  STAMP_FILE="$BUILD_ROOT/.fuzz.coverage.${pid}.stamp"
  export COVERAGE_BIN

  BUILD_KEY="$P_BUILD_KEY"
  NEED_BUILD=0
  if [ ! -f "$STAMP_FILE" ] || [ "$(cat "$STAMP_FILE" 2>/dev/null)" != "$BUILD_KEY" ]; then
    NEED_BUILD=1
  elif [ ! -s "$COVERAGE_BIN" ] || [ -n "$(find "$P_PRISM_ROOT/src" "$P_PRISM_ROOT/include" "$P_PRISM_GEN" harnesses/prism -type f -newer "$COVERAGE_BIN" -print -quit 2>/dev/null)" ]; then
    NEED_BUILD=1
  elif ! smoke_check_coverage_bin "$COVERAGE_BIN"; then
    echo "Existing $COVERAGE_BIN failed smoke check; rebuilding..."
    NEED_BUILD=1
  fi

  if [ "$NEED_BUILD" -eq 1 ]; then
    if [ "$P_CACHE_HIT" -eq 1 ]; then
      rm -rf "$P_CACHE"
      ruby "$COLLECT_RB" "$WORK_DIR" "$PAIRS_META" "$LIVE_SEEDS_DIR" --recollect-pair "$pid"
      read_pair_meta "$pid"
    fi
    rm -f "$COVERAGE_TMP_BIN"
    ruby -rfileutils -ropen3 -rrbconfig - "$REPO_ROOT" "$P_WORK" "$P_LABEL" "$P_PRISM_ROOT" "$P_PRISM_GEN" "$COVERAGE_TMP_BIN" "$BUILD_JOBS" "${P_FLAGS[@]}" << 'RUBY'
      repo_root, p_work, label, raw_prism_root, raw_prism_gen, raw_cov_tmp_bin, raw_jobs, *p_flags = ARGV
      repo_root = File.expand_path(repo_root)
      p_work = File.expand_path(p_work)
      prism_root = File.expand_path(raw_prism_root, repo_root)
      prism_gen = raw_prism_gen.to_s.empty? ? nil : File.expand_path(raw_prism_gen, repo_root)
      cov_tmp_bin = File.expand_path(raw_cov_tmp_bin, repo_root)
      build_jobs = [raw_jobs.to_i, 1].max

      src_files = Dir.glob(File.join(prism_root, "src", "**", "*.c")).sort + [
        File.join(repo_root, "harnesses/prism/coverage.c"),
        File.join(repo_root, "harnesses/prism/parse.c")
      ]

      inc_flags = ["-I#{File.join(prism_root, 'include')}"]
      inc_flags << "-I#{prism_gen}" if prism_gen && Dir.exist?(prism_gen)
      inc_flags.push("-I#{File.join(repo_root, 'harnesses/prism')}", "-I#{File.join(repo_root, 'harnesses/prism/include')}")

      find_exe = lambda do |name|
        ENV.fetch("PATH", "").split(File::PATH_SEPARATOR).each do |dir|
          next if dir.empty?

          cand = File.join(dir, name)
          return cand if File.file?(cand) && File.executable?(cand)
        end
        nil
      end

      ccache_bin = ENV["FUZZ_CCACHE"].to_s.strip == "0" ? nil : find_exe.call("ccache")
      ccache_dir = nil
      if ccache_bin
        cands = []
        env_cdir = ENV["CCACHE_DIR"].to_s.strip
        cands << env_cdir unless env_cdir.empty?
        cands << "/ccache"
        cands << File.join(repo_root, ".cache", "ccache")
        cands << File.join(ENV.fetch("TMPDIR", "/tmp"), "prism-fuzzer-ccache-#{Process.uid}")
        ccache_dir = cands.find do |d|
          begin
            FileUtils.mkdir_p(d) unless Dir.exist?(d)
            Dir.exist?(d) && File.writable?(d)
          rescue SystemCallError
            false
          end
        end
        ccache_bin = nil unless ccache_dir
      end

      img_id = ENV["FUZZ_IMAGE_ID"].to_s.strip
      ccache_base_env = if ccache_bin
                          ns = ["cc=clang", "cov=1"]
                          ns << "img=#{img_id[0, 19]}" unless img_id.empty?
                          {
                            "CCACHE_DIR" => ccache_dir,
                            "CCACHE_NOHASHDIR" => "1",
                            "CCACHE_SLOPPINESS" => "include_file_mtime,include_file_ctime,time_macros",
                            "CCACHE_NAMESPACE" => ns.join("|")
                          }
                        else
                          {}
                        end
      cc_prefix = ccache_bin ? [ccache_bin, "clang"] : ["clang"]

      ld_flags = []
      if find_exe.call("ld.lld")
        _o, st = Open3.capture2e("clang", "-fuse-ld=lld", "-x", "c", "-", "-o", File::NULL, stdin_data: "int main(void){return 0;}\n")
        ld_flags << "-fuse-ld=lld" if st.success?
      end
      gc_flags = RbConfig::CONFIG["host_os"].to_s.include?("darwin") ? ["-Wl,-dead_strip"] : ["-Wl,--gc-sections"]

      compile_parallel = lambda do |obj_dir, extra_cflags, extra_env: {}, chdir: p_work|
        FileUtils.rm_rf(obj_dir)
        FileUtils.mkdir_p(obj_dir)
        objs = Array.new(src_files.size)
        q = Thread::Queue.new
        src_files.each_with_index { |src, idx| q.push([src, idx]) }
        err_mu = Mutex.new
        first_err = nil
        env = ccache_base_env.merge(extra_env)
        n_threads = [src_files.size, build_jobs].min

        Array.new(n_threads) do
          Thread.new do
            loop do
              break if err_mu.synchronize { !first_err.nil? }

              item = begin
                q.pop(true)
              rescue ThreadError
                break
              end
              src, idx = item
              obj = File.join(obj_dir, "#{idx}_#{File.basename(src, '.c')}.o")
              cmd = [*cc_prefix, *inc_flags, *extra_cflags, "-c", src, "-o", obj]
              out, st = Open3.capture2e(env, *cmd, chdir: chdir)
              if st.success?
                objs[idx] = obj
              else
                err_mu.synchronize { first_err ||= "Command failed (#{cmd.join(' ')}):\n#{out}" }
                break
              end
            end
          end
        end.each(&:join)

        abort(first_err) if first_err
        objs
      end

      run_link = lambda do |*cmd|
        out, st = Open3.capture2e(*cmd, chdir: p_work)
        abort("Link failed (#{cmd.join(' ')}):\n#{out}") unless st.success?
      end

      reach_obj_dir = File.join(p_work, "obj_reach")
      cov_obj_dir = File.join(p_work, "obj_cov")
      reach_bin = File.join(p_work, "fuzz.reach")
      keeplist = File.join(p_work, "keeplist")

      begin
        puts "Building reachability binary for #{label} (#{build_jobs} jobs#{ccache_bin ? ', ccache' : ''})..."
        reach_objs = compile_parallel.call(
          reach_obj_dir,
          ["-O0", "-DSLOW", "-flto", "-ffunction-sections", "-fdata-sections", *p_flags]
        )
        run_link.call("clang", "-O0", "-flto", *ld_flags, *gc_flags, *reach_objs, "-o", reach_bin)

        nm_out, nm_st = Open3.capture2("llvm-nm", "--defined-only", reach_bin)
        abort("llvm-nm failed on #{reach_bin}") unless nm_st.success?

        skip_re = /\A_?(?:main|run_file|run_stdin|setup_signal_handlers|handle_crash_signal|handle_stop_signal|harness|harness_parse|check_node_location|fuzz_.*|pm_fuzz_.*|pm_node_type|pm_diagnostic_type|pm_diagnostic_id_name)\z/
        syms = []
        nm_out.each_line do |line|
          cols = line.strip.split(/\s+/)
          next unless cols.size >= 3 && %w[T t].include?(cols[1])

          sym = cols[2]
          next if sym.match?(skip_re)

          syms << "fun:#{sym}"
        end
        File.write(keeplist, syms.uniq.sort.map { |s| "#{s}\n" }.join)
        fixed_t = Time.at(946_684_800)
        File.utime(fixed_t, fixed_t, keeplist)
      ensure
        FileUtils.rm_rf(reach_obj_dir)
        FileUtils.rm_f(reach_bin)
      end

      begin
        puts "Building coverage binary for #{label} (#{cov_tmp_bin})..."
        prof_instr_args = ccache_bin ? ["--ccache-skip", "-fprofile-instr-generate"] : ["-fprofile-instr-generate"]
        prof_list_args = ccache_bin ? ["--ccache-skip", "-fprofile-list=keeplist"] : ["-fprofile-list=keeplist"]
        cov_objs = compile_parallel.call(
          cov_obj_dir,
          [
            "-O1", "-DSLOW", "-DPROFILE", *p_flags,
            "-fcoverage-prefix-map=#{prism_root}=.",
            *prof_instr_args, "-fcoverage-mapping",
            *prof_list_args
          ],
          extra_env: ccache_bin ? { "CCACHE_EXTRAFILES" => "keeplist" } : {}
        )
        run_link.call("clang", "-O1", "-fprofile-instr-generate", "-fcoverage-mapping", *ld_flags, *cov_objs, "-o", cov_tmp_bin)
      ensure
        FileUtils.rm_rf(cov_obj_dir)
        FileUtils.rm_f(keeplist)
      end
RUBY

    if ! smoke_check_coverage_bin "$COVERAGE_TMP_BIN"; then
      echo "Error: newly built coverage binary for ${P_LABEL} failed smoke check." >&2
      exit 1
    fi
    mv -f "$COVERAGE_TMP_BIN" "$COVERAGE_BIN"
    printf '%s' "$BUILD_KEY" > "$STAMP_FILE"
  else
    echo "Using existing coverage binary for ${P_LABEL} ($COVERAGE_BIN)..."
  fi

  P_PROFDATA="$P_OUT/coverage.profdata"
  P_LCOV="$P_OUT/lcov.info"
  P_SUMMARY_TXT="$P_OUT/summary.txt"
  P_SUMMARY_JSON="$P_WORK/summary.json"
  IGNORE_REGEX='(^|/)(harnesses|triage|runtime|test/fuzz|targets/gen)/'

  # Fast zero-delta reuse: when a pair's cache hit and 0 new inputs arrived in the
  # current time window, reuse the existing rendered pair report directly.
  PREV_PAIR_DIR="$FINAL_COVERAGE_DIR/pairs/$pid"
  if [ "$P_CACHE_HIT" -eq 1 ] && [ "$P_DELTA_COUNT" -eq 0 ] &&
     [ -s "$PREV_PAIR_DIR/coverage.profdata" ] &&
     [ -f "$PREV_PAIR_DIR/lcov.info" ] &&
     [ -s "$PREV_PAIR_DIR/summary.txt" ] &&
     [ -f "$PREV_PAIR_DIR/report/index.html" ] &&
     [ -s "$P_CACHE/summary.json" ]; then
    echo "Reusing cached coverage for ${P_LABEL} (0 new inputs, ${P_CACHED_COUNT} cached)..."
    rm -rf "$P_OUT" "$P_PROFRAW"
    cp -R "$PREV_PAIR_DIR" "$P_OUT"
    cp "$P_CACHE/summary.json" "$P_SUMMARY_JSON"
    : > "$P_WORK/reused_prev_html"
    echo ""
    echo "=== Coverage Summary: ${P_LABEL} (cached) ==="
    cat "$P_SUMMARY_TXT"
    if [ "$P_PRIMARY" -eq 1 ]; then
      cp "$P_PROFDATA" "$COVERAGE_DIR/coverage.profdata"
      cp "$P_LCOV" "$COVERAGE_DIR/lcov.info"
      cp "$P_SUMMARY_TXT" "$COVERAGE_DIR/summary.txt"
    fi
    ruby "$EMIT_COV_RB" "$WORK_DIR" "$PAIRS_META" "$COVERAGE_DIR" "$COVERAGE_DIR/coverage.json" --mode running --stage "replaying"
    ruby "$COMMIT_CACHE_RB" "$CACHE_ROOT" "$pid" "$COVERAGE_BIN" "$P_WORK" "$P_PROFDATA" "$P_SUMMARY_JSON"
    continue
  fi

  export LLVM_PROFILE_FILE="$P_PROFRAW/coverage-%${JOBS}m.profraw"
  Q_LIST="$P_WORK/queue.list"
  C_LIST="$P_WORK/crash.list"

  replay_pair_lists() {
    if [ -s "$Q_LIST" ]; then
      xargs -0 -P "$JOBS" -n 256 bash -c 'run_queue_batch "$@"' _ < "$Q_LIST"
    fi
    if [ -s "$C_LIST" ]; then
      xargs -0 -P "$JOBS" -n 1 bash -c 'timeout -k 1s 0.2s "$COVERAGE_BIN" "$1" 2>/dev/null || true' _ < "$C_LIST"
    fi
  }

  if [ "$P_CACHE_HIT" -eq 1 ]; then
    if [ "$P_DELTA_COUNT" -gt 0 ]; then
      echo "Replaying ${P_DELTA_COUNT} new inputs for ${P_LABEL} (+${P_CACHED_COUNT} cached, ${JOBS} workers)..."
      replay_pair_lists
    else
      echo "Rendering coverage from cached profile for ${P_LABEL} (${P_CACHED_COUNT} cached inputs)..."
    fi
  else
    echo "Replaying ${P_DELTA_COUNT} inputs for ${P_LABEL} (${JOBS} workers)..."
    replay_pair_lists
  fi

  P_PROFRAW_LIST="$P_WORK/profraw.list"
  : > "$P_PROFRAW_LIST"
  if [ "$P_CACHE_HIT" -eq 1 ] && [ -s "$P_CACHE/cached.profdata" ]; then
    printf '%s\n' "$P_CACHE/cached.profdata" >> "$P_PROFRAW_LIST"
  fi
  find "$P_PROFRAW" -name "coverage-*.profraw" -print >> "$P_PROFRAW_LIST"

  if [ ! -s "$P_PROFRAW_LIST" ]; then
    echo "Warning: no profile data produced for ${P_LABEL}." >&2
    continue
  fi

  if ! llvm-profdata merge -sparse -f "$P_PROFRAW_LIST" -o "$P_PROFDATA"; then
    if [ "$P_CACHE_HIT" -eq 1 ]; then
      echo "Warning: cached profile merge failed for ${P_LABEL}; replaying full pair corpus..." >&2
      rm -rf "$P_CACHE" "$P_PROFRAW"
      mkdir -p "$P_PROFRAW"
      ruby "$COLLECT_RB" "$WORK_DIR" "$PAIRS_META" "$LIVE_SEEDS_DIR" --recollect-pair "$pid"
      read_pair_meta "$pid"
      replay_pair_lists
      find "$P_PROFRAW" -name "coverage-*.profraw" -print > "$P_PROFRAW_LIST"
      if [ ! -s "$P_PROFRAW_LIST" ]; then
        echo "Warning: no profile data produced for ${P_LABEL}." >&2
        continue
      fi
      llvm-profdata merge -sparse -f "$P_PROFRAW_LIST" -o "$P_PROFDATA"
    else
      exit 1
    fi
  fi
  rm -rf "$P_PROFRAW"

  llvm-cov export "$COVERAGE_BIN" \
    -instr-profile="$P_PROFDATA" \
    --compilation-dir="$P_PRISM_ROOT" \
    --summary-only \
    --ignore-filename-regex="$IGNORE_REGEX" \
    > "$P_SUMMARY_JSON"

  llvm-cov export "$COVERAGE_BIN" \
    -instr-profile="$P_PROFDATA" \
    --compilation-dir="$P_PRISM_ROOT" \
    --format=lcov \
    --ignore-filename-regex="$IGNORE_REGEX" \
    > "$P_LCOV"

  echo ""
  echo "=== Coverage Summary: ${P_LABEL} ==="
  llvm-cov report "$COVERAGE_BIN" \
    -instr-profile="$P_PROFDATA" \
    --compilation-dir="$P_PRISM_ROOT" \
    --ignore-filename-regex="$IGNORE_REGEX" \
    | tee "$P_SUMMARY_TXT"

  # Publish summary metrics immediately into coverage/coverage.js before slow HTML source rendering runs.
  ruby "$EMIT_COV_RB" "$WORK_DIR" "$PAIRS_META" "$COVERAGE_DIR" "$COVERAGE_DIR/coverage.json" --mode running --stage "rendering_html"

  llvm-cov show "$COVERAGE_BIN" \
    -instr-profile="$P_PROFDATA" \
    --compilation-dir="$P_PRISM_ROOT" \
    --format=html \
    --show-branches=count \
    --show-line-counts-or-regions \
    --ignore-filename-regex="$IGNORE_REGEX" \
    -o "$P_REPORT"

  if [ "$P_PRIMARY" -eq 1 ]; then
    cp "$P_PROFDATA" "$COVERAGE_DIR/coverage.profdata"
    cp "$P_LCOV" "$COVERAGE_DIR/lcov.info"
    cp "$P_SUMMARY_TXT" "$COVERAGE_DIR/summary.txt"
  fi

  ruby "$COMMIT_CACHE_RB" "$CACHE_ROOT" "$pid" "$COVERAGE_BIN" "$P_WORK" "$P_PROFDATA" "$P_SUMMARY_JSON"
done

# 3. Assemble report/coverage/coverage.json and coverage.js across all (source, target) pairs.
JSON_FILE="$COVERAGE_DIR/coverage.json"
ruby "$EMIT_COV_RB" "$WORK_DIR" "$PAIRS_META" "$COVERAGE_DIR" "$JSON_FILE" --mode complete

rm -rf "$OLD_COVERAGE_DIR"
if [ -d "$FINAL_COVERAGE_DIR" ]; then
  mv "$FINAL_COVERAGE_DIR" "$OLD_COVERAGE_DIR"
fi
mv "$COVERAGE_DIR" "$FINAL_COVERAGE_DIR"
rm -rf "$OLD_COVERAGE_DIR"

if [ "$COVERAGE_FINAL" = "1" ] || [ "$COVERAGE_NO_CACHE" = "1" ]; then
  if [ -d "$CACHE_ROOT" ]; then
    rm -rf "$CACHE_ROOT"
    if [ "$COVERAGE_FINAL" = "1" ]; then
      echo "Cleaned up incremental coverage cache ($CACHE_ROOT)."
    fi
  fi
fi

echo ""
echo "Coverage artifacts written to $FINAL_COVERAGE_DIR:"
echo "  - JSON breakdown:         $FINAL_COVERAGE_DIR/coverage.json"
echo "  - Pair reports:           $FINAL_COVERAGE_DIR/pairs/<source>__<target>/report/index.html"
echo "  - Primary LCOV / Summary: $FINAL_COVERAGE_DIR/lcov.info, $FINAL_COVERAGE_DIR/summary.txt"
