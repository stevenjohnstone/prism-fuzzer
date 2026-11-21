#!/usr/bin/env bash
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
mkdir -p "$BUILD_ROOT" "$WS_DIR" "$REPORT_DIR"

WORK_DIR=$(mktemp -d)
PAIRS_META="$WORK_DIR/pairs_meta.json"
LIVE_SEEDS_DIR="$WORK_DIR/live_seeds"
COVERAGE_TMP_BIN="$BUILD_ROOT/.fuzz.coverage.tmp.$$"
COVERAGE_DIR="$WS_DIR/.coverage.tmp.$$"
OLD_COVERAGE_DIR="$WS_DIR/.coverage.old.$$"
export REPO_ROOT WS_DIR BUILD_ROOT

cleanup_coverage() {
  local rc=$?
  if [ ! -e "$FINAL_COVERAGE_DIR" ] && [ -d "$OLD_COVERAGE_DIR" ]; then
    mv "$OLD_COVERAGE_DIR" "$FINAL_COVERAGE_DIR" 2>/dev/null || true
  fi
  rm -rf "$WORK_DIR" "$COVERAGE_TMP_BIN" "$COVERAGE_DIR" "$OLD_COVERAGE_DIR"
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

# 1. Resolve (source, target) pairs from the topology and collect deduplicated
#    queue, crash, hang, corpus, and grammar inputs per pair.
ruby -rdigest -rjson -rfileutils -rshellwords - "$WORK_DIR" "$PAIRS_META" "$LIVE_SEEDS_DIR" << 'RUBY'
  work_dir, pairs_meta_path, live_seeds_dir = ARGV
  repo_root = ENV.fetch("REPO_ROOT", Dir.pwd)
  ws_dir = ENV.fetch("WS_DIR", "tmp/fuzz")
  build_root = ENV.fetch("BUILD_ROOT", File.join(ws_dir, "build"))
  ws_afl = ENV.fetch("WORKSPACE_AFL_DIR", File.join(ws_dir, "afl"))
  ws_corpus = ENV.fetch("WORKSPACE_CORPUS_DIR", File.join(ws_dir, "corpus"))

  require_relative "runtime/topology" if File.file?("runtime/topology.rb")
  topo = defined?(PrismFuzzer::Topology) ? PrismFuzzer::Topology.discover(start_dir: repo_root, afl_dir: ws_afl) : nil

  user_flags = Shellwords.split(ENV.fetch("FUZZ_FLAGS", ""))
  default_defines = if topo && defined?(PrismFuzzer::Topology)
                      PrismFuzzer::Topology.default_coverage_define_flags(topo)
                    else
                      %w[-DPM_INTEGER_DIVIDE_THRESHOLD=8 -DPRISM_DEPTH_MAXIMUM=128 -DFUZZ_MAX_INPUT_SIZE=1024 -DFUZZ_MAX_ALLOCATED=128 -DFUZZ_HARD_RSS_LIMIT=2048]
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

  # Override first prism_a dir from PRISM_A_DIR / PRISM_DIR if explicitly provided without resolved path
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
    if defined?(PrismFuzzer::Topology) && !File.file?(File.join(p["gen_dir"].to_s, "node_locations.inc"))
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
  ORACLE32_MAGIC = 0x504D3634
  unwrap_pm64_if_present = lambda do |data|
    return data if data.bytesize < 17

    magic, olen = data.byteslice(0, 8).unpack("V2")
    return data unless magic == ORACLE32_MAGIC
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

  rd_flags = File::RDONLY | (defined?(File::NOATIME) ? File::NOATIME : 0)
  generators_cfg = topo && topo["generators"].is_a?(Hash) ? topo["generators"] : {}
  grammar_gids = generators_cfg.select { |_, gc| gc.is_a?(Hash) && gc["kind"].to_s == "grammar" }.keys.map(&:to_s)
  multi_grammar = grammar_gids.size > 1
  dir_has_files = lambda do |cd|
    cd && Dir.exist?(cd) && Dir.children(cd).any? { |f| !f.start_with?(".") && File.file?(File.join(cd, f)) }
  end
  any_gid_live_subdirs = live_seeds_dir && grammar_gids.any? { |k| dir_has_files.call(File.join(live_seeds_dir, k)) }
  any_gid_configured_seeds = grammar_gids.any? do |k|
    g_cfg = generators_cfg[k]
    dir_has_files.call(g_cfg["seeds_dir"]) || dir_has_files.call("/tmp/afl-tmpdir/#{k}/seeds")
  end

  pairs_out = pairs.each_with_index.map do |pair, idx|
    pid = pair["id"].to_s
    pwork = File.join(work_dir, "pairs", pid)
    FileUtils.mkdir_p(pwork)
    staged_dir = File.join(pwork, "staged")
    FileUtils.mkdir_p(staged_dir)

    pair_workers = Array(pair["workers"]).map(&:to_s)
    # Fallback when topology had no workers configured: walk all discovered worker directories for the first pair.
    if pair_workers.empty? && topo.nil? && idx == 0
      pair_workers = worker_dirs.keys.sort
    end

    cross_set = Array(pair["cross_oracle_workers"]).each_with_object({}) { |w, h| h[w.to_s] = true }
    seen = {}
    queue_files = []
    crash_files = []
    staged_seq = 0

    add_raw_file = lambda do |full, target_list, unwrap_cross: false, copy_always: false|
      return unless File.file?(full)

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

    # 2. Generators targeting this pair source (corpus + grammar seeds)
    Array(pair["generators"]).each do |gid|
      g = generators_cfg[gid]
      next unless g.is_a?(Hash)

      if g["kind"].to_s == "corpus"
        c_dir = g["dir"] ? File.expand_path(g["dir"], repo_root) : File.expand_path(ws_corpus, repo_root)
        if Dir.exist?(c_dir)
          Dir.children(c_dir).sort.each do |fname|
            next if fname.start_with?(".") || fname.start_with?("README")
            add_raw_file.call(File.join(c_dir, fname), queue_files)
          end
        end
      elsif g["kind"].to_s == "grammar"
        gid_live_dir = live_seeds_dir ? File.join(live_seeds_dir, gid.to_s) : nil
        live_root_files = dir_has_files.call(live_seeds_dir)
        allow_shared_fallback = !multi_grammar
        allow_flat_live_fallback = !multi_grammar || (!any_gid_live_subdirs && !any_gid_configured_seeds && idx == 0)
        candidates = [
          gid_live_dir,
          g["seeds_dir"],
          "/tmp/afl-tmpdir/#{gid}/seeds",
          (allow_flat_live_fallback && live_root_files ? live_seeds_dir : nil),
          (allow_shared_fallback ? "/tmp/afl-tmpdir/grammar/seeds" : nil),
          (allow_shared_fallback ? File.join(ws_dir, "seeds") : nil)
        ].compact.uniq
        seed_src = candidates.find { |cd| dir_has_files.call(cd) }
        if seed_src
          Dir.children(seed_src).reject { |f| f.start_with?(".") }.select { |f| File.file?(File.join(seed_src, f)) }.sort.first(5000).each do |fname|
            add_raw_file.call(File.join(seed_src, fname), queue_files, copy_always: true)
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

    File.open(File.join(pwork, "queue.list"), "wb") { |f| queue_files.each { |p| f.write(p); f.write("\0") } }
    File.open(File.join(pwork, "crash.list"), "wb") { |f| crash_files.each { |p| f.write(p); f.write("\0") } }

    pair_flags = Array(pair["cflags"]).map(&:to_s)
    explicit_macros = defined_macro_names.call(pair_flags + user_flags)
    effective_defaults = default_defines.reject do |tok|
      macro = tok.sub(/\A-D/, "").split("=", 2).first
      explicit_macros[macro]
    end
    compile_flags = effective_defaults + pair_flags + user_flags

    pair.merge(
      "primary" => (idx == 0),
      "compile_flags" => compile_flags,
      "queue_count" => queue_files.size,
      "crash_count" => crash_files.size,
      "input_count" => queue_files.size + crash_files.size
    )
  end

  File.write(pairs_meta_path, JSON.pretty_generate({
    "pairs" => pairs_out,
    "worker_pairs" => worker_pairs
  }))
  puts "Prepared #{pairs_out.size} coverage pair(s): " + pairs_out.map { |p| "#{p["label"]}=#{p["input_count"]} inputs" }.join(", ")
RUBY

TOTAL_INPUTS=$(ruby -rjson -e 'puts JSON.parse(File.read(ARGV[0]))["pairs"].sum { |p| p["input_count"].to_i }' "$PAIRS_META")
if [ "$TOTAL_INPUTS" -eq 0 ]; then
  echo "No fuzz inputs found in ${WORKSPACE_AFL_DIR:-$WS_DIR/afl}. Run fuzzing first." >&2
  exit 1
fi

JOBS=$(nproc 2>/dev/null || echo 4)
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

# 2. Build (if stale) and run coverage for each (source, target) pair.
PAIR_IDS=$(ruby -rjson -e 'JSON.parse(File.read(ARGV[0]))["pairs"].each { |p| puts p["id"] }' "$PAIRS_META")

for pid in $PAIR_IDS; do
  P_WORK="$WORK_DIR/pairs/$pid"
  P_OUT="$COVERAGE_DIR/pairs/$pid"
  P_REPORT="$P_OUT/report"
  P_PROFRAW="$P_WORK/profraw"
  mkdir -p "$P_OUT" "$P_PROFRAW"

  P_FLAGS=()
  {
    IFS='' read -r -d '' P_LABEL
    IFS='' read -r -d '' P_PRISM_ROOT
    IFS='' read -r -d '' P_PRISM_GEN
    IFS='' read -r -d '' P_INPUT_COUNT
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
      p["input_count"].to_i,
      p["primary"] ? 1 : 0,
      *Array(p["compile_flags"]).map(&:to_s)
    ].each { |v| $stdout.write("#{v}\0") }
  ' "$PAIRS_META" "$pid")

  if [ "$P_INPUT_COUNT" -eq 0 ]; then
    echo "Skipping coverage replay for pair '${P_LABEL}' (0 inputs)."
    continue
  fi

  COVERAGE_BIN="$BUILD_ROOT/fuzz.coverage.${pid}"
  STAMP_FILE="$BUILD_ROOT/.fuzz.coverage.${pid}.stamp"
  export COVERAGE_BIN

  BUILD_KEY=$(ruby -rdigest -rjson -e '
    puts Digest::SHA256.hexdigest(JSON.generate([ARGV[0], ARGV[1], ARGV[2], ARGV[3], ENV["LLVM_VERSION"].to_s]))
  ' "$P_PRISM_ROOT" "$P_PRISM_GEN" "${P_FLAGS[*]}" "$(clang --version | awk 'NR==1{print}')")

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
    src_files=()
    while IFS= read -r -d '' file; do
      src_files+=("$file")
    done < <(find "$P_PRISM_ROOT/src" -name '*.c' -print0)

    gen_inc=()
    [ -d "$P_PRISM_GEN" ] && gen_inc=("-I$P_PRISM_GEN")

    reach_bin="$P_WORK/fuzz.reach"
    keeplist="$P_WORK/keeplist"

    echo "Building reachability binary for ${P_LABEL}..."
    clang -O0 "-I$P_PRISM_ROOT/include" "${gen_inc[@]}" -Iharnesses/prism -Iharnesses/prism/include -DSLOW -flto -ffunction-sections -fdata-sections "${P_FLAGS[@]}" -Wl,--gc-sections \
      "${src_files[@]}" harnesses/prism/coverage.c harnesses/prism/parse.c -o "$reach_bin"

    llvm-nm --defined-only "$reach_bin" | grep " [Tt] " | grep -Ev '[Tt] (main|run_file|run_stdin|setup_signal_handlers|handle_crash_signal|handle_stop_signal|harness|harness_parse|check_node_location|fuzz_.*|pm_node_type|pm_diagnostic_type|pm_diagnostic_id_name)$' | awk '{print $3}' | sed 's/^/fun:/' > "$keeplist"
    rm -f "$reach_bin"

    echo "Building coverage binary for ${P_LABEL} (${COVERAGE_BIN})..."
    rm -f "$COVERAGE_TMP_BIN"
    clang -O1 "-I$P_PRISM_ROOT/include" "${gen_inc[@]}" -Iharnesses/prism -Iharnesses/prism/include -DSLOW -DPROFILE "${P_FLAGS[@]}" \
      -fcoverage-prefix-map="${P_PRISM_ROOT}=." \
      -fprofile-instr-generate -fcoverage-mapping \
      -fprofile-list="$keeplist" \
      "${src_files[@]}" harnesses/prism/coverage.c harnesses/prism/parse.c -o "$COVERAGE_TMP_BIN"

    rm -f "$keeplist"
    if ! smoke_check_coverage_bin "$COVERAGE_TMP_BIN"; then
      echo "Error: newly built coverage binary for ${P_LABEL} failed smoke check." >&2
      exit 1
    fi
    mv -f "$COVERAGE_TMP_BIN" "$COVERAGE_BIN"
    printf '%s' "$BUILD_KEY" > "$STAMP_FILE"
  else
    echo "Using existing coverage binary for ${P_LABEL} ($COVERAGE_BIN)..."
  fi

  export LLVM_PROFILE_FILE="$P_PROFRAW/coverage-%${JOBS}m.profraw"
  Q_LIST="$P_WORK/queue.list"
  C_LIST="$P_WORK/crash.list"

  echo "Replaying ${P_INPUT_COUNT} inputs for ${P_LABEL} (${JOBS} workers)..."
  if [ -s "$Q_LIST" ]; then
    xargs -0 -P "$JOBS" -n 256 bash -c 'run_queue_batch "$@"' _ < "$Q_LIST"
  fi
  if [ -s "$C_LIST" ]; then
    xargs -0 -P "$JOBS" -n 1 bash -c 'timeout -k 1s 0.2s "$COVERAGE_BIN" "$1" 2>/dev/null || true' _ < "$C_LIST"
  fi

  P_PROFRAW_LIST="$P_WORK/profraw.list"
  find "$P_PROFRAW" -name "coverage-*.profraw" -print > "$P_PROFRAW_LIST"
  if [ ! -s "$P_PROFRAW_LIST" ]; then
    echo "Warning: no profile data produced for ${P_LABEL}." >&2
    continue
  fi

  P_PROFDATA="$P_OUT/coverage.profdata"
  P_LCOV="$P_OUT/lcov.info"
  P_SUMMARY_TXT="$P_OUT/summary.txt"
  P_SUMMARY_JSON="$P_WORK/summary.json"
  IGNORE_REGEX='(^|/)(harnesses|triage|runtime|test/fuzz|targets/gen)/'

  llvm-profdata merge -sparse -f "$P_PROFRAW_LIST" -o "$P_PROFDATA"
  rm -rf "$P_PROFRAW"

  llvm-cov export "$COVERAGE_BIN" \
    -instr-profile="$P_PROFDATA" \
    --compilation-dir="$P_PRISM_ROOT" \
    --format=lcov \
    --ignore-filename-regex="$IGNORE_REGEX" \
    > "$P_LCOV"

  llvm-cov export "$COVERAGE_BIN" \
    -instr-profile="$P_PROFDATA" \
    --compilation-dir="$P_PRISM_ROOT" \
    --summary-only \
    --ignore-filename-regex="$IGNORE_REGEX" \
    > "$P_SUMMARY_JSON"

  llvm-cov show "$COVERAGE_BIN" \
    -instr-profile="$P_PROFDATA" \
    --compilation-dir="$P_PRISM_ROOT" \
    --format=html \
    --show-branches=count \
    --show-line-counts-or-regions \
    --ignore-filename-regex="$IGNORE_REGEX" \
    -o "$P_REPORT"

  echo ""
  echo "=== Coverage Summary: ${P_LABEL} ==="
  llvm-cov report "$COVERAGE_BIN" \
    -instr-profile="$P_PROFDATA" \
    --compilation-dir="$P_PRISM_ROOT" \
    --ignore-filename-regex="$IGNORE_REGEX" \
    | tee "$P_SUMMARY_TXT"

  if [ "$P_PRIMARY" -eq 1 ]; then
    cp "$P_PROFDATA" "$COVERAGE_DIR/coverage.profdata"
    cp "$P_LCOV" "$COVERAGE_DIR/lcov.info"
    cp "$P_SUMMARY_TXT" "$COVERAGE_DIR/summary.txt"
  fi
done

# 3. Assemble report/coverage/coverage.json across all (source, target) pairs.
JSON_FILE="$COVERAGE_DIR/coverage.json"
export FINAL_COVERAGE_DIR REPORT_DIR
ruby -rjson -rpathname -rtime - "$WORK_DIR" "$PAIRS_META" "$COVERAGE_DIR" "$JSON_FILE" << 'RUBY'
  work_dir, pairs_meta_path, coverage_dir, out_json_path = ARGV
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
  meta_doc = JSON.parse(File.read(pairs_meta_path))
  pairs_meta = meta_doc.fetch("pairs")
  worker_pairs = meta_doc.fetch("worker_pairs", {})

  METRICS = %w[lines functions instantiations regions branches].freeze

  def extract_summary(summary_hash)
    return {} unless summary_hash

    out = {}
    METRICS.each do |m|
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
    has_cov = File.exist?(sum_path) && File.exist?(prof_path)

    if has_cov
      raw = JSON.parse(File.read(sum_path)).dig("data", 0) || {}
      totals = extract_summary(raw["totals"])
      src_prefix = File.expand_path(p["source_path"].to_s).sub(%r{/\z}, "") + "/"
      files = (raw["files"] || []).filter_map do |f|
        raw_fname = f["filename"].to_s
        fname = raw_fname.delete_prefix(src_prefix).sub(%r{\A\./}, "")
        fsum = extract_summary(f["summary"])
        next if fsum.dig("lines", "count").to_i.zero? && fsum.dig("functions", "count").to_i.zero?

        html_sub = raw_fname.sub(%r{\A\./}, "").sub(%r{\A/}, "")
        {
          "filename" => fname,
          "report_rel_path" => "#{cov_rel_prefix}/pairs/#{pid}/report/coverage/#{html_sub}.html",
          "summary" => fsum
        }
      end.sort_by { |f| f["filename"] }

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
        "report_rel_path" => "#{cov_rel_prefix}/pairs/#{pid}/report/index.html",
        "lcov_rel_path" => "#{cov_rel_prefix}/pairs/#{pid}/lcov.info",
        "summary_rel_path" => "#{cov_rel_prefix}/pairs/#{pid}/summary.txt",
        "file_report_prefix" => "#{cov_rel_prefix}/pairs/#{pid}/report/coverage/",
        "totals" => totals,
        "files" => files
      }.compact
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
  unless pairs_out.any? { |p| p["has_coverage"] }
    abort "Error: no coverage profile data was produced for any (source, target) pair."
  end

  payload = {
    "generated_at" => Time.now.iso8601,
    "primary_pair_id" => primary_pair && primary_pair["id"],
    "totals" => primary_pair ? primary_pair["totals"] : {},
    "pairs" => pairs_out,
    "worker_pairs" => worker_pairs
  }.compact

  File.write(out_json_path, JSON.pretty_generate(payload))
RUBY

rm -rf "$OLD_COVERAGE_DIR"
if [ -d "$FINAL_COVERAGE_DIR" ]; then
  mv "$FINAL_COVERAGE_DIR" "$OLD_COVERAGE_DIR"
fi
mv "$COVERAGE_DIR" "$FINAL_COVERAGE_DIR"
rm -rf "$OLD_COVERAGE_DIR"

echo ""
echo "Coverage artifacts written to $FINAL_COVERAGE_DIR:"
echo "  - JSON breakdown:         $FINAL_COVERAGE_DIR/coverage.json"
echo "  - Pair reports:           $FINAL_COVERAGE_DIR/pairs/<source>__<target>/report/index.html"
echo "  - Primary LCOV / Summary: $FINAL_COVERAGE_DIR/lcov.info, $FINAL_COVERAGE_DIR/summary.txt"
