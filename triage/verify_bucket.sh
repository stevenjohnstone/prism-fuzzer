#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=""
FUZZ_ROOT=""
BUCKET_DIR=""
PROFILE=""
RUNNER=""
BUILD_ONLY=0
REBUILD=0
SKIP_MIN="${VERIFY_SKIP_MIN:-0}"
INPUT_MIN_ONLY="${VERIFY_INPUT_MIN_ONLY:-0}"
TIMEOUT_SEC="${VERIFY_TIMEOUT:-5}"
MAX_FAILURES="${VERIFY_MAX_FAILURES:-0}"
EXTRACT_DIR=""
QUIET=0
VERBOSE=0
JSON_MODE=0
SYMBOLIZE="${VERIFY_SYMBOLIZE:-0}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_FUZZ_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: verify_bucket.sh [--repo-root DIR] [--fuzz-root DIR] [--bucket-dir DIR] [OPTIONS]
  --repo-root DIR           Target Prism source directory (alias: --target DIR; default: PRISM_A_DIR or build/targets/prism_a)
  --fuzz-root DIR           prism-fuzzer root containing harnesses/prism (default: script repo)
  --profile NAME            asan_ubsan | asan_ubsan_slow | msan_slow | lsan_slow | xallocator | diff_parse_y | diff_parse_y_asan | cruby_compile | cruby_compile_asan | cruby_pipeline | cruby_pipeline_asan | diff_prism | arm32_oracle | ppc_oracle
  --runner PATH             Use a precompiled verify_runner binary
  --build-only              Build (if stale) and print the runner binary path
  --rebuild-verifiers       Force recompilation of verify_runner (bypasses source fingerprint cache)
  --timeout SEC             Per-input timeout in seconds (default: 5)
  --max-failures N          Stop checking after N failing inputs (default: 0 = all)
  --extract-survivors DIR   Copy any still-failing inputs into DIR
  --input-min-only          Check only input.min (skip pending/archived inputs)
  --skip-min                Skip checking input.min
  --symbolize               Enable external llvm-symbolizer (slower on many crashes)
  --quiet                   Suppress stderr dumps on failures
  --verbose                 Print full captured stderr for failures
  --json                    Emit machine-readable JSON output
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo-root|--target)
      REPO_ROOT="${2:-}"; shift 2 ;;
    --fuzz-root)
      FUZZ_ROOT="${2:-}"; shift 2 ;;
    --bucket-dir)
      BUCKET_DIR="${2:-}"; shift 2 ;;
    --profile)
      PROFILE="${2:-}"; shift 2 ;;
    --runner)
      RUNNER="${2:-}"; shift 2 ;;
    --build-only)
      BUILD_ONLY=1; shift ;;
    --rebuild-verifiers|--rebuild)
      REBUILD=1; shift ;;
    --input-min-only)
      INPUT_MIN_ONLY=1; shift ;;
    --skip-min)
      SKIP_MIN=1; shift ;;
    --symbolize)
      SYMBOLIZE=1; shift ;;
    --timeout)
      TIMEOUT_SEC="${2:-}"; shift 2 ;;
    --max-failures)
      MAX_FAILURES="${2:-}"; shift 2 ;;
    --extract-survivors)
      EXTRACT_DIR="${2:-}"; shift 2 ;;
    --quiet)
      QUIET=1; shift ;;
    --verbose)
      VERBOSE=1; shift ;;
    --json)
      JSON_MODE=1; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "verify_bucket.sh: unknown option '$1'" >&2
      usage >&2
      exit 2 ;;
  esac
done

if [ -z "$FUZZ_ROOT" ]; then
  FUZZ_ROOT="$DEFAULT_FUZZ_ROOT"
fi

ws_build_dir="${FUZZ_BUILD_DIR:-}"
if [ -z "$ws_build_dir" ] && [ -f "$FUZZ_ROOT/runtime/topology.rb" ]; then
  ws_build_dir="$(ruby -r"$FUZZ_ROOT/runtime/topology" -e '
    t = PrismFuzzer::Topology.discover(triage_dir: ARGV[0], start_dir: ARGV[1])
    puts PrismFuzzer::Topology.workspace_paths(t, fuzz_root: ARGV[1])[:build_dir] if t
  ' "$BUCKET_DIR" "$FUZZ_ROOT" 2>/dev/null || true)"
fi
ws_build_dir="${ws_build_dir:-$FUZZ_ROOT/tmp/fuzz/build}"

if [ -z "$REPO_ROOT" ]; then
  meta_src_a=""
  if [ -n "$BUCKET_DIR" ] && [ -f "$BUCKET_DIR/meta.json" ]; then
    meta_src_a="$(ruby -rjson -e '
      m = begin
        JSON.parse(File.read(ARGV[0]))
      rescue Errno::ENOENT
        {}
      rescue JSON::ParserError => e
        warn "verify_bucket.sh: failed to parse #{ARGV[0]}: #{e.message}"
        {}
      end
      srcs = m.dig("target", "sources")
      id = srcs.is_a?(Hash) ? (srcs["prism_a"] || srcs["prism"] || srcs["source"]) : nil
      puts id if id && !id.to_s.empty?
    ' "$BUCKET_DIR/meta.json" || true)"
  fi
  for cand in "${PRISM_A_DIR:-}" "${PRISM_DIR:-}" "${PRISM_ROOT:-}" "${meta_src_a:+$ws_build_dir/targets/$meta_src_a}" "$ws_build_dir/targets/prism_a"; do
    if [ -n "$cand" ] && [ -f "$cand/include/prism.h" ] && [ -d "$cand/src" ]; then
      REPO_ROOT="$cand"
      break
    fi
  done
fi

res_topo="$ws_build_dir/topology.resolved.json"
if [ -z "$REPO_ROOT" ] && [ -f "$res_topo" ]; then
  REPO_ROOT="$(ruby -rjson -e '
    t = begin
      JSON.parse(File.read(ARGV[0]))
    rescue Errno::ENOENT
      {}
    rescue JSON::ParserError => e
      warn "verify_bucket.sh: failed to parse #{ARGV[0]}: #{e.message}"
      {}
    end
    cov_id = t.dig("coverage", "source") || t.fetch("sources", {}).find { |_, v| v.is_a?(Hash) && v["kind"] == "prism" }&.first
    p = cov_id && t.dig("sources", cov_id, "path")
    puts p if p && !p.to_s.empty?
  ' "$res_topo" || true)"
fi

if [ -z "$PROFILE" ]; then
  if [ -n "$BUCKET_DIR" ]; then
    profile_rb=""
    if [ -f "$SCRIPT_DIR/lib/verify_profile.rb" ]; then
      profile_rb="$SCRIPT_DIR/lib/verify_profile.rb"
    elif [ -f "$FUZZ_ROOT/triage/lib/verify_profile.rb" ]; then
      profile_rb="$FUZZ_ROOT/triage/lib/verify_profile.rb"
    fi

    if [ -n "$profile_rb" ] && command -v ruby >/dev/null 2>&1; then
      PROFILE="$(ruby "$profile_rb" infer "$BUCKET_DIR" 2>/dev/null || true)"
    fi
    PROFILE="${PROFILE:-asan_ubsan}"
  else
    PROFILE="asan_ubsan"
  fi
fi

if [ "$PROFILE" != "cruby_compile" ] && [ "$PROFILE" != "cruby_compile_asan" ] && [ "$PROFILE" != "cruby_pipeline" ] && [ "$PROFILE" != "cruby_pipeline_asan" ]; then
  if [ -z "$REPO_ROOT" ]; then
    echo "verify_bucket.sh: --repo-root is required (or set PRISM_A_DIR / run make targets-sync)" >&2
    usage >&2
    exit 2
  fi

  if [ ! -f "$REPO_ROOT/include/prism.h" ] || [ ! -d "$REPO_ROOT/src" ]; then
    echo "verify_bucket.sh: invalid Prism root '$REPO_ROOT'" >&2
    exit 2
  fi
fi

if [ "$BUILD_ONLY" -eq 0 ] && [ -z "$BUCKET_DIR" ]; then
  echo "verify_bucket.sh: --bucket-dir is required" >&2
  usage >&2
  exit 2
fi

if [ ! -f "$FUZZ_ROOT/harnesses/prism/parse.c" ] || [ ! -f "$FUZZ_ROOT/triage/verify_runner.c" ]; then
  echo "verify_bucket.sh: invalid fuzz root '$FUZZ_ROOT'" >&2
  exit 2
fi

if [ "$BUILD_ONLY" -eq 0 ] && [ ! -d "$BUCKET_DIR" ]; then
  echo "verify_bucket.sh: bucket directory not found: '$BUCKET_DIR'" >&2
  exit 2
fi

ensure_target_templates() {
  local target_root="$1"
  local cache_dir="$2"
  local tpl_script="$target_root/templates/template.rb"
  local cfg="$target_root/config.yml"
  [ -f "$tpl_script" ] && [ -f "$cfg" ] || return 0

  local stamp="$cache_dir/.templates.sha256"
  local check_out
  if ! check_out="$(ruby -rdigest -e '
    target, stamp = ARGV
    cfg = File.join(target, "config.yml")
    tpl_dir = File.join(target, "templates")
    inputs = ([cfg] + Dir.glob(File.join(tpl_dir, "**", "*")).select { |p| File.file?(p) }).uniq.sort
    digest = Digest::SHA256.new
    inputs.each do |p|
      rel = p.delete_prefix(target + "/")
      digest.update("#{rel}\0#{File.size(p)}\0")
      digest.update(File.binread(p))
      digest.update("\0")
    end
    cur_sha = digest.hexdigest
    max_in_mtime = inputs.map { |p| File.mtime(p) }.max

    expected = []
    %w[src include].each do |sub|
      base = File.join(tpl_dir, sub)
      next unless File.directory?(base)
      Dir.glob(File.join(base, "**", "*.erb")).each do |erb|
        rel = erb.delete_prefix(tpl_dir + "/").delete_suffix(".erb")
        expected << File.join(target, rel)
      end
    end

    missing = expected.any? { |p| !File.file?(p) }
    stale_out = !missing && expected.any? { |p| File.mtime(p) < max_in_mtime }
    stale_stamp = File.file?(stamp) && File.read(stamp).strip != cur_sha
    need = (missing || stale_out || stale_stamp) ? 1 : 0
    puts "#{need} #{cur_sha}"
  ' "$target_root" "$stamp")"; then
    echo "verify_bucket.sh: failed to inspect templates under '$target_root'" >&2
    exit 125
  fi

  local need_gen="${check_out%% *}"
  local tpl_sha="${check_out#* }"
  if [ "$need_gen" -eq 1 ]; then
    if [ ! -w "$target_root" ]; then
      echo "verify_bucket.sh: target '$target_root' is not writable for template generation" >&2
      exit 125
    fi
    if [ "$JSON_MODE" -eq 0 ] && [ "$BUILD_ONLY" -eq 0 ]; then
      echo "Generating templates for $target_root..." >&2
    fi
    if ! (cd "$target_root" && (ruby templates/template.rb || rake templates)) >&2; then
      echo "verify_bucket.sh: template generation failed under '$target_root'" >&2
      exit 125
    fi
  fi

  local tmp_stamp="$stamp.tmp.$$"
  if printf '%s\n' "$tpl_sha" > "$tmp_stamp" 2>/dev/null; then
    mv -f "$tmp_stamp" "$stamp"
  else
    rm -f "$tmp_stamp"
  fi
}

check_target_api_support() {
  local target_root="$1"
  if [ ! -f "$target_root/include/prism.h" ] ||
     ! grep -rqE '\bpm_parse\(' "$target_root/include" 2>/dev/null ||
     { ! grep -rqE '\bpm_parser_new\(' "$target_root/include" 2>/dev/null &&
       ! grep -rqE '\bpm_parser_init\(' "$target_root/include" 2>/dev/null; }; then
    echo "verify_bucket.sh: target Prism at '$target_root' lacks Prism C parser APIs (pm_parse/pm_parser_new/pm_parser_init)" >&2
    exit 125
  fi
}

resolve_prism_b_dir() {
  local ws_b="$1"
  if [ -n "${PRISM_B_DIR:-}" ]; then
    printf '%s\n' "$PRISM_B_DIR"
    return 0
  fi
  local meta_src_b=""
  if [ -n "$BUCKET_DIR" ] && [ -f "$BUCKET_DIR/meta.json" ]; then
    meta_src_b="$(ruby -rjson -e '
      m = begin
        JSON.parse(File.read(ARGV[0]))
      rescue Errno::ENOENT
        {}
      rescue JSON::ParserError => e
        warn "verify_bucket.sh: failed to parse #{ARGV[0]}: #{e.message}"
        {}
      end
      id = m.dig("target", "sources", "prism_b")
      if id && !id.to_s.empty?
        p = File.join(ARGV[1], "targets", id)
        puts p if File.directory?(p)
      end
    ' "$BUCKET_DIR/meta.json" "$ws_b" || true)"
  fi
  printf '%s\n' "${meta_src_b:-$ws_b/targets/prism_b}"
}

compute_build_fingerprint() {
  local target_root="$1"
  local extra_target_root="$2"
  local fuzz_root="$3"
  local cc="$4"
  shift 4
  ruby -rdigest -e '
    target, extra_target, fuzz, cc, *flags = ARGV
    paths = []
    search_dirs = [
      File.join(target, "src"),
      File.join(target, "include"),
      File.join(fuzz, "harnesses", "prism")
    ]
    unless extra_target.to_s.empty?
      search_dirs << File.join(extra_target, "src")
      search_dirs << File.join(extra_target, "include")
    end
    search_dirs.each do |dir|
      next unless File.directory?(dir)
      Dir.glob(File.join(dir, "**", "*")).each do |p|
        paths << p if File.file?(p)
      end
    end
    runner_c = File.join(fuzz, "triage", "verify_runner.c")
    paths << runner_c if File.file?(runner_c)
    d = Digest::SHA256.new
    d.update("#{target}\0#{extra_target}\0#{fuzz}\0#{cc}\0#{flags.join("\0")}\0")
    paths.uniq.sort.each do |p|
      st = File.stat(p)
      d.update("#{p}\0#{st.size}\0#{st.mtime.tv_sec}\0#{st.mtime.nsec}\n")
    end
    puts d.hexdigest
  ' "$target_root" "$extra_target_root" "$fuzz_root" "$cc" "$@"
}

resolve_default_max_input() {
  ruby -rjson -rzlib -rrubygems/package -e '
    ws_build, bucket = ARGV
    max_in = 1024
    [File.join(ws_build.to_s, "topology.resolved.json"), File.join(File.dirname(ws_build.to_s), "topology.json")].each do |tp|
      next unless File.file?(tp)
      t = begin
        JSON.parse(File.read(tp))
      rescue StandardError
        next
      end
      d = t.dig("defaults", "max_input_size").to_i
      max_in = d if d > max_in
      Array(t["workers"]).each do |w|
        wm = w.is_a?(Hash) ? w["max_input_size"].to_i : 0
        max_in = wm if wm > max_in
      end
      (t["generators"].is_a?(Hash) ? t["generators"].values : []).each do |g|
        gm = g.is_a?(Hash) ? g["max_input_size"].to_i : 0
        max_in = gm if gm > max_in
      end
      break
    end
    if bucket && !bucket.empty? && File.directory?(bucket)
      min_f = File.join(bucket, "input.min")
      if File.file?(min_f)
        pay = File.size(min_f) - 4
        max_in = pay if pay > max_in
      end
      tgz = File.join(bucket, "inputs.tar.gz")
      if File.file?(tgz)
        begin
          Zlib::GzipReader.open(tgz) do |gz|
            Gem::Package::TarReader.new(gz) do |tar|
              tar.each do |entry|
                next unless entry.file?
                pay = entry.header.size.to_i - 4
                max_in = pay if pay > max_in
              end
            end
          end
        rescue StandardError
          nil
        end
      end
    end
    puts max_in
  ' "$ws_build_dir" "${BUCKET_DIR:-}" 2>/dev/null || echo 1024
}

diff_bucket_needs_asan() {
  local bucket="$1"
  if [ "${VERIFY_DIFF_ASAN:-}" = "1" ]; then
    return 0
  elif [ "${VERIFY_DIFF_ASAN:-}" = "0" ]; then
    return 1
  fi
  [ -n "$bucket" ] && [ -f "$bucket/meta.json" ] || return 1
  ruby -rjson -e '
    m = JSON.parse(File.read(ARGV[0]))
    tool = m.dig("symptom", "sanitizer", "tool").to_s
    reason = m["reason"].to_s
    headline = m.dig("symptom", "headline").to_s.strip
    asan_reasons = %w[
      stack-overflow heap-buffer-overflow stack-buffer-overflow global-buffer-overflow
      heap-use-after-free stack-use-after-scope stack-use-after-return
      dynamic-stack-buffer-overflow intra-object-overflow container-overflow
      initialization-order-fiasco bad-free double-free alloc-dealloc-mismatch
    ]
    needs = tool == "AddressSanitizer" ||
            asan_reasons.include?(reason) ||
            (reason == "SEGV" && headline.empty?)
    exit(needs ? 0 : 1)
  ' "$bucket/meta.json" >/dev/null 2>&1
}

build_verify_runner() {
  local profile="$1"
  if [ "$profile" = "diff_parse_y" ] && diff_bucket_needs_asan "${BUCKET_DIR:-}"; then
    profile="diff_parse_y_asan"
  elif [ "$profile" = "cruby_compile" ] && diff_bucket_needs_asan "${BUCKET_DIR:-}"; then
    profile="cruby_compile_asan"
  elif [ "$profile" = "cruby_pipeline" ] && diff_bucket_needs_asan "${BUCKET_DIR:-}"; then
    profile="cruby_pipeline_asan"
  fi
  local cache_dir="${VERIFY_BUILD_DIR:-$ws_build_dir/verify}"
  if ! mkdir -p "$cache_dir" 2>/dev/null || [ ! -w "$cache_dir" ]; then
    local target_key
    target_key="$(ruby -rdigest -e 'puts Digest::SHA256.hexdigest(File.expand_path(ARGV[0]))[0, 12]' "${REPO_ROOT:-$FUZZ_ROOT}")"
    cache_dir="${TMPDIR:-/tmp}/prism-fuzzer-verify/$target_key"
    mkdir -p "$cache_dir"
  fi

  if [ -n "$REPO_ROOT" ]; then
    ensure_target_templates "$REPO_ROOT" "$cache_dir"
    check_target_api_support "$REPO_ROOT"
  fi

  local prism_b=""
  if [ "$profile" = "diff_prism" ]; then
    prism_b="$(resolve_prism_b_dir "$ws_build_dir")"
    if [ -d "$prism_b" ]; then
      mkdir -p "$cache_dir/prism-b"
      ensure_target_templates "$prism_b" "$cache_dir/prism-b"
    fi
    if [ ! -f "$prism_b/include/prism.h" ] || [ ! -d "$prism_b/src" ]; then
      echo "verify_bucket.sh: diff_prism profile requires PRISM_B_DIR (missing '$prism_b')" >&2
      exit 2
    fi
  fi

  local sub_loc_gen="$FUZZ_ROOT/harnesses/prism/gen_node_locations.rb"
  local sub_loc_inc="$cache_dir/node_locations.inc"
  if [ -n "$REPO_ROOT" ] && [ -f "$sub_loc_gen" ] && [ -f "$REPO_ROOT/config.yml" ]; then
    if [ ! -f "$sub_loc_inc" ] || [ "$REPO_ROOT/config.yml" -nt "$sub_loc_inc" ] || [ "$sub_loc_gen" -nt "$sub_loc_inc" ]; then
      ruby "$sub_loc_gen" "$REPO_ROOT/config.yml" "$sub_loc_inc" >&2 || {
        echo "verify_bucket.sh: failed to generate $sub_loc_inc" >&2
        exit 125
      }
    fi
  fi

  local cc="${CC:-clang}"
  local max_input="${FUZZ_MAX_INPUT_SIZE:-}"
  if [ -z "$max_input" ]; then
    max_input="$(resolve_default_max_input)"
  fi
  local max_alloc="${FUZZ_MAX_ALLOCATED:-128}"
  local hard_rss="${FUZZ_HARD_RSS_LIMIT:-$((max_alloc * 16))}"

  local flags=()
  local probe_arr=()
  if [ "$profile" = "diff_parse_y" ] || [ "$profile" = "diff_parse_y_asan" ] || [ "$profile" = "cruby_compile" ] || [ "$profile" = "cruby_compile_asan" ] || [ "$profile" = "cruby_pipeline" ] || [ "$profile" = "cruby_pipeline_asan" ]; then
    flags=("$profile" "$max_input")
  elif [ "$profile" = "diff_prism" ]; then
    flags=("diff_prism" "$max_input" "$prism_b")
  else
    flags=(
      -O1 -fno-omit-frame-pointer -ggdb3 -std=c99
      -Wno-gnu-statement-expression-from-macro-expansion
      -Wno-switch
      "-I$REPO_ROOT/include"
      "-I$cache_dir"
      "-I$FUZZ_ROOT/harnesses/prism"
      "-DPRISM_EXCLUDE_JSON"
      "-DPRISM_EXCLUDE_PRETTYPRINT"
      "-DPM_INTEGER_DIVIDE_THRESHOLD=8"
      "-DPRISM_DEPTH_MAXIMUM=128"
      "-DPRISM_FUZZ_INLINE_ASSERTS"
      "-DFUZZ_MAX_INPUT_SIZE=$max_input"
      "-DFUZZ_MAX_ALLOCATED=$max_alloc"
      "-DFUZZ_HARD_RSS_LIMIT=$hard_rss"
    )

    # Probe historical Prism C API differences across 2024–2026 commits so older commits compile cleanly.
    local compat_h="$cache_dir/prism_fuzz_compat.h"
    local compat_args=(--include-dir "$REPO_ROOT/include" --output "$compat_h" --cflags)
    if [ -f "$sub_loc_inc" ]; then
      compat_args+=(--subloc-inc "$sub_loc_inc")
    else
      compat_args+=(--subloc-inc "$cache_dir/.missing_node_locations.inc")
    fi
    local probe_out
    if ! probe_out="$(ruby "$FUZZ_ROOT/harnesses/prism/gen_api_compat.rb" "${compat_args[@]}")"; then
      exit 125
    fi
    local pf
    while IFS= read -r pf; do
      [ -n "$pf" ] || continue
      if [ "$pf" = "-DPM_ARENA_INITIAL_SIZE=0" ]; then
        if [ "$profile" != "xallocator" ]; then
          flags+=("$pf")
        fi
        continue
      fi
      probe_arr+=("$pf")
      flags+=("$pf")
    done <<< "$probe_out"

    case "$profile" in
      asan_ubsan)
        flags+=("-fsanitize=address,undefined" -fno-sanitize-recover=all) ;;
      asan_ubsan_slow)
        flags+=(-DSLOW "-fsanitize=address,undefined" -fno-sanitize-recover=all) ;;
      msan_slow)
        if [ "$(uname -s)" = "Darwin" ]; then
          echo "verify_bucket.sh: MSan verification requires Linux (run './campaigns/default.rb verify -- --bucket ...' or 'make verify BUCKET=...' in Docker)" >&2
          exit 2
        fi
        flags+=(-DSLOW -fsanitize=memory -fsanitize-memory-track-origins -fno-sanitize-recover=all) ;;
      lsan_slow)
        flags+=(-DSLOW -fsanitize=leak -fno-sanitize-recover=all) ;;
      xallocator)
        flags+=("-I$FUZZ_ROOT/harnesses/prism/include" -DPRISM_XALLOCATOR) ;;
      arm32_oracle)
        if [ "$(uname -s)" = "Darwin" ] || ! command -v arm-linux-gnueabihf-gcc >/dev/null 2>&1 || ! command -v qemu-arm >/dev/null 2>&1; then
          echo "verify_bucket.sh: arm32_oracle verification requires Linux with qemu-arm and arm-linux-gnueabihf-gcc (run './campaigns/default.rb verify -- --bucket ...' or 'make verify BUCKET=...' in Docker)" >&2
          exit 2
        fi
        if [ -f "$FUZZ_ROOT/harnesses/prism/gen_serialize_walk.rb" ] && [ -f "$REPO_ROOT/config.yml" ] && \
           grep -rq 'PM_SCOPE_NODE' "$REPO_ROOT/include" 2>/dev/null && \
           ruby "$FUZZ_ROOT/harnesses/prism/gen_serialize_walk.rb" "$REPO_ROOT/config.yml" "$cache_dir/node_serialize_walk.inc" >/dev/null 2>&1; then
          flags+=("-I$cache_dir")
        else
          flags+=(-DPRISM_FUZZ_NO_SERIALIZE_SCAN)
        fi
        flags+=(-Wno-missing-braces "-I$FUZZ_ROOT/harnesses/prism" -DPRISM_OSS_FUZZ -DPRISM_EXCLUDE_JSON -DPRISM_EXCLUDE_PRETTYPRINT "-fsanitize=address,undefined" -fno-sanitize-recover=all) ;;
      ppc_oracle)
        if [ "$(uname -s)" = "Darwin" ] || ! command -v powerpc-linux-gnu-gcc >/dev/null 2>&1 || ! command -v qemu-ppc >/dev/null 2>&1; then
          echo "verify_bucket.sh: ppc_oracle verification requires Linux with qemu-ppc and powerpc-linux-gnu-gcc (run './campaigns/default.rb verify -- --bucket ...' or 'make verify BUCKET=...' in Docker)" >&2
          exit 2
        fi
        if [ -f "$FUZZ_ROOT/harnesses/prism/gen_serialize_walk.rb" ] && [ -f "$REPO_ROOT/config.yml" ]; then
          ruby "$FUZZ_ROOT/harnesses/prism/gen_serialize_walk.rb" "$REPO_ROOT/config.yml" "$cache_dir/node_serialize_walk.inc" >&2 || {
            echo "verify_bucket.sh: failed to generate node_serialize_walk.inc against '$REPO_ROOT/config.yml'" >&2
            exit 125
          }
        fi
        flags+=(-msecure-plt -Wno-missing-braces "-I$cache_dir" "-I$FUZZ_ROOT/harnesses/prism" '-DFUZZ_ORACLE_NAMESPACE="oracle_ppc"' '-DFUZZ_ORACLE_LEN_KEY="ppc_len"' -DPRISM_OSS_FUZZ -DPRISM_EXCLUDE_JSON -DPRISM_EXCLUDE_PRETTYPRINT "-fsanitize=address,undefined" -fno-sanitize-recover=all) ;;
      *)
        echo "verify_bucket.sh: unknown profile '$profile'" >&2
        exit 2 ;;
    esac
  fi

  local bin="$cache_dir/verify_runner.$profile"
  local fp_file="$bin.fingerprint"
  local current_fp=""
  local needs_build=0
  if [ "$REBUILD" -eq 1 ] || [ ! -x "$bin" ]; then
    needs_build=1
  elif [ "$profile" = "arm32_oracle" ] && [ ! -x "$bin.arm32" ]; then
    needs_build=1
  elif [ "$profile" = "ppc_oracle" ] && [ ! -x "$bin.ppc" ]; then
    needs_build=1
  elif [ -f "$fp_file" ]; then
    current_fp="$(compute_build_fingerprint "$REPO_ROOT" "$prism_b" "$FUZZ_ROOT" "$cc" "${flags[@]}")"
    if [ "$(cat "$fp_file" 2>/dev/null)" != "$current_fp" ]; then
      needs_build=1
    fi
  else
    local newer_roots=("$REPO_ROOT/src" "$REPO_ROOT/include" "$FUZZ_ROOT/harnesses/prism" "$FUZZ_ROOT/triage/verify_runner.c")
    if [ -n "$prism_b" ]; then
      [ -d "$prism_b/src" ] && newer_roots+=("$prism_b/src")
      [ -d "$prism_b/include" ] && newer_roots+=("$prism_b/include")
    fi
    if [ -n "$(find "${newer_roots[@]}" -type f -newer "$bin" -print -quit 2>/dev/null)" ]; then
      needs_build=1
    fi
  fi

  if [ "$needs_build" -eq 1 ]; then
    local tmp_bin="$bin.tmp.$$"
    rm -f "$tmp_bin"
    if [ "$JSON_MODE" -eq 0 ] && [ "$BUILD_ONLY" -eq 0 ]; then
      echo "Building verify_runner ($profile)..." >&2
    fi
    if [ "$profile" = "diff_parse_y" ] || [ "$profile" = "diff_parse_y_asan" ]; then
      local diff_extra_args=()
      if [ "$profile" = "diff_parse_y_asan" ]; then
        diff_extra_args=(--cflag -DPM_ARENA_INITIAL_SIZE=0 --cflag -fsanitize=address)
      fi
      if ! "$FUZZ_ROOT/harnesses/prism/build_diff.sh" \
          --mode verify \
          --prism-root "$REPO_ROOT" \
          --fuzz-root "$FUZZ_ROOT" \
          --oracle-dir "$cache_dir/diff-oracle" \
          --cc "$cc" \
          --max-input-size "$max_input" \
          ${diff_extra_args[@]+"${diff_extra_args[@]}"} \
          --output "$tmp_bin"; then
        rm -f "$tmp_bin"
        echo "verify_bucket.sh: failed to compile verify_runner ($profile) against '$REPO_ROOT'" >&2
        exit 125
      fi
    elif [ "$profile" = "cruby_compile" ] || [ "$profile" = "cruby_compile_asan" ]; then
      local compile_extra_args=()
      if [ "$profile" = "cruby_compile_asan" ]; then
        compile_extra_args=(--cflag -fsanitize=address)
      fi
      if ! "$FUZZ_ROOT/harnesses/prism/build_cruby_compile.sh" \
          --mode verify \
          --fuzz-root "$FUZZ_ROOT" \
          --oracle-dir "$cache_dir/compile-oracle" \
          --cc "$cc" \
          --max-input-size "$max_input" \
          ${compile_extra_args[@]+"${compile_extra_args[@]}"} \
          --output "$tmp_bin"; then
        rm -f "$tmp_bin"
        echo "verify_bucket.sh: failed to compile verify_runner ($profile)" >&2
        exit 125
      fi
    elif [ "$profile" = "cruby_pipeline" ] || [ "$profile" = "cruby_pipeline_asan" ]; then
      local pipeline_extra_args=()
      if [ "$profile" = "cruby_pipeline_asan" ]; then
        pipeline_extra_args=(--cflag -fsanitize=address)
      fi
      if ! "$FUZZ_ROOT/harnesses/prism/build_cruby_compile.sh" \
          --mode verify \
          --pipeline-diff \
          --fuzz-root "$FUZZ_ROOT" \
          --oracle-dir "$cache_dir/pipeline-oracle" \
          --cc "$cc" \
          --max-input-size "$max_input" \
          ${pipeline_extra_args[@]+"${pipeline_extra_args[@]}"} \
          --output "$tmp_bin"; then
        rm -f "$tmp_bin"
        echo "verify_bucket.sh: failed to compile verify_runner ($profile)" >&2
        exit 125
      fi
    elif [ "$profile" = "diff_prism" ]; then
      if ! "$FUZZ_ROOT/harnesses/prism/build_prism_diff.sh" \
          --mode verify \
          --prism-a "$REPO_ROOT" \
          --prism-b "$prism_b" \
          --fuzz-root "$FUZZ_ROOT" \
          --work-dir "$cache_dir/prism-diff" \
          --cc "$cc" \
          --max-input-size "$max_input" \
          --output "$tmp_bin"; then
        rm -f "$tmp_bin"
        echo "verify_bucket.sh: failed to compile verify_runner ($profile) against '$REPO_ROOT' vs '$prism_b'" >&2
        exit 125
      fi
    elif [ "$profile" = "arm32_oracle" ] || [ "$profile" = "ppc_oracle" ]; then
      local cross_triplet cross_gcc qemu_bin cross_suffix
      local cross_ldflags=()
      if [ "$profile" = "ppc_oracle" ]; then
        cross_triplet="powerpc-linux-gnu"
        cross_gcc="powerpc-linux-gnu-gcc"
        qemu_bin="/usr/bin/qemu-ppc"
        cross_suffix=".ppc"
        cross_ldflags=(-latomic)
      else
        cross_triplet="arm-linux-gnueabihf"
        cross_gcc="arm-linux-gnueabihf-gcc"
        qemu_bin="/usr/bin/qemu-arm"
        cross_suffix=".arm32"
      fi
      shopt -s nullglob
      local cross_srcs=(
        "$REPO_ROOT"/src/*.c
        "$REPO_ROOT"/src/*/*.c
        "$FUZZ_ROOT/harnesses/prism/parse32.c"
        "$FUZZ_ROOT/harnesses/prism/fuzz.c"
        "$FUZZ_ROOT/triage/verify_runner.c"
      )
      local obj_dir
      obj_dir="$(mktemp -d "${TMPDIR:-/tmp}/pf-verify-cross.XXXXXX")"
      local tmp_cross="$bin$cross_suffix.tmp.$$"
      rm -f "$tmp_cross"
      local vjobs="${JOBS:-8}"
      case "$vjobs" in ''|*[!0-9]*|0) vjobs=4 ;; esac
      local cc_wrap=("$cc")
      if [ "${FUZZ_CCACHE:-1}" != "0" ] && command -v ccache >/dev/null 2>&1; then
        for cand in "${CCACHE_DIR:-}" "/ccache" "$FUZZ_ROOT/.cache/ccache" "${TMPDIR:-/tmp}/prism-fuzzer-ccache-$(id -u)"; do
          [ -n "$cand" ] || continue
          if mkdir -p "$cand" 2>/dev/null && [ -w "$cand" ]; then
            cc_wrap=("env" "CCACHE_DIR=$cand" "CCACHE_NOHASHDIR=1" "CCACHE_NAMESPACE=verify|$profile|${FUZZ_IMAGE_ID:-}" "ccache" "$cc")
            break
          fi
        done
      fi
      local objs=()
      local pids=()
      local c_rc=0
      local src obj idx=0
      for src in "${cross_srcs[@]}"; do
        obj="$obj_dir/${idx}_$(basename "$src" .c).o"
        idx=$((idx + 1))
        local cross_unit_flags=()
        case "$src" in
          "$REPO_ROOT"/src/*)
            if [ "$(basename "$src")" != "arena.c" ] && [ -f "$FUZZ_ROOT/harnesses/prism/include/fuzz_arena_unslab.h" ]; then
              cross_unit_flags=(-include "$FUZZ_ROOT/harnesses/prism/include/fuzz_arena_unslab.h")
            fi
            ;;
        esac
        (
          "${cc_wrap[@]}" --target="$cross_triplet" -isystem "/usr/$cross_triplet/include" \
            "${flags[@]}" ${cross_unit_flags[@]+"${cross_unit_flags[@]}"} -c "$src" -o "$obj"
        ) &
        pids+=("$!")
        objs+=("$obj")
        if [ "${#pids[@]}" -ge "$vjobs" ]; then
          wait "${pids[0]}" || c_rc=1
          pids=("${pids[@]:1}")
        fi
      done
      local pid
      for pid in "${pids[@]+"${pids[@]}"}"; do
        wait "$pid" || c_rc=1
      done
      if [ "$c_rc" -ne 0 ]; then
        rm -rf "$obj_dir" "$tmp_cross" "$tmp_bin"
        echo "verify_bucket.sh: failed to compile 32-bit verify_runner ($profile) against '$REPO_ROOT'" >&2
        exit 125
      fi
      if ! "$cross_gcc" -no-pie -fsanitize=address,undefined "${objs[@]}" ${cross_ldflags[@]+"${cross_ldflags[@]}"} -o "$tmp_cross"; then
        rm -rf "$obj_dir" "$tmp_cross" "$tmp_bin"
        echo "verify_bucket.sh: failed to link 32-bit verify_runner ($profile) against '$REPO_ROOT'" >&2
        exit 125
      fi
      rm -rf "$obj_dir"

      local proxy_srcs=(
        "$REPO_ROOT"/src/*.c
        "$REPO_ROOT"/src/*/*.c
        "$FUZZ_ROOT/harnesses/prism/mutator_oracle64.c"
        "$FUZZ_ROOT/triage/verify_runner.c"
      )
      local proxy_flags=(
        -O2 -std=c99
        -Wno-gnu-statement-expression-from-macro-expansion
        -Wno-switch -Wno-unused-function
        -U_FORTIFY_SOURCE -UNDEBUG -DNDEBUG=1 -fno-sanitize=all
        "-I$REPO_ROOT/include"
        "-I$cache_dir"
        "-I$FUZZ_ROOT/harnesses/prism"
        -DPRISM_EXCLUDE_JSON -DPRISM_EXCLUDE_PRETTYPRINT
        -DPM_INTEGER_DIVIDE_THRESHOLD=8 -DPRISM_DEPTH_MAXIMUM=128
        "-DFUZZ_MAX_INPUT_SIZE=$max_input"
        -DPRISM_VERIFY_ORACLE64_PROXY
        "-DPRISM_VERIFY_QEMU_BIN=\"$qemu_bin\""
        "-DPRISM_VERIFY_SYSROOT=\"/usr/$cross_triplet\""
        "-DPRISM_VERIFY_TARGET_SUFFIX=\"$cross_suffix\""
        ${probe_arr[@]+"${probe_arr[@]}"}
      )
      local proxy_dir
      proxy_dir="$(mktemp -d "${TMPDIR:-/tmp}/pf-verify-proxy.XXXXXX")"
      local proxy_objs=()
      pids=()
      c_rc=0
      idx=0
      for src in "${proxy_srcs[@]}"; do
        obj="$proxy_dir/${idx}_$(basename "$src" .c).o"
        idx=$((idx + 1))
        (
          "${cc_wrap[@]}" "${proxy_flags[@]}" -c "$src" -o "$obj"
        ) &
        pids+=("$!")
        proxy_objs+=("$obj")
        if [ "${#pids[@]}" -ge "$vjobs" ]; then
          wait "${pids[0]}" || c_rc=1
          pids=("${pids[@]:1}")
        fi
      done
      for pid in "${pids[@]+"${pids[@]}"}"; do
        wait "$pid" || c_rc=1
      done
      if [ "$c_rc" -ne 0 ] || ! "$cc" "${proxy_flags[@]}" "${proxy_objs[@]}" -o "$tmp_bin"; then
        rm -rf "$proxy_dir" "$tmp_cross" "$tmp_bin"
        echo "verify_bucket.sh: failed to compile 64-bit proxy verify_runner ($profile) against '$REPO_ROOT'" >&2
        exit 125
      fi
      rm -rf "$proxy_dir"
      mv -f "$tmp_cross" "$bin$cross_suffix"
    else
      shopt -s nullglob
      local srcs=(
        "$REPO_ROOT"/src/*.c
        "$REPO_ROOT"/src/*/*.c
        "$FUZZ_ROOT/harnesses/prism/parse.c"
        "$FUZZ_ROOT/harnesses/prism/fuzz.c"
        "$FUZZ_ROOT/triage/verify_runner.c"
      )
      local vjobs="${JOBS:-8}"
      case "$vjobs" in ''|*[!0-9]*|0) vjobs=4 ;; esac
      local cc_wrap=("$cc")
      if [ "${FUZZ_CCACHE:-1}" != "0" ] && command -v ccache >/dev/null 2>&1; then
        for cand in "${CCACHE_DIR:-}" "/ccache" "$FUZZ_ROOT/.cache/ccache" "${TMPDIR:-/tmp}/prism-fuzzer-ccache-$(id -u)"; do
          [ -n "$cand" ] || continue
          if mkdir -p "$cand" 2>/dev/null && [ -w "$cand" ]; then
            cc_wrap=("env" "CCACHE_DIR=$cand" "CCACHE_NOHASHDIR=1" "CCACHE_NAMESPACE=verify|$profile|${FUZZ_IMAGE_ID:-}" "ccache" "$cc")
            break
          fi
        done
      fi
      local obj_dir
      obj_dir="$(mktemp -d "${TMPDIR:-/tmp}/pf-verify-host.XXXXXX")"
      local objs=()
      local pids=()
      local c_rc=0
      local src obj idx=0
      for src in "${srcs[@]}"; do
        obj="$obj_dir/${idx}_$(basename "$src" .c).o"
        idx=$((idx + 1))
        local unit_flags=()
        case "$src" in
          "$REPO_ROOT"/src/*)
            if [ "$(basename "$src")" != "arena.c" ] && [ -f "$FUZZ_ROOT/harnesses/prism/include/fuzz_arena_unslab.h" ]; then
              unit_flags=(-include "$FUZZ_ROOT/harnesses/prism/include/fuzz_arena_unslab.h")
            fi
            ;;
        esac
        (
          "${cc_wrap[@]}" "${flags[@]}" ${unit_flags[@]+"${unit_flags[@]}"} -c "$src" -o "$obj"
        ) &
        pids+=("$!")
        objs+=("$obj")
        if [ "${#pids[@]}" -ge "$vjobs" ]; then
          wait "${pids[0]}" || c_rc=1
          pids=("${pids[@]:1}")
        fi
      done
      local pid
      for pid in "${pids[@]+"${pids[@]}"}"; do
        wait "$pid" || c_rc=1
      done
      if [ "$c_rc" -ne 0 ] || ! "$cc" "${flags[@]}" "${objs[@]}" -o "$tmp_bin"; then
        rm -rf "$obj_dir" "$tmp_bin"
        echo "verify_bucket.sh: failed to compile verify_runner ($profile) against '$REPO_ROOT'" >&2
        exit 125
      fi
      rm -rf "$obj_dir"
    fi
    mv -f "$tmp_bin" "$bin"
    current_fp="$(compute_build_fingerprint "$REPO_ROOT" "$prism_b" "$FUZZ_ROOT" "$cc" "${flags[@]}")"
    local tmp_fp="$fp_file.tmp.$$"
    printf '%s\n' "$current_fp" > "$tmp_fp"
    mv -f "$tmp_fp" "$fp_file"
  fi

  printf '%s\n' "$bin"
}

if [ -z "$RUNNER" ]; then
  RUNNER="$(build_verify_runner "$PROFILE")"
fi

if [ "$BUILD_ONLY" -eq 1 ]; then
  printf '%s\n' "$RUNNER"
  exit 0
fi

max_alloc="${FUZZ_MAX_ALLOCATED:-128}"
hard_rss="${FUZZ_HARD_RSS_LIMIT:-$((max_alloc * 16))}"
sym_flag=""
if [ "$SYMBOLIZE" != "1" ]; then
  sym_flag=":symbolize=0"
fi
leak_flag=""
if [ "$PROFILE" = "diff_parse_y" ] || [ "$PROFILE" = "diff_parse_y_asan" ] || [ "$PROFILE" = "cruby_compile" ] || [ "$PROFILE" = "cruby_compile_asan" ] || [ "$PROFILE" = "cruby_pipeline" ] || [ "$PROFILE" = "cruby_pipeline_asan" ]; then
  leak_flag=":detect_leaks=0:detect_stack_use_after_return=0"
fi
export ASAN_OPTIONS="${ASAN_OPTIONS:-abort_on_error=1:handle_abort=1:handle_segv=2:use_sigaltstack=1${leak_flag}:max_allocation_size_mb=${max_alloc}:hard_rss_limit_mb=${hard_rss}${sym_flag}}"
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-abort_on_error=1:print_stacktrace=1${sym_flag}}"
export MSAN_OPTIONS="${MSAN_OPTIONS:-abort_on_error=1:handle_abort=1:max_allocation_size_mb=${max_alloc}:hard_rss_limit_mb=${hard_rss}${sym_flag}}"
export LSAN_OPTIONS="${LSAN_OPTIONS:-handle_abort=1:max_allocation_size_mb=${max_alloc}:hard_rss_limit_mb=${hard_rss}${sym_flag}}"

args=(--timeout "$TIMEOUT_SEC" --max-failures "$MAX_FAILURES")
if [ -n "$EXTRACT_DIR" ]; then
  mkdir -p "$EXTRACT_DIR"
  args+=(--extract-dir "$EXTRACT_DIR")
fi
[ "$QUIET" -eq 1 ] && args+=(--quiet)
[ "$VERBOSE" -eq 1 ] && args+=(--verbose)
[ "$JSON_MODE" -eq 1 ] && args+=(--json)

if [ "$BUILD_ONLY" -eq 0 ] && [ "$SKIP_MIN" -eq 1 ] && [ "$INPUT_MIN_ONLY" -eq 1 ]; then
  echo "verify_bucket.sh: --input-min-only and --skip-min cannot be combined" >&2
  exit 2
fi

if [ "$INPUT_MIN_ONLY" -eq 1 ]; then
  if [ -f "$BUCKET_DIR/input.min" ]; then
    args+=("$BUCKET_DIR/input.min")
  fi
  exec "$RUNNER" "${args[@]}"
fi

if [ "$SKIP_MIN" -eq 0 ] && [ -f "$BUCKET_DIR/input.min" ]; then
  args+=("$BUCKET_DIR/input.min")
fi

if [ -f "$BUCKET_DIR/.inputs.pending" ] && [ -s "$BUCKET_DIR/.inputs.pending" ]; then
  args+=(--pack "$BUCKET_DIR/.inputs.pending")
fi

if [ -f "$BUCKET_DIR/inputs.tar.gz" ]; then
  set +e
  gzip -dc "$BUCKET_DIR/inputs.tar.gz" | "$RUNNER" "${args[@]}" --tar -
  pipe_rcs=("${PIPESTATUS[@]}")
  set -e
  gzip_rc="${pipe_rcs[0]:-0}"
  runner_rc="${pipe_rcs[1]:-1}"
  if [ "$gzip_rc" -ne 0 ] && [ "$gzip_rc" -ne 141 ]; then
    echo "verify_bucket.sh: failed to decompress '$BUCKET_DIR/inputs.tar.gz' (gzip exit=$gzip_rc)" >&2
    exit 2
  fi
  exit "$runner_rc"
fi

shopt -s nullglob
raw_files=("$BUCKET_DIR"/id*)
for f in ${raw_files[@]+"${raw_files[@]}"}; do
  if [ -f "$f" ]; then
    args+=("$f")
  fi
done

exec "$RUNNER" "${args[@]}"
