#!/usr/bin/env bash
set -euo pipefail

MODE="fuzz"
FUZZ_ROOT=""
RUBY_DIR="${RUBY_ORACLE_DIR:-/opt/ruby}"
ORACLE_DIR=""
OUTPUT=""
AFL_PATH_ARG=""
CC_BIN="${CC:-clang}"
MAX_INPUT_SIZE="${FUZZ_MAX_INPUT_SIZE:-1024}"
PIPELINE_DIFF=0
EXTRA_CFLAGS=()

usage() {
  cat <<'EOF'
Usage: build_cruby_compile.sh --mode {fuzz|verify} --output FILE [OPTIONS]
  --mode MODE             fuzz (AFL PCGUARD) or verify (verify_runner)
  --pipeline-diff         Instrument parse.o + prism.o + compile.o + iseq.o and enable 4-stage pipeline diff
  --fuzz-root DIR         Fuzz harness repository root
  --ruby-dir DIR          Built CRuby static source tree (default: /opt/ruby)
  --oracle-dir DIR        Cache directory for libcruby_compile.a and objects
  --afl-path DIR          AFL++ instrumentation directory (required for --mode fuzz)
  --cc BIN                C compiler (for --mode verify; default: $CC or clang)
  --max-input-size N      FUZZ_MAX_INPUT_SIZE value (default: 1024)
  --cflag FLAG            Extra C compiler flag for harness sources (repeatable)
  --output FILE           Output binary path
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --mode)
      MODE="${2:-}"; shift 2 ;;
    --pipeline-diff)
      PIPELINE_DIFF=1; shift ;;
    --fuzz-root)
      FUZZ_ROOT="${2:-}"; shift 2 ;;
    --ruby-dir)
      RUBY_DIR="${2:-}"; shift 2 ;;
    --oracle-dir)
      ORACLE_DIR="${2:-}"; shift 2 ;;
    --afl-path)
      AFL_PATH_ARG="${2:-}"; shift 2 ;;
    --cc)
      CC_BIN="${2:-}"; shift 2 ;;
    --max-input-size)
      MAX_INPUT_SIZE="${2:-}"; shift 2 ;;
    --cflag)
      EXTRA_CFLAGS+=("${2:-}"); shift 2 ;;
    --output)
      OUTPUT="${2:-}"; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "build_cruby_compile.sh: unknown option '$1'" >&2
      usage >&2
      exit 2 ;;
  esac
done

if [ -z "$OUTPUT" ]; then
  echo "build_cruby_compile.sh: --output is required" >&2
  usage >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_FUZZ_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
if [ -z "$FUZZ_ROOT" ]; then
  FUZZ_ROOT="$DEFAULT_FUZZ_ROOT"
fi

if [ -z "$ORACLE_DIR" ]; then
  if [ "$PIPELINE_DIFF" -eq 1 ]; then
    ORACLE_DIR="$(dirname "$OUTPUT")/pipeline-oracle"
  else
    ORACLE_DIR="$(dirname "$OUTPUT")/compile-oracle"
  fi
fi

if [ ! -f "$RUBY_DIR/libruby-static.a" ] || [ ! -f "$RUBY_DIR/compile.c" ] || [ ! -f "$RUBY_DIR/iseq.c" ]; then
  echo "build_cruby_compile.sh: CRuby static tree not found under '$RUBY_DIR' (missing libruby-static.a, compile.c, or iseq.c)" >&2
  exit 2
fi

if [ "$PIPELINE_DIFF" -eq 1 ] && { [ ! -f "$RUBY_DIR/parse.c" ] || [ ! -f "$RUBY_DIR/prism/prism.c" ]; }; then
  echo "build_cruby_compile.sh: CRuby static tree under '$RUBY_DIR' missing parse.c or prism/prism.c for --pipeline-diff" >&2
  exit 2
fi

req_members=(compile.o iseq.o)
if [ "$PIPELINE_DIFF" -eq 1 ]; then
  req_members+=(parse.o prism.o)
fi
archive_members="$(ar t "$RUBY_DIR/libruby-static.a")"
for req_member in "${req_members[@]}"; do
  if ! printf '%s\n' "$archive_members" | grep -qx "$req_member"; then
    echo "build_cruby_compile.sh: $req_member member not found in '$RUBY_DIR/libruby-static.a'" >&2
    exit 2
  fi
done

if [ "$MODE" = "fuzz" ] && [ -z "$AFL_PATH_ARG" ]; then
  AFL_PATH_ARG="$FUZZ_ROOT/build/afl"
fi

mkdir -p "$ORACLE_DIR" "$(dirname "$OUTPUT")"

COMPILE_TMP_WORK="$(mktemp -d "${TMPDIR:-/tmp}/pf-compile.XXXXXX")"
cleanup_compile_tmp() {
  rm -rf "$COMPILE_TMP_WORK"
}
trap cleanup_compile_tmp EXIT

with_oracle_lock() {
  local lock_file="$ORACLE_DIR/.oracle.lock"
  if command -v flock >/dev/null 2>&1; then
    (
      exec 9>"$lock_file"
      flock 9
      "$@"
    )
  else
    local lock_dir="$ORACLE_DIR/.oracle.lockdir"
    while ! mkdir "$lock_dir" 2>/dev/null; do
      sleep 0.05
    done
    local rc=0
    "$@" || rc=$?
    rmdir "$lock_dir" 2>/dev/null || true
    return $rc
  fi
}

resolve_writable_ccache_dir() {
  local cand
  for cand in "${CCACHE_DIR:-}" "/ccache" "$FUZZ_ROOT/.cache/ccache" "${TMPDIR:-/tmp}/prism-fuzzer-ccache-$(id -u)"; do
    [ -n "$cand" ] || continue
    if mkdir -p "$cand" 2>/dev/null && [ -w "$cand" ]; then
      printf '%s\n' "$cand"
      return 0
    fi
  done
  return 1
}

RUBY_ARCH="$(ruby -rrbconfig -e 'puts RbConfig::CONFIG.fetch("arch")')"
mapfile -t MAINLIBS_ARR < <(ruby -rrbconfig -rshellwords -e 'Shellwords.split(RbConfig::CONFIG["MAINLIBS"] || "").each { |t| puts t }')
mapfile -t COMPILE_CPP_FLAGS < <(ruby -rshellwords -e '
  ruby_dir = ARGV[0]
  make_out = IO.popen(["make", "-C", ruby_dir, "-n", "-W", "parse.c", "parse.o"], err: [:child, :out], &:read)
  compile_line = make_out.lines.reverse.find { |l| l.include?(" -c ") && l.include?("parse.c") }
  abort "Failed to inspect compile flags from #{ruby_dir}/Makefile" unless compile_line

  out = []
  Shellwords.split(compile_line).each do |tok|
    if tok.start_with?("-I")
      path = tok[2..]
      full = path.start_with?("/") ? path : File.expand_path(path, ruby_dir)
      out << "-I#{full}"
    elsif tok.start_with?("-D", "-U")
      out << tok
    end
  end
  prism_inc = File.join(ruby_dir, "prism")
  out << "-I#{prism_inc}" if File.directory?(prism_inc) && !out.include?("-I#{prism_inc}")
  out << "-DPRISM_XALLOCATOR" unless out.any? { |t| t.start_with?("-DPRISM_XALLOCATOR") }
  out.uniq.each { |t| puts t }
' "$RUBY_DIR")
RUBY_COMPILE_FLAGS="${COMPILE_CPP_FLAGS[*]}"

PRISM_CPP_FLAGS=()
RUBY_PRISM_FLAGS=""
if [ "$PIPELINE_DIFF" -eq 1 ]; then
  mapfile -t PRISM_CPP_FLAGS < <(ruby -rshellwords -e '
    ruby_dir = ARGV[0]
    make_out = IO.popen(["make", "-C", ruby_dir, "-n", "-W", "prism/prism.c", "prism/prism.o"], err: [:child, :out], &:read)
    compile_line = make_out.lines.reverse.find { |l| l.include?(" -c ") && l.include?("prism.c") }
    out = []
    if compile_line
      Shellwords.split(compile_line).each do |tok|
        if tok.start_with?("-I")
          path = tok[2..]
          full = path.start_with?("/") ? path : File.expand_path(path, ruby_dir)
          out << "-I#{full}"
        elsif tok.start_with?("-D", "-U")
          out << tok
        end
      end
    end
    [File.join(ruby_dir, "prism", "include"), File.join(ruby_dir, "prism")].each do |inc|
      out << "-I#{inc}" if File.directory?(inc) && !out.include?("-I#{inc}")
    end
    out << "-DPRISM_XALLOCATOR" unless out.any? { |t| t.start_with?("-DPRISM_XALLOCATOR") }
    out.uniq.each { |t| puts t }
  ' "$RUBY_DIR")
  RUBY_PRISM_FLAGS="${PRISM_CPP_FLAGS[*]}"
fi

RUBY_EMBED_INC=(
  "-I$RUBY_DIR/.ext/include/$RUBY_ARCH"
  "-I$RUBY_DIR/include"
)

EXTRA_LDFLAGS=()
for flag in "${EXTRA_CFLAGS[@]+"${EXTRA_CFLAGS[@]}"}"; do
  case "$flag" in
    -fsanitize*|-fno-sanitize*|-fprofile*|-fcoverage*|-L*|-Wl,*|-l*|-pthread|-m*|-static*)
      EXTRA_LDFLAGS+=("$flag")
      ;;
  esac
done

extra_cflags_defines_macro() {
  local name=$1
  local prev=""
  local flag
  for flag in "${EXTRA_CFLAGS[@]+"${EXTRA_CFLAGS[@]}"}"; do
    if [ "$prev" = "-D" ]; then
      case "$flag" in
        "$name"|"$name="*) return 0 ;;
      esac
      prev=""
      continue
    fi
    case "$flag" in
      -D) prev="-D" ;;
      "-D$name"|"-D$name="*) return 0 ;;
    esac
  done
  return 1
}

if [ "$MODE" = "fuzz" ]; then
  TARGET_CC=(env "AFL_PATH=$AFL_PATH_ARG" "AFL_LLVM_INSTRUMENT=PCGUARD" afl-clang-fast)
  ORACLE_DEP="$AFL_PATH_ARG/SanitizerCoveragePCGUARD.so"
  if [ ! -f "$ORACLE_DEP" ]; then
    echo "build_cruby_compile.sh: missing AFL PCGUARD pass '$ORACLE_DEP' (run ./campaigns/default.rb build / make build first)" >&2
    exit 2
  fi
else
  TARGET_CC=("$CC_BIN")
  ORACLE_DEP="$(command -v "$CC_BIN" 2>/dev/null || printf '%s' "$CC_BIN")"
fi

ORACLE_MODE="host"
if [ "$MODE" = "fuzz" ]; then
  ORACLE_MODE="fuzz"
fi

probe_cc_supports() {
  local probe_obj="$COMPILE_TMP_WORK/.flag-probe.$$.$RANDOM.o"
  rm -f "$probe_obj"
  if printf '#include <string.h>\nint compile_flag_probe(void) { return 0; }\n' \
      | "${TARGET_CC[@]}" -x c -O2 "$@" -Werror -c - -o "$probe_obj" >/dev/null 2>&1; then
    rm -f "$probe_obj"
    return 0
  fi
  rm -f "$probe_obj"
  return 1
}

HAS_EXPLICIT_O0=0
for flag in "${EXTRA_CFLAGS[@]+"${EXTRA_CFLAGS[@]}"}"; do
  if [ "$flag" = "-O0" ]; then
    HAS_EXPLICIT_O0=1
    break
  fi
done

extra_cflags_uses_asan() {
  local flag
  for flag in "${EXTRA_CFLAGS[@]+"${EXTRA_CFLAGS[@]}"}"; do
    case "$flag" in
      -fsanitize=*address*) return 0 ;;
    esac
  done
  return 1
}

WANT_ASAN_UAR=0
if [ "${AFL_USE_ASAN:-0}" = "1" ] || extra_cflags_uses_asan; then
  WANT_ASAN_UAR=1
fi

ENABLE_RUBY_ASSERT=1
if extra_cflags_defines_macro FUZZ_NO_RUBY_ASSERT; then
  ENABLE_RUBY_ASSERT=0
fi

probe_cache_key="$(ruby -rdigest -e 'puts Digest::SHA256.hexdigest(ARGV.join("\0"))[0, 16]' \
  "${FUZZ_IMAGE_ID:-}" "${TARGET_CC[*]}" "$HAS_EXPLICIT_O0" "$WANT_ASAN_UAR" "$ORACLE_DEP")"
PROBE_CACHE_FILE="$ORACLE_DIR/.cc-probes.$probe_cache_key.sh"

if [ -f "$PROBE_CACHE_FILE" ]; then
  # shellcheck disable=SC1090
  source "$PROBE_CACHE_FILE"
else
  HARDEN_CFLAGS=()
  if probe_cc_supports -fstack-protector-strong; then
    HARDEN_CFLAGS+=(-fstack-protector-strong)
  fi
  if [ "$HAS_EXPLICIT_O0" -eq 0 ]; then
    if probe_cc_supports -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3; then
      HARDEN_CFLAGS+=(-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3)
    elif probe_cc_supports -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2; then
      HARDEN_CFLAGS+=(-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2)
    fi
  fi
  if probe_cc_supports -ftrivial-auto-var-init=pattern; then
    HARDEN_CFLAGS+=(-ftrivial-auto-var-init=pattern)
  fi

  UBS_TRAP_STYLE=""
  if probe_cc_supports -fsanitize=unreachable -fsanitize-trap=unreachable; then
    UBS_TRAP_STYLE="per-check"
  elif probe_cc_supports -fsanitize=unreachable -fsanitize-undefined-trap-on-error; then
    UBS_TRAP_STYLE="gcc-all"
  fi

  probe_trap_ubsan_flags() {
    [ -n "$UBS_TRAP_STYLE" ] || return 0

    local enabled=()
    local check
    for check in "$@"; do
      if [ "$UBS_TRAP_STYLE" = "per-check" ]; then
        if probe_cc_supports "-fsanitize=$check" "-fsanitize-trap=$check"; then
          enabled+=("$check")
        fi
      else
        if probe_cc_supports "-fsanitize=$check" -fsanitize-undefined-trap-on-error; then
          enabled+=("$check")
        fi
      fi
    done

    if [ "${#enabled[@]}" -gt 0 ]; then
      local joined
      joined="$(IFS=,; printf '%s' "${enabled[*]}")"
      if [ "$UBS_TRAP_STYLE" = "per-check" ]; then
        printf '%s\n' "-fsanitize=$joined" "-fsanitize-trap=$joined"
      else
        printf '%s\n' "-fsanitize=$joined" "-fsanitize-undefined-trap-on-error"
      fi
    fi
  }

  ASAN_UAR_FLAGS=()
  if [ "$WANT_ASAN_UAR" -eq 1 ]; then
    if probe_cc_supports -fsanitize=address -fsanitize-address-use-after-return=never; then
      ASAN_UAR_FLAGS=(-fsanitize-address-use-after-return=never)
    fi
  fi

  # Omit signed-integer-overflow and null on CRuby compile.c (-fno-strict-overflow;
  # NULL dereference bugs like compile_keyword_arg should emit clean SIGSEGV backtraces).
  mapfile -t BASE_COMPILE_TRAP_FLAGS < <(probe_trap_ubsan_flags \
    unreachable bounds local-bounds object-size return shift-exponent vla-bound)
  mapfile -t HARNESS_SAN_FLAGS < <(probe_trap_ubsan_flags \
    unreachable bounds local-bounds object-size null return shift-exponent shift-base signed-integer-overflow pointer-overflow vla-bound)

  tmp_probe_cache="$COMPILE_TMP_WORK/cc-probes.sh"
  {
    declare -p HARDEN_CFLAGS ASAN_UAR_FLAGS BASE_COMPILE_TRAP_FLAGS HARNESS_SAN_FLAGS
  } > "$tmp_probe_cache"
  mv -f "$tmp_probe_cache" "$PROBE_CACHE_FILE" 2>/dev/null || true
fi

COMPILE_HARDEN_FLAGS=("${BASE_COMPILE_TRAP_FLAGS[@]+"${BASE_COMPILE_TRAP_FLAGS[@]}"}" "${HARDEN_CFLAGS[@]+"${HARDEN_CFLAGS[@]}"}")
if [ "${AFL_USE_ASAN:-0}" = "1" ] && [ "${#ASAN_UAR_FLAGS[@]}" -gt 0 ]; then
  COMPILE_HARDEN_FLAGS+=("${ASAN_UAR_FLAGS[@]}")
fi

ORACLE_STAMP_FILE="$ORACLE_DIR/.oracle.stamp"
ORACLE_PREFIX="libcruby_compile"
if [ "$PIPELINE_DIFF" -eq 1 ]; then
  ORACLE_PREFIX="libcruby_pipeline"
fi
ORACLE_ARCHIVE="$ORACLE_DIR/$ORACLE_PREFIX.a"

prism_compile_dep="$RUBY_DIR/prism_compile.c"
oracle_fp_deps=(
  "$RUBY_DIR/libruby-static.a"
  "$RUBY_DIR/compile.c"
  "$prism_compile_dep"
  "$RUBY_DIR/iseq.c"
  "$ORACLE_DEP"
)
if [ "$PIPELINE_DIFF" -eq 1 ]; then
  oracle_fp_deps+=("$RUBY_DIR/parse.c" "$RUBY_DIR/prism/prism.c")
fi
oracle_fp="$(ruby -rdigest -e '
  files = ARGV[2..]
  d = Digest::SHA256.new
  d.update("#{ARGV[0]}\0#{ARGV[1]}\0#{ENV.fetch("FUZZ_IMAGE_ID", "")}\0")
  files.each do |f|
    if File.file?(f)
      st = File.stat(f)
      d.update("#{f}\0#{st.size}\0#{st.mtime.tv_sec}\0#{st.mtime.nsec}\0")
    else
      d.update("missing:#{f}\0")
    end
  end
  puts d.hexdigest
' "$ORACLE_MODE" "$PIPELINE_DIFF|$ENABLE_RUBY_ASSERT|$RUBY_COMPILE_FLAGS|$RUBY_PRISM_FLAGS|${COMPILE_HARDEN_FLAGS[*]+"${COMPILE_HARDEN_FLAGS[*]}"}" \
  "${oracle_fp_deps[@]}")"

KEYED_ORACLE_ARCHIVE="$ORACLE_DIR/$ORACLE_PREFIX.${oracle_fp:0:16}.a"

setup_cc_runner() {
  CC_RUNNER=("${TARGET_CC[@]}")
  if [ "${FUZZ_CCACHE:-1}" != "0" ] && command -v ccache >/dev/null 2>&1; then
    local cdir=""
    if cdir="$(resolve_writable_ccache_dir)"; then
      local ns="cruby_compile|pipe=$PIPELINE_DIFF|mode=$MODE|img=${FUZZ_IMAGE_ID:-}|dep=$ORACLE_DEP|ijon=${AFL_LLVM_IJON:-0}|asan=${AFL_USE_ASAN:-0}|ubsan=${AFL_USE_UBSAN:-0}"
      if [ "${TARGET_CC[0]}" = "env" ]; then
        CC_RUNNER=("env" "CCACHE_DIR=$cdir" "CCACHE_NOHASHDIR=1" "CCACHE_NAMESPACE=$ns" "${TARGET_CC[@]:1:2}" "ccache" "${TARGET_CC[@]:3}")
      else
        CC_RUNNER=("env" "CCACHE_DIR=$cdir" "CCACHE_NOHASHDIR=1" "CCACHE_NAMESPACE=$ns" "ccache" "${TARGET_CC[@]}")
      fi
    fi
  fi
}

ensure_oracle_archive() {
  if [ ! -f "$KEYED_ORACLE_ARCHIVE" ]; then
    local tmp_compile_o="$COMPILE_TMP_WORK/compile.o"
    local tmp_iseq_o="$COMPILE_TMP_WORK/iseq.o"
    local tmp_parse_o="$COMPILE_TMP_WORK/parse.o"
    local tmp_prism_o="$COMPILE_TMP_WORK/prism.o"
    local tmp_assert_h="$COMPILE_TMP_WORK/force_ruby_assert.h"
    local tmp_archive="$COMPILE_TMP_WORK/$ORACLE_PREFIX.a"
    rm -f "$tmp_compile_o" "$tmp_iseq_o" "$tmp_parse_o" "$tmp_prism_o" "$tmp_assert_h" "$tmp_archive"

    local assert_flags=()
    if [ "$ENABLE_RUBY_ASSERT" -eq 1 ]; then
      # Enable RUBY_ASSERT across parse.c, compile.c, prism_compile.c, and iseq.c without
      # defining RUBY_DEBUG=1 or VM_CHECK_MODE=1 (which alter VM/Ractor struct layouts).
      cat <<'EOF' > "$tmp_assert_h"
#include "ruby/internal/config.h"
#include "ruby/assert.h"
#undef RBIMPL_ASSERT_OR_ASSUME
#define RBIMPL_ASSERT_OR_ASSUME RUBY_ASSERT_ALWAYS
EOF
      assert_flags=(-include "$tmp_assert_h")
    fi

    setup_cc_runner
    local pids=()
    local archive_objs=(compile.o iseq.o)

    "${CC_RUNNER[@]}" \
      -O2 -ggdb3 -gdwarf-4 -fno-strict-overflow -fvisibility=hidden -fPIE -w \
      "${COMPILE_CPP_FLAGS[@]}" \
      ${assert_flags[@]+"${assert_flags[@]}"} \
      ${COMPILE_HARDEN_FLAGS[@]+"${COMPILE_HARDEN_FLAGS[@]}"} \
      -c "$RUBY_DIR/compile.c" -o "$tmp_compile_o" &
    pids+=("$!")

    "${CC_RUNNER[@]}" \
      -O2 -ggdb3 -gdwarf-4 -fno-strict-overflow -fvisibility=hidden -fPIE -w \
      "${COMPILE_CPP_FLAGS[@]}" \
      ${assert_flags[@]+"${assert_flags[@]}"} \
      ${COMPILE_HARDEN_FLAGS[@]+"${COMPILE_HARDEN_FLAGS[@]}"} \
      -c "$RUBY_DIR/iseq.c" -o "$tmp_iseq_o" &
    pids+=("$!")

    if [ "$PIPELINE_DIFF" -eq 1 ]; then
      local prism_assert_flags=()
      if [ "$ENABLE_RUBY_ASSERT" -eq 1 ]; then
        prism_assert_flags=(-UNDEBUG)
      fi

      "${CC_RUNNER[@]}" \
        -O2 -ggdb3 -gdwarf-4 -fno-strict-overflow -fvisibility=hidden -fPIE -w \
        "${COMPILE_CPP_FLAGS[@]}" \
        ${assert_flags[@]+"${assert_flags[@]}"} \
        ${COMPILE_HARDEN_FLAGS[@]+"${COMPILE_HARDEN_FLAGS[@]}"} \
        -c "$RUBY_DIR/parse.c" -o "$tmp_parse_o" &
      pids+=("$!")

      "${CC_RUNNER[@]}" \
        -O2 -ggdb3 -gdwarf-4 -fno-strict-overflow -fvisibility=hidden -fPIE -w \
        "${PRISM_CPP_FLAGS[@]}" \
        ${prism_assert_flags[@]+"${prism_assert_flags[@]}"} \
        ${COMPILE_HARDEN_FLAGS[@]+"${COMPILE_HARDEN_FLAGS[@]}"} \
        -c "$RUBY_DIR/prism/prism.c" -o "$tmp_prism_o" &
      pids+=("$!")

      archive_objs=(parse.o prism.o compile.o iseq.o)
    fi

    local pid
    for pid in "${pids[@]}"; do
      wait "$pid"
    done

    cp "$RUBY_DIR/libruby-static.a" "$tmp_archive"
    (cd "$COMPILE_TMP_WORK" && ar r "$tmp_archive" "${archive_objs[@]}" && rm -f "${archive_objs[@]}")
    ranlib "$tmp_archive"

    local staged="$KEYED_ORACLE_ARCHIVE.tmp.$$"
    cp "$tmp_archive" "$staged"
    mv -f "$staged" "$KEYED_ORACLE_ARCHIVE"
  fi

  if [ ! -f "$ORACLE_ARCHIVE" ] || [ ! -f "$ORACLE_STAMP_FILE" ] || [ "$(cat "$ORACLE_STAMP_FILE" 2>/dev/null)" != "$oracle_fp" ]; then
    ln -f "$KEYED_ORACLE_ARCHIVE" "$ORACLE_ARCHIVE" 2>/dev/null || cp -f "$KEYED_ORACLE_ARCHIVE" "$ORACLE_ARCHIVE"
    local tmp_st="$ORACLE_STAMP_FILE.tmp.$$"
    printf '%s\n' "$oracle_fp" > "$tmp_st"
    mv -f "$tmp_st" "$ORACLE_STAMP_FILE"
  fi
}

if [ ! -f "$KEYED_ORACLE_ARCHIVE" ] || [ ! -f "$ORACLE_ARCHIVE" ] || [ ! -f "$ORACLE_STAMP_FILE" ] || [ "$(cat "$ORACLE_STAMP_FILE" 2>/dev/null)" != "$oracle_fp" ]; then
  with_oracle_lock ensure_oracle_archive
fi

LINK_EXPORT_FLAGS=()
if [ "$(uname -s)" = "Linux" ]; then
  LINK_EXPORT_FLAGS=("-Wl,--export-dynamic")
fi

mapfile -t PROVENANCE_CFLAGS < <(ruby -r"${FUZZ_ROOT}/runtime/provenance" -e '
  fuzz_root, ruby_dir, c, d = ARGV
  if c.to_s.empty? || c == "unknown"
    git = FuzzProvenance.detect_git_state(fuzz_root, paths: FuzzProvenance::GIT_DIRTY_PATHS)
    c = git["git_commit"] if git && git["git_commit"]
    d = git["git_dirty"] ? "1" : "0" if git && !git["git_dirty"].nil? && (d.to_s.empty? || d == "unknown")
  end
  c = "unknown" if c.to_s.empty? || !c.match?(/\A[0-9a-fA-F]{7,40}\z/)
  d = "unknown" unless %w[0 1].include?(d.to_s)
  puts "-DFUZZ_GIT_COMMIT=#{c}"
  puts "-DFUZZ_GIT_DIRTY=#{d}"

  oracle = FuzzProvenance.detect_oracle_dir_versions(ruby_dir) || {}
  {
    "FUZZ_RUBY_VERSION" => oracle["version"],
    "FUZZ_RUBY_REVISION" => oracle["revision"],
    "FUZZ_RUBY_RELEASE_DATE" => oracle["release_date"]
  }.each do |macro, val|
    next if val.nil? || val.empty? || !val.match?(/\A[0-9A-Za-z._-]+\z/)

    puts %(-D#{macro}="#{val}")
  end
' "$FUZZ_ROOT" "$RUBY_DIR" "${FUZZ_GIT_COMMIT:-}" "${FUZZ_GIT_DIRTY:-}")

setup_cc_runner
HARNESS_SRC="$FUZZ_ROOT/harnesses/prism/cruby_compile.c"

if [ "$MODE" = "fuzz" ]; then
  HARNESS_OBJ="$COMPILE_TMP_WORK/cruby_compile.o"
  HARNESS_CFLAGS=(
    -g -gdwarf-4 -O2 -std=gnu99 -Wall -Wextra -Werror -Wno-unused-parameter -fPIE
    ${ASAN_UAR_FLAGS[@]+"${ASAN_UAR_FLAGS[@]}"}
    ${HARDEN_CFLAGS[@]+"${HARDEN_CFLAGS[@]}"}
    ${HARNESS_SAN_FLAGS[@]+"${HARNESS_SAN_FLAGS[@]}"}
    ${PROVENANCE_CFLAGS[@]+"${PROVENANCE_CFLAGS[@]}"}
    "-I$FUZZ_ROOT/harnesses/prism"
    "-I$FUZZ_ROOT/harnesses/prism/include"
    "${RUBY_EMBED_INC[@]}"
  )
  extra_cflags_defines_macro FUZZ_MAX_INPUT_SIZE || HARNESS_CFLAGS+=("-DFUZZ_MAX_INPUT_SIZE=$MAX_INPUT_SIZE")
  if [ "$PIPELINE_DIFF" -eq 1 ]; then
    HARNESS_CFLAGS+=(-DFUZZ_CRUBY_PIPELINE_DIFF)
  fi
  HARNESS_CFLAGS+=(${EXTRA_CFLAGS[@]+"${EXTRA_CFLAGS[@]}"})
  "${CC_RUNNER[@]}" "${HARNESS_CFLAGS[@]}" -c "$HARNESS_SRC" -o "$HARNESS_OBJ"

  tmp_out="$OUTPUT.tmp.$$"
  tmp_map="$COMPILE_TMP_WORK/link.map"
  tmp_ids="$OUTPUT.ids.tmp.$$"
  rm -f "$tmp_out" "$tmp_map" "$tmp_ids"
  MAP_FLAGS=()
  if [ "$(uname -s)" = "Linux" ]; then
    MAP_FLAGS=("-Wl,-Map=$tmp_map")
  fi
  "${TARGET_CC[@]}" \
    -g -gdwarf-4 -O2 -fPIE "${LINK_EXPORT_FLAGS[@]}" ${MAP_FLAGS[@]+"${MAP_FLAGS[@]}"} \
    ${EXTRA_LDFLAGS[@]+"${EXTRA_LDFLAGS[@]}"} \
    "$HARNESS_OBJ" "$KEYED_ORACLE_ARCHIVE" \
    "${MAINLIBS_ARR[@]}" \
    -o "$tmp_out"
  if [ -f "$tmp_map" ]; then
    ruby "$FUZZ_ROOT/harnesses/prism/gen_diff_ids.rb" \
      --bin "$tmp_out" \
      --map "$tmp_map" \
      --archive "$KEYED_ORACLE_ARCHIVE" \
      --output "$tmp_ids"
    rm -f "$tmp_map"
    mv -f "$tmp_ids" "$OUTPUT.ids"
  fi
  mv -f "$tmp_out" "$OUTPUT"
elif [ "$MODE" = "verify" ]; then
  OBJ_DIR="$COMPILE_TMP_WORK/verify_objs"
  mkdir -p "$OBJ_DIR"
  HARNESS_OBJ="$OBJ_DIR/cruby_compile.o"
  RUNNER_OBJ="$OBJ_DIR/verify_runner.o"

  VERIFY_CFLAGS=(
    -O1 -fno-omit-frame-pointer -ggdb3 -gdwarf-4 -std=gnu99
    -Wall -Wextra -Werror -Wno-unused-parameter -fPIE -DPRISM_DIFF_NO_MAIN
    ${ASAN_UAR_FLAGS[@]+"${ASAN_UAR_FLAGS[@]}"}
    ${HARDEN_CFLAGS[@]+"${HARDEN_CFLAGS[@]}"}
    ${HARNESS_SAN_FLAGS[@]+"${HARNESS_SAN_FLAGS[@]}"}
    ${PROVENANCE_CFLAGS[@]+"${PROVENANCE_CFLAGS[@]}"}
    "-I$FUZZ_ROOT/harnesses/prism"
    "-I$FUZZ_ROOT/harnesses/prism/include"
    "${RUBY_EMBED_INC[@]}"
  )
  extra_cflags_defines_macro FUZZ_MAX_INPUT_SIZE || VERIFY_CFLAGS+=("-DFUZZ_MAX_INPUT_SIZE=$MAX_INPUT_SIZE")
  if [ "$PIPELINE_DIFF" -eq 1 ]; then
    VERIFY_CFLAGS+=(-DFUZZ_CRUBY_PIPELINE_DIFF)
  fi
  VERIFY_CFLAGS+=(${EXTRA_CFLAGS[@]+"${EXTRA_CFLAGS[@]}"})
  "${CC_RUNNER[@]}" "${VERIFY_CFLAGS[@]}" -c "$HARNESS_SRC" -o "$HARNESS_OBJ"

  "${CC_RUNNER[@]}" \
    -O1 -fno-omit-frame-pointer -ggdb3 -gdwarf-4 -std=gnu99 \
    -Wall -Wextra -Wno-unused-parameter -fPIE \
    ${ASAN_UAR_FLAGS[@]+"${ASAN_UAR_FLAGS[@]}"} \
    ${HARDEN_CFLAGS[@]+"${HARDEN_CFLAGS[@]}"} \
    ${HARNESS_SAN_FLAGS[@]+"${HARNESS_SAN_FLAGS[@]}"} \
    ${EXTRA_CFLAGS[@]+"${EXTRA_CFLAGS[@]}"} \
    -c "$FUZZ_ROOT/triage/verify_runner.c" -o "$RUNNER_OBJ"

  tmp_out="$OUTPUT.tmp.$$"
  rm -f "$tmp_out"
  "$CC_BIN" \
    -O1 -fno-omit-frame-pointer -ggdb3 -gdwarf-4 -fPIE "${LINK_EXPORT_FLAGS[@]}" \
    ${EXTRA_LDFLAGS[@]+"${EXTRA_LDFLAGS[@]}"} \
    "$RUNNER_OBJ" "$HARNESS_OBJ" "$KEYED_ORACLE_ARCHIVE" \
    "${MAINLIBS_ARR[@]}" \
    -o "$tmp_out"
  mv -f "$tmp_out" "$OUTPUT"
else
  echo "build_cruby_compile.sh: invalid --mode '$MODE' (expected fuzz or verify)" >&2
  exit 2
fi
