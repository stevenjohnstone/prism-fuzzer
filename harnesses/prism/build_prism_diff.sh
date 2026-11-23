#!/usr/bin/env bash
set -euo pipefail

MODE="fuzz"
PRISM_A_ROOT=""
PRISM_B_ROOT=""
FUZZ_ROOT=""
WORK_DIR=""
OUTPUT=""
AFL_PATH_ARG=""
CC_BIN="${CC:-clang}"
MAX_INPUT_SIZE="${FUZZ_MAX_INPUT_SIZE:-1024}"
EXTRA_CFLAGS=()

usage() {
  cat <<'EOF'
Usage: build_prism_diff.sh --mode {fuzz|verify} --prism-a DIR --prism-b DIR --output FILE [OPTIONS]
  --mode MODE             fuzz (AFL PCGUARD) or verify (verify_runner)
  --prism-a DIR           First Prism root (reference / baseline)
  --prism-b DIR           Second Prism root (candidate / optimized)
  --fuzz-root DIR         prism-fuzzer root containing harnesses/prism
  --work-dir DIR          Intermediate object cache directory
  --afl-path DIR          AFL++ instrumentation directory (required for --mode fuzz)
  --cc BIN                C compiler (for --mode verify; default: $CC or clang)
  --max-input-size N      FUZZ_MAX_INPUT_SIZE (default: 1024)
  --cflag FLAG            Extra compiler flag (repeatable)
  --output FILE           Output binary path
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --mode) MODE="${2:-}"; shift 2 ;;
    --prism-a) PRISM_A_ROOT="${2:-}"; shift 2 ;;
    --prism-b) PRISM_B_ROOT="${2:-}"; shift 2 ;;
    --fuzz-root) FUZZ_ROOT="${2:-}"; shift 2 ;;
    --work-dir) WORK_DIR="${2:-}"; shift 2 ;;
    --afl-path) AFL_PATH_ARG="${2:-}"; shift 2 ;;
    --cc) CC_BIN="${2:-}"; shift 2 ;;
    --max-input-size) MAX_INPUT_SIZE="${2:-}"; shift 2 ;;
    --cflag) EXTRA_CFLAGS+=("${2:-}"); shift 2 ;;
    --output) OUTPUT="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "build_prism_diff.sh: unknown option '$1'" >&2; exit 2 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -n "$FUZZ_ROOT" ] || FUZZ_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
[ -n "$PRISM_A_ROOT" ] && [ -n "$PRISM_B_ROOT" ] && [ -n "$OUTPUT" ] || { usage >&2; exit 2; }
[ -n "$WORK_DIR" ] || WORK_DIR="$(dirname "$OUTPUT")/prism-diff-build"
[ -n "$AFL_PATH_ARG" ] || AFL_PATH_ARG="$FUZZ_ROOT/build/afl"

mkdir -p "$WORK_DIR" "$(dirname "$OUTPUT")"

if [ "$MODE" = "fuzz" ]; then
  PRISM_CC=(env "AFL_PATH=$AFL_PATH_ARG" "AFL_LLVM_INSTRUMENT=PCGUARD" afl-clang-fast)
else
  PRISM_CC=("$CC_BIN")
fi

# Note: Mac/BSD nm/objcopy vs Linux ELF llvm-objcopy/objcopy compatibility:
OBJCOPY_BIN="$(command -v objcopy || command -v llvm-objcopy || true)"
NM_BIN="$(command -v nm || command -v llvm-nm || true)"
[ -n "$OBJCOPY_BIN" ] && [ -n "$NM_BIN" ] || { echo "build_prism_diff.sh: need objcopy and nm" >&2; exit 2; }

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

ASAN_NO_DEAD_STRIP=()
if [ "${AFL_USE_ASAN:-0}" = "1" ]; then
  if "${PRISM_CC[@]}" -fno-sanitize-address-globals-dead-stripping -x c -c /dev/null -o "$WORK_DIR/.probe.o" >/dev/null 2>&1; then
    ASAN_NO_DEAD_STRIP=(-fno-sanitize-address-globals-dead-stripping)
  fi
  rm -f "$WORK_DIR/.probe.o"
else
  case " ${EXTRA_CFLAGS[*]:-} ${CFLAGS:-} " in
    *-fsanitize=*address*)
      if "${PRISM_CC[@]}" -fno-sanitize-address-globals-dead-stripping -x c -c /dev/null -o "$WORK_DIR/.probe.o" >/dev/null 2>&1; then
        ASAN_NO_DEAD_STRIP=(-fno-sanitize-address-globals-dead-stripping)
      fi
      rm -f "$WORK_DIR/.probe.o"
      ;;
  esac
fi

build_isolated_side() {
  local side_tag=$1
  local prism_root=$2
  local side_dir="$WORK_DIR/side_${side_tag}"
  local out_archive="$WORK_DIR/libprism_side_${side_tag}.a"
  rm -rf "$side_dir" "$out_archive"
  mkdir -p "$side_dir/objs" "$side_dir/gen"

  mapfile -t git_meta < <(ruby -r"$FUZZ_ROOT/runtime/provenance" -e '
    git = FuzzProvenance.detect_git_state(ARGV[0], paths: FuzzProvenance::PRISM_DIRTY_PATHS) || {}
    puts(git["git_commit"] || "unknown")
    puts(git["git_dirty"].nil? ? "unknown" : (git["git_dirty"] ? "1" : "0"))
  ' "$prism_root")
  local git_commit="${git_meta[0]}"
  local git_dirty="${git_meta[1]}"

  shopt -s nullglob
  local srcs=("$prism_root"/src/*.c "$prism_root"/src/*/*.c)
  shopt -u nullglob
  [ "${#srcs[@]}" -gt 0 ] || { echo "build_prism_diff.sh: no sources in '$prism_root/src'" >&2; exit 2; }

  local common_flags=(
    -O1 -g -fno-omit-frame-pointer -std=c99
    -Wno-gnu-statement-expression-from-macro-expansion
    -Wno-switch
    -fPIC -fvisibility=hidden
    "-I$prism_root/include"
    "-I$FUZZ_ROOT/harnesses/prism/include"
    "-DFUZZ_GIT_COMMIT=$git_commit"
    "-DFUZZ_GIT_DIRTY=$git_dirty"
    "-DFUZZ_IJON_SIDE_SALT=$([ "$side_tag" = "a" ] && printf 0x13579bdfU || printf 0x2468ace0U)"
    ${ASAN_NO_DEAD_STRIP[@]+"${ASAN_NO_DEAD_STRIP[@]}"}
  )
  extra_cflags_defines_macro PM_INTEGER_DIVIDE_THRESHOLD || common_flags+=(-DPM_INTEGER_DIVIDE_THRESHOLD=8)
  extra_cflags_defines_macro PRISM_DEPTH_MAXIMUM || common_flags+=(-DPRISM_DEPTH_MAXIMUM=128)
  extra_cflags_defines_macro FUZZ_MAX_INPUT_SIZE || common_flags+=("-DFUZZ_MAX_INPUT_SIZE=$MAX_INPUT_SIZE")
  common_flags+=(${EXTRA_CFLAGS[@]+"${EXTRA_CFLAGS[@]}"})

  local objs=()
  for src in "${srcs[@]}"; do
    local rel="${src#"$prism_root/src/"}"
    local obj="$side_dir/objs/${rel%.c}.o"
    mkdir -p "$(dirname "$obj")"
    "${PRISM_CC[@]}" "${common_flags[@]}" -c "$src" -o "$obj"
    objs+=("$obj")
  done

  local side_scan_flags=()
  if [ -f "$FUZZ_ROOT/harnesses/prism/gen_serialize_walk.rb" ] && [ -f "$prism_root/config.yml" ] && \
     grep -rq 'PM_SCOPE_NODE' "$prism_root/include" 2>/dev/null && \
     ruby "$FUZZ_ROOT/harnesses/prism/gen_serialize_walk.rb" "$prism_root/config.yml" "$side_dir/gen/node_serialize_walk.inc" >/dev/null 2>&1; then
    side_scan_flags+=("-I$side_dir/gen")
  else
    side_scan_flags+=(-DPRISM_FUZZ_NO_SERIALIZE_SCAN)
  fi

  local side_obj="$side_dir/objs/prism_diff_side.o"
  "${PRISM_CC[@]}" "${common_flags[@]}" "${side_scan_flags[@]}" -c "$FUZZ_ROOT/harnesses/prism/prism_diff_side.c" -o "$side_obj"
  objs+=("$side_obj")

  ar rcs "$out_archive" "${objs[@]}"

  local sym_map="$side_dir/redefine.map"
  "$NM_BIN" --defined-only -g -P "$out_archive" | ruby -e '
    tag = ARGV.fetch(0)
    seen = {}
    $stdin.each_line do |ln|
      sym = ln.strip.split(/\s+/, 2).first
      next if sym.nil? || sym.empty?
      next if sym.start_with?("__asan_", "__ubsan_", "__msan_", "__lsan_", "__tsan_", "__sanitizer_", "__sancov_", "__afl_", "__llvm_", "sancov.")
      next if seen[sym]
      seen[sym] = true
      if sym =~ /\Afuzz_prism_side_(run|free|info|locate_serialize)\z/
        puts "#{sym} fuzz_prism_side_#{tag}_#{$1}"
      else
        puts "#{sym} __prism_#{tag}_#{sym}"
      end
    end
  ' "$side_tag" > "$sym_map"

  "$OBJCOPY_BIN" --redefine-syms="$sym_map" "$out_archive"
  ranlib "$out_archive"
}

build_isolated_side "a" "$PRISM_A_ROOT"
build_isolated_side "b" "$PRISM_B_ROOT"

LIB_A="$WORK_DIR/libprism_side_a.a"
LIB_B="$WORK_DIR/libprism_side_b.a"
DRIVER_OBJ="$WORK_DIR/prism_diff.o"

DRIVER_SRC="$FUZZ_ROOT/harnesses/prism/prism_diff.c"
DRIVER_FLAGS=(-Wall -Wextra -Werror)
if [ "$MODE" = "verify" ]; then
  DRIVER_FLAGS+=(-DPRISM_PRISM_DIFF_NO_MAIN)
fi

"${PRISM_CC[@]}" -O1 -g -fno-omit-frame-pointer -std=c99 \
  "${DRIVER_FLAGS[@]}" \
  "-I$FUZZ_ROOT/harnesses/prism" \
  ${EXTRA_CFLAGS[@]+"${EXTRA_CFLAGS[@]}"} \
  -c "$DRIVER_SRC" -o "$DRIVER_OBJ"

tmp_out="$OUTPUT.tmp.$$"
tmp_map="$OUTPUT.map.$$"
tmp_ids="$OUTPUT.ids.tmp.$$"
rm -f "$tmp_out" "$tmp_map" "$tmp_ids"
if [ "$MODE" = "verify" ]; then
  RUNNER_OBJ="$WORK_DIR/verify_runner.o"
  "${PRISM_CC[@]}" -O1 -g -fno-omit-frame-pointer -std=c99 -Wall -Wextra \
    ${EXTRA_CFLAGS[@]+"${EXTRA_CFLAGS[@]}"} \
    -c "$FUZZ_ROOT/triage/verify_runner.c" -o "$RUNNER_OBJ"
  "${PRISM_CC[@]}" -O1 -g ${EXTRA_CFLAGS[@]+"${EXTRA_CFLAGS[@]}"} \
    "$RUNNER_OBJ" "$DRIVER_OBJ" "$LIB_A" "$LIB_B" -lm -o "$tmp_out"
else
  MAP_FLAGS=()
  if [ "$(uname -s)" = "Linux" ]; then
    MAP_FLAGS=("-Wl,-Map=$tmp_map")
  fi
  "${PRISM_CC[@]}" -O1 -g ${EXTRA_CFLAGS[@]+"${EXTRA_CFLAGS[@]}"} \
    ${MAP_FLAGS[@]+"${MAP_FLAGS[@]}"} \
    "$DRIVER_OBJ" "$LIB_A" "$LIB_B" -lm -o "$tmp_out"
  if [ -f "$tmp_map" ]; then
    ruby "$FUZZ_ROOT/harnesses/prism/gen_diff_ids.rb" \
      --bin "$tmp_out" \
      --map "$tmp_map" \
      --archive-a "$LIB_A" \
      --archive-b "$LIB_B" \
      --output "$tmp_ids"
    rm -f "$tmp_map"
    mv -f "$tmp_ids" "$OUTPUT.ids"
  fi
fi
mv -f "$tmp_out" "$OUTPUT"
