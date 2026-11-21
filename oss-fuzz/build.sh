#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${SRC:-.}/prism"
FUZZ_ROOT="${FUZZ_ROOT:-}"
if [ -n "$FUZZ_ROOT" ] && [ -f "$FUZZ_ROOT/harnesses/prism/parse.c" ]; then
  HARNESS_DIR="$FUZZ_ROOT/harnesses/prism"
  DICT_FILE="$FUZZ_ROOT/dict/prism.dict"
  CORPUS_RB="$FUZZ_ROOT/runtime/corpus.rb"
  GEN_LOC_RB="$HARNESS_DIR/gen_node_locations.rb"
elif [ -n "$FUZZ_ROOT" ] && [ -f "$FUZZ_ROOT/harness/parse.c" ]; then
  HARNESS_DIR="$FUZZ_ROOT/harness"
  DICT_FILE="$FUZZ_ROOT/dict"
  CORPUS_RB="$FUZZ_ROOT/runtime/corpus.rb"
  GEN_LOC_RB="$HARNESS_DIR/gen_node_locations.rb"
elif [ -f "$REPO_ROOT/test/fuzz/harness/parse.c" ]; then
  FUZZ_ROOT="$REPO_ROOT/test/fuzz"
  HARNESS_DIR="$FUZZ_ROOT/harness"
  DICT_FILE="$FUZZ_ROOT/dict"
  CORPUS_RB="$FUZZ_ROOT/runtime/corpus.rb"
  GEN_LOC_RB="$HARNESS_DIR/gen_node_locations.rb"
elif [ -f "${SRC:-}/prism-fuzzer/harnesses/prism/parse.c" ]; then
  FUZZ_ROOT="$SRC/prism-fuzzer"
  HARNESS_DIR="$FUZZ_ROOT/harnesses/prism"
  DICT_FILE="$FUZZ_ROOT/dict/prism.dict"
  CORPUS_RB="$FUZZ_ROOT/runtime/corpus.rb"
  GEN_LOC_RB="$HARNESS_DIR/gen_node_locations.rb"
elif [ -f "${SRC:-}/ruby-fuzz/harnesses/prism/parse.c" ]; then
  FUZZ_ROOT="$SRC/ruby-fuzz"
  HARNESS_DIR="$FUZZ_ROOT/harnesses/prism"
  DICT_FILE="$FUZZ_ROOT/dict/prism.dict"
  CORPUS_RB="$FUZZ_ROOT/runtime/corpus.rb"
  GEN_LOC_RB="$HARNESS_DIR/gen_node_locations.rb"
elif [ -f "$SCRIPT_DIR/../harnesses/prism/parse.c" ]; then
  FUZZ_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
  if [ ! -f "$REPO_ROOT/include/prism.h" ]; then
    REPO_ROOT="$(cd "$FUZZ_ROOT/tmp/fuzz/build/targets/prism_a" 2>/dev/null || cd "$FUZZ_ROOT/../.." && pwd)"
  fi
  HARNESS_DIR="$FUZZ_ROOT/harnesses/prism"
  DICT_FILE="$FUZZ_ROOT/dict/prism.dict"
  CORPUS_RB="$FUZZ_ROOT/runtime/corpus.rb"
  GEN_LOC_RB="$HARNESS_DIR/gen_node_locations.rb"
else
  echo "build.sh: cannot locate Prism fuzz harness (checked '$REPO_ROOT/test/fuzz/harness/parse.c', '${SRC:-}/prism-fuzzer/harnesses/prism/parse.c', and '$SCRIPT_DIR/../harnesses/prism/parse.c'). Pass FUZZ_ROOT, mount prism-fuzzer at \$SRC/prism-fuzzer, or build with PRISM_FUZZER_REPO=<git-url>." >&2
  exit 2
fi

cd "$REPO_ROOT"

WORK_DIR="${WORK:-}"
CLEANUP_WORK=0
if [ -z "$WORK_DIR" ]; then
  WORK_DIR="$(mktemp -d)"
  CLEANUP_WORK=1
fi
trap 'if [ "$CLEANUP_WORK" -eq 1 ]; then rm -rf "$WORK_DIR"; fi' EXIT

mkdir -p "$OUT" "$WORK_DIR"

# Generate C parser headers and sources from templates using Ruby stdlib only.
ruby templates/template.rb
GEN_INC_DIR="${OSS_FUZZ_GEN_DIR:-$WORK_DIR/oss-fuzz-gen}"
mkdir -p "$GEN_INC_DIR"
ruby "$GEN_LOC_RB" "$REPO_ROOT/config.yml" "$GEN_INC_DIR/node_locations.inc"

shopt -s nullglob
SRCS=(
  src/*.c
  src/*/*.c
  "$HARNESS_DIR/parse.c"
  "$HARNESS_DIR/fuzz.c"
)
shopt -u nullglob

COMMON_DEFINES=(
  -DPRISM_OSS_FUZZ
  -DPM_ARENA_INITIAL_SIZE=0
  -DPM_INTEGER_DIVIDE_THRESHOLD=8
  -DPRISM_DEPTH_MAXIMUM=128
  "-I$GEN_INC_DIR"
  "-I$HARNESS_DIR"
  -Wno-gnu-statement-expression-from-macro-expansion
  -Wno-switch
)

if [ "${AFL_LLVM_CMPLOG:-}" = "1" ]; then
  # Match test/fuzz/Makefile CmpLog builds so AFL++ Redqueen hooks libc strncasecmp.
  CMPLOG_SRCS=()
  for src in "${SRCS[@]}"; do
    [ "$src" = "src/strncasecmp.c" ] && continue
    CMPLOG_SRCS+=("$src")
  done
  SRCS=("${CMPLOG_SRCS[@]}")
  COMMON_DEFINES+=(
    -Dpm_strncasecmp=strncasecmp
  )
fi

pack_seed_zip() {
  local src_dir="$1"
  local zip_path="$2"
  rm -f "$zip_path"
  if command -v zip >/dev/null 2>&1; then
    zip -r -j -q "$zip_path" "$src_dir"
  else
    python3 -c '
import os, sys, zipfile
src_dir, zip_path = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    for root, _, files in os.walk(src_dir):
        for fn in sorted(files):
            zf.write(os.path.join(root, fn), arcname=fn)
' "$src_dir" "$zip_path"
  fi
}

build_target() {
  local name="$1"
  local max_input_size="$2"
  shift 2

  local obj_dir="$WORK_DIR/obj-$name"
  local seed_dir="$WORK_DIR/seeds-$name"
  rm -rf "$obj_dir" "$seed_dir"
  mkdir -p "$obj_dir"

  local objs=()
  local pids=()
  local nproc_count
  nproc_count="$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"

  # Compile C99 sources with $CC/$CFLAGS; link C++ fuzzing engine with $CXX/$CXXFLAGS.
  for src in "${SRCS[@]}"; do
    local rel="${src#./}"
    local obj="$obj_dir/${rel//\//_}.o"
    "$CC" -std=c99 -Iinclude $CFLAGS "${COMMON_DEFINES[@]}" "$@" -c "$src" -o "$obj" &
    pids+=("$!")
    objs+=("$obj")
    if [ "${#pids[@]}" -ge "$nproc_count" ]; then
      wait "${pids[0]}"
      pids=("${pids[@]:1}")
    fi
  done
  for pid in "${pids[@]}"; do
    wait "$pid"
  done

  "$CXX" $CXXFLAGS "${objs[@]}" -o "$OUT/$name" $LIB_FUZZING_ENGINE

  cp "$DICT_FILE" "$OUT/${name}.dict"
  if [ -f "${SRC:-}/${name}.options" ]; then
    cp "${SRC}/${name}.options" "$OUT/${name}.options"
  elif [ -f "$FUZZ_ROOT/oss-fuzz/${name}.options" ]; then
    cp "$FUZZ_ROOT/oss-fuzz/${name}.options" "$OUT/${name}.options"
  else
    echo "build.sh: missing ${name}.options in '${SRC:-}' and '$FUZZ_ROOT/oss-fuzz'" >&2
    exit 2
  fi

  local corpus_fixtures="${CORPUS_FIXTURES_DIR:-}"
  if [ -z "$corpus_fixtures" ] && [ -d "$REPO_ROOT/test/prism/fixtures" ]; then
    corpus_fixtures="$REPO_ROOT/test/prism/fixtures"
  fi
  CORPUS_FIXTURES_DIR="$corpus_fixtures" FUZZ_MAX_INPUT_SIZE="$max_input_size" ruby -E UTF-8 "$CORPUS_RB" --no-minimize "$seed_dir"
  pack_seed_zip "$seed_dir" "$OUT/${name}_seed_corpus.zip"
}

build_target \
  prism_parse_fuzzer \
  8192 \
  -DPRISM_EXCLUDE_SERIALIZATION \
  -DPRISM_EXCLUDE_JSON \
  -DPRISM_EXCLUDE_PRETTYPRINT

build_target \
  prism_full_fuzzer \
  1024 \
  -DSLOW

