#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export UBSAN_OPTIONS="${UBSAN_OPTIONS:-abort_on_error=1:print_stacktrace=1}"
: "${SIGLINES:=10}"
: "${HALFEMPTY_THREADS:=2}"
: "${HALFEMPTY_TIMEOUT:=15}"
: "${HALFEMPTY_MAX_TIME:=45}"
: "${HALFEMPTY_FINE_MAX_BYTES:=512}"
: "${HALFEMPTY_SKIP_FINE:=0}"

FUZZ_EXE=$1
INPUT=$2
OUTPUT=$3

if [ ! -f "$INPUT" ] || [ "$(wc -c < "$INPUT")" -lt 4 ]; then
  exit 1
fi

start_sec=$SECONDS
set +e
initial_out=$(timeout -k 1 "$HALFEMPTY_TIMEOUT" "$FUZZ_EXE" "$INPUT" 2>&1)
initial_rc=$?
set -e
init_elapsed=$(( SECONDS - start_sec ))

if [ "$initial_rc" -eq 0 ] || [ "$initial_rc" -eq 124 ] || [ "$initial_rc" -eq 137 ]; then
  echo "Input $INPUT did not crash cleanly (rc=$initial_rc); skipping halfempty" >&2
  exit 1
fi

FUZZ_SIG=$(printf '%s\n' "$initial_out" | "$SCRIPT_DIR/signature.sh")
if [ -z "$FUZZ_SIG" ]; then
  exit 1
fi

# Adaptive per-candidate timeout: 1s for fast crashes (<1s), up to 3s for slower sanitizers.
child_timeout="${HALFEMPTY_CHILD_TIMEOUT:-}"
if [ -z "$child_timeout" ]; then
  if [ "$init_elapsed" -lt 1 ]; then
    child_timeout=1
  else
    child_timeout=3
  fi
fi

# INVARIANT[...] signatures depend solely on the INVARIANT[...] line (never stack frames),
# so disable DWARF symbolization and CRuby backtraces across candidate probes, and pass
# FUZZ_FAST_INV_EXACT when the INVARIANT prefix contains no digits requiring sed normalization.
FUZZ_FAST_INV_EXACT=""
first_inv_line=$(printf '%s\n' "$initial_out" | sed -n '/^INVARIANT\[/{p;q;}')
if [ -n "$first_inv_line" ]; then
  export ASAN_OPTIONS="${ASAN_OPTIONS:+$ASAN_OPTIONS:}symbolize=0"
  export UBSAN_OPTIONS="${UBSAN_OPTIONS:+$UBSAN_OPTIONS:}symbolize=0"
  export MSAN_OPTIONS="${MSAN_OPTIONS:+$MSAN_OPTIONS:}symbolize=0"
  export LSAN_OPTIONS="${LSAN_OPTIONS:+$LSAN_OPTIONS:}symbolize=0"
  export FUZZ_DIFF_BACKTRACE="${FUZZ_DIFF_BACKTRACE:-0}"
  inv_prefix="${first_inv_line% \[detail: *}"
  case "$inv_prefix" in
    *[0-9]*) ;;
    *) FUZZ_FAST_INV_EXACT="$inv_prefix" ;;
  esac
fi

workdir=$(mktemp -d "${TMPDIR:-/tmp}/halfempty_work.XXXXXX")
trap 'rm -rf "$workdir"' EXIT

head -c 4 "$INPUT" > "$workdir/header.bin"
tail -c +5 "$INPUT" > "$workdir/body.bin"
body_size=$(wc -c < "$workdir/body.bin" | tr -d ' ')

verify_candidate_body() {
  local cand_body=$1
  [ -f "$cand_body" ] || return 1
  FUZZ_SIG="$FUZZ_SIG" \
    FUZZ_FAST_INV_EXACT="$FUZZ_FAST_INV_EXACT" \
    FUZZ_EXE="$FUZZ_EXE" \
    FUZZ_HEADER_FILE="$workdir/header.bin" \
    FUZZ_WORKDIR="$workdir" \
    "$SCRIPT_DIR/halfempty_compare.sh" < "$cand_body" >/dev/null 2>&1
}

run_halfempty_bounded() {
  local budget=$1
  local in_body=$2
  local out_body=$3
  shift 3
  if [ "$budget" -lt 1 ]; then
    return 1
  fi
  timeout -k 2 "$budget" \
    env \
      FUZZ_SIG="$FUZZ_SIG" \
      FUZZ_FAST_INV_EXACT="$FUZZ_FAST_INV_EXACT" \
      FUZZ_EXE="$FUZZ_EXE" \
      FUZZ_HEADER_FILE="$workdir/header.bin" \
      FUZZ_WORKDIR="$workdir" \
      halfempty -q --noverify \
        -T "$child_timeout" \
        -P "$HALFEMPTY_THREADS" \
        "$@" \
        "$SCRIPT_DIR/halfempty_compare.sh" "$in_body" \
        -o "$out_body" >/dev/null 2>&1
}

cp "$workdir/body.bin" "$workdir/body.min"

if [ "$body_size" -gt 0 ]; then
  if [ "$body_size" -le "$HALFEMPTY_FINE_MAX_BYTES" ] && [ "$HALFEMPTY_SKIP_FINE" != "1" ]; then
    if run_halfempty_bounded "$HALFEMPTY_MAX_TIME" "$workdir/body.bin" "$workdir/body.cand" \
        --stable \
        --zero-skip-multiplier=0.0005 \
        --bisect-skip-multiplier=0.0005 \
        --zero-char=32 && verify_candidate_body "$workdir/body.cand"; then
      mv -f "$workdir/body.cand" "$workdir/body.min"
    fi
  else
    # Phase 1: fast O(log N) structural chunk deletion without O(N^2) byte-zeroing.
    phase1_budget=$(( (HALFEMPTY_MAX_TIME * 2 + 2) / 3 ))
    [ "$phase1_budget" -gt "$HALFEMPTY_MAX_TIME" ] && phase1_budget="$HALFEMPTY_MAX_TIME"
    [ "$HALFEMPTY_SKIP_FINE" = "1" ] && phase1_budget="$HALFEMPTY_MAX_TIME"

    p1_start=$SECONDS
    if run_halfempty_bounded "$phase1_budget" "$workdir/body.bin" "$workdir/body.phase1" \
        --bisect-skip-multiplier=0.004 \
        --zero-skip-multiplier=1.0 && verify_candidate_body "$workdir/body.phase1"; then
      mv -f "$workdir/body.phase1" "$workdir/body.min"
    fi
    p1_elapsed=$(( SECONDS - p1_start ))

    # Phase 2: polish with --stable and space-zeroing only if Phase 1 reduced the body
    # into the compact <= HALFEMPTY_FINE_MAX_BYTES regime and wall-clock budget remains.
    cur_size=$(wc -c < "$workdir/body.min" | tr -d ' ')
    rem_budget=$(( HALFEMPTY_MAX_TIME - p1_elapsed ))
    if [ "$HALFEMPTY_SKIP_FINE" != "1" ] && [ "$cur_size" -gt 0 ] && [ "$cur_size" -le "$HALFEMPTY_FINE_MAX_BYTES" ] && [ "$rem_budget" -ge 3 ]; then
      if run_halfempty_bounded "$rem_budget" "$workdir/body.min" "$workdir/body.phase2" \
          --stable \
          --zero-skip-multiplier=0.0005 \
          --bisect-skip-multiplier=0.0005 \
          --zero-char=32 && verify_candidate_body "$workdir/body.phase2"; then
        mv -f "$workdir/body.phase2" "$workdir/body.min"
      fi
    fi
  fi
fi

cat "$workdir/header.bin" "$workdir/body.min" > "$OUTPUT"
