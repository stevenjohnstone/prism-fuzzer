#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

: "${FUZZ_SIG:?halfempty_compare.sh requires FUZZ_SIG}"
: "${FUZZ_EXE:?halfempty_compare.sh requires FUZZ_EXE}"
: "${FUZZ_HEADER_FILE:?halfempty_compare.sh requires FUZZ_HEADER_FILE}"

# FUZZ_SIG, FUZZ_FAST_INV_EXACT, FUZZ_EXE, FUZZ_HEADER_FILE, and FUZZ_WORKDIR
# are passed via environment variables.
tmpfile="${FUZZ_WORKDIR:-${TMPDIR:-/tmp}}/he_cand.$$"
cleanup() {
  rm -f "$tmpfile"
}
trap cleanup EXIT
trap 'cleanup; exit 143' TERM INT

cat "$FUZZ_HEADER_FILE" - > "$tmpfile" || exit 1

rc=0
out=$("$FUZZ_EXE" "$tmpfile" 2>&1) || rc=$?

if [ "$rc" -eq 0 ]; then
  exit 1
fi

# Zero-fork fast path for digit-free INVARIANT[...] lines (avoids spawning
# bash + sed + awk + xxh64sum + cut on every candidate probe).
if [ -n "${FUZZ_FAST_INV_EXACT:-}" ]; then
  NL='
'
  nl_out="${NL}${out}${NL}"
  case "$nl_out" in
    *"${NL}INVARIANT["*)
      first_inv="INVARIANT[${nl_out#*${NL}INVARIANT\[}"
      first_inv="${first_inv%%"${NL}"*}"
      first_inv="${first_inv% \[detail: *}"
      case "$first_inv" in
        *[0-9]*) ;;
        *)
          [ "$first_inv" = "$FUZZ_FAST_INV_EXACT" ]
          exit $?
          ;;
      esac
      ;;
  esac
fi

sig=$(printf '%s\n' "$out" | "$SCRIPT_DIR/signature.sh")
[ "$sig" = "$FUZZ_SIG" ]
