#!/usr/bin/env bash
set -euo pipefail

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

exec "$FUZZ_ROOT/triage/verify_bucket.sh" \
  --repo-root "$REPO_ROOT" \
  --fuzz-root "$FUZZ_ROOT" \
  --bucket-dir "$SCRIPT_DIR" \
  --profile "lsan_slow" \
  "$@"
