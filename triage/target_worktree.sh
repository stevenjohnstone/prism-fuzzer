#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ] || [ -z "${1:-}" ]; then
  echo "Usage: target_worktree.sh <git-rev> [worktree-dir] [repo-dir]" >&2
  exit 2
fi

REV="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FUZZ_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WS_BUILD_DIR="${FUZZ_BUILD_DIR:-}"
if [ -z "$WS_BUILD_DIR" ] && [ -f "$FUZZ_ROOT/runtime/topology.rb" ]; then
  WS_BUILD_DIR="$(ruby -r"$FUZZ_ROOT/runtime/topology" -e '
    t = PrismFuzzer::Topology.discover(start_dir: ARGV[0])
    puts PrismFuzzer::Topology.workspace_paths(t, fuzz_root: ARGV[0])[:build_dir] if t
  ' "$FUZZ_ROOT" 2>/dev/null || true)"
fi
WS_BUILD_DIR="${WS_BUILD_DIR:-$FUZZ_ROOT/tmp/fuzz/build}"
WORKTREE_DIR="${2:-$WS_BUILD_DIR/.fuzz-target-worktree}"
SOURCE_REPO="${3:-}"

if [ -z "$SOURCE_REPO" ]; then
  FALLBACK_REPO=""
  for cand in "$FUZZ_ROOT"/.cache/repos/prism-*.git "${PRISM_A_DIR:-}" "$WS_BUILD_DIR/targets/prism_a"; do
    if [ -n "$cand" ] && git -C "$cand" rev-parse --git-dir >/dev/null 2>&1; then
      [ -n "$FALLBACK_REPO" ] || FALLBACK_REPO="$cand"
      if git -C "$cand" rev-parse --verify "${REV}^{commit}" >/dev/null 2>&1; then
        SOURCE_REPO="$cand"
        break
      fi
    fi
  done
  SOURCE_REPO="${SOURCE_REPO:-$FALLBACK_REPO}"
fi

if [ -z "$SOURCE_REPO" ]; then
  echo "target_worktree.sh: no Prism git repository found (run make targets-sync or pass repo-dir)" >&2
  exit 2
fi

if ! SHA="$(git -C "$SOURCE_REPO" rev-parse --verify "${REV}^{commit}" 2>/dev/null)"; then
  git -C "$SOURCE_REPO" fetch origin "$REV" >/dev/null 2>&1 || true
  if ! SHA="$(git -C "$SOURCE_REPO" rev-parse --verify "${REV}^{commit}" 2>/dev/null)"; then
    echo "target_worktree.sh: unknown git revision '$REV' in $SOURCE_REPO" >&2
    exit 2
  fi
fi

git -C "$SOURCE_REPO" worktree prune >&2

if [ -d "$WORKTREE_DIR" ] && git -C "$WORKTREE_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git -C "$WORKTREE_DIR" checkout --detach --force "$SHA" >&2
  git -C "$WORKTREE_DIR" clean -fdq >&2
else
  rm -rf "$WORKTREE_DIR"
  mkdir -p "$(dirname "$WORKTREE_DIR")"
  git -C "$SOURCE_REPO" worktree prune >&2
  git -C "$SOURCE_REPO" worktree add --detach "$WORKTREE_DIR" "$SHA" >&2
fi

cd "$WORKTREE_DIR" && pwd

