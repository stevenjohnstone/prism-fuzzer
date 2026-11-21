# Prism Fuzzing Patches

Ordered patch series applied by [`runtime/topology.rb`](../../runtime/topology.rb) / [`bin/topology.rb`](../../bin/topology.rb) to checked-out upstream `ruby/prism` worktrees when `patches: auto` is active:

1. [`0001-arena-32bit-alignment.patch`](0001-arena-32bit-alignment.patch) — Aligns `pm_arena_block_t.data` to `pm_arena_align_t` (`void *`, `uint64_t`, `double`) so 32-bit targets (`arm32`, `ppc`) satisfy UBSan/8-byte alignment after the 12-byte block header.
2. [`0002-accel-swar-backend-define.patch`](0002-accel-swar-backend-define.patch) — Allows `-DPRISM_ACCEL_SWAR` to select the portable SWAR backend explicitly during SIMD-vs-SWAR differential fuzzing (`fuzz.accel`).
3. [`0003-integer-divide-threshold-guard.patch`](0003-integer-divide-threshold-guard.patch) — Wraps `#define PM_INTEGER_DIVIDE_THRESHOLD` in `#ifndef` so harness builds can lower `-DPM_INTEGER_DIVIDE_THRESHOLD=8` and exercise big-integer Karatsuba/divide-and-conquer paths within small inputs.

When building an upstream Prism revision that already includes any patch (checked via `git apply --reverse --check`), `PrismFuzzer::Topology` skips that patch automatically and records skipped vs applied patches in provenance metadata.
