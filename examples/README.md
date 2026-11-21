# Example Fuzzing Topologies

Ready-to-run campaign scripts demonstrating features of the `prism-fuzzer` DSL (`lib/prism_fuzzer.rb` / `runtime/campaign_dsl.rb`) and unified `<ws>/report/` bundling (`report`).

Each example uses its own isolated `workspace` under `tmp/examples/` so it never collides with `tmp/fuzz/`.

| Example | Highlights |
| :--- | :--- |
| [`01_ab_pr_diff.rb`](01_ab_pr_diff.rb) | **A/B Prism Differential + Multi-Target Coverage**: compares `:baseline` vs. `:candidate` with `prism_diff_prism` + `ijon: true`, while building separate native vs. `PRISM_ACCEL_SWAR` coverage pairs. |
| [`02_cross_arch_endian_gauntlet.rb`](02_cross_arch_endian_gauntlet.rb) | **32-bit Alignment & Big-Endianness Gauntlet**: QEMU `arm32` + `ppc` cross-oracle targets (`mutator_oracle64.so`) with and without IJON alongside native host ASan/UBSan + slow serialization workers. |
| [`03_ijon_state_factory.rb`](03_ijon_state_factory.rb) | **Multi-Island Sync Factory**: isolates high-speed `fuzz.ijon` and `fuzz.native`+`fuzz.sand` (`aux_fuzzer`) exploration islands from a slower `san_hub` (ASan/MSan/LSan + CRuby `fuzz.diff`), bridging finds via `peer_import` and dual `lrama` grammar generators (`foreign_sync`). |
| [`04_define_flag_matrix.rb`](04_define_flag_matrix.rb) | **Compile-Time `#define` Matrix**: uses Ruby data-driven DSL iteration over preprocessor variants (`PRISM_ACCEL_SWAR`, small `PM_ARENA_INITIAL_SIZE` / `PRISM_DEPTH_MAXIMUM`, `PRISM_FUZZ_ALLOW_STREAM_WITH_IJON`, `PRISM_FUZZ_NO_STACK_BUDGET`, `PRISM_FUZZ_NO_SCOPE_FORWARDING`). |
| [`05_ci_regression_gate.rb`](05_ci_regression_gate.rb) | **Timed Nightly CI Gate**: time-boxed `duration` with automatic `after_run { report ...; publish ... }` archiving into `reports/` for GitHub Pages. |
| [`06_imperative_orchestrator.rb`](06_imperative_orchestrator.rb) | **Imperative Ruby API**: drives `PrismFuzzer::Campaign::Instance` directly in pure Ruby (`validate!`, `sync!`, `build!`, `start!`, `wait!`, `report!`, `print_stats`) via `autorun: false`. |

## Trying Any Example

```bash
# Schema + reference validation
./examples/01_ab_pr_diff.rb validate

# Preview container commands, workspace paths, and planned launch topology
./examples/03_ijon_state_factory.rb plan
./examples/03_ijon_state_factory.rb run --dry-run

# Launch inside Docker (uses its own hashed container name & tmp/examples/ workspace)
./examples/01_ab_pr_diff.rb run

# Generate the self-contained <ws>/report/ bundle (triage + coverage + unified HTML)
./examples/01_ab_pr_diff.rb report
```

You can also inspect or run any example via [`bin/campaign.rb`](../bin/campaign.rb) (for example, `./bin/campaign.rb compile examples/04_define_flag_matrix.rb`).
