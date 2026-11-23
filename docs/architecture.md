# prism-fuzzer Architecture

`prism-fuzzer` separates fuzzing infrastructure from the `ruby/prism` and `ruby/ruby` repositories so harnesses, triage algorithms, AFL++ patches, campaigns, and historical campaign reports evolve independently of target source trees.

## 1. Ruby Campaign DSL, Lifecycle Runner & Compiled Topology IR (`campaigns/*.rb` + `runtime/campaign*.rb` + `runtime/topology.rb`)

1. **Ruby Campaign DSL, Workspaces & Topology Schema**: Campaigns are authored as runnable Ruby scripts ([`campaigns/default.rb`](../campaigns/default.rb) or external scripts importing [`lib/prism_fuzzer.rb`](../lib/prism_fuzzer.rb) / `PrismFuzzer.campaign` via `runtime/campaign_dsl.rb`) and compile down to a static topology IR validated against the Draft 2020-12 [`topology.schema.json`](../topology.schema.json) schema (`runtime/json_schema.rb` / `./campaigns/default.rb validate`). Each campaign can declare an isolated `workspace` (e.g., `workspace "tmp/runs/pr_1234"`, compiling to `dir`, `build_dir`, `report_dir`, `triage_dir`, `coverage_dir`, and `logs_dir` while sharing `.cache/repos/` mirrors, `build/afl/` passes, and `reports/`), an optional lifecycle `duration` timer and `after_run` pipeline (`report`, `publish`), explicit `sources`, `generators`, `fuzzers`, `sync_groups`, and individual `workers`.
2. **Executable Script Dispatch, Progress UI & Logs (`runtime/campaign.rb` / `runtime/progress.rb`)**: Executing a campaign script directly (`./campaigns/default.rb run`, `./my_campaign.rb attach`, `./my_campaign.rb logs build`, `./my_campaign.rb stats`) or driving the returned `PrismFuzzer::Campaign::Instance` imperatively (`start!`, `wait!`, `report!`, `stats`) manages Docker builds, AFL++ passes, sync/build, timed/detached containers (hashed per campaign name + resolved workspace dir), and post-run workflows directly in Ruby without `make`. Each lifecycle step renders a BuildKit-style scrolling stage box on interactive TTYs that collapses into a completion summary while teeing full command output to `<ws>/logs/<step>.log`, and `runtime/run.sh` records startup (`logs/run.log`) and per-worker tmux pane logs (`logs/workers/<id>.log`) so failures remain inspectable even after `--rm` containers exit. Under the hood, `runtime/topology.rb` resolves DSL inputs into `<build_dir>/topology.resolved.json`, exports workspace paths, resolves external Docker bind mounts, builds binaries incrementally (`<build_dir>/.stamps/`), and generates per-worker launch plans.
3. **Mirrors & Portable Checkouts**: Remote git repositories are cached once as bare mirrors under `.cache/repos/` and checked out cleanly into `<build_dir>/targets/<source_id>/` via shallow local fetches (`file://`) so there are no host-specific git `worktree` or `alternates` paths when bind-mounted into Docker at `/prism-fuzzer`.
4. **Patch Series (`patches/prism/`)**: Before building, `PrismFuzzer::Topology` applies `patches/prism/*.patch` in order (`patches: auto`). If a patch has already landed upstream at the requested commit (`git apply --reverse --check`), it is automatically skipped and recorded in `.fuzz-target-state.json` under `skipped_patches`.
5. **Template & Include Generation**: If a Prism checkout has stale or missing generated sources (`src/node.c`, `include/prism/ast.h`), `PrismFuzzer::Topology` runs Prism's stdlib-only `ruby templates/template.rb` (requiring no `Gemfile` or `bundle`) and generates per-target `node_locations.inc` and `node_serialize_walk.inc` into `<build_dir>/targets/gen/<source_id>/` rather than writing into `harnesses/prism/`.
6. **CRuby Oracle**: When the active `ruby` source matches the commit baked into `/opt/ruby` inside the `prism-fuzzer` image, `fuzz.diff` reuses `/opt/ruby/libruby-static.a`. When another `RUBY_REF` is requested, `./bin/campaign.rb build --build-ruby` compiles it incrementally into `<build_dir>/targets/ruby/<sha>/`.

## 2. Prism-vs-Prism Differential Fuzzing (`prism_diff_prism`)

Comparing any two Prism versions (such as `main` before vs. after an optimizer/parser refactor, or release vs. PR) inside a single in-process AFL++ target requires both libraries to link without `pm_*` symbol collisions:

1. `harnesses/prism/build_prism_diff.sh` compiles `prism_a/src/*.c` + `prism_diff_side.c` against `prism_a/include` into `libprism_side_a.a`, and `prism_b/src/*.c` + `prism_diff_side.c` against `prism_b/include` into `libprism_side_b.a`.
2. `objcopy --redefine-syms` prefixes all exported non-runtime/non-sanitizer symbols with `__prism_a_*` / `__prism_b_*` and exposes only `fuzz_prism_side_{a,b}_{run,free,info}`.
3. `harnesses/prism/prism_diff.c` feeds each 4-byte-header + Ruby input to both sides via AFL++ PCGUARD persistent mode and asserts parity across:
   - `parsed_size`, `continuable`, `data_loc`
   - `error_count`, first error diagnostic type & location
   - `warning_count`, `comment_count`, `magic_comment_count`
   - full `pm_serialize` byte buffer and `pm_prettyprint` output
4. Linker `-Map` slices are processed by [`harnesses/prism/gen_diff_ids.rb`](../harnesses/prism/gen_diff_ids.rb) into `<binary>.ids` attributing every edge to `Domain=prism_a`, `Domain=prism_b`, or `Domain=harness`.

## 3. Topology-Driven Orchestration, Triage & GitHub Pages (`gh-pages` worktree)

- `runtime/provenance.rb` snapshots compiled binaries, `.ids`, `fuzz-ruby-ext`, `prism_lib`, `tmp/fuzz/bin/topology.json`, and scripts into `tmp/fuzz/snapshot/`.
- `runtime/run.sh`, `runtime/status.rb`, `triage/triage.rb`, `triage/cluster.rb`, `triage/verify.rb`, `triage/explain.rb`, `report/coverage.sh`, `report/report.rb`, and `report/sankey.rb` all discover sync groups, generators, fuzzer shapes, source pairs, and worker metadata directly from `topology.json`.
- `bin/publish.rb` attaches `reports/` as a gitignored `gh-pages` branch worktree (or targets `--out-dir DIR`), copies all report, `llvm-cov` HTML, and triage bucket artifacts into `runs/<run-id>/report/`, and regenerates `index.html` at the root of `gh-pages` without committing generated artifacts to `main`.
