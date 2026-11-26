# Grammar-Mutator Integration & Patch (`grammar-mutator.patch`)

[`grammar-mutator.patch`](grammar-mutator.patch) patches AFL++'s [Grammar-Mutator](https://github.com/AFLplusplus/Grammar-Mutator) (pinned to `stable` commit `f5daa1db93b9865000f282f5a261babf55d2eba7` in [`docker/Dockerfile`](../../docker/Dockerfile)) for use with our custom Ruby grammar ([`grammar/ruby.json`](../../grammar/ruby.json)).

## How It Runs (`mutator_mixed` Mode)

Campaign workers declare `mutator "libgrammarmutator-ruby.so"` (e.g. `small-diff-gm` in `campaigns/ijon-funnel.rb`, `ijon-diff-gm` in `campaigns/ijon-small.rb`, `diff-gm` in `campaigns/default.rb`, `small-compile-gm` in `campaigns/compile.rb`, and `small-pipeline-gm` in `campaigns/pipeline.rb`).

- **Build (`runtime/lib/topology/builder.rb`)**: Compiles `libgrammarmutator-ruby.so` and `grammar_generator-ruby` on demand into `<ws>/build/` with `NO_ANTLR=1` (zero Java/ANTLR4 dependency, ~4s build), stamped against `grammar/ruby.json` and `grammar-mutator.patch`.
- **Launch (`launch_planner.rb` + `launch_stager.rb`)**:
  - Sets `AFL_CUSTOM_MUTATOR_LIBRARY=<bin_dir>/libgrammarmutator-ruby.so` **without** `AFL_CUSTOM_MUTATOR_ONLY`, and sets `GRAMMAR_MUTATOR_TREE_DIR=/tmp/afl-tmpdir/<worker_id>/trees` (on in-memory `tmpfs`).
  - Generates 200 initial grammar seeds and companion `.tree` files via `grammar_generator-ruby` alongside the worker's regular corpus seeds.
- **Mixed structural + byte-level pipeline**:
  - Entries with a `.tree` file (initial generator seeds + Grammar-Mutator outputs) are mutated by **both** Grammar-Mutator (subtree splicing via `chunk_store`, tree mutation, tree trimming) **and** AFL++ havoc.
  - Havoc-mutated or synced entries without a `.tree` file skip Grammar-Mutator in O(1) (since runtime ANTLR4 reverse-parsing is disabled) and run through normal AFL++ havoc at full speed—so bidirectional sync with other workers incurs zero parsing overhead.

## Summary of Patch Changes

### 1. UTF-8 Multi-Byte Terminal Escaping (`grammars/f1_c_gen.py`)

Upstream `f1_c_gen.py` iterates over Python `str` codepoints and passes character/escape counts as byte lengths to `node_create_with_val`. For multi-byte UTF-8 terminals in `grammar/ruby.json`, that produces invalid C escapes or truncated byte lengths. The patch encodes each terminal as UTF-8 bytes and emits exact C byte strings and byte lengths.

### 2. Zero-ANTLR Build & Skipping Runtime Reverse-Parsing (`src/Makefile`, `src/tree.c`, `src/grammar_mutator.c`)

When Grammar-Mutator sees a queue entry without a companion `.tree` file, upstream calls `load_tree_from_test_case_ex()` to invoke an ANTLR4 C++ parser at runtime. On arbitrary byte-mutated Ruby inputs, reverse-parsing is slow and fails on non-grammar tokens.

With `NO_ANTLR=1`:
- `src/grammar_mutator.c` skips `load_tree_from_test_case_ex()` and returns `NULL` immediately when no `.tree` file exists.
- `src/tree.c` stubs `tree_parse()` under `-DGRAMMAR_MUTATOR_NO_ANTLR`.
- `src/Makefile` omits `libantlr4_shim.a` and `libantlr4-runtime.a`, allowing a pure C + Python build with no Java or `antlr4.jar` requirement.

### 3. Per-Worker `tmpfs` `.tree` Directory (`src/grammar_mutator.c`)

Upstream writes `.tree` files next to `queue/` inside the bind-mounted AFL++ output directory, creating heavy host bind-mount I/O on macOS/Docker. The patch reads `GRAMMAR_MUTATOR_TREE_DIR` (falling back to `/tmp/afl-tmpdir/grammar/trees`) so every worker stores its `.tree` files on in-memory `tmpfs` without colliding with other workers or parallel benchmark runs.

### 4. Preserving `data->trimmed_tree` Across `afl_custom_post_trim(data, 0)` (`src/grammar_mutator.c`)

When trimming uncovers a new coverage edge, AFL++ 5.03c calls `afl_custom_post_trim(data, 0)` and then immediately calls `save_if_interesting()` → `afl_custom_queue_new_entry()`. Upstream frees `data->trimmed_tree` in `afl_custom_post_trim(data, 0)`, losing the tree before `afl_custom_queue_new_entry()` can save it. The patch keeps `data->trimmed_tree` alive across `post_trim(data, 0)` so `afl_custom_queue_new_entry()` can consume it, write its `.tree` file, and add its subtrees to `chunk_store`; unused trimmed trees are freed at the start of the next `init_trim`, `trim`, or `fuzz_count`.

### 5. `$ORIGIN` RPATH (`src/Makefile`)

Links `grammar_generator-ruby` with `-Wl,-rpath,'$ORIGIN'` so it resolves `libgrammarmutator-ruby.so` from the same `<ws>/build/` or `<ws>/bin/` snapshot directory.

## Benchmarking Against `lrama-fuzz`

Use [`runtime/fuzzer_bench.rb`](../../runtime/fuzzer_bench.rb) (`make fuzzer-bench`) to compare plain AFL++, Grammar-Mutator (`mutator`, `mutator_mixed`), and `lrama-fuzz` (`lrama`) on identical seeds and time budgets:

```bash
FUZZER_BENCH_ARGS="--shapes prism_diff_ruby --ijon on --grammar none,mutator,mutator_mixed,lrama --duration 60" make fuzzer-bench
```
