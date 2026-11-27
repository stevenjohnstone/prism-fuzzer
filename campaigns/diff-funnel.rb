#!/usr/bin/env ruby
# frozen_string_literal: true

# Aggressive Differential Parsing Funnel Campaign (`diff-funnel-prism-fleet`, 20 workers):
#   Dedicates all 20 cores to high-speed Prism vs CRuby `parse.y` differential
#   fuzzing — zero ASan/MSan/LSan/QEMU/slow overhead — pairing a 15-worker 256 B
#   velocity factory (`afl-small`) with a 5-worker 8 KiB deep-context island
#   (`afl-8k`) connected via strictly one-way `small -> 8k` `peer_import` bridges:
#
#   1. `afl-small` (256 B payload / `-G 260`, 15 workers):
#      - 5x hybrid `fuzz.ijon.diff` (`FUZZ_IJON_MODE=both`) + `libprismmutator.so`
#        across `explore` (-M), `fast`, `coe`, `rare`, `quad -P exploit`
#      - 2x pure AST (`AFL_CUSTOM_MUTATOR_ONLY=1`) on `both` & `cruby` IJON modes
#      - 1x hybrid `cruby`-only IJON + `libprismmutator.so`
#      - 2x pure PCGUARD `fuzz.diff` + `libprismmutator.so` (zero IJON overhead)
#      - 4x non-AST havoc diversity (MOpt `-L 0`, ASCII `-Z -a text`, `mmopt`)
#      - 1x `fuzz.ijon` + `libprismmutator.so` (catches `node_location` underflows
#        & `xallocator` leaks while feeding compact valid Prism seeds to diff)
#
#   2. `afl-8k` (8,192 B payload / `-G 8196`, 5 workers):
#      Imports compact breakthroughs one-way from `small-diff-main` and
#      `small-ast-only-1`, splicing them into 8 KiB inputs across hybrid AST,
#      pure AST (`cruby` IJON), ASCII-text havoc, and pure PCGUARD `fuzz.diff`.
#
#   All workers run with `no_trim: true` (`AFL_DISABLE_TRIM=1`); AST compaction
#   is handled organically inside `libprismmutator.so` (`emit_ast_shrink`).
#
# Usage:
#   ./campaigns/diff-funnel.rb validate
#   ./campaigns/diff-funnel.rb run
#   CAMPAIGN=campaigns/diff-funnel.rb make run

fuzz_lib = File.expand_path("../lib", __dir__)
$LOAD_PATH.unshift(fuzz_lib) unless $LOAD_PATH.include?(fuzz_lib)
require "prism_fuzzer"

DEFAULT_PRISM_REF = "a5e01d818fa45f2cea9232754251a6855f82ab98"
DEFAULT_RUBY_REF = "0d399335b733776187e43a783e5f950c18ad881c"

non_empty_env = ->(key) do
  val = ENV[key].to_s.strip
  val.empty? ? nil : val
end

prism_dir = non_empty_env.call("PRISM_DIR")
prism_patches = non_empty_env.call("PRISM_PATCHES")
prism_templates = non_empty_env.call("PRISM_TEMPLATES")
ruby_dir = non_empty_env.call("RUBY_DIR") || non_empty_env.call("RUBY_ORACLE_DIR_CUSTOM")

small_max_input = Integer(non_empty_env.call("FUZZ_SMALL_MAX_INPUT_SIZE") || "256")
large_max_input = Integer(non_empty_env.call("FUZZ_LARGE_MAX_INPUT_SIZE") || non_empty_env.call("FUZZ_MAX_INPUT_SIZE") || "8192")
max_allocated_mb = Integer(non_empty_env.call("FUZZ_MAX_ALLOCATED") || "256")
run_duration = non_empty_env.call("FUZZ_DURATION")

PrismFuzzer.campaign "diff-funnel-prism-fleet" do
  workspace "tmp/fuzz-diff-funnel", build_dir: "tmp/fuzz-diff-funnel/build"
  duration run_duration if run_duration
  defaults max_input_size: small_max_input, max_allocated_mb: max_allocated_mb
  after_run { report }

  prism :prism_a,
        repo: non_empty_env.call("PRISM_REPO") || PrismFuzzer::CampaignDSL::PRISM_DEFAULT_REPO,
        ref: non_empty_env.call("PRISM_REF") || (prism_dir ? nil : DEFAULT_PRISM_REF),
        dir: prism_dir,
        patches: prism_patches || (prism_dir ? "none" : "auto"),
        templates: prism_templates || "auto"

  ruby :ruby,
       repo: non_empty_env.call("RUBY_REPO") || PrismFuzzer::CampaignDSL::RUBY_DEFAULT_REPO,
       ref: non_empty_env.call("RUBY_REF") || (ruby_dir ? nil : DEFAULT_RUBY_REF),
       dir: ruby_dir

  coverage source: :prism_a, fuzzer: "fuzz", diff_fuzzer: "fuzz.diff"

  corpus_generator :corpus_small,
                   source: :prism_a,
                   fuzzer: "fuzz",
                   dir: "corpus-256",
                   max_input_size: small_max_input
  corpus_generator :corpus_8k,
                   source: :prism_a,
                   fuzzer: "fuzz",
                   dir: "corpus-8k",
                   max_input_size: large_max_input

  fuzzer "fuzz",           shape: :prism_parse,     source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto, document_ids: true
  fuzzer "fuzz.ijon",      shape: :prism_parse,     source: :prism_a, sanitizers: [], mode: :fast, afl: :lto, ijon: true, xallocator: true, document_ids: true
  fuzzer "fuzz.diff",      shape: :prism_diff_ruby, prism: :prism_a,  ruby: :ruby, sanitizers: [], afl: :pcguard, document_ids: true
  fuzzer "fuzz.ijon.diff", shape: :prism_diff_ruby, prism: :prism_a,  ruby: :ruby, sanitizers: [], afl: :pcguard, ijon: true, document_ids: true

  sync_group "afl-small", dir: "afl-small", primary: true
  sync_group "afl-8k",    dir: "afl-8k"

  # ===========================================================================
  # Island 1: 256 B High-Velocity Differential Factory (`afl-small`, 15 workers)
  # ===========================================================================
  worker :"small-diff-main", fuzzer: "fuzz.ijon.diff", sync_group: "afl-small", afl_role: :main, max_input_size: small_max_input do
    mutator "libprismmutator.so"
    schedule "explore"
    no_trim true
    mem_limit :none
    keep_open_on_exit true
    env FUZZ_IJON_MODE: "both"
    seeds from: :corpus_small, filter: :self_pass, cache_key: "small_ijon_diff"
    color "#f97316"
  end

  small_diff_workers = [
    # Hybrid AST + IJON (both Prism & parse.y AST signals)
    { id: "small-ast-fast",   fuzzer: "fuzz.ijon.diff", mutator: "libprismmutator.so", schedule: "fast",    afl_flags: [],             env: { FUZZ_IJON_MODE: "both" },  color: "#fb923c" },
    { id: "small-ast-coe",    fuzzer: "fuzz.ijon.diff", mutator: "libprismmutator.so", schedule: "coe",     afl_flags: [],             env: { FUZZ_IJON_MODE: "both" },  color: "#fdba74" },
    { id: "small-ast-rare",   fuzzer: "fuzz.ijon.diff", mutator: "libprismmutator.so", schedule: "rare",    afl_flags: [],             env: { FUZZ_IJON_MODE: "both" },  color: "#f59e0b" },
    { id: "small-ast-quad",   fuzzer: "fuzz.ijon.diff", mutator: "libprismmutator.so", schedule: "quad",    afl_flags: %w[-P exploit], env: { FUZZ_IJON_MODE: "both" },  color: "#d97706" },
    # Pure AST (syntax-preserving deep grammar exploration)
    { id: "small-ast-only-1", fuzzer: "fuzz.ijon.diff", mutator: "libprismmutator.so", schedule: "explore", afl_flags: [],             env: { FUZZ_IJON_MODE: "both",  AFL_CUSTOM_MUTATOR_ONLY: "1" }, color: "#eab308" },
    { id: "small-ast-only-2", fuzzer: "fuzz.ijon.diff", mutator: "libprismmutator.so", schedule: "rare",    afl_flags: [],             env: { FUZZ_IJON_MODE: "cruby", AFL_CUSTOM_MUTATOR_ONLY: "1" }, color: "#ca8a04" },
    # Hybrid AST + parse.y-only IJON
    { id: "small-ast-cruby",  fuzzer: "fuzz.ijon.diff", mutator: "libprismmutator.so", schedule: "fast",    afl_flags: [],             env: { FUZZ_IJON_MODE: "cruby" }, color: "#facc15" },
    # Pure PCGUARD + AST (maximum exec/s, zero IJON overhead)
    { id: "small-ast-cfg-1",  fuzzer: "fuzz.diff",      mutator: "libprismmutator.so", schedule: "explore", afl_flags: [],             env: {},                          color: "#38bdf8" },
    { id: "small-ast-cfg-2",  fuzzer: "fuzz.diff",      mutator: "libprismmutator.so", schedule: "fast",    afl_flags: [],             env: {},                          color: "#0ea5e9" },
    # Non-AST havoc diversity (lexer/encoding/CR/NUL/escape edge cases)
    { id: "small-havoc-mopt", fuzzer: "fuzz.ijon.diff", schedule: "fast",  afl_flags: %w[-L 0],       env: { FUZZ_IJON_MODE: "both" }, color: "#ef4444" },
    { id: "small-havoc-text", fuzzer: "fuzz.ijon.diff", schedule: "coe",   afl_flags: %w[-Z -a text], env: { FUZZ_IJON_MODE: "both" }, color: "#f43f5e" },
    { id: "small-havoc-mm",   fuzzer: "fuzz.ijon.diff", schedule: "mmopt", afl_flags: [],             env: { FUZZ_IJON_MODE: "both" }, color: "#ec4899" },
    { id: "small-cfg-mopt",   fuzzer: "fuzz.diff",      schedule: "fast",  afl_flags: %w[-L 0],       env: {},                         color: "#60a5fa" }
  ]

  workers small_diff_workers, kind: :afl, sync_group: "afl-small", afl_role: :secondary, max_input_size: small_max_input, mem_limit: :none do |w, cfg|
    w.no_trim true
    cache_id = cfg["fuzzer"] == "fuzz.diff" ? "small_cfg_diff" : "small_ijon_diff"
    w.seeds from: :corpus_small, filter: :self_pass, cache_key: cache_id
  end

  # Sidekick fast Prism-only IJON+AST worker (~48k exec/s): catches node_location
  # underflows & xallocator leaks while feeding compact valid Prism seeds into diff.
  worker :"small-prism-ast", fuzzer: "fuzz.ijon", sync_group: "afl-small", afl_role: :secondary, max_input_size: small_max_input do
    mutator "libprismmutator.so"
    schedule "explore"
    no_trim true
    mem_limit :none
    env AFL_CRASH_EXITCODE: "23"
    seeds from: :corpus_small, shard_group: :small_prism
    color "#10b981"
  end

  # ===========================================================================
  # Island 2: 8 KiB Deep-Context Differential Island (`afl-8k`, 5 workers)
  #   One-way `peer_import` from `afl-small` (`small-diff-main`, `small-ast-only-1`).
  # ===========================================================================
  worker :"8k-diff-main", fuzzer: "fuzz.ijon.diff", sync_group: "afl-8k", afl_role: :main, max_input_size: large_max_input do
    mutator "libprismmutator.so"
    schedule "explore"
    no_trim true
    mem_limit :none
    env FUZZ_IJON_MODE: "both"
    peer_import group: "afl-small", worker: :"small-diff-main",  alias: "small_diff_feed"
    peer_import group: "afl-small", worker: :"small-ast-only-1", alias: "small_ast_feed"
    seeds from: :corpus_8k, filter: :self_pass, cache_key: "large_ijon_diff"
    color "#ea580c"
  end

  large_diff_workers = [
    { id: "8k-ast-rare",   fuzzer: "fuzz.ijon.diff", mutator: "libprismmutator.so", schedule: "rare",    afl_flags: [],             env: { FUZZ_IJON_MODE: "both" }, color: "#c2410c" },
    { id: "8k-ast-only",   fuzzer: "fuzz.ijon.diff", mutator: "libprismmutator.so", schedule: "explore", afl_flags: [],             env: { FUZZ_IJON_MODE: "cruby", AFL_CUSTOM_MUTATOR_ONLY: "1" }, color: "#9a3412" },
    { id: "8k-havoc-text", fuzzer: "fuzz.ijon.diff", schedule: "coe",               afl_flags: %w[-Z -a text],                      env: { FUZZ_IJON_MODE: "both" }, color: "#e11d48" },
    { id: "8k-cfg-ast",    fuzzer: "fuzz.diff",      mutator: "libprismmutator.so", schedule: "fast",    afl_flags: [],             env: {},                         color: "#2563eb" }
  ]

  workers large_diff_workers, kind: :afl, sync_group: "afl-8k", afl_role: :secondary, max_input_size: large_max_input, mem_limit: :none do |w, cfg|
    w.no_trim true
    cache_id = cfg["fuzzer"] == "fuzz.diff" ? "large_cfg_diff" : "large_ijon_diff"
    w.seeds from: :corpus_8k, filter: :self_pass, cache_key: cache_id
  end
end
