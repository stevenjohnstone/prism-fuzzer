#!/usr/bin/env ruby
# frozen_string_literal: true

# Two-Island Asymmetric Funnel Campaign (`ijon-funnel-prism-fleet`, 22 workers):
#   Pairs a high-velocity 256-byte exploration factory (`afl-small`, 14 AFL++
#   workers + `grammar-256`) with an 8 KiB deep-state/bignum/cross-arch hub
#   (`afl-8k`, 6 AFL++ workers + `grammar-8k`) connected via strictly one-way
#   `small -> 8k` `peer_import` bridges:
#
#   1. `afl-small` (256 B payload / `-G 260`, 14 workers + `grammar-256`):
#      Maximizes `execs/s` and per-byte mutation density across native IJON+SAND,
#      CmpLog+ASan/UBSan, slow AST/span/stream invariants, MSan, LSan, and a
#      5-worker CRuby `parse.y` differential squadron without wasting sync cycles
#      truncating multi-kilobyte inputs.
#
#   2. `afl-8k` (8,192 B payload / `-G 8196`, 6 workers + `grammar-8k`):
#      Imports every compact breakthrough from `small-scout`, `small-asan`, and
#      `small-diff` while receiving multi-kilobyte bignum, long-mantissa float,
#      and deep AST seeds from `grammar-8k`. Havoc splicing combines 256 B syntax
#      primitives with 8 KiB inputs across ASan+CmpLog, slow serialization/stream
#      invariants, MSan, CRuby `parse.y` diff, and IJON-guided 32-bit `arm32`
#      (little-endian) + `ppc` (big-endian) cross-arch AST oracles.
#
# Usage:
#   ./campaigns/ijon-funnel.rb validate
#   ./campaigns/ijon-funnel.rb run
#   CAMPAIGN=campaigns/ijon-funnel.rb make run

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

prism_b_ref = non_empty_env.call("PRISM_B_REF")
prism_b_dir = non_empty_env.call("PRISM_B_DIR")
prism_b_active = !prism_b_ref.nil? || !prism_b_dir.nil?

ruby_dir = non_empty_env.call("RUBY_DIR") || non_empty_env.call("RUBY_ORACLE_DIR_CUSTOM")

small_max_input = Integer(non_empty_env.call("FUZZ_SMALL_MAX_INPUT_SIZE") || "256")
large_max_input = Integer(non_empty_env.call("FUZZ_LARGE_MAX_INPUT_SIZE") || non_empty_env.call("FUZZ_MAX_INPUT_SIZE") || "8192")
max_allocated_mb = Integer(non_empty_env.call("FUZZ_MAX_ALLOCATED") || "256")

PrismFuzzer.campaign "ijon-funnel-prism-fleet" do
  workspace "tmp/fuzz-ijon-funnel", build_dir: "tmp/fuzz-ijon-funnel/build"
  defaults max_input_size: small_max_input, max_allocated_mb: max_allocated_mb
  after_run { report }

  prism :prism_a,
        repo: non_empty_env.call("PRISM_REPO") || PrismFuzzer::CampaignDSL::PRISM_DEFAULT_REPO,
        ref: non_empty_env.call("PRISM_REF") || (prism_dir ? nil : DEFAULT_PRISM_REF),
        dir: prism_dir,
        patches: prism_patches || (prism_dir ? "none" : "auto"),
        templates: prism_templates || "auto"

  if prism_b_active
    b_patches = non_empty_env.call("PRISM_B_PATCHES")
    b_templates = non_empty_env.call("PRISM_B_TEMPLATES")
    prism :prism_b,
          repo: non_empty_env.call("PRISM_B_REPO") || PrismFuzzer::CampaignDSL::PRISM_DEFAULT_REPO,
          ref: prism_b_ref,
          dir: prism_b_dir,
          patches: b_patches || (prism_b_dir ? "none" : "auto"),
          templates: b_templates || "auto"
  end

  ruby :ruby,
       repo: non_empty_env.call("RUBY_REPO") || PrismFuzzer::CampaignDSL::RUBY_DEFAULT_REPO,
       ref: non_empty_env.call("RUBY_REF") || (ruby_dir ? nil : DEFAULT_RUBY_REF),
       dir: ruby_dir

  # Keep deterministic non-IJON CFG binaries for triage edge-clustering maps.
  coverage source: :prism_a, fuzzer: "fuzz", diff_fuzzer: "fuzz.diff"

  # Separate size-matched seed corpora:
  # - corpus_small: AST-split <= 256 B statements so 256 B workers never truncate seeds
  # - corpus_8k:    full unsplit fixtures + 2 KB arena & 4 KB stream fgets boundary seeds
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

  ijon_stream_defs = { PRISM_FUZZ_ALLOW_STREAM_WITH_IJON: 1 }
  fuzzer "fuzz.ijon",       shape: :prism_parse,        source: :prism_a, sanitizers: [],             mode: :fast, afl: :lto,     ijon: true, xallocator: true
  fuzzer "fuzz.ijon.asan",  shape: :prism_parse,        source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto,     ijon: true
  fuzzer "fuzz.ijon.slow",  shape: :prism_parse,        source: :prism_a, sanitizers: %i[asan ubsan], mode: :slow, afl: :lto,     ijon: true, defines: ijon_stream_defs
  fuzzer "fuzz.ijon.msan",  shape: :prism_parse,        source: :prism_a, sanitizers: [:msan],        mode: :slow, afl: :lto,     ijon: true, defines: ijon_stream_defs
  fuzzer "fuzz.ijon.lsan",  shape: :prism_parse,        source: :prism_a, sanitizers: [:lsan],        mode: :slow, afl: :lto,     ijon: true, defines: ijon_stream_defs
  fuzzer "fuzz.ijon.diff",  shape: :prism_diff_ruby,    prism: :prism_a,  ruby: :ruby, sanitizers: [],             afl: :pcguard, ijon: true, document_ids: true

  fuzzer "fuzz.sand",       shape: :prism_parse,        source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :sand
  fuzzer "fuzz.cmplog",     shape: :prism_parse,        source: :prism_a, sanitizers: [],             mode: :fast, afl: :cmplog
  fuzzer "fuzz",            shape: :prism_parse,        source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto,     document_ids: true
  fuzzer "fuzz.lsan",       shape: :prism_parse,        source: :prism_a, sanitizers: [:lsan],        mode: :slow, afl: :lto
  fuzzer "fuzz.diff",       shape: :prism_diff_ruby,    prism: :prism_a,  ruby: :ruby, sanitizers: [],             afl: :pcguard, document_ids: true

  # IJON-enabled 32-bit ARM32 (LE) & PowerPC (BE) cross-arch AST/bignum oracles
  fuzzer "fuzz.arm32",      shape: :prism_cross_oracle, source: :prism_a, arch: :arm32, sanitizers: %i[asan ubsan], afl: :pcguard, ijon: true, mutator: "mutator_oracle64.so", repro: "fuzz.arm32.repro"
  fuzzer "fuzz.ppc",        shape: :prism_cross_oracle, source: :prism_a, arch: :ppc,   sanitizers: %i[asan ubsan], afl: :pcguard, ijon: true, mutator: "mutator_oracle64.so", repro: "fuzz.ppc.repro"

  if prism_b_active
    fuzzer "fuzz.ijon.prism_diff",
           shape: :prism_diff_prism,
           prism_a: :prism_a,
           prism_b: :prism_b,
           sanitizers: %i[asan ubsan],
           afl: :pcguard,
           ijon: true,
           document_ids: true
  end

  sync_group "afl-8k",    dir: "afl-8k",    primary: true
  sync_group "afl-small", dir: "afl-small"

  # ===========================================================================
  # Island 1: 256 B High-Velocity Factory (`afl-small`, 15 AFL++ workers)
  #   No incoming imports from `afl-8k` so workers never waste cycles on
  #   truncated >256 B prefixes.
  # ===========================================================================
  worker :"small-scout", fuzzer: "fuzz.ijon", sync_group: "afl-small", afl_role: :main, max_input_size: small_max_input do
    aux_fuzzer "fuzz.sand"
    schedule "explore"
    seeds from: :corpus_small, shard_group: :small_prism
    mem_limit :none
    env AFL_SAN_ABSTRACTION: "coverage_increase", AFL_CRASH_EXITCODE: "23"
    color "#4ade80"
  end

  small_san_workers = [
    { id: "small-explore-2", fuzzer: "fuzz.ijon",      schedule: "fast",    afl_flags: %w[-L 0],       mem_limit: :none, env: { AFL_CRASH_EXITCODE: "23" }, color: "#22c55e" },
    { id: "small-ast",       fuzzer: "fuzz.ijon",      mutator: "libprismmutator.so", schedule: "explore", mem_limit: :none, env: { AFL_CRASH_EXITCODE: "23" }, color: "#10b981" },
    { id: "small-asan",      fuzzer: "fuzz.ijon.asan", cmplog: "fuzz.cmplog", schedule: "exploit",     loopcount: 2000, keep_open_on_exit: true, color: "#60a5fa" },
    { id: "small-asan-coe",  fuzzer: "fuzz.ijon.asan", schedule: "coe",     afl_flags: %w[-P explore], loopcount: 2000, color: "#38bdf8" },
    { id: "small-asan-text", fuzzer: "fuzz.ijon.asan", schedule: "lin",     afl_flags: %w[-Z -a text], loopcount: 2000, color: "#818cf8" },
    { id: "small-slow",      fuzzer: "fuzz.ijon.slow", schedule: "fast",    no_trim: true,             loopcount: 2000, color: "#f472b6" },
    { id: "small-slow-2",    fuzzer: "fuzz.ijon.slow", schedule: "quad",    afl_flags: %w[-P exploit], no_trim: true, loopcount: 2000, color: "#ec4899" },
    { id: "small-msan",      fuzzer: "fuzz.ijon.msan", schedule: "fast",    no_trim: true,             loopcount: 2000, color: "#a78bfa" },
    { id: "small-lsan",      fuzzer: "fuzz.ijon.lsan", schedule: "rare",    no_trim: true,             loopcount: 2000, color: "#c084fc" }
  ]
  if prism_b_active
    small_san_workers << {
      id: "small-prism-diff",
      fuzzer: "fuzz.ijon.prism_diff",
      schedule: "explore",
      mem_limit: :none,
      color: "#facc15"
    }
  end

  workers small_san_workers, kind: :afl, sync_group: "afl-small", afl_role: :secondary, max_input_size: small_max_input do
    seeds from: :corpus_small, shard_group: :small_prism
  end

  small_diff_workers = [
    { id: "small-diff",       fuzzer: "fuzz.ijon.diff", schedule: "explore", afl_flags: [],             no_trim: false, color: "#f97316" },
    { id: "small-diff-ast",   fuzzer: "fuzz.ijon.diff", mutator: "libprismmutator.so", schedule: "explore", afl_flags: [], no_trim: false, color: "#fb923c" },
    { id: "small-diff-text",  fuzzer: "fuzz.ijon.diff", schedule: "coe",     afl_flags: %w[-Z -a text], no_trim: false, color: "#fdba74" },
    { id: "small-cfg-diff",   fuzzer: "fuzz.diff",      schedule: "mmopt",   afl_flags: [],             no_trim: true,  color: "#f59e0b" },
    { id: "small-cfg-diff-2", fuzzer: "fuzz.diff",      schedule: "fast",    afl_flags: %w[-L 0],       no_trim: true,  color: "#fbbf24" }
  ]

  workers small_diff_workers, kind: :afl, sync_group: "afl-small", afl_role: :secondary, max_input_size: small_max_input, mem_limit: :none do |w, cfg|
    cache_id = cfg["fuzzer"] == "fuzz.diff" ? "small_cfg_diff" : "small_ijon_diff"
    w.seeds from: :corpus_small, filter: :self_pass, cache_key: cache_id
  end

  # ===========================================================================
  # Island 2: 8 KiB Deep-State, Bignum & Cross-Arch Hub (`afl-8k`, 7 AFL++ workers)
  #   Pulls one-way discoveries from `afl-small` (`small-scout`, `small-asan`,
  #   `small-diff`), splicing compact building blocks into 8 KiB programs,
  #   Karatsuba bignums, stream chunks, and 32-bit LE/BE AST checks.
  # ===========================================================================
  worker :"8k-main", fuzzer: "fuzz.ijon.asan", sync_group: "afl-8k", afl_role: :main, max_input_size: large_max_input do
    cmplog "fuzz.cmplog"
    schedule "explore"
    loopcount 2000
    keep_open_on_exit true
    peer_import group: "afl-small", worker: :"small-scout", alias: "small_scout_feed"
    peer_import group: "afl-small", worker: :"small-asan",  alias: "small_asan_feed"
    peer_import group: "afl-small", worker: :"small-diff",  alias: "small_diff_feed"
    seeds from: :corpus_8k, shard_group: :large_prism
    color "#2563eb"
  end

  large_san_workers = [
    { id: "8k-slow", fuzzer: "fuzz.ijon.slow", schedule: "exploit", no_trim: true, loopcount: 2000, color: "#db2777" },
    { id: "8k-msan", fuzzer: "fuzz.ijon.msan", schedule: "fast",    no_trim: true, loopcount: 2000, color: "#7c3aed" }
  ]
  if prism_b_active
    large_san_workers << {
      id: "8k-prism-diff",
      fuzzer: "fuzz.ijon.prism_diff",
      schedule: "explore",
      mem_limit: :none,
      color: "#eab308"
    }
  end

  workers large_san_workers, kind: :afl, sync_group: "afl-8k", afl_role: :secondary, max_input_size: large_max_input do
    seeds from: :corpus_8k, shard_group: :large_prism
  end

  worker :"8k-diff", fuzzer: "fuzz.ijon.diff", sync_group: "afl-8k", afl_role: :secondary, max_input_size: large_max_input do
    schedule "explore"
    mem_limit :none
    seeds from: :corpus_8k, filter: :self_pass, cache_key: "large_ijon_diff"
    color "#ea580c"
  end

  worker :"8k-diff-ast", fuzzer: "fuzz.ijon.diff", sync_group: "afl-8k", afl_role: :secondary, max_input_size: large_max_input do
    mutator "libprismmutator.so"
    schedule "explore"
    mem_limit :none
    seeds from: :corpus_8k, filter: :self_pass, cache_key: "large_ijon_diff"
    color "#fb923c"
  end

  large_cross_workers = [
    { id: "8k-arm32", fuzzer: "fuzz.arm32", schedule: "explore", mem_limit: :none, color: "#14b8a6" },
    { id: "8k-ppc",   fuzzer: "fuzz.ppc",   schedule: "explore", no_trim: true, mem_limit: :none, color: "#d946ef" }
  ]

  workers large_cross_workers, kind: :afl, sync_group: "afl-8k", afl_role: :secondary, max_input_size: large_max_input do
    seeds from: :corpus_8k, shard_group: :large_cross
  end
end
