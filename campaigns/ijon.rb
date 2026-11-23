#!/usr/bin/env ruby
# frozen_string_literal: true

# IJON-Centric Fleet Campaign (`ijon-prism-fleet`):
#   Makes an IJON-aware sync group (`afl-ijon`) the primary hub so sanitized,
#   invariant (`mode: :slow`), MSan, and CRuby `parse.y` differential workers
#   share IJON's state/distance view: they retain `ijon_set` discoveries during
#   sync AND seed their own `ijon_max` champion tables to hill-climb directly
#   under ASan, UBSan, MSan, serialization invariants, and CRuby `parse.y`.
#   A companion `:afl` anchor group keeps pure CFG-guided and 32-bit cross-arch
#   workers connected via bidirectional `peer_import`.
#
# Usage:
#   ./campaigns/ijon.rb validate
#   ./campaigns/ijon.rb run
#   CAMPAIGN=campaigns/ijon.rb make run

fuzz_lib = File.expand_path("../lib", __dir__)
$LOAD_PATH.unshift(fuzz_lib) unless $LOAD_PATH.include?(fuzz_lib)
require "prism_fuzzer"

DEFAULT_PRISM_REF = "a1d1d96c368d49b752d06e361823a098b54f9a9d"
DEFAULT_RUBY_REF = "e10a8eea54c38f0326472d7266e9e81ecc7d7bf9"

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

max_input_size = Integer(non_empty_env.call("FUZZ_MAX_INPUT_SIZE") || "1024")
max_allocated_mb = Integer(non_empty_env.call("FUZZ_MAX_ALLOCATED") || "128")

PrismFuzzer.campaign "ijon-prism-fleet" do
  workspace "tmp/fuzz-ijon", build_dir: "tmp/fuzz-ijon/build"
  defaults max_input_size: max_input_size, max_allocated_mb: max_allocated_mb
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

  corpus_generator :corpus, source: :prism_a, fuzzer: "fuzz"
  grammar_generator :grammar,
                    source: :prism_a,
                    fuzzer: "fuzz.ijon",
                    sync_group: "afl-ijon",
                    seeds_dir: "/tmp/afl-tmpdir/ijon-grammar/seeds",
                    schedule: "lrama",
                    ulimit_v_kb: 4_194_304,
                    color: "#34d399"

  # IJON-instrumented binaries (share 64 KiB ijon_set bitmap & 512-slot ijon_max hills).
  # Slow / MSan / LSan builds enable PRISM_FUZZ_ALLOW_STREAM_WITH_IJON so stream_mode
  # (and INVARIANT[stream_diff]) stays active alongside source-level PM_IJON_* hooks.
  ijon_stream_defs = { PRISM_FUZZ_ALLOW_STREAM_WITH_IJON: 1 }
  fuzzer "fuzz.ijon",       shape: :prism_parse,     source: :prism_a, sanitizers: [],             mode: :fast, afl: :lto,     ijon: true, xallocator: true
  fuzzer "fuzz.ijon.asan",  shape: :prism_parse,     source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto,     ijon: true
  fuzzer "fuzz.ijon.slow",  shape: :prism_parse,     source: :prism_a, sanitizers: %i[asan ubsan], mode: :slow, afl: :lto,     ijon: true, defines: ijon_stream_defs
  fuzzer "fuzz.ijon.msan",  shape: :prism_parse,     source: :prism_a, sanitizers: [:msan],        mode: :slow, afl: :lto,     ijon: true, defines: ijon_stream_defs
  fuzzer "fuzz.ijon.lsan",  shape: :prism_parse,     source: :prism_a, sanitizers: [:lsan],        mode: :slow, afl: :lto,     ijon: true, defines: ijon_stream_defs
  fuzzer "fuzz.ijon.diff",  shape: :prism_diff_ruby, prism: :prism_a,  ruby: :ruby, sanitizers: %i[asan ubsan], afl: :pcguard, ijon: true, document_ids: true

  # Shared SAND / CmpLog helpers + pure-CFG / cross-arch anchor binaries
  fuzzer "fuzz.sand",       shape: :prism_parse,     source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :sand
  fuzzer "fuzz.cmplog",     shape: :prism_parse,     source: :prism_a, sanitizers: [],             mode: :fast, afl: :cmplog
  fuzzer "fuzz",            shape: :prism_parse,     source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto,     document_ids: true
  fuzzer "fuzz.lsan",       shape: :prism_parse,     source: :prism_a, sanitizers: [:lsan],        mode: :slow, afl: :lto
  fuzzer "fuzz.diff",       shape: :prism_diff_ruby, prism: :prism_a,  ruby: :ruby, sanitizers: %i[asan ubsan], afl: :pcguard, document_ids: true
  fuzzer "fuzz.arm32",      shape: :prism_cross_oracle, source: :prism_a, arch: :arm32, sanitizers: %i[asan ubsan], afl: :pcguard, mutator: "mutator_oracle64.so", repro: "fuzz.arm32.repro"
  fuzzer "fuzz.ppc",        shape: :prism_cross_oracle, source: :prism_a, arch: :ppc,   sanitizers: %i[asan ubsan], afl: :pcguard, mutator: "mutator_oracle64.so", repro: "fuzz.ppc.repro"

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

  sync_group "afl-ijon", dir: "afl-ijon", primary: true
  sync_group :afl,       dir: "afl"

  worker :grammar, kind: :generator, generator: :grammar, color: "#34d399"

  # Fast native IJON scout paired with ASan+UBSan SAND (-w); CmpLog (-c) runs on ijon-asan & main
  worker :"ijon-scout", fuzzer: "fuzz.ijon", sync_group: "afl-ijon", afl_role: :main do
    aux_fuzzer "fuzz.sand"
    schedule "explore"
    foreign_sync :grammar
    peer_import group: :afl, worker: :main, alias: "cfg_peer"
    peer_import group: :afl, worker: :diff, alias: "cfg_diff_peer"
    seeds from: :corpus, shard_group: :ijon_prism
    mem_limit :none
    env AFL_SAN_ABSTRACTION: "coverage_increase", AFL_SYNC_TIME: "1", AFL_CRASH_EXITCODE: "23"
    color "#4ade80"
  end

  ijon_san_workers = [
    {
      id: "ijon-asan",
      fuzzer: "fuzz.ijon.asan",
      cmplog: "fuzz.cmplog",
      schedule: "exploit",
      loopcount: 2000,
      keep_open_on_exit: true,
      color: "#60a5fa"
    },
    { id: "ijon-slow", fuzzer: "fuzz.ijon.slow", schedule: "fast", no_trim: true, loopcount: 2000, color: "#f472b6" },
    { id: "ijon-msan", fuzzer: "fuzz.ijon.msan", schedule: "fast", no_trim: true, loopcount: 2000, color: "#a78bfa" }
  ]
  if prism_b_active
    ijon_san_workers << {
      id: "ijon-prism-diff",
      fuzzer: "fuzz.ijon.prism_diff",
      schedule: "explore",
      mem_limit: :none,
      color: "#facc15"
    }
  end

  workers ijon_san_workers, kind: :afl, sync_group: "afl-ijon", afl_role: :secondary do
    seeds from: :corpus, shard_group: :ijon_prism
  end

  ijon_diff_variants = [
    { id: "ijon-diff",   schedule: "explore", afl_flags: [],                   no_trim: false, color: "#f97316" },
    { id: "ijon-diff-2", schedule: "fast",    afl_flags: %w[-L 0],             no_trim: true },
    { id: "ijon-diff-3", schedule: "coe",     afl_flags: %w[-Z -a text],       no_trim: false },
    { id: "ijon-diff-4", schedule: "exploit", afl_flags: %w[-P explore],       no_trim: true }
  ]

  workers ijon_diff_variants, kind: :afl, fuzzer: "fuzz.ijon.diff", sync_group: "afl-ijon", afl_role: :secondary, mem_limit: :none, color: "#fb923c" do
    seeds from: :corpus, filter: :self_pass, cache_key: "ijon_diff"
  end

  # Pure-CFG & cross-arch anchor group (no ijon-max stage overhead; cross-synced with afl-ijon)
  worker :main, fuzzer: "fuzz", sync_group: :afl, afl_role: :main do
    schedule "exploit"
    cmplog "fuzz.cmplog"
    loopcount 2000
    seeds from: :corpus
    peer_import group: "afl-ijon", worker: :"ijon-scout", alias: "ijon_scout_peer"
    peer_import group: "afl-ijon", worker: :"ijon-asan",  alias: "ijon_asan_peer"
    color "#38bdf8"
  end

  cfg_diff_variants = [
    { id: :diff,    schedule: "explore", afl_flags: [],             no_trim: false },
    { id: "diff-2", schedule: "lin",     afl_flags: %w[-P exploit], no_trim: true }
  ]

  workers cfg_diff_variants, kind: :afl, fuzzer: "fuzz.diff", sync_group: :afl, afl_role: :secondary, mem_limit: :none, color: "#fdba74" do
    seeds from: :corpus, filter: :self_pass, cache_key: "diff"
  end

  cfg_cross_workers = [
    { id: :arm32, fuzzer: "fuzz.arm32", schedule: "explore", mem_limit: :none, color: "#2dd4bf" },
    { id: :ppc,   fuzzer: "fuzz.ppc",   schedule: "explore", no_trim: true, mem_limit: :none, color: "#e879f9" }
  ]

  workers cfg_cross_workers, kind: :afl, sync_group: :afl, afl_role: :secondary do
    seeds from: :corpus, shard_group: :cfg_prism
  end
end
