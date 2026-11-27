#!/usr/bin/env ruby
# frozen_string_literal: true

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

max_input_size = Integer(non_empty_env.call("FUZZ_MAX_INPUT_SIZE") || "1024")
max_allocated_mb = Integer(non_empty_env.call("FUZZ_MAX_ALLOCATED") || "128")

PrismFuzzer.campaign "default-prism-fleet" do
  workspace "tmp/fuzz"
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

  coverage source: :prism_a, fuzzer: "fuzz", diff_fuzzer: "fuzz.diff"

  corpus_generator :corpus, source: :prism_a, fuzzer: "fuzz"

  fuzzer "fuzz.msan",     shape: :prism_parse, source: :prism_a, sanitizers: [:msan],          mode: :slow, afl: :lto
  fuzzer "fuzz.lsan",     shape: :prism_parse, source: :prism_a, sanitizers: [:lsan],          mode: :slow, afl: :lto
  fuzzer "fuzz.ijon",     shape: :prism_parse, source: :prism_a, sanitizers: [],               mode: :fast, afl: :lto, ijon: true, xallocator: true
  fuzzer "fuzz.native",   shape: :prism_parse, source: :prism_a, sanitizers: [],               mode: :fast, afl: :lto,  xallocator: true
  fuzzer "fuzz",          shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan],   mode: :fast, afl: :lto,  document_ids: true
  fuzzer "fuzz.sand",     shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan],   mode: :fast, afl: :sand
  fuzzer "fuzz.slow",     shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan],   mode: :slow, afl: :lto
  fuzzer "fuzz.cmplog",   shape: :prism_parse, source: :prism_a, sanitizers: [],               mode: :fast, afl: :cmplog
  fuzzer "fuzz.diff",      shape: :prism_diff_ruby, prism: :prism_a, ruby: :ruby, sanitizers: [], afl: :pcguard, document_ids: true
  fuzzer "fuzz.ijon.diff", shape: :prism_diff_ruby, prism: :prism_a, ruby: :ruby, sanitizers: [], afl: :pcguard, ijon: true, document_ids: true
  fuzzer "fuzz.arm32",    shape: :prism_cross_oracle, source: :prism_a, arch: :arm32, sanitizers: %i[asan ubsan], afl: :pcguard, mutator: "mutator_oracle64.so", repro: "fuzz.arm32.repro"
  fuzzer "fuzz.ppc",      shape: :prism_cross_oracle, source: :prism_a, arch: :ppc,   sanitizers: %i[asan ubsan], afl: :pcguard, mutator: "mutator_oracle64.so", repro: "fuzz.ppc.repro"

  if prism_b_active
    fuzzer "fuzz.prism_diff",
           shape: :prism_diff_prism,
           prism_a: :prism_a,
           prism_b: :prism_b,
           sanitizers: %i[asan ubsan],
           afl: :pcguard,
           document_ids: true
  end

  sync_group :afl,        dir: "afl",      primary: true
  sync_group "afl-ijon",  dir: "afl-ijon"

  worker :main, fuzzer: "fuzz", sync_group: :afl, afl_role: :main do
    schedule "exploit"
    cmplog "fuzz.cmplog"
    loopcount 2000
    seeds from: :corpus
    peer_import group: "afl-ijon", worker: :ijon, alias: "ijon_peer"
    keep_open_on_exit true
    color "#60a5fa"
  end

  worker :ijon, fuzzer: "fuzz.ijon", sync_group: "afl-ijon", afl_role: :main do
    schedule "explore"
    seeds from: :corpus, shard_group: :prism
    mem_limit max_allocated_mb * 16
    env AFL_CRASH_EXITCODE: "23"
    ulimit_v_kb 4_194_304
    color "#4ade80"
  end

  shard_workers = [
    { id: :msan, fuzzer: "fuzz.msan", schedule: "fast", no_trim: true, loopcount: 2000, color: "#a78bfa" },
    { id: :slow, fuzzer: "fuzz.slow", schedule: "fast", no_trim: true, loopcount: 2000, color: "#f472b6" },
    {
      id: "main-2",
      fuzzer: "fuzz.native",
      aux_fuzzer: "fuzz.sand",
      schedule: "explore",
      afl_flags: %w[-P explore -L 0],
      no_trim: true,
      mem_limit: :none,
      env: { AFL_SAN_ABSTRACTION: "coverage_increase", AFL_CRASH_EXITCODE: "23" },
      color: "#38bdf8"
    },
    { id: :arm32, fuzzer: "fuzz.arm32", schedule: "explore", mem_limit: :none, color: "#2dd4bf" },
    { id: :ppc,   fuzzer: "fuzz.ppc",   schedule: "explore", no_trim: true, mem_limit: :none, color: "#e879f9" }
  ]
  if prism_b_active
    shard_workers << {
      id: :prism_diff,
      fuzzer: "fuzz.prism_diff",
      schedule: "explore",
      mem_limit: :none,
      color: "#facc15"
    }
  end

  workers shard_workers, kind: :afl, sync_group: :afl, afl_role: :secondary do
    seeds from: :corpus, shard_group: :prism
  end

  diff_variants = [
    { id: :diff,       fuzzer: "fuzz.diff",      schedule: "explore", afl_flags: [],             no_trim: false, color: "#f97316" },
    { id: "diff-2",    fuzzer: "fuzz.diff",      schedule: "fast",    afl_flags: %w[-L 0],       no_trim: true },
    { id: "diff-3",    fuzzer: "fuzz.diff",      schedule: "coe",     afl_flags: %w[-Z -a text], no_trim: false },
    { id: "diff-4",    fuzzer: "fuzz.diff",      schedule: "lin",     afl_flags: %w[-P exploit], no_trim: true },
    { id: "diff-ijon", fuzzer: "fuzz.ijon.diff", schedule: "explore", afl_flags: [],             no_trim: false, env: { FUZZ_IJON_MODE: "both" } },
    { id: "diff-ast",  fuzzer: "fuzz.ijon.diff", mutator: "libprismmutator.so", schedule: "explore", afl_flags: [], no_trim: false, env: { FUZZ_IJON_MODE: "both" } }
  ]

  workers diff_variants, kind: :afl, sync_group: :afl, afl_role: :secondary, mem_limit: :none, color: "#fb923c" do |w, cfg|
    cache_id = cfg["fuzzer"] == "fuzz.ijon.diff" ? "ijon_diff" : "diff"
    w.seeds from: :corpus, filter: :self_pass, cache_key: cache_id
  end
end
