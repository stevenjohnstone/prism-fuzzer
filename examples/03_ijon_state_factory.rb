#!/usr/bin/env ruby
# frozen_string_literal: true

# Three-Island Pipeline:
#   1. `ijon_island`: ultra-fast native xallocator + IJON parser fed by grammar #1
#   2. `sand_island`: AFL++ Sand (`aux_fuzzer`) pairing fast native execution with heavy sanitizer checks
#   3. `san_hub`:     primary ASan/UBSan + MSan + LSan + CRuby parse.y differential hub
#      fed by grammar #2 AND asymmetric `peer_import` bridges pulling discoveries
#      from both exploration islands without throttling their raw exec/s.
#
# Usage:
#   ./examples/03_ijon_state_factory.rb validate
#   ./examples/03_ijon_state_factory.rb run

fuzz_lib = File.expand_path("../lib", __dir__)
$LOAD_PATH.unshift(fuzz_lib) unless $LOAD_PATH.include?(fuzz_lib)
require "prism_fuzzer"

PrismFuzzer.campaign "ijon-state-factory" do
  workspace "tmp/examples/03_ijon_factory"
  defaults max_input_size: 1024, max_allocated_mb: 128

  after_run do
    report threads: 4, top: 25
  end

  prism :prism_a,
        repo: PrismFuzzer::CampaignDSL::PRISM_DEFAULT_REPO,
        ref: ENV.fetch("PRISM_REF", "a1d1d96c368d49b752d06e361823a098b54f9a9d"),
        patches: "auto"

  ruby :ruby,
       repo: PrismFuzzer::CampaignDSL::RUBY_DEFAULT_REPO,
       ref: ENV.fetch("RUBY_REF", "495f3778a4020ecc828083239e945e60c51245ae")

  coverage source: :prism_a, fuzzer: "fuzz.asan", diff_fuzzer: "fuzz.diff"

  corpus_generator :corpus, source: :prism_a, fuzzer: "fuzz.asan"

  fuzzer "fuzz.native",  shape: :prism_parse,     source: :prism_a, sanitizers: [],               mode: :fast, afl: :lto,     xallocator: true
  fuzzer "fuzz.sand",    shape: :prism_parse,     source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :sand
  fuzzer "fuzz.ijon",    shape: :prism_parse,     source: :prism_a, sanitizers: [],               mode: :fast, afl: :lto,     ijon: true, xallocator: true
  fuzzer "fuzz.asan",    shape: :prism_parse,     source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto,     document_ids: true
  fuzzer "fuzz.msan",    shape: :prism_parse,     source: :prism_a, sanitizers: [:msan],          mode: :slow, afl: :lto
  fuzzer "fuzz.lsan",    shape: :prism_parse,     source: :prism_a, sanitizers: [:lsan],          mode: :slow, afl: :lto
  fuzzer "fuzz.cmplog",  shape: :prism_parse,     source: :prism_a, sanitizers: [],               mode: :fast, afl: :cmplog
  fuzzer "fuzz.diff",    shape: :prism_diff_ruby, prism: :prism_a,  ruby: :ruby, sanitizers: [],             afl: :pcguard, ijon: true, document_ids: true

  sync_group :san_hub,     dir: "afl-hub",  primary: true
  sync_group :ijon_island, dir: "afl-ijon"
  sync_group :sand_island, dir: "afl-sand"

  # Island 1: Dedicated high-throughput IJON state explorers
  worker :ijon_scout, fuzzer: "fuzz.ijon", sync_group: :ijon_island, afl_role: :main do
    schedule "explore"
    seeds from: :corpus, shard_group: :ijon
    mem_limit 2048
    env AFL_SYNC_TIME: "1", AFL_CRASH_EXITCODE: "23"
    color "#4ade80"
  end

  worker :ijon_exploit, fuzzer: "fuzz.ijon", sync_group: :ijon_island, afl_role: :secondary do
    schedule "exploit"
    seeds from: :corpus, shard_group: :ijon
    mem_limit 2048
    env AFL_CRASH_EXITCODE: "23"
    color "#22c55e"
  end

  # Island 2: Fast uninstrumented executor paired with AFL++ Sand coverage-increase sanitizer triggers
  worker :sand_runner, fuzzer: "fuzz.native", aux_fuzzer: "fuzz.sand", sync_group: :sand_island, afl_role: :main do
    schedule "fast"
    no_trim true
    mem_limit :none
    seeds from: :corpus
    env AFL_SAN_ABSTRACTION: "coverage_increase", AFL_CRASH_EXITCODE: "23"
    color "#38bdf8"
  end

  # Primary Hub: Pulls breakthroughs from both islands and tests every sanitizer + parse.y
  worker :hub_main, fuzzer: "fuzz.asan", sync_group: :san_hub, afl_role: :main do
    schedule "exploit"
    cmplog "fuzz.cmplog"
    peer_import group: :ijon_island, worker: :ijon_scout,  alias: "ijon_feed"
    peer_import group: :sand_island, worker: :sand_runner, alias: "sand_feed"
    seeds from: :corpus, shard_group: :hub
    keep_open_on_exit true
    color "#60a5fa"
  end

  workers(kind: :afl, sync_group: :san_hub, afl_role: :secondary) do
    worker :hub_msan, fuzzer: "fuzz.msan", schedule: "fast",    no_trim: true, color: "#a78bfa" do
      seeds from: :corpus, shard_group: :hub
    end
    worker :hub_lsan, fuzzer: "fuzz.lsan", schedule: "fast",    no_trim: true, color: "#c084fc" do
      seeds from: :corpus, shard_group: :hub
    end
    worker :hub_diff, fuzzer: "fuzz.diff", schedule: "explore", mem_limit: :none, color: "#fb923c" do
      seeds from: :corpus, filter: :self_pass
    end
  end
end
