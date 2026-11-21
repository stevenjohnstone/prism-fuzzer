#!/usr/bin/env ruby
# frozen_string_literal: true

# Compile-Time Define & Feature-Flag Matrix
# Uses Ruby metaprogramming inside the DSL to build an ensemble over distinct
# Prism preprocessor configurations (`PRISM_ACCEL_SWAR`, small depth/arena slab
# bounds, streaming+IJON, disabled stack budget, disabled scope forwarding).
# `coverage_target_for_fuzzer` automatically compiles separate LLVM coverage
# binaries and HTML sub-reports per unique `(source, cflags)` target!
#
# Usage:
#   ./examples/04_define_flag_matrix.rb validate
#   ./examples/04_define_flag_matrix.rb plan | ruby -rjson -e 'puts JSON.parse(STDIN.read)["fuzzers"].keys'

fuzz_lib = File.expand_path("../lib", __dir__)
$LOAD_PATH.unshift(fuzz_lib) unless $LOAD_PATH.include?(fuzz_lib)
require "prism_fuzzer"

MATRIX_VARIANTS = [
  { name: "default",        schedule: "exploit", color: "#60a5fa", defines: {},                                            ijon: false },
  { name: "swar",           schedule: "fast",    color: "#38bdf8", defines: { PRISM_ACCEL_SWAR: true },                    ijon: false },
  { name: "tiny_arena",     schedule: "explore", color: "#fbbf24", defines: { PM_ARENA_INITIAL_SIZE: 64, PRISM_DEPTH_MAXIMUM: 16 }, ijon: false },
  { name: "stream_ijon",    schedule: "fast",    color: "#4ade80", defines: { PRISM_FUZZ_ALLOW_STREAM_WITH_IJON: true },   ijon: true },
  { name: "no_stack_guard", schedule: "lin",     color: "#f472b6", defines: { PRISM_FUZZ_NO_STACK_BUDGET: true },          ijon: false },
  { name: "no_forwarding",  schedule: "coe",     color: "#a78bfa", defines: { PRISM_FUZZ_NO_SCOPE_FORWARDING: true },      ijon: false }
].freeze

PrismFuzzer.campaign "define-flag-matrix" do
  workspace "tmp/examples/04_define_matrix"
  defaults max_input_size: 1024, max_allocated_mb: 128

  after_run do
    report threads: 4
  end

  prism :prism_a,
        repo: PrismFuzzer::CampaignDSL::PRISM_DEFAULT_REPO,
        ref: ENV.fetch("PRISM_REF", "a1d1d96c368d49b752d06e361823a098b54f9a9d"),
        patches: "auto"

  coverage source: :prism_a, fuzzer: "fuzz.default"
  corpus_generator :corpus, source: :prism_a, fuzzer: "fuzz.default"
  fuzzer "fuzz.cmplog", shape: :prism_parse, source: :prism_a, sanitizers: [], mode: :fast, afl: :cmplog

  MATRIX_VARIANTS.each do |v|
    opts = {
      shape: :prism_parse,
      source: :prism_a,
      sanitizers: %i[asan ubsan],
      mode: :fast,
      afl: :lto,
      ijon: v[:ijon],
      document_ids: v[:name] == "default"
    }
    opts[:defines] = v[:defines] unless v[:defines].empty?
    fuzzer "fuzz.#{v[:name]}", **opts
  end

  sync_group :afl, dir: "afl", primary: true

  MATRIX_VARIANTS.each_with_index do |v, idx|
    worker :"w_#{v[:name]}",
           fuzzer: "fuzz.#{v[:name]}",
           sync_group: :afl,
           afl_role: idx.zero? ? :main : :secondary,
           schedule: v[:schedule],
           cmplog: idx.zero? ? "fuzz.cmplog" : nil,
           color: v[:color] do
      seeds from: :corpus, shard_group: :matrix
    end
  end
end
