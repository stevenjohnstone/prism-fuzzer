#!/usr/bin/env ruby
# frozen_string_literal: true

# 32-bit Alignment, Truncation & Big-Endianness Gauntlet (`arm32` + `ppc` via QEMU)
# paired against native 64-bit ASan/UBSan + slow serialization workers.
# Exercises cross-arch PM64 oracle envelopes (`mutator_oracle64.so`) both with and
# without IJON state guidance.
#
# Usage:
#   ./examples/02_cross_arch_endian_gauntlet.rb validate
#   ./examples/02_cross_arch_endian_gauntlet.rb run

fuzz_lib = File.expand_path("../lib", __dir__)
$LOAD_PATH.unshift(fuzz_lib) unless $LOAD_PATH.include?(fuzz_lib)
require "prism_fuzzer"

PrismFuzzer.campaign "cross-arch-endian-gauntlet" do
  workspace "tmp/examples/02_cross_arch_gauntlet"
  defaults max_input_size: 1024, max_allocated_mb: 128

  after_run do
    report threads: 4
  end

  prism :prism_a,
        repo: PrismFuzzer::CampaignDSL::PRISM_DEFAULT_REPO,
        ref: ENV.fetch("PRISM_REF", "a1d1d96c368d49b752d06e361823a098b54f9a9d"),
        patches: "auto"

  coverage source: :prism_a, fuzzer: "fuzz.host"

  corpus_generator :corpus, source: :prism_a, fuzzer: "fuzz.host"

  fuzzer "fuzz.host",       shape: :prism_parse,        source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto, document_ids: true
  fuzzer "fuzz.host.slow",  shape: :prism_parse,        source: :prism_a, sanitizers: %i[asan ubsan], mode: :slow, afl: :lto
  fuzzer "fuzz.cmplog",     shape: :prism_parse,        source: :prism_a, sanitizers: [],               mode: :fast, afl: :cmplog
  fuzzer "fuzz.arm32",      shape: :prism_cross_oracle, source: :prism_a, arch: :arm32, sanitizers: %i[asan ubsan], afl: :pcguard, mutator: "mutator_oracle64.so", repro: "fuzz.arm32.repro"
  fuzzer "fuzz.arm32.ijon", shape: :prism_cross_oracle, source: :prism_a, arch: :arm32, sanitizers: %i[asan ubsan], afl: :pcguard, ijon: true, mutator: "mutator_oracle64.so", repro: "fuzz.arm32.ijon.repro"
  fuzzer "fuzz.ppc",        shape: :prism_cross_oracle, source: :prism_a, arch: :ppc,   sanitizers: %i[asan ubsan], afl: :pcguard, mutator: "mutator_oracle64.so", repro: "fuzz.ppc.repro"
  fuzzer "fuzz.ppc.ijon",   shape: :prism_cross_oracle, source: :prism_a, arch: :ppc,   sanitizers: %i[asan ubsan], afl: :pcguard, ijon: true, mutator: "mutator_oracle64.so", repro: "fuzz.ppc.ijon.repro"

  sync_group :afl, dir: "afl", primary: true

  worker :host_main, fuzzer: "fuzz.host", sync_group: :afl, afl_role: :main do
    schedule "exploit"
    cmplog "fuzz.cmplog"
    seeds from: :corpus, shard_group: :cross
    color "#60a5fa"
  end

  workers(kind: :afl, sync_group: :afl, afl_role: :secondary, mem_limit: :none) do
    worker :host_slow,  fuzzer: "fuzz.host.slow",  schedule: "fast",    no_trim: true, loopcount: 1500, color: "#f472b6" do
      seeds from: :corpus, shard_group: :cross
    end
    worker :arm32_fast, fuzzer: "fuzz.arm32",      schedule: "fast",    color: "#2dd4bf" do
      seeds from: :corpus, shard_group: :cross
    end
    worker :arm32_ijon, fuzzer: "fuzz.arm32.ijon", schedule: "explore", no_trim: true, color: "#14b8a6" do
      seeds from: :corpus, shard_group: :cross
    end
    worker :ppc_fast,   fuzzer: "fuzz.ppc",        schedule: "lin",     color: "#e879f9" do
      seeds from: :corpus, shard_group: :cross
    end
    worker :ppc_ijon,   fuzzer: "fuzz.ppc.ijon",   schedule: "explore", no_trim: true, color: "#c084fc" do
      seeds from: :corpus, shard_group: :cross
    end
  end
end
