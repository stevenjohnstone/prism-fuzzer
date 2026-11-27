#!/usr/bin/env ruby
# frozen_string_literal: true

# Compare two Prism revisions side by side (`baseline` vs. `candidate`) with
# differential fuzzing, IJON state guidance, and multi-target (native vs. SWAR)
# LLVM source coverage tracking.
#
# Usage:
#   PRISM_A_REF=988b037fad3cdca5a3a633927978d5a4a45b150b PRISM_B_REF=main ./examples/01_ab_pr_diff.rb validate
#   ./examples/01_ab_pr_diff.rb run --duration 1h
#   ./examples/01_ab_pr_diff.rb report

fuzz_lib = File.expand_path("../lib", __dir__)
$LOAD_PATH.unshift(fuzz_lib) unless $LOAD_PATH.include?(fuzz_lib)
require "prism_fuzzer"

env_or = ->(key, fallback) {
  v = ENV[key].to_s.strip
  v.empty? ? fallback : v
}

base_dir = env_or.call("PRISM_A_DIR", nil)
cand_dir = env_or.call("PRISM_B_DIR", nil)

PrismFuzzer.campaign "ab-pr-diff" do
  workspace "tmp/examples/01_ab_pr_diff"
  duration ENV.fetch("CAMPAIGN_DURATION", "1h")
  defaults max_input_size: 1024, max_allocated_mb: 128

  after_run do
    report threads: 4, top: 20
  end

  prism :baseline,
        repo: PrismFuzzer::CampaignDSL::PRISM_DEFAULT_REPO,
        ref: base_dir ? nil : env_or.call("PRISM_A_REF", "988b037fad3cdca5a3a633927978d5a4a45b150b"),
        dir: base_dir,
        patches: base_dir ? "none" : "auto"

  prism :candidate,
        repo: PrismFuzzer::CampaignDSL::PRISM_DEFAULT_REPO,
        ref: cand_dir ? nil : env_or.call("PRISM_B_REF", "a1d1d96c368d49b752d06e361823a098b54f9a9d"),
        dir: cand_dir,
        patches: cand_dir ? "none" : "auto"

  # Primary coverage attribution targets :candidate, while `diff_ab` automatically
  # tracks and links BOTH (baseline, native) and (candidate, native) pairs.
  coverage source: :candidate, fuzzer: "cand.asan"

  corpus_generator :corpus, source: :candidate, fuzzer: "cand.asan"

  fuzzer "base.asan",    shape: :prism_parse, source: :baseline,  sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
  fuzzer "cand.native",  shape: :prism_parse, source: :candidate, sanitizers: [],               mode: :fast, afl: :lto, xallocator: true
  fuzzer "cand.asan",    shape: :prism_parse, source: :candidate, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto, document_ids: true
  fuzzer "cand.swar",    shape: :prism_parse, source: :candidate, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto, defines: { PRISM_ACCEL_SWAR: true }
  fuzzer "cand.slow",    shape: :prism_parse, source: :candidate, sanitizers: %i[asan ubsan], mode: :slow, afl: :lto
  fuzzer "cand.cmplog",  shape: :prism_parse, source: :candidate, sanitizers: [],               mode: :fast, afl: :cmplog

  fuzzer "diff.ab",
         shape: :prism_diff_prism,
         prism_a: :baseline,
         prism_b: :candidate,
         sanitizers: %i[asan ubsan],
         afl: :pcguard,
         ijon: true,
         document_ids: true

  sync_group :afl, dir: "afl", primary: true

  worker :main, fuzzer: "cand.asan", sync_group: :afl, afl_role: :main do
    schedule "exploit"
    cmplog "cand.cmplog"
    loopcount 2000
    seeds from: :corpus, shard_group: :ab
    color "#60a5fa"
  end

  workers(kind: :afl, sync_group: :afl, afl_role: :secondary) do
    worker "base_asan",   fuzzer: "base.asan",   schedule: "fast",    color: "#94a3b8" do
      seeds from: :corpus, shard_group: :ab
    end
    worker "cand_swar",   fuzzer: "cand.swar",   schedule: "fast",    color: "#38bdf8" do
      seeds from: :corpus, shard_group: :ab
    end
    worker "cand_slow",   fuzzer: "cand.slow",   schedule: "explore", no_trim: true, loopcount: 1000, color: "#f472b6" do
      seeds from: :corpus, shard_group: :ab
    end
    worker "ab_ijon_1",   fuzzer: "diff.ab",     schedule: "explore", mem_limit: :none, color: "#facc15" do
      seeds from: :corpus, filter: :self_pass, cache_key: "diff_ab", shard_group: :ab_diff
    end
    worker "ab_ijon_2",   fuzzer: "diff.ab",     schedule: "quad",    mem_limit: :none, no_trim: true, afl_flags: %w[-P explore], color: "#fb923c" do
      seeds from: :corpus, filter: :self_pass, cache_key: "diff_ab", shard_group: :ab_diff
    end
  end
end
