#!/usr/bin/env ruby
# frozen_string_literal: true

# Automated Nightly CI Gate
# Time-boxed campaign (`duration`) paired with full post-run `report` (triage +
# coverage + unified HTML report) and GitHub Pages `publish` archiving.
#
# Usage:
#   CI_DURATION=30m CI_RUN_ID=nightly-2026-11-22 ./examples/05_ci_regression_gate.rb run

fuzz_lib = File.expand_path("../lib", __dir__)
$LOAD_PATH.unshift(fuzz_lib) unless $LOAD_PATH.include?(fuzz_lib)
require "prism_fuzzer"

run_id = ENV.fetch("CI_RUN_ID", "nightly-gate")

PrismFuzzer.campaign "ci-regression-gate" do
  workspace ENV.fetch("WORKSPACE", "tmp/examples/05_ci_gate/#{run_id}")
  duration ENV.fetch("CI_DURATION", "15m")
  defaults max_input_size: 2048, max_allocated_mb: 256

  after_run do
    report threads: 4, top: 25
    publish run_id: run_id,
            title: ENV.fetch("CI_TITLE", "Nightly Prism + CRuby Gate (#{run_id})"),
            out_dir: ENV.fetch("REPORTS_DIR", "reports")
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
  grammar_generator :grammar,
                    source: :prism_a,
                    fuzzer: "fuzz.asan",
                    sync_group: :afl,
                    seeds_dir: "/tmp/afl-tmpdir/ci_grammar/seeds",
                    schedule: "lrama",
                    color: "#34d399"

  fuzzer "fuzz.asan",   shape: :prism_parse,     source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto, document_ids: true
  fuzzer "fuzz.slow",   shape: :prism_parse,     source: :prism_a, sanitizers: %i[asan ubsan], mode: :slow, afl: :lto
  fuzzer "fuzz.msan",   shape: :prism_parse,     source: :prism_a, sanitizers: [:msan],          mode: :slow, afl: :lto
  fuzzer "fuzz.cmplog", shape: :prism_parse,     source: :prism_a, sanitizers: [],               mode: :fast, afl: :cmplog
  fuzzer "fuzz.diff",   shape: :prism_diff_ruby, prism: :prism_a,  ruby: :ruby, sanitizers: %i[asan ubsan], afl: :pcguard, document_ids: true

  sync_group :afl, dir: "afl", primary: true

  worker :grammar, kind: :generator, generator: :grammar, color: "#34d399"

  worker :main, fuzzer: "fuzz.asan", sync_group: :afl, afl_role: :main do
    schedule "exploit"
    cmplog "fuzz.cmplog"
    foreign_sync :grammar
    seeds from: :corpus, shard_group: :ci
    color "#60a5fa"
  end

  workers(kind: :afl, sync_group: :afl, afl_role: :secondary) do
    worker :slow,   fuzzer: "fuzz.slow", schedule: "fast",    color: "#f472b6" do
      seeds from: :corpus, shard_group: :ci
    end
    worker :msan,   fuzzer: "fuzz.msan", schedule: "fast",    no_trim: true, color: "#a78bfa" do
      seeds from: :corpus, shard_group: :ci
    end
    worker :diff_1, fuzzer: "fuzz.diff", schedule: "explore", mem_limit: :none, color: "#f97316" do
      seeds from: :corpus, filter: :self_pass, cache_key: "ci_diff"
    end
    worker :diff_2, fuzzer: "fuzz.diff", schedule: "quad",    mem_limit: :none, afl_flags: %w[-L 0], color: "#fb923c" do
      seeds from: :corpus, filter: :self_pass, cache_key: "ci_diff"
    end
  end
end
