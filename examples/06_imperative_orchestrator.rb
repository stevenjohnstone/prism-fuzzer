#!/usr/bin/env ruby
# frozen_string_literal: true

# Imperative Orchestration Example:
# Demonstrates driving `PrismFuzzer::Campaign::Instance` directly in pure Ruby
# (`autorun: false`), e.g. to gate subsequent work or trigger `report!` based
# on live stats or CLI flags (`--execute` starts the campaign; default validates
# and inspects current stats without starting Docker containers).
#
# Usage:
#   ./examples/06_imperative_orchestrator.rb
#   ./examples/06_imperative_orchestrator.rb --execute

fuzz_lib = File.expand_path("../lib", __dir__)
$LOAD_PATH.unshift(fuzz_lib) unless $LOAD_PATH.include?(fuzz_lib)
require "prism_fuzzer"

phase1 = PrismFuzzer.campaign "imperative-phase-1", autorun: false do
  workspace "tmp/examples/06_imperative"
  duration "10m"
  defaults max_input_size: 1024, max_allocated_mb: 128

  after_run do
    report threads: 2
  end

  prism :prism_a,
        repo: PrismFuzzer::CampaignDSL::PRISM_DEFAULT_REPO,
        ref: ENV.fetch("PRISM_REF", "a1d1d96c368d49b752d06e361823a098b54f9a9d"),
        patches: "auto"

  coverage source: :prism_a, fuzzer: "fuzz.fast"
  corpus_generator :corpus, source: :prism_a, fuzzer: "fuzz.fast"

  fuzzer "fuzz.fast", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto, ijon: true, document_ids: true
  fuzzer "fuzz.slow", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :slow, afl: :lto

  sync_group :afl, dir: "afl", primary: true

  worker :scout,      fuzzer: "fuzz.fast", sync_group: :afl, afl_role: :main,      schedule: "explore", color: "#4ade80" do
    seeds from: :corpus
  end
  worker :serializer, fuzzer: "fuzz.slow", sync_group: :afl, afl_role: :secondary, schedule: "fast",    color: "#f472b6" do
    seeds from: :corpus
  end
end

if __FILE__ == $PROGRAM_NAME && !Thread.current[:prism_fuzzer_compiling_dsl]
  phase1.validate!
  if ARGV.include?("--execute")
    phase1.sync!
    phase1.build!(skip_sync: true)
    phase1.start!(detach: true, skip_sync: true, skip_build: true)
    phase1.wait!
    phase1.report!
    phase1.print_stats
  else
    st = phase1.stats
    puts "Validated imperative campaign '#{phase1.ir['name']}' (container: #{phase1.container_name})"
    puts "Workspace: #{phase1.workspace[:fuzz_dir]} (execs so far: #{st.dig('fleet', 'total_execs') || 0})"
    puts "Pass --execute to run sync -> build -> fuzz -> report imperatively."
  end
end
