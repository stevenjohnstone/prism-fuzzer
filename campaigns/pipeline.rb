#!/usr/bin/env ruby
# frozen_string_literal: true

# CRuby Full-Pipeline Differential + Compiler Campaign (`cruby-pipeline-fleet`, 10 workers):
#   Combines `shape: :cruby_pipeline_diff` (instrumenting `prism.o` + `parse.o` +
#   `compile.o` + `iseq.o` and comparing all 4 stages: `prism_parse && prism_compile`
#   vs `parsey_parse && parsey_compile`) alongside `shape: :cruby_compile` (pure
#   compiler-edge crash & internal bytecode-verifier hunting).
#
# Usage:
#   ./campaigns/pipeline.rb validate
#   ./campaigns/pipeline.rb build
#   ./campaigns/pipeline.rb run

fuzz_lib = File.expand_path("../lib", __dir__)
$LOAD_PATH.unshift(fuzz_lib) unless $LOAD_PATH.include?(fuzz_lib)
require "prism_fuzzer"

DEFAULT_PRISM_REF = "a5e01d818fa45f2cea9232754251a6855f82ab98"
DEFAULT_RUBY_REF = "17eecca74a586156acebb8b06417f4df17cdedfc"

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

PrismFuzzer.campaign "cruby-pipeline-fleet" do
  workspace "tmp/fuzz-pipeline", build_dir: "tmp/fuzz-pipeline/build"
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

  coverage source: :prism_a, fuzzer: "fuzz", diff_fuzzer: "fuzz.pipeline"

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

  grammar_generator :grammar_small,
                    source: :prism_a,
                    fuzzer: "fuzz",
                    sync_group: "afl-small",
                    seeds_dir: "/tmp/afl-tmpdir/pipeline-grammar-256/seeds",
                    max_input_size: small_max_input,
                    schedule: "lrama",
                    ulimit_v_kb: 4_194_304,
                    color: "#34d399"
  grammar_generator :grammar_8k,
                    source: :prism_a,
                    fuzzer: "fuzz",
                    sync_group: "afl-8k",
                    seeds_dir: "/tmp/afl-tmpdir/pipeline-grammar-8k/seeds",
                    max_input_size: large_max_input,
                    schedule: "lrama",
                    ulimit_v_kb: 4_194_304,
                    color: "#10b981"

  fuzzer "fuzz",               shape: :prism_parse,         source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto, document_ids: true
  fuzzer "fuzz.pipeline",      shape: :cruby_pipeline_diff, ruby: :ruby, prism: :prism_a, sanitizers: [], afl: :pcguard, document_ids: true
  fuzzer "fuzz.ijon.pipeline", shape: :cruby_pipeline_diff, ruby: :ruby, prism: :prism_a, sanitizers: [], afl: :pcguard, ijon: true, document_ids: true
  fuzzer "fuzz.compile",       shape: :cruby_compile,       ruby: :ruby, prism: :prism_a, sanitizers: [], afl: :pcguard, document_ids: true

  sync_group "afl-8k",    dir: "afl-8k",    primary: true
  sync_group "afl-small", dir: "afl-small"

  worker :"grammar-256", kind: :generator, generator: :grammar_small, max_input_size: small_max_input, color: "#34d399"
  worker :"grammar-8k",  kind: :generator, generator: :grammar_8k,    max_input_size: large_max_input, color: "#10b981"

  worker :"small-pipeline-main", fuzzer: "fuzz.ijon.pipeline", sync_group: "afl-small", afl_role: :main, max_input_size: small_max_input do
    schedule "explore"
    foreign_sync :grammar_small
    seeds from: :corpus_small, filter: :self_pass, cache_key: "pipeline_small_pass"
    loopcount 1000
    mem_limit :none
    env AFL_SYNC_TIME: "1"
    color "#38bdf8"
  end

  [
    { id: "small-pipeline-fast",    fuzzer: "fuzz.pipeline",      schedule: "fast",    afl_flags: %w[-L 0],       color: "#0ea5e9" },
    { id: "small-pipeline-exploit", fuzzer: "fuzz.ijon.pipeline", schedule: "exploit", afl_flags: [],             color: "#0284c7" },
    { id: "small-compile-fast",     fuzzer: "fuzz.compile",       schedule: "fast",    afl_flags: %w[-P explore], color: "#f97316" },
    { id: "small-pipeline-text",    fuzzer: "fuzz.pipeline",      schedule: "lin",     afl_flags: %w[-Z -a text], color: "#7dd3fc" }
  ].each do |spec|
    worker spec[:id], fuzzer: spec[:fuzzer], sync_group: "afl-small", afl_role: :secondary, max_input_size: small_max_input do
      schedule spec[:schedule]
      afl_flags(*spec[:afl_flags]) unless spec[:afl_flags].empty?
      loopcount 1000
      mem_limit :none
      color spec[:color]
    end
  end

  worker :"8k-pipeline-main", fuzzer: "fuzz.ijon.pipeline", sync_group: "afl-8k", afl_role: :main, max_input_size: large_max_input do
    schedule "explore"
    foreign_sync :grammar_8k
    seeds from: :corpus_8k, filter: :self_pass, cache_key: "pipeline_8k_pass"
    peer_import group: "afl-small", worker: :"small-pipeline-main", alias: "small_pipeline"
    loopcount 1000
    mem_limit :none
    keep_open_on_exit true
    color "#2563eb"
  end

  [
    { id: "8k-pipeline-fast", fuzzer: "fuzz.pipeline", schedule: "fast", afl_flags: [],             color: "#1d4ed8" },
    { id: "8k-compile-quad",  fuzzer: "fuzz.compile",  schedule: "quad", afl_flags: %w[-P exploit], color: "#ea580c" }
  ].each do |spec|
    worker spec[:id], fuzzer: spec[:fuzzer], sync_group: "afl-8k", afl_role: :secondary, max_input_size: large_max_input do
      schedule spec[:schedule]
      afl_flags(*spec[:afl_flags]) unless spec[:afl_flags].empty?
      loopcount 1000
      mem_limit :none
      color spec[:color]
    end
  end
end
