#!/usr/bin/env ruby
# frozen_string_literal: true

# CRuby Dual-Compiler Campaign (`cruby-compile-fleet`, 22 workers):
#   Targets CRuby's bytecode compilers (`compile.c` + `prism_compile.c` + `iseq.c`)
#   with PCGUARD edge feedback, patchless IJON, Prism AST mutators (`libprismmutator.so`),
#   ASan + stack-UAR (`FUZZ_DISABLE_GC=1`), trapping UBSan, and ABI-safe `RUBY_ASSERT_ALWAYS`.
#   Inputs are gated on parser agreement (both Prism and `parse.y` accept the Ruby
#   syntax) and then compiled through both `parser: :prism` and `parser: :parse_y`
#   across decoded `RubyVM::InstructionSequence` optimization masks.
#
# Usage:
#   ./campaigns/compile.rb validate
#   ./campaigns/compile.rb build
#   ./campaigns/compile.rb run

fuzz_lib = File.expand_path("../lib", __dir__)
$LOAD_PATH.unshift(fuzz_lib) unless $LOAD_PATH.include?(fuzz_lib)
require "prism_fuzzer"

DEFAULT_PRISM_REF = "a5e01d818fa45f2cea9232754251a6855f82ab98"
DEFAULT_RUBY_REF = "ccbb1f62315dcc9f8de0e2f85e6901ee2ac80f9a"

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

PrismFuzzer.campaign "cruby-compile-fleet" do
  workspace "tmp/fuzz-compile", build_dir: "tmp/fuzz-compile/build"
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

  coverage source: :prism_a, fuzzer: "fuzz"

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
                    seeds_dir: "/tmp/afl-tmpdir/compile-grammar-256/seeds",
                    max_input_size: small_max_input,
                    schedule: "lrama",
                    ulimit_v_kb: 4_194_304,
                    color: "#34d399"
  grammar_generator :grammar_8k,
                    source: :prism_a,
                    fuzzer: "fuzz",
                    sync_group: "afl-8k",
                    seeds_dir: "/tmp/afl-tmpdir/compile-grammar-8k/seeds",
                    max_input_size: large_max_input,
                    schedule: "lrama",
                    ulimit_v_kb: 4_194_304,
                    color: "#10b981"

  fuzzer "fuzz",              shape: :prism_parse,   source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto, document_ids: true
  fuzzer "fuzz.compile",      shape: :cruby_compile, ruby: :ruby, prism: :prism_a, sanitizers: [], afl: :pcguard, document_ids: true
  fuzzer "fuzz.ijon.compile", shape: :cruby_compile, ruby: :ruby, prism: :prism_a, sanitizers: [], afl: :pcguard, ijon: true, document_ids: true
  fuzzer "fuzz.compile.asan", shape: :cruby_compile, ruby: :ruby, prism: :prism_a, sanitizers: [:asan], afl: :pcguard, document_ids: true

  sync_group "afl-8k",    dir: "afl-8k",    primary: true
  sync_group "afl-small", dir: "afl-small"

  worker :"grammar-256", kind: :generator, generator: :grammar_small, max_input_size: small_max_input, color: "#34d399"
  worker :"grammar-8k",  kind: :generator, generator: :grammar_8k,    max_input_size: large_max_input, color: "#10b981"

  worker :"small-compile-main", fuzzer: "fuzz.ijon.compile", sync_group: "afl-small", afl_role: :main, max_input_size: small_max_input do
    schedule "explore"
    foreign_sync :grammar_small
    seeds from: :corpus_small, filter: :self_pass, cache_key: "compile_small_pass"
    loopcount 1000
    mem_limit :none
    env AFL_SYNC_TIME: "1"
    color "#f97316"
  end

  [
    { id: "small-compile-fast",     fuzzer: "fuzz.compile",      schedule: "fast",    afl_flags: %w[-L 0],       color: "#fb923c" },
    { id: "small-compile-exploit",  fuzzer: "fuzz.ijon.compile", schedule: "exploit", afl_flags: [],             color: "#f59e0b" },
    { id: "small-compile-coe",      fuzzer: "fuzz.ijon.compile", schedule: "coe",     afl_flags: [],             color: "#eab308" },
    { id: "small-compile-rare",     fuzzer: "fuzz.compile",      schedule: "rare",    afl_flags: [],             color: "#facc15" },
    { id: "small-compile-seek",     fuzzer: "fuzz.compile",      schedule: "seek",    afl_flags: [],             color: "#fde047" },
    { id: "small-compile-mmopt",    fuzzer: "fuzz.compile",      schedule: "mmopt",   afl_flags: [],             color: "#fdba74" },
    { id: "small-compile-text",     fuzzer: "fuzz.compile",      schedule: "lin",     afl_flags: %w[-Z -a text], color: "#fed7aa" },
    { id: "small-compile-ast-1",    fuzzer: "fuzz.ijon.compile", mutator: "libprismmutator.so", schedule: "explore", afl_flags: [], color: "#fbbf24" },
    { id: "small-compile-ast-2",    fuzzer: "fuzz.compile",      mutator: "libprismmutator.so", schedule: "fast",    afl_flags: [], color: "#f59e0b" },
    { id: "small-compile-ast-only", fuzzer: "fuzz.ijon.compile", mutator: "libprismmutator.so", schedule: "rare",    afl_flags: [], env: { AFL_CUSTOM_MUTATOR_ONLY: "1" }, color: "#d97706" },
    { id: "small-compile-asan",     fuzzer: "fuzz.compile.asan", schedule: "fast",    afl_flags: [], loopcount: 50, env: { FUZZ_DISABLE_GC: "1" }, color: "#ef4444" }
  ].each do |spec|
    worker spec[:id], fuzzer: spec[:fuzzer], sync_group: "afl-small", afl_role: :secondary, max_input_size: small_max_input do
      mutator spec[:mutator] if spec[:mutator]
      schedule spec[:schedule]
      afl_flags(*spec[:afl_flags]) unless spec[:afl_flags].empty?
      loopcount(spec[:loopcount] || 1000)
      env(**spec[:env]) if spec[:env]
      mem_limit :none
      color spec[:color]
    end
  end

  worker :"8k-compile-main", fuzzer: "fuzz.ijon.compile", sync_group: "afl-8k", afl_role: :main, max_input_size: large_max_input do
    schedule "explore"
    foreign_sync :grammar_8k
    seeds from: :corpus_8k, filter: :self_pass, cache_key: "compile_8k_pass"
    peer_import group: "afl-small", worker: :"small-compile-main", alias: "small_compile"
    loopcount 1000
    mem_limit :none
    keep_open_on_exit true
    color "#ea580c"
  end

  [
    { id: "8k-compile-fast",    fuzzer: "fuzz.compile",      schedule: "fast",    afl_flags: %w[-L 0],      color: "#c2410c" },
    { id: "8k-compile-exploit", fuzzer: "fuzz.ijon.compile", schedule: "exploit", afl_flags: [],            color: "#9a3412" },
    { id: "8k-compile-quad",    fuzzer: "fuzz.compile",      schedule: "quad",    afl_flags: %w[-P exploit], color: "#7c2d12" },
    { id: "8k-compile-rare",    fuzzer: "fuzz.compile",      schedule: "rare",    afl_flags: [],            color: "#b45309" },
    { id: "8k-compile-ast-1",   fuzzer: "fuzz.ijon.compile", mutator: "libprismmutator.so", schedule: "explore", afl_flags: [], color: "#d97706" },
    { id: "8k-compile-ast-2",   fuzzer: "fuzz.compile",      mutator: "libprismmutator.so", schedule: "fast",    afl_flags: [], color: "#f59e0b" },
    { id: "8k-compile-asan",    fuzzer: "fuzz.compile.asan", schedule: "fast",    afl_flags: [], loopcount: 50, env: { FUZZ_DISABLE_GC: "1" }, color: "#dc2626" }
  ].each do |spec|
    worker spec[:id], fuzzer: spec[:fuzzer], sync_group: "afl-8k", afl_role: :secondary, max_input_size: large_max_input do
      mutator spec[:mutator] if spec[:mutator]
      schedule spec[:schedule]
      afl_flags(*spec[:afl_flags]) unless spec[:afl_flags].empty?
      loopcount(spec[:loopcount] || 1000)
      env(**spec[:env]) if spec[:env]
      mem_limit :none
      color spec[:color]
    end
  end
end
