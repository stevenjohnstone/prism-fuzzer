#!/usr/bin/env ruby
# frozen_string_literal: true

# CRuby Dual-Compiler Small-Input Campaign (`cruby-compile-small`, 20 workers):
#   All workers are capped at 256-byte Ruby payloads (260 bytes with 4-byte header)
#   to maximize exec/s and avoid O(2^N) nested-`ensure` blowups on multi-KB inputs.
#   Single unified sync group (`afl`) combines PCGUARD, ISeq-guided IJON,
#   Prism AST mutators (`libprismmutator.so`), and 3 ASan + stack-UAR
#   (`FUZZ_DISABLE_GC=1`) workers sized to fit 20 P-cores cleanly.
#
# Usage:
#   ./campaigns/compile-small.rb validate
#   ./campaigns/compile-small.rb build
#   ./campaigns/compile-small.rb run

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
ruby_dir = non_empty_env.call("RUBY_DIR") || non_empty_env.call("RUBY_ORACLE_DIR_CUSTOM")

max_input = Integer(non_empty_env.call("FUZZ_MAX_INPUT_SIZE") || "256")
max_allocated_mb = Integer(non_empty_env.call("FUZZ_MAX_ALLOCATED") || "256")
# Work around CRuby #22533 (iseq_peephole_optimize infinite loop) until fixed upstream;
# set FUZZ_DISABLE_PEEPHOLE=0 to re-enable peephole optimization across workers.
disable_peephole = non_empty_env.call("FUZZ_DISABLE_PEEPHOLE") || "1"
base_compile_env = disable_peephole == "0" ? {} : { FUZZ_DISABLE_PEEPHOLE: disable_peephole }

PrismFuzzer.campaign "cruby-compile-small" do
  workspace "tmp/fuzz-compile-small", build_dir: "tmp/fuzz-compile-small/build"
  defaults max_input_size: max_input, max_allocated_mb: max_allocated_mb
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
                   max_input_size: max_input

  fuzzer "fuzz",              shape: :prism_parse,   source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto, document_ids: true
  fuzzer "fuzz.compile",      shape: :cruby_compile, ruby: :ruby, prism: :prism_a, sanitizers: [], afl: :pcguard, document_ids: true
  fuzzer "fuzz.ijon.compile", shape: :cruby_compile, ruby: :ruby, prism: :prism_a, sanitizers: [], afl: :pcguard, ijon: true, document_ids: true
  fuzzer "fuzz.compile.asan", shape: :cruby_compile, ruby: :ruby, prism: :prism_a, sanitizers: [:asan], afl: :pcguard, document_ids: true

  sync_group "afl", dir: "afl", primary: true

  worker :"compile-main", fuzzer: "fuzz.ijon.compile", sync_group: "afl", afl_role: :main, max_input_size: max_input do
    schedule "explore"
    seeds from: :corpus_small, filter: :self_pass, cache_key: "compile_small_pass"
    loopcount 1000
    mem_limit :none
    env(**base_compile_env) unless base_compile_env.empty?
    keep_open_on_exit true
    color "#f97316"
  end

  [
    { id: "compile-fast-1",   fuzzer: "fuzz.compile",      schedule: "fast",    afl_flags: %w[-L 0],        color: "#fb923c" },
    { id: "compile-exploit",  fuzzer: "fuzz.ijon.compile", schedule: "exploit", afl_flags: [],              color: "#f59e0b" },
    { id: "compile-coe",      fuzzer: "fuzz.ijon.compile", schedule: "coe",     afl_flags: [],              color: "#eab308" },
    { id: "compile-quad",     fuzzer: "fuzz.ijon.compile", schedule: "quad",    afl_flags: %w[-P exploit],  color: "#ca8a04" },
    { id: "compile-rare-1",   fuzzer: "fuzz.compile",      schedule: "rare",    afl_flags: [],              color: "#facc15" },
    { id: "compile-rare-2",   fuzzer: "fuzz.ijon.compile", schedule: "rare",    afl_flags: [],              color: "#a16207" },
    { id: "compile-seek",     fuzzer: "fuzz.compile",      schedule: "seek",    afl_flags: [],              color: "#fde047" },
    { id: "compile-mmopt",    fuzzer: "fuzz.compile",      schedule: "mmopt",   afl_flags: [],              color: "#fdba74" },
    { id: "compile-text",     fuzzer: "fuzz.compile",      schedule: "lin",     afl_flags: %w[-Z -a text],  color: "#fed7aa" },
    { id: "compile-ast-1",    fuzzer: "fuzz.ijon.compile", mutator: "libprismmutator.so", schedule: "explore", afl_flags: [], color: "#fbbf24" },
    { id: "compile-ast-2",    fuzzer: "fuzz.ijon.compile", mutator: "libprismmutator.so", schedule: "fast",    afl_flags: [], color: "#d97706" },
    { id: "compile-ast-3",    fuzzer: "fuzz.ijon.compile", mutator: "libprismmutator.so", schedule: "coe",     afl_flags: [], color: "#b45309" },
    { id: "compile-ast-4",    fuzzer: "fuzz.compile",      mutator: "libprismmutator.so", schedule: "fast",    afl_flags: [], color: "#f59e0b" },
    { id: "compile-ast-5",    fuzzer: "fuzz.compile",      mutator: "libprismmutator.so", schedule: "explore", afl_flags: [], color: "#c2410c" },
    { id: "compile-ast-6",    fuzzer: "fuzz.compile",      mutator: "libprismmutator.so", schedule: "rare",    afl_flags: [], color: "#9a3412" },
    { id: "compile-ast-only", fuzzer: "fuzz.ijon.compile", mutator: "libprismmutator.so", schedule: "rare",    afl_flags: [], env: { AFL_CUSTOM_MUTATOR_ONLY: "1" }, color: "#78350f" },
    { id: "compile-asan-1",   fuzzer: "fuzz.compile.asan", schedule: "fast",    afl_flags: [], loopcount: 50, env: { FUZZ_DISABLE_GC: "1" }, color: "#ef4444" },
    { id: "compile-asan-2",   fuzzer: "fuzz.compile.asan", mutator: "libprismmutator.so", schedule: "explore", afl_flags: [], loopcount: 50, env: { FUZZ_DISABLE_GC: "1" }, color: "#dc2626" },
    { id: "compile-asan-3",   fuzzer: "fuzz.compile.asan", schedule: "rare",    afl_flags: [], loopcount: 50, env: { FUZZ_DISABLE_GC: "1" }, color: "#b91c1c" }
  ].each do |spec|
    worker spec[:id], fuzzer: spec[:fuzzer], sync_group: "afl", afl_role: :secondary, max_input_size: max_input do
      mutator spec[:mutator] if spec[:mutator]
      schedule spec[:schedule]
      afl_flags(*spec[:afl_flags]) unless spec[:afl_flags].empty?
      loopcount(spec[:loopcount] || 1000)
      worker_env = base_compile_env.merge(spec[:env] || {})
      env(**worker_env) unless worker_env.empty?
      mem_limit :none
      color spec[:color]
    end
  end
end
