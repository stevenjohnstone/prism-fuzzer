# frozen_string_literal: true

module PrismFuzzer
  module Topology
    TOPOLOGY_SCHEMA_VERSION = 2
    SCHEMA_FILENAME = "topology.schema.json"
    PRISM_DEFAULT_REPO = "https://github.com/ruby/prism.git"
    RUBY_DEFAULT_REPO = "https://github.com/ruby/ruby.git"

    DEFAULT_WARNING_FLAGS = %w[
      -Wno-gnu-statement-expression-from-macro-expansion
      -Wno-switch
    ].freeze

    CROSS_ARCH_CONFIGS = {
      "arm32" => {
        triple: "arm-linux-gnueabihf",
        qemu: "/usr/bin/qemu-arm",
        sysroot: "/usr/arm-linux-gnueabihf",
        rt_suffix: "armhf",
        extra_cflags: [],
        extra_ldflags: [],
        repro_cflags: [],
        profile: "arm32_oracle"
      },
      "ppc" => {
        triple: "powerpc-linux-gnu",
        qemu: "/usr/bin/qemu-ppc",
        sysroot: "/usr/powerpc-linux-gnu",
        rt_suffix: "ppc",
        extra_cflags: [
          "-msecure-plt",
          '-DFUZZ_ORACLE_NAMESPACE="oracle_ppc"',
          '-DFUZZ_ORACLE_LEN_KEY="ppc_len"'
        ],
        extra_ldflags: ["-latomic"],
        repro_cflags: [
          '-DORACLE_REPLAY_QEMU_BIN="/usr/bin/qemu-ppc"',
          '-DORACLE_REPLAY_QEMU_ARGV0="qemu-ppc"',
          '-DORACLE_REPLAY_SYSROOT="/usr/powerpc-linux-gnu"',
          '-DORACLE_REPLAY_TARGET_ENV="FUZZ_PPC_BIN"'
        ],
        profile: "ppc_oracle"
      }
    }.freeze

    # Instrumentation modes that emit coverage guidance and support AFL_LLVM_IJON.
    COVERAGE_GUIDED_IJON_MODES = %w[lto pcguard].freeze

    # Extensible registry of pre-implemented fuzzer shapes. New shapes can be
    # added here (and wired into build_shape!) without changing consumers.
    SHAPES = {
      "prism_parse" => {
        source_roles: { "source" => :prism },
        default_afl: "lto",
        supported_afl_modes: %w[lto pcguard sand cmplog],
        verify_profile: ->(spec) {
          sans = Array(spec["sanitizers"]).map(&:to_s)
          return "msan_slow" if sans.include?("msan")
          return "lsan_slow" if sans.include?("lsan")
          return "xallocator" if spec["xallocator"]
          return "asan_ubsan_slow" if spec["mode"].to_s == "slow"

          "asan_ubsan"
        },
        coverage_source: ->(spec) { spec["source"] },
        coverage_sources: ->(spec) { [spec["source"]] },
        explain_sources: ->(spec) { [spec["source"]] }
      },
      "prism_diff_ruby" => {
        source_roles: { "prism" => :prism, "ruby" => :ruby },
        default_afl: "pcguard",
        supported_afl_modes: %w[pcguard],
        verify_profile: ->(_spec) { "diff_parse_y" },
        coverage_source: ->(spec) { spec["prism"] },
        coverage_sources: ->(spec) { [spec["prism"]] },
        explain_sources: ->(spec) { [spec["prism"]] }
      },
      "prism_diff_prism" => {
        source_roles: { "prism_a" => :prism, "prism_b" => :prism },
        default_afl: "pcguard",
        supported_afl_modes: %w[pcguard],
        verify_profile: ->(_spec) { "diff_prism" },
        coverage_source: ->(spec) { spec["prism_a"] },
        coverage_sources: ->(spec) { [spec["prism_a"], spec["prism_b"]] },
        explain_sources: ->(spec) { [spec["prism_a"], spec["prism_b"]] }
      },
      "prism_cross_oracle" => {
        source_roles: { "source" => :prism },
        default_afl: "pcguard",
        supported_afl_modes: %w[pcguard],
        verify_profile: ->(spec) { "#{spec.fetch('arch')}_oracle" },
        coverage_source: ->(spec) { spec["source"] },
        coverage_sources: ->(spec) { [spec["source"]] },
        explain_sources: ->(spec) { [spec["source"]] }
      }
    }.freeze

    FALLBACK_PALETTE = %w[
      #60a5fa #34d399 #f472b6 #fbbf24 #a78bfa #38bdf8
      #fb7185 #4ade80 #f97316 #2dd4bf #e879f9 #facc15
    ].freeze

    COVERAGE_ORTHOGONAL_FLAG_PATTERNS = [
      /\A-g(?:gdb3|line-tables-only|\d)?\z/,
      /\A-O(?:0|1|2|3|s|z|fast)?\z/,
      /\A-fsanitize=/,
      /\A-fno-sanitize/,
      /\A-fno-omit-frame-pointer\z/,
      /\A-fprofile-/,
      /\A-fcoverage-/,
      /\A-fvisibility=/,
      /\A-std=/,
      /\A-W/,
      /\A-D(?:PRISM_FUZZ_IJON|PRISM_FUZZ_ALLOW_STREAM_WITH_IJON|PRISM_NO_SOURCE_IJON|PRISM_XALLOCATOR|SLOW)(?:=.*)?\z/
    ].freeze

    class TopologyError < StandardError; end
  end
end
