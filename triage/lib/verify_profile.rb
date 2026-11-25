# frozen_string_literal: true

require "json"

common_lib = File.expand_path("../../runtime/common.rb", __dir__)
require common_lib if File.file?(common_lib)

topology_lib = File.expand_path("../../runtime/topology.rb", __dir__)
require topology_lib if File.file?(topology_lib)

# Centralizes verify-profile inference, cross-oracle/diff bucket detection, and
# reclassification executable resolution across triage, verify, verify_bucket, and retriage.
module FuzzVerifyProfile
  CROSS_ORACLE_TARGETS = {
    "arm32" => {
      profile: "arm32_oracle",
      namespace: "oracle_arm32",
      cc_target: "arm-linux-gnueabihf",
      sysroot: "/usr/arm-linux-gnueabihf",
      gcc: "arm-linux-gnueabihf-gcc",
      extra_cflags: [],
      extra_ldflags: [],
      repro_exe: "fuzz.arm32.repro"
    },
    "ppc" => {
      profile: "ppc_oracle",
      namespace: "oracle_ppc",
      cc_target: "powerpc-linux-gnu",
      sysroot: "/usr/powerpc-linux-gnu",
      gcc: "powerpc-linux-gnu-gcc",
      extra_cflags: %w[-msecure-plt],
      extra_ldflags: %w[-latomic],
      repro_exe: "fuzz.ppc.repro"
    }
  }.freeze

  module_function

  def utf8_safe(text)
    return PrismFuzzer::Common.utf8_safe(text) if defined?(PrismFuzzer::Common)
    return "" if text.nil?

    s = text.to_s
    if s.encoding == Encoding::BINARY
      s = s.dup.force_encoding(Encoding::UTF_8)
    elsif s.encoding != Encoding::UTF_8
      return s.encode(Encoding::UTF_8, invalid: :replace, undef: :replace, replace: "?")
    end
    s.valid_encoding? ? s : s.scrub("?")
  end

  def resolve_topology_fuzzer(executable: "", triage_dir: nil)
    return nil unless defined?(PrismFuzzer::Topology) && !executable.to_s.empty?

    bin_dir = if triage_dir && !triage_dir.to_s.empty?
                PrismFuzzer::Topology.triage_workspace_candidates(triage_dir)
                                  .map { |r| File.join(r, "bin") }
                                  .find { |d| File.directory?(d) }
              end
    topo = PrismFuzzer::Topology.discover(triage_dir: triage_dir, bin_dir: bin_dir)
    return nil unless topo

    PrismFuzzer::Topology.fuzzer_spec(topo, executable.to_s)
  end

  def prism_diff_bucket?(executable: "", crash_output: "", triage_dir: nil)
    co = utf8_safe(crash_output)
    return true if co.include?("INVARIANT[diff_prism]") || co.include?("CRASH[diff_prism]")
    return true if executable.to_s.end_with?("prism_diff")

    fspec = resolve_topology_fuzzer(executable: executable, triage_dir: triage_dir)
    fspec && fspec["shape"].to_s == "prism_diff_prism"
  end

  def cruby_compile_bucket?(executable: "", crash_output: "", triage_dir: nil)
    co = utf8_safe(crash_output)
    return true if co.include?("INVARIANT[cruby_compile]") || co.include?("CRASH[cruby_compile]")
    return true if executable.to_s.end_with?("compile")

    fspec = resolve_topology_fuzzer(executable: executable, triage_dir: triage_dir)
    fspec && fspec["shape"].to_s == "cruby_compile"
  end

  def diff_bucket?(executable: "", crash_output: "", triage_dir: nil)
    return false if prism_diff_bucket?(executable: executable, crash_output: crash_output, triage_dir: triage_dir)
    return false if cruby_compile_bucket?(executable: executable, crash_output: crash_output, triage_dir: triage_dir)

    co = utf8_safe(crash_output)
    return true if executable.to_s.end_with?("diff") ||
                   co.include?("INVARIANT[diff_parse_y]") ||
                   co.include?("CRASH[diff_parse_y]")

    fspec = resolve_topology_fuzzer(executable: executable, triage_dir: triage_dir)
    fspec && fspec["shape"].to_s == "prism_diff_ruby"
  end

  def cross_oracle_kind(executable: "", crash_output: "", triage_dir: nil)
    exe = executable.to_s
    exe_base = File.basename(exe)
    co = utf8_safe(crash_output)
    fspec = resolve_topology_fuzzer(executable: exe, triage_dir: triage_dir)
    if fspec && fspec["shape"].to_s == "prism_cross_oracle"
      arch = fspec["arch"].to_s
      return arch if CROSS_ORACLE_TARGETS.key?(arch)
    end
    CROSS_ORACLE_TARGETS.each do |kind, cfg|
      return kind if co.include?("INVARIANT[#{cfg[:namespace]}]:") ||
                     exe.end_with?(kind, "#{kind}.repro") ||
                     exe_base == cfg[:repro_exe] ||
                     exe_base.match?(/(?:\A|[._-])#{Regexp.escape(kind)}(?:[._-]ijon)?(?:\.repro)?\z/)
    end
    nil
  end

  def bucket_verify_profile(reason:, executable: "", crash_output: "", triage_dir: nil)
    exe = executable.to_s
    if prism_diff_bucket?(executable: exe, crash_output: crash_output, triage_dir: triage_dir)
      "diff_prism"
    elsif cruby_compile_bucket?(executable: exe, crash_output: crash_output, triage_dir: triage_dir)
      "cruby_compile"
    elsif diff_bucket?(executable: exe, crash_output: crash_output, triage_dir: triage_dir)
      "diff_parse_y"
    elsif (oracle_kind = cross_oracle_kind(executable: exe, crash_output: crash_output, triage_dir: triage_dir))
      CROSS_ORACLE_TARGETS.fetch(oracle_kind)[:profile]
    elsif exe.end_with?("msan") || reason == "use-of-uninitialized-value"
      "msan_slow"
    elsif exe.end_with?("lsan") || reason == "memory-leak"
      "lsan_slow"
    elsif reason == "allocation-size-too-big" || exe.end_with?("native") ||
          (exe.end_with?("ijon") && !resolve_topology_fuzzer(executable: exe, triage_dir: triage_dir))
      "xallocator"
    elsif exe.end_with?("slow")
      "asan_ubsan_slow"
    elsif (fspec = resolve_topology_fuzzer(executable: exe, triage_dir: triage_dir)) && fspec["verify_profile"]
      fspec["verify_profile"].to_s
    else
      "asan_ubsan"
    end
  end

  # Infers the verification profile for a bucket directory from metadata, verify.sh,
  # testcase.c, or build.sh without duplicating heuristics across Ruby and shell callers.
  def infer_bucket_profile(bucket_dir, meta = nil)
    if meta.nil? && bucket_dir && !bucket_dir.to_s.empty?
      meta_path = File.join(bucket_dir, "meta.json")
      meta = if defined?(PrismFuzzer::Common)
               PrismFuzzer::Common.read_json(meta_path, context: "FuzzVerifyProfile")
             else
               begin
                 JSON.parse(File.read(meta_path, encoding: "UTF-8"))
               rescue Errno::ENOENT, Errno::ENOTDIR
                 nil
               rescue JSON::ParserError, EncodingError, SystemCallError, IOError => e
                 warn "FuzzVerifyProfile: failed to read JSON #{meta_path}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
                 nil
               end
             end
    end

    meta_hash = meta.is_a?(Hash) ? meta : nil
    if meta_hash && meta_hash["verify_profile"] && !meta_hash["verify_profile"].to_s.empty?
      return meta_hash["verify_profile"].to_s
    end

    reason = meta_hash&.dig("reason") || (bucket_dir && !bucket_dir.to_s.empty? ? File.basename(File.dirname(bucket_dir)) : "")
    reproduced_by = meta_hash&.dig("reproduced_by").to_s
    return "diff_prism" if reproduced_by.end_with?("prism_diff")
    return "cruby_compile" if reproduced_by.end_with?("compile")
    return "diff_parse_y" if reproduced_by.end_with?("diff")
    return "#{Regexp.last_match(1)}_oracle" if reproduced_by =~ /(arm32|ppc)(?:\.repro)?\z/
    return "msan_slow" if reproduced_by.end_with?("msan") || reason == "use-of-uninitialized-value"
    return "lsan_slow" if reproduced_by.end_with?("lsan") || reason == "memory-leak"
    return "xallocator" if reason == "allocation-size-too-big" || reproduced_by.end_with?("ijon", "native")
    return "asan_ubsan_slow" if reproduced_by.end_with?("slow")

    unless reproduced_by.empty?
      tdir = bucket_dir && !bucket_dir.to_s.empty? ? File.dirname(File.dirname(bucket_dir)) : nil
      fspec = resolve_topology_fuzzer(executable: reproduced_by, triage_dir: tdir)
      if fspec
        return "diff_prism" if fspec["shape"].to_s == "prism_diff_prism"
        return "cruby_compile" if fspec["shape"].to_s == "cruby_compile"
        return "diff_parse_y" if fspec["shape"].to_s == "prism_diff_ruby"
        return "#{fspec['arch']}_oracle" if fspec["shape"].to_s == "prism_cross_oracle" && CROSS_ORACLE_TARGETS.key?(fspec["arch"].to_s)
        return fspec["verify_profile"].to_s if fspec["verify_profile"]
      end
    end

    if bucket_dir && !bucket_dir.to_s.empty?
      verify_sh = File.join(bucket_dir, "verify.sh")
      if File.file?(verify_sh)
        m = File.read(verify_sh).match(/--profile\s+"?([a-z0-9_]+)"?/)
        return m[1] if m
      end

      testcase_c = File.join(bucket_dir, "testcase.c")
      if File.file?(testcase_c)
        text = File.read(testcase_c)
        return "diff_prism" if text.match?(/(INVARIANT|CRASH)\[diff_prism\]/)
        return "cruby_compile" if text.match?(/(INVARIANT|CRASH)\[cruby_compile\]/)
        return "diff_parse_y" if text.match?(/(INVARIANT|CRASH)\[diff_parse_y\]|#include <ruby\.h>/)
      end

      build_sh = File.join(bucket_dir, "build.sh")
      if File.file?(build_sh)
        text = File.read(build_sh)
        return "arm32_oracle" if text.include?("arm-linux-gnueabihf")
        return "ppc_oracle" if text.include?("powerpc-linux-gnu")
        return "msan_slow" if text.include?("-fsanitize=memory")
        return "lsan_slow" if text.include?("-fsanitize=leak")
        return "cruby_compile" if text.include?("build_cruby_compile.sh")
        return "diff_parse_y" if text.include?("build_diff.sh")
        return "asan_ubsan_slow" if text.include?("-DSLOW")
      end
    end

    "asan_ubsan"
  end

  def resolve_reclassify_executable(meta, profile, build_rel: nil, fuzz_root: nil)
    if meta.is_a?(Hash) && (tbin = meta.dig("target", "binary")).is_a?(String) && !tbin.empty?
      froot = fuzz_root || (defined?(PrismFuzzer::Common) ? PrismFuzzer::Common.locate_fuzz_root(__dir__) : nil) || File.expand_path("../..", __dir__)
      cand = File.exist?(tbin) ? tbin : File.join(froot, tbin)
      return cand if File.executable?(cand) && !File.directory?(cand)
    end

    bdir = build_rel && !build_rel.empty? ? build_rel : "./tmp/fuzz/build"
    reproduced_by = meta&.dig("reproduced_by").to_s
    unless reproduced_by.empty?
      return File.join(bdir, "fuzz") if %w[fuzz.sand fuzz.cmplog ./build/fuzz.sand ./build/fuzz.cmplog].include?(File.basename(reproduced_by)) || %w[./build/fuzz.sand ./build/fuzz.cmplog fuzz.sand fuzz.cmplog].include?(reproduced_by)
      # Raw archived bytes already have IJON stream-mode bit cleared; classify via fuzz.native
      # when built so we avoid redundant normalization while keeping the same replay chain.
      return File.join(bdir, "fuzz.native") if profile == "xallocator" && reproduced_by.end_with?("ijon") && File.executable?(File.join(bdir, "fuzz.native"))
      return File.join(bdir, "fuzz.prism_diff") if reproduced_by.end_with?("prism_diff")
      return File.join(bdir, "fuzz.compile") if reproduced_by.end_with?("compile")
      return File.join(bdir, "fuzz.diff") if reproduced_by.end_with?("diff")
      if reproduced_by =~ /(arm32|ppc)(?:\.repro)?\z/
        return File.join(bdir, "fuzz.#{Regexp.last_match(1)}.repro")
      end

      return reproduced_by.include?("/") ? reproduced_by : File.join(bdir, reproduced_by)
    end

    case profile
    when "asan_ubsan_slow"
      File.join(bdir, "fuzz.slow")
    when "msan_slow"
      File.join(bdir, "fuzz.msan")
    when "lsan_slow"
      File.join(bdir, "fuzz.lsan")
    when "xallocator"
      File.executable?(File.join(bdir, "fuzz.native")) ? File.join(bdir, "fuzz.native") : File.join(bdir, "fuzz")
    when "diff_prism"
      File.join(bdir, "fuzz.prism_diff")
    when "cruby_compile"
      File.join(bdir, "fuzz.compile")
    when "diff_parse_y"
      File.join(bdir, "fuzz.diff")
    when "arm32_oracle"
      File.join(bdir, "fuzz.arm32.repro")
    when "ppc_oracle"
      File.join(bdir, "fuzz.ppc.repro")
    else
      File.join(bdir, "fuzz")
    end
  end
end

if __FILE__ == $PROGRAM_NAME
  cmd = ARGV.shift
  case cmd
  when "infer"
    bucket_dir = ARGV[0]
    abort "Usage: #{$PROGRAM_NAME} infer BUCKET_DIR" if bucket_dir.nil? || bucket_dir.empty?
    puts FuzzVerifyProfile.infer_bucket_profile(bucket_dir)
  else
    abort "Usage: #{$PROGRAM_NAME} infer BUCKET_DIR"
  end
end
