# frozen_string_literal: true

require_relative "../lib/autorun"

require "fileutils"
require "json"
require "shellwords"

require_relative "../../runtime/topology"
require_relative "../../triage/triage"

# Verifies [3/8] triage.rb option header decoding/encoding, Loupe URL generation,
# verify.sh profile selection, crash output parsing, and strict C99 Prism harness
# invariant/legacy-API checks.
class TriageReproTest < Minitest::Test
  CLEAN_TOPOLOGY_ENV = {
    "CAMPAIGN" => nil,
    "TOPOLOGY" => nil,
    "TOPOLOGY_FILE" => nil,
    "TOPOLOGY_RESOLVED" => nil,
    "FUZZ_DIR" => nil,
    "FUZZ_BUILD_DIR" => nil,
    "TRIAGE_DIR" => nil,
    "TRIAGE_CORPUS_DIR" => nil,
    "TRIAGE_COVERAGE_BIN" => nil,
    "TRIAGE_COVERAGE_IDS" => nil,
    "TRIAGE_DIFF_COVERAGE_BIN" => nil,
    "TRIAGE_DIFF_COVERAGE_IDS" => nil,
    "TRIAGE_EXPLAIN_BIN" => nil,
    "TRIAGE_DIGEST" => nil
  }.freeze

  UNMAKE_ENV = {
    "MAKEFLAGS" => nil,
    "MFLAGS" => nil,
    "MAKELEVEL" => nil
  }.freeze

  COMMON_HARNESS_FLAGS = %w[
    -O1
    -std=c99
    -fsanitize=address,undefined
    -DPRISM_DEPTH_MAXIMUM=128
    -DPM_INTEGER_DIVIDE_THRESHOLD=8
    -DFUZZ_MAX_INPUT_SIZE=1024
    -DFUZZ_MAX_ALLOCATED=128
    -DFUZZ_HARD_RSS_LIMIT=2048
    -Wno-gnu-statement-expression-from-macro-expansion
    -Wno-switch
  ].freeze

  @prism_cache_mutex = Mutex.new
  @prism_cache = {}

  def self.prism_test_artifacts(prism_a, cc:, root_dir:, gen_dir_candidate:)
    @prism_cache_mutex.synchronize do
      @prism_cache[prism_a] ||= begin
        cache_dir = Dir.mktmpdir("triage-repro-prism-")
        Minitest.after_run { FileUtils.rm_rf(cache_dir) }

        objs_dir = File.join(cache_dir, "objs")
        FileUtils.mkdir_p(objs_dir)
        prism_srcs = Dir.glob(File.join(prism_a, "src", "**", "*.c")).sort
        raise "missing Prism C sources under #{prism_a}/src" if prism_srcs.empty?

        out, err, st = Open3.capture3(
          cc,
          "-O1", "-std=c99", "-DPRISM_EXPORT_SYMBOLS", "-fsanitize=address,undefined",
          "-I#{File.join(prism_a, 'include')}",
          "-I#{File.join(prism_a, 'src')}",
          *prism_srcs,
          "-c",
          chdir: objs_dir
        )
        raise "failed to compile Prism objects:\n#{out}\n#{err}" unless st.success?

        lib_path = File.join(cache_dir, "libprism_test.a")
        objs = Dir.glob(File.join(objs_dir, "*.o")).sort
        ar_out, ar_err, ar_st = Open3.capture3("ar", "rcs", lib_path, *objs)
        raise "ar rcs failed:\n#{ar_out}\n#{ar_err}" unless ar_st.success?

        gen_dir = if gen_dir_candidate &&
                     File.file?(File.join(gen_dir_candidate, "node_locations.inc")) &&
                     File.file?(File.join(gen_dir_candidate, "prism_fuzz_compat.h"))
                    gen_dir_candidate
                  else
                    local_gen = File.join(cache_dir, "gen")
                    PrismFuzzer::Topology.ensure_harness_generated_inc!(prism_a, local_gen, fuzz_root: root_dir)
                    local_gen
                  end

        { dir: cache_dir, lib: lib_path, gen_dir: gen_dir }
      end
    end
  end

  def test_option_header_decode_encode_and_ijon_normalization
    with_tmpdir("triage-repro-") do |workdir|
      nonempty_in = File.join(workdir, "repro_nonempty.bin")
      empty_in = File.join(workdir, "repro_empty.bin")
      enc_oob_in = File.join(workdir, "repro_enc_oob.bin")
      min_oob_in = File.join(workdir, "repro_min_oob.bin")
      stream_slow_in = File.join(workdir, "repro_stream_slow.bin")
      node_loc_in = File.join(workdir, "repro_node_loc.bin")

      File.binwrite(nonempty_in, "\x2a\x05\x1b\xff1 + 2\n".b)
      File.binwrite(empty_in, "\x00\x00\x03\x01".b)
      File.binwrite(enc_oob_in, "\xa3\xc5\x28\x31/\\M".b)
      File.binwrite(min_oob_in, "\x80\x00\x03\x01/\\M".b)
      File.binwrite(stream_slow_in, "\xc8\x80\x00\xa91 + 2\n".b)
      File.binwrite(node_loc_in, "\x00\x00\x03\x011 + 2\n".b)

      nonempty_h = FuzzTriage.decode_fuzz_header(File.binread(nonempty_in))
      assert_equal(-1, nonempty_h[:start_line])
      assert nonempty_h[:partial_script]
      assert nonempty_h[:encoding_locked]
      assert_equal %w[a l], nonempty_h[:command_line_chars]
      assert_equal "4.1", nonempty_h[:version]
      assert_equal "1 + 2\n".b, nonempty_h[:source]

      empty_h = FuzzTriage.decode_fuzz_header(File.binread(empty_in))
      assert empty_h[:valid_header]
      assert_equal 1, empty_h[:start_line]
      assert_equal "4.1", empty_h[:version]
      assert_equal "".b, empty_h[:source]

      enc_oob_h = FuzzTriage.decode_fuzz_header(File.binread(enc_oob_in))
      assert enc_oob_h[:has_encoding_opts]
      assert_equal "ASCII-8BIT", enc_oob_h[:encoding]
      assert_equal "3.3", enc_oob_h[:version]
      assert_equal 0, enc_oob_h[:start_line]
      assert enc_oob_h[:main_script]
      assert enc_oob_h[:partial_script]
      assert enc_oob_h[:freeze]
      assert_equal "fuzz.rb", enc_oob_h[:filepath]

      min_oob_h = FuzzTriage.decode_fuzz_header(File.binread(min_oob_in))
      assert min_oob_h[:has_encoding_opts]
      assert_equal "ASCII-8BIT", min_oob_h[:encoding]
      assert_equal "4.1", min_oob_h[:version]
      assert_equal 1, min_oob_h[:start_line]
      assert_equal "/\\M".b, min_oob_h[:source]

      stream_slow_h = FuzzTriage.decode_fuzz_header(File.binread(stream_slow_in))
      assert stream_slow_h[:stream_mode]
      assert stream_slow_h[:has_limit_opts]
      assert_equal "INT32_MIN", stream_slow_h[:start_line_c]
      assert_equal "512", stream_slow_h[:stack_budget]
      assert stream_slow_h[:shebang_callback]

      node_loc_h = FuzzTriage.decode_fuzz_header(File.binread(node_loc_in))
      assert_equal [0x00, 0x00, 0x03, 0x01], node_loc_h[:header_bytes]
      assert_equal "1 + 2\n".b, node_loc_h[:source]

      # Round-trip encoding/decoding coverage
      assert_equal "\x00\x00\x03\x01".b, FuzzTriage.encode_fuzz_header
      encoded = FuzzTriage.encode_fuzz_header(
        ruby_version: "3.5",
        encoding: "EUC-JP",
        frozen_string_literal: true,
        partial_script: true,
        freeze: true,
        attach_comments: true,
        encoding_locked: true,
        stream_mode: true,
        main_script: true,
        command_line: "ax",
        scopes_count: 2,
        forwarding: "pk"
      )
      rt = FuzzTriage.decode_fuzz_header(encoded + "puts 1\n".b)
      assert_equal "3.5", rt[:version]
      assert_equal "EUC-JP", rt[:encoding]
      assert rt[:has_frozen_string_literal]
      assert rt[:frozen_string_literal]
      assert rt[:partial_script]
      assert rt[:freeze]
      assert rt[:attach_comments]
      assert rt[:encoding_locked]
      assert rt[:stream_mode]
      assert rt[:main_script]
      assert_equal %w[a x], rt[:command_line_chars]
      assert_equal 2, rt[:scopes_count]
      assert_equal %w[p k], rt[:forwarding_chars]

      neg_line_hdr = FuzzTriage.encode_fuzz_header(
        ruby_version: "4.1",
        partial_script: true,
        encoding_locked: true,
        command_line: "al",
        start_line: -1
      )
      neg_decoded = FuzzTriage.decode_fuzz_header(neg_line_hdr)
      assert_equal(-1, neg_decoded[:start_line])
      assert neg_decoded[:partial_script]
      assert neg_decoded[:encoding_locked]
      assert_equal %w[a l], neg_decoded[:command_line_chars]

      assert_raises(ArgumentError) { FuzzTriage.encode_fuzz_header(ruby_version: "9.9") }
      assert_raises(ArgumentError) { FuzzTriage.encode_fuzz_header(encoding: "BOGUS") }
      assert_raises(ArgumentError) { FuzzTriage.encode_fuzz_header(start_line: 200) }
      assert_raises(ArgumentError) { FuzzTriage.encode_fuzz_header(scopes_count: 4) }

      # IJON stream-bit normalization (suppressed unless PRISM_FUZZ_ALLOW_STREAM_WITH_IJON is active)
      assert_nil FuzzTriage.normalize_ijon_crash_bytes("\x2a\x11\x22\x33abc".b), "expected nil when stream bit unset"
      assert_equal "\x2a\x11\x22\x33abc".b, FuzzTriage.normalize_ijon_crash_bytes("\x6a\x11\x22\x33abc".b), "expected stream bit cleared"
      assert FuzzTriage.fuzzer_suppresses_stream?({ "shape" => "prism_parse", "ijon" => true })
      refute FuzzTriage.fuzzer_suppresses_stream?({ "shape" => "prism_parse", "ijon" => true, "defines" => { "PRISM_FUZZ_ALLOW_STREAM_WITH_IJON" => 1 } })
      refute FuzzTriage.fuzzer_suppresses_stream?({ "shape" => "prism_parse", "ijon" => true, "cflags" => ["-DPRISM_FUZZ_ALLOW_STREAM_WITH_IJON"] })
      refute FuzzTriage.fuzzer_suppresses_stream?({ "shape" => "prism_diff_ruby", "ijon" => true })
    end
  end

  def test_prism_loupe_urls_and_sanitizer_detection
    with_tmpdir("triage-repro-") do |workdir|
      nonempty_in = File.join(workdir, "repro_nonempty.bin")
      empty_in = File.join(workdir, "repro_empty.bin")
      enc_oob_in = File.join(workdir, "repro_enc_oob.bin")

      File.binwrite(nonempty_in, "\x2a\x05\x1b\xff1 + 2\n".b)
      File.binwrite(empty_in, "\x00\x00\x03\x01".b)
      File.binwrite(enc_oob_in, "\xa3\xc5\x28\x31/\\M".b)

      expected_nonempty_url = "https://stevenjohnstone.github.io/prism-loupe/?code=MSArIDIK&ruby_ver=4.1&line=-1&cmd=al&partial=1&enc_lock=1&scopes=a%2Cfoo%2C~MSArIA%3Bp%3Ab%2Cit"
      assert_equal expected_nonempty_url, FuzzTriage.build_prism_loupe_url(File.binread(nonempty_in))

      expected_empty_url = "https://stevenjohnstone.github.io/prism-loupe/?code=&ruby_ver=4.1"
      assert_equal expected_empty_url, FuzzTriage.build_prism_loupe_url(File.binread(empty_in))

      expected_enc_oob_url = "https://stevenjohnstone.github.io/prism-loupe/?code=L1xN&enc=ASCII-8BIT&ruby_ver=3.3&line=0&cmd=al&main=1&partial=1&freeze=1&filepath=fuzz.rb&scopes=%3A%3Bk%3Ab%2Cit"
      assert_equal expected_enc_oob_url, FuzzTriage.build_prism_loupe_url(File.binread(enc_oob_in))

      san_flag = FuzzTriage.sanitizer_loupe_crash?(
        "undefined-behavior",
        "src/line_offset_list.c:85:58: runtime error: signed integer overflow\n"
      )
      assert san_flag, "expected sanitizer_loupe_crash? to return true for UBSAN runtime error"
      assert_equal(
        "https://stevenjohnstone.github.io/prism-loupe/?code=&san=1&ruby_ver=4.1",
        FuzzTriage.build_prism_loupe_url(File.binread(empty_in), sanitize: san_flag)
      )

      refute FuzzTriage.sanitizer_loupe_crash?("ABRT", "INVARIANT[node_location]: type=PM_WHILE_NODE kind=length_underflow\n")
      assert FuzzTriage.sanitizer_loupe_crash?("heap-buffer-overflow", "SUMMARY: AddressSanitizer: heap-buffer-overflow\n")
    end
  end

  def test_verify_profile_selection_and_topology_overrides
    with_tmpdir("triage-repro-") do |workdir|
      assert_equal "asan_ubsan_slow", FuzzTriage.bucket_verify_profile(reason: "ABRT", executable: "./build/fuzz.slow")
      assert_equal "msan_slow", FuzzTriage.bucket_verify_profile(reason: "use-of-uninitialized-value", executable: "./build/fuzz.msan")
      assert_equal "lsan_slow", FuzzTriage.bucket_verify_profile(reason: "memory-leak", executable: "./build/fuzz.lsan")
      assert_equal "xallocator", FuzzTriage.bucket_verify_profile(reason: "allocation-size-too-big", executable: "./build/fuzz.native")

      slow_vsh = FuzzTriage.verify_script(reason: "ABRT", executable: "./build/fuzz.slow")
      assert_includes slow_vsh, '--profile "asan_ubsan_slow"'

      diff_inv = "INVARIANT[diff_parse_y]: kind=syntax_mismatch sub=prism_ok_cruby_err [detail: prism_errs=0 cruby=SyntaxError]\n"
      diff_crash = "CRASH[diff_parse_y]: signal=SIGSEGV (11)\n" \
                   "/prism/build/fuzz.diff(rb_print_backtrace+0x28) [0xaaaa0800] /opt/ruby/vm_dump.c:1108\n"
      assert_equal "diff_parse_y", FuzzTriage.bucket_verify_profile(reason: "ABRT", executable: "./build/fuzz.diff")
      assert_equal "diff_parse_y", FuzzTriage.bucket_verify_profile(reason: "ABRT", executable: "./build/fuzz", crash_output: diff_inv)
      assert_equal "diff_parse_y", FuzzTriage.bucket_verify_profile(reason: "SEGV", executable: "./build/fuzz", crash_output: diff_crash)

      stream_slow_in = File.join(workdir, "repro_stream_slow.bin")
      File.binwrite(stream_slow_in, "\xc8\x80\x00\xa91 + 2\n".b)
      diff_io = FuzzTriage.input_and_options_metadata(stream_slow_in, reason: "ABRT", crash_output: diff_inv, executable: "./build/fuzz.diff")
      assert_equal "4.1", diff_io.dig("options", "ruby_version")
      assert_equal false, diff_io.dig("options", "stream_mode")

      topo_ijon_dir = File.join(workdir, "topo_ijon_profile")
      FileUtils.mkdir_p(topo_ijon_dir)
      topo_path = File.join(topo_ijon_dir, "topology.json")
      File.write(topo_path, JSON.generate({
        "schema_version" => 2,
        "name" => "triage-ijon-profile",
        "workspace" => { "dir" => topo_ijon_dir, "build_dir" => File.join(topo_ijon_dir, "build") },
        "sources" => { "prism_a" => { "kind" => "prism", "repo" => "https://example.invalid/prism.git", "ref" => "main" } },
        "fuzzers" => {
          "fuzz.asan_ijon" => { "shape" => "prism_parse", "source" => "prism_a", "sanitizers" => %w[asan ubsan], "afl" => "pcguard", "ijon" => true },
          "fuzz.xalloc_ijon" => { "shape" => "prism_parse", "source" => "prism_a", "sanitizers" => [], "afl" => "lto", "ijon" => true, "xallocator" => true },
          "fuzz.pdiff_ijon" => { "shape" => "prism_diff_prism", "prism_a" => "prism_a", "prism_b" => "prism_a", "afl" => "pcguard", "ijon" => true }
        },
        "sync_groups" => { "afl" => { "dir" => "afl" } },
        "workers" => []
      }))

      with_env(CLEAN_TOPOLOGY_ENV.merge("TOPOLOGY" => topo_path)) do
        assert_equal "asan_ubsan", FuzzTriage.bucket_verify_profile(reason: "SEGV", executable: "./build/fuzz.asan_ijon")
        assert_equal "xallocator", FuzzTriage.bucket_verify_profile(reason: "ABRT", executable: "./build/fuzz.xalloc_ijon")
        assert_equal "diff_prism", FuzzTriage.bucket_verify_profile(reason: "ABRT", executable: "./build/fuzz.pdiff_ijon")
      end
    end
  end

  def test_finalize_triage_metadata_preserves_custom_and_ijon_repro_profiles
    with_tmpdir("triage-repro-") do |workdir|
      ext_topo_ws = File.join(workdir, "ext_finalize_ws")
      ext_topo_build = File.join(ext_topo_ws, "build")
      ext_topo_triage = File.join(ext_topo_ws, "triage")
      FileUtils.mkdir_p([
        ext_topo_build,
        File.join(ext_topo_triage, "ABRT", "diff_ab_sig"),
        File.join(ext_topo_triage, "SEGV", "arm_ijon_sig")
      ])
      File.write(File.join(ext_topo_build, "topology.resolved.json"), JSON.generate({
        "schema_version" => 2,
        "name" => "custom-finalize-profile-test",
        "workspace" => { "dir" => ext_topo_ws, "build_dir" => ext_topo_build, "triage_dir" => ext_topo_triage },
        "sources" => { "prism_a" => { "kind" => "prism", "repo" => "https://example.invalid/prism.git", "ref" => "main" } },
        "fuzzers" => {
          "diff.ab" => { "shape" => "prism_diff_prism", "prism_a" => "prism_a", "prism_b" => "prism_a", "binary" => "diff.ab" },
          "fuzz.arm32.ijon" => { "shape" => "prism_cross_oracle", "source" => "prism_a", "arch" => "arm32", "ijon" => true, "binary" => "fuzz.arm32.ijon", "repro" => "fuzz.arm32.ijon.repro" },
          "oracle.custom32" => { "shape" => "prism_cross_oracle", "source" => "prism_a", "arch" => "arm32", "binary" => "oracle.custom32", "repro" => "oracle.custom32.repro" }
        },
        "sync_groups" => {},
        "workers" => []
      }))

      with_env(CLEAN_TOPOLOGY_ENV) do
        assert_equal "arm32", FuzzTriage.cross_oracle_kind(executable: "fuzz.arm32.ijon.repro", crash_output: "SUMMARY: AddressSanitizer: SEGV")
        assert_equal "ppc", FuzzTriage.cross_oracle_kind(executable: "fuzz.ppc.ijon.repro", crash_output: "SUMMARY: AddressSanitizer: SEGV")
        assert_equal "arm32", FuzzTriage.cross_oracle_kind(executable: "oracle.custom32.repro", crash_output: "SUMMARY: AddressSanitizer: SEGV", triage_dir: ext_topo_triage)
        assert_equal "diff_prism", FuzzTriage.bucket_verify_profile(reason: "ABRT", executable: "diff.ab", crash_output: "Assertion failed", triage_dir: ext_topo_triage)

        ab_bucket = File.join(ext_topo_triage, "ABRT", "diff_ab_sig")
        File.binwrite(File.join(ab_bucket, "input.min"), "\x00\x00\x03\x011 + 2")
        File.write(File.join(ab_bucket, "verify.sh"), FuzzTriage.verify_script(reason: "ABRT", executable: "diff.ab", crash_output: "Assertion failed", triage_dir: ext_topo_triage))
        File.write(File.join(ab_bucket, "meta.json"), JSON.pretty_generate(FuzzTriage.build_bucket_metadata(
          bucket_id: "ABRT/diff_ab_sig",
          reason: "ABRT",
          signature: "diff_ab_sig",
          reproducible: true,
          timed_out: false,
          executable: "diff.ab",
          crash_output: "INVARIANT[diff_prism]: kind=error_mismatch\n",
          minimized_input: File.join(ab_bucket, "input.min"),
          raw_size_bytes: 9,
          raw_sha256: "0" * 64,
          minimized_matches_signature: true,
          occurrences: { "count" => 1 },
          triage_dir: ext_topo_triage
        )))

        arm_bucket = File.join(ext_topo_triage, "SEGV", "arm_ijon_sig")
        File.binwrite(File.join(arm_bucket, "input.min"), "\x00\x00\x03\x011 + 2")
        File.write(File.join(arm_bucket, "verify.sh"), FuzzTriage.verify_script(reason: "SEGV", executable: "fuzz.arm32.ijon.repro", crash_output: "SUMMARY: AddressSanitizer: SEGV", triage_dir: ext_topo_triage))
        File.write(File.join(arm_bucket, "meta.json"), JSON.pretty_generate(FuzzTriage.build_bucket_metadata(
          bucket_id: "SEGV/arm_ijon_sig",
          reason: "SEGV",
          signature: "arm_ijon_sig",
          reproducible: true,
          timed_out: false,
          executable: "fuzz.arm32.ijon.repro",
          crash_output: "SUMMARY: AddressSanitizer: SEGV\n",
          minimized_input: File.join(arm_bucket, "input.min"),
          raw_size_bytes: 9,
          raw_sha256: "1" * 64,
          minimized_matches_signature: true,
          occurrences: { "count" => 1 },
          triage_dir: ext_topo_triage
        )))

        # Stub repro binary so classify_crash_execution uses fspec["repro"] (fuzz.arm32.ijon.repro), not fuzz.arm32.repro
        ijon_bin = write_executable(File.join(ext_topo_build, "fuzz.arm32.ijon"), "#!/bin/sh\nexit 0\n")
        ijon_repro = write_executable(File.join(ext_topo_build, "fuzz.arm32.ijon.repro"), "#!/bin/sh\necho 'SUMMARY: AddressSanitizer: SEGV' >&2\nexit 1\n")
        cdir = File.join(ext_topo_ws, "afl", "arm_w", "crashes")
        FileUtils.mkdir_p(cdir)
        cinfo = FuzzTriage.classify_crash_execution(cdir, File.join(arm_bucket, "input.min"), ijon_bin, triage_dir: ext_topo_triage)
        assert_equal File.basename(ijon_repro), File.basename(cinfo[:executable])

        FuzzTriage.finalize_triage_metadata(ext_topo_triage, coverage_bin: "")
        assert_includes File.read(File.join(ab_bucket, "verify.sh")), '--profile "diff_prism"'
        assert_includes File.read(File.join(arm_bucket, "verify.sh")), '--profile "arm32_oracle"'
        assert_equal "diff_prism", JSON.parse(File.read(File.join(ab_bucket, "meta.json")))["verify_profile"]
        assert_equal "arm32_oracle", JSON.parse(File.read(File.join(arm_bucket, "meta.json")))["verify_profile"]
      end
    end
  end

  def test_parse_crash_output_asan_ubsan_lsan_and_invariants
    diff_inv = "INVARIANT[diff_parse_y]: kind=syntax_mismatch sub=prism_ok_cruby_err [detail: prism_errs=0 cruby=SyntaxError]\n"
    parsed_diff = FuzzTriage.parse_crash_output(diff_inv)
    assert_equal "diff_parse_y", parsed_diff.dig("symptom", "invariant", "namespace")
    assert_equal "syntax_mismatch", parsed_diff.dig("symptom", "invariant", "fields", "kind")
    assert_equal "prism_ok_cruby_err", parsed_diff.dig("symptom", "invariant", "fields", "sub")

    parsed_diff_granular = FuzzTriage.parse_crash_output(
      "INVARIANT[diff_parse_y]: kind=syntax_mismatch sub=prism_ok_cruby_err nul=1 utf8=0 prism=ok cruby=ArgumentError:unknown_encoding [detail: prism_errs=0 cruby=ArgumentError: unknown encoding name: foo]\n"
    )
    assert_equal 1, parsed_diff_granular.dig("symptom", "invariant", "fields", "nul")
    assert_equal 0, parsed_diff_granular.dig("symptom", "invariant", "fields", "utf8")
    assert_equal "ok", parsed_diff_granular.dig("symptom", "invariant", "fields", "prism")
    assert_equal "ArgumentError:unknown_encoding", parsed_diff_granular.dig("symptom", "invariant", "fields", "cruby")

    parsed_diff_ast = FuzzTriage.parse_crash_output(
      "INVARIANT[diff_parse_y]: kind=ast_block_owner_mismatch sub=operator [detail: idx=0 prism=r cruby=&]\n"
    )
    assert_equal "ast_block_owner_mismatch", parsed_diff_ast.dig("symptom", "invariant", "fields", "kind")
    assert_equal "operator", parsed_diff_ast.dig("symptom", "invariant", "fields", "sub")
    assert_equal "r", parsed_diff_ast.dig("symptom", "invariant", "detail", "prism")
    assert_equal "&", parsed_diff_ast.dig("symptom", "invariant", "detail", "cruby")

    diff_crash = "CRASH[diff_parse_y]: signal=SIGSEGV (11)\n" \
                 "/prism/build/fuzz.diff(rb_print_backtrace+0x28) [0xaaaa0800] /opt/ruby/vm_dump.c:1108\n" \
                 "/prism/build/fuzz.diff(diff_fatal_signal_handler+0x4c) [0xaaaa1000] /prism/harnesses/prism/diff.c:96\n" \
                 "linux-vdso.so.1(__kernel_rt_sigreturn+0x0) [0xffff0000]\n" \
                 "/prism/build/fuzz.diff(rb_st_free_table+0x14) [0xaaaa2000] /opt/ruby/st.c:667\n" \
                 "/prism/build/fuzz.diff(ruby_yyparse+0x40) [0xaaaa3000] /prism/parse.y:4532\n" \
                 "/prism/build/fuzz.diff(ast_s_parse) /opt/ruby/ast.c:135\n"
    parsed_diff_crash = FuzzTriage.parse_crash_output(diff_crash)
    assert_equal "CRASH[diff_parse_y]: signal=SIGSEGV (11)", parsed_diff_crash.dig("symptom", "headline")
    assert_equal 6, parsed_diff_crash["frames"].size
    assert_equal "harness", parsed_diff_crash["frames"][1]["scope"]
    assert_equal "__kernel_rt_sigreturn", parsed_diff_crash["frames"][2]["func"]
    assert_equal "rb_st_free_table", parsed_diff_crash["frames"][3]["func"]
    assert_equal "/opt/ruby/st.c", parsed_diff_crash["frames"][3]["file"]
    assert_equal 667, parsed_diff_crash["frames"][3]["line"]
    assert_equal "ruby_yyparse", parsed_diff_crash["frames"][4]["func"]
    assert_equal "parse.y", parsed_diff_crash["frames"][4]["file"]
    assert_equal 4532, parsed_diff_crash["frames"][4]["line"]
    assert_equal "ast_s_parse", parsed_diff_crash["frames"][5]["func"]
    assert_equal "/opt/ruby/ast.c", parsed_diff_crash["frames"][5]["file"]
    assert_equal 135, parsed_diff_crash["frames"][5]["line"]

    nonutf8_out = "INVARIANT[diff_parse_y]: kind=syntax_mismatch sub=prism_ok_cruby_err nul=0 utf8=0 prism=ok cruby=ArgumentError:unknown_encoding [detail: prism_errs=0 cruby=ArgumentError: unknown encoding name: Windows-31J\xBB\xFF]\n".b.dup.force_encoding("UTF-8")
    assert FuzzTriage.utf8_safe(nonutf8_out).valid_encoding?
    assert FuzzTriage.utf8_safe(nonutf8_out.b).valid_encoding?
    assert FuzzTriage.diff_bucket?(crash_output: nonutf8_out)
    refute FuzzTriage.sanitizer_loupe_crash?("ABRT", nonutf8_out)
    assert JSON.pretty_generate(FuzzTriage.parse_crash_output(nonutf8_out)).valid_encoding?

    parsed_inv = FuzzTriage.parse_crash_output(
      "Reading 11 bytes from x\n" \
      "INVARIANT[node_location]: type=PM_WHILE_NODE kind=length_underflow [detail: parent=PM_STATEMENTS_NODE start=6 length=4294967294 parsed_size=12]\n" \
      "    #0 0xffff9c3374d8 in abort stdlib/abort.c:79:7\n" \
      "    #1 0xaaaa in fuzz_invariant_fail /prism/harnesses/prism/parse.c:94:5\n" \
      "    #2 0xaaab in pm_visit_node /prism/prism/templates/src/node.c.erb:409:32\n" \
      "    #3 0xaaac in parse_while /prism/src/prism.c:20046:5\n"
    )
    assert_equal "node_location", parsed_inv.dig("symptom", "invariant", "namespace")
    assert_equal "PM_WHILE_NODE", parsed_inv.dig("symptom", "invariant", "fields", "type")
    assert_equal 4_294_967_294, parsed_inv.dig("symptom", "invariant", "detail", "length")
    assert_equal %w[external harness prism prism], parsed_inv["frames"].map { |f| f["scope"] }
    assert_equal "templates/src/node.c.erb", parsed_inv["frames"][2]["file"]
    assert_equal "src/prism.c", parsed_inv["frames"][3]["file"]
    assert_equal 20_046, parsed_inv["frames"][3]["line"]

    parsed_sub_inv = FuzzTriage.parse_crash_output(
      "INVARIANT[node_sub_location]: type=PM_CALL_NODE field=message_loc kind=length_underflow [detail: parent=PM_STATEMENTS_NODE start=8 length=4294967292 parsed_size=20]\n" \
      "    #0 0xffff9c3374d8 in abort stdlib/abort.c:79:7\n" \
      "    #1 0xaaaa in fuzz_check_sub_location /prism/harnesses/prism/parse.c:884:9\n"
    )
    assert_equal "node_sub_location", parsed_sub_inv.dig("symptom", "invariant", "namespace")
    assert_equal "PM_CALL_NODE", parsed_sub_inv.dig("symptom", "invariant", "fields", "type")
    assert_equal "message_loc", parsed_sub_inv.dig("symptom", "invariant", "fields", "field")
    assert_equal "length_underflow", parsed_sub_inv.dig("symptom", "invariant", "fields", "kind")
    assert_equal 4_294_967_292, parsed_sub_inv.dig("symptom", "invariant", "detail", "length")

    parsed_ub = FuzzTriage.parse_crash_output(
      "src/prism.c:15213:5: runtime error: signed integer overflow: 1 + 2147483647 cannot be represented in type 'int32_t'\n" \
      "    #0 0xaaaa in parser_warn_indentation_mismatch /prism/src/prism.c:15213:5\n" \
      "    #1 0xaaab in _start (/prism/build/fuzz+0x10d9ec) (BuildId: abc)\n" \
      "SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior src/prism.c:15213:5\n"
    )
    assert_equal "src/prism.c", parsed_ub.dig("symptom", "ubsan", "file")
    assert_equal 15_213, parsed_ub.dig("symptom", "ubsan", "line")
    assert_equal "signed integer overflow", parsed_ub.dig("symptom", "ubsan", "check")
    assert_equal "/prism/build/fuzz+0x10d9ec", parsed_ub["frames"][1]["module"]

    parsed_asan = FuzzTriage.parse_crash_output(
      "==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000014 at pc 0xaaaa bp 0xffff sp 0xffff\n" \
      "READ of size 4 at 0x502000000014 thread T0\n" \
      "    #0 0xaaaa in pm_parser_lex /prism/src/prism.c:1234:9\n" \
      "SUMMARY: AddressSanitizer: heap-buffer-overflow /prism/src/prism.c:1234:9 in pm_parser_lex\n"
    )
    assert_equal "AddressSanitizer", parsed_asan.dig("symptom", "sanitizer", "tool")
    assert_equal "heap-buffer-overflow", parsed_asan.dig("symptom", "sanitizer", "kind")
    assert_equal({ "op" => "READ", "size" => 4 }, parsed_asan.dig("symptom", "sanitizer", "access"))
    assert_equal "ERROR: AddressSanitizer: heap-buffer-overflow in pm_parser_lex (src/prism.c:1234)", parsed_asan.dig("symptom", "headline")
    assert_equal "AddressSanitizer: heap-buffer-overflow /prism/src/prism.c:1234:9 in pm_parser_lex", parsed_asan.dig("symptom", "summary")
    assert_equal "src/prism.c", parsed_asan["frames"][0]["file"]
    assert_equal 1234, parsed_asan["frames"][0]["line"]

    lsan_out = "==5678==ERROR: LeakSanitizer: detected memory leaks\n" \
               "Direct leak of 32 byte(s) in 1 object(s) allocated from:\n" \
               "    #0 0xbbbb in malloc (/usr/lib/libasan.so+0x1234)\n" \
               "    #1 0xcccc in pm_arena_alloc /prism/src/arena.c:42:10\n" \
               "SUMMARY: AddressSanitizer: 32 byte(s) leaked in 1 allocation(s).\n"
    parsed_lsan = FuzzTriage.parse_crash_output(lsan_out)
    assert_equal "LeakSanitizer", parsed_lsan.dig("symptom", "sanitizer", "tool")
    assert_equal "detected-memory-leaks", parsed_lsan.dig("symptom", "sanitizer", "kind")
    assert_equal "ERROR: LeakSanitizer: detected memory leaks in pm_arena_alloc (src/arena.c:42)", parsed_lsan.dig("symptom", "headline")
    assert_equal "src/arena.c", parsed_lsan["frames"][1]["file"]
    assert_equal "memory-leak", FuzzTriage.infer_crash_reason(lsan_out)

    so_out = "AddressSanitizer:DEADLYSIGNAL\n" \
             "=================================================================\n" \
             "==7==ERROR: AddressSanitizer: stack-overflow on address 0xffffc19be9f0 (pc 0xaaaaac541d14 bp 0xffffc19bf200 sp 0xffffc19be9f0 T0)\n" \
             "    #0 0xaaaaac541d14 in __asan_memcpy (/prism/bin/fuzz.ijon.diff+0x1c1d14)\n" \
             "    #1 0xaaaaac65c3a8 in parser_lex /prism/src/prism.c:10179:32\n" \
             "    #2 0xaaaaac63d120 in parse_parentheses /prism/src/prism.c:15000:9\n" \
             "SUMMARY: AddressSanitizer: stack-overflow (/prism/bin/fuzz.ijon.diff+0x1c1d14) in __asan_memcpy\n" \
             "==7==ABORTING\n"
    parsed_so = FuzzTriage.parse_crash_output(so_out)
    assert_equal "stack-overflow", FuzzTriage.infer_crash_reason(so_out, "SEGV")
    assert_equal "stack-overflow", FuzzTriage.infer_crash_reason(so_out.lines.first(5).join, "SEGV")
    assert_equal({ "tool" => "AddressSanitizer", "kind" => "stack-overflow" }, parsed_so.dig("symptom", "sanitizer"))
    assert_equal "ERROR: AddressSanitizer: stack-overflow in parser_lex (src/prism.c:10179)", parsed_so.dig("symptom", "headline")
    require_relative "../../triage/cluster"
    so_bucket = {
      "verify_profile" => "diff_parse_y",
      "reason" => "stack-overflow",
      "symptom" => parsed_so["symptom"],
      "frames" => parsed_so["frames"]
    }
    assert_equal "crash_or_inv", FuzzClustering.oracle_family(so_bucket)
  end

  def test_compiled_harness_slow_invariants_with_mock_wraps
    prism_a = require_prism_a!
    artifacts = self.class.prism_test_artifacts(prism_a, cc: c_compiler, root_dir: root_dir, gen_dir_candidate: prism_a_gen_dir)

    with_tmpdir("triage-repro-") do |workdir|
      mock_wrap_c = File.join(workdir, "mock_wrap.c")
      mock_wrap_o = File.join(workdir, "mock_wrap.o")
      File.write(mock_wrap_c, <<~'C')
        #include <prism.h>
        #include <stddef.h>
        #include <stdint.h>
        #include <string.h>

        extern pm_node_t *__real_pm_parse(pm_parser_t *parser);
        extern pm_node_t *__real_pm_parse_stream(pm_parser_t **parser, pm_arena_t *arena, pm_source_t *source, const pm_options_t *options);
        extern size_t __real_pm_source_length(const pm_source_t *source);

        static int g_mock_spurious = 0;

        pm_node_t *__wrap_pm_parse(pm_parser_t *parser) {
            pm_node_t *node = __real_pm_parse(parser);
            const uint8_t *start = pm_parser_start(parser);
            const uint8_t *end = pm_parser_end(parser);
            if (node != NULL && start != NULL && end != NULL && end >= start &&
                (size_t) (end - start) >= 12 && memcmp(start, "MOCK_ZERO_ER", 12) == 0 &&
                PM_NODE_TYPE_P(node, PM_PROGRAM_NODE)) {
                pm_program_node_t *prog = (pm_program_node_t *) node;
                if (prog->statements != NULL && prog->statements->body.size > 0) {
                    static pm_error_recovery_node_t er = {
                        .base = { .type = PM_ERROR_RECOVERY_NODE, .location = { .start = 0, .length = 1 } },
                        .unexpected = NULL
                    };
                    prog->statements->body.nodes[0] = &er.base;
                }
            }
            return node;
        }

        pm_node_t *__wrap_pm_parse_stream(pm_parser_t **parser, pm_arena_t *arena, pm_source_t *source, const pm_options_t *options) {
            pm_node_t *node = __real_pm_parse_stream(parser, arena, source, options);
            g_mock_spurious = 0;
            if (parser != NULL && *parser != NULL) {
                const uint8_t *start = pm_parser_start(*parser);
                const uint8_t *end = pm_parser_end(*parser);
                if (start != NULL && end != NULL && end >= start &&
                    (size_t) (end - start) >= 18 && memcmp(start, "MOCK_SPURIOUS_STOP", 18) == 0) {
                    g_mock_spurious = 1;
                }
            }
            return node;
        }

        size_t __wrap_pm_source_length(const pm_source_t *source) {
            size_t len = __real_pm_source_length(source);
            if (g_mock_spurious && len > 1) return len - 1;
            return len;
        }
      C

      assert_cmd(
        c_compiler, "-O1", "-c", "-std=c99", "-fsanitize=address,undefined",
        "-I#{File.join(prism_a, 'include')}",
        mock_wrap_c, "-o", mock_wrap_o
      )

      driver_c = write_harness_driver(File.join(workdir, "harness_driver.c"))
      parse_slow_o = File.join(workdir, "harness_parse_slow.o")
      harness_slow = File.join(workdir, "harness_slow")

      assert_cmd(
        c_compiler, "-O1", "-std=c99", "-DSLOW", "-DPRISM_DEPTH_MAXIMUM=128",
        "-Wno-gnu-statement-expression-from-macro-expansion", "-Wno-switch",
        "-fsanitize=address,undefined",
        "-I#{File.join(prism_a, 'include')}",
        "-I#{artifacts[:gen_dir]}",
        "-c", repo_path("harnesses/prism/parse.c"),
        "-o", parse_slow_o
      )
      assert_cmd(
        c_compiler, "-O1", "-std=c99", "-fsanitize=address,undefined",
        "-Wl,--wrap=pm_parse", "-Wl,--wrap=pm_parse_stream", "-Wl,--wrap=pm_source_length",
        driver_c, parse_slow_o, mock_wrap_o, artifacts[:lib],
        "-o", harness_slow
      )

      ok_inputs = {
        "sd_nul.bin" => "\x40\x00\x03\x01\x00\n__END__\n ".b,
        "sd_ctrld.bin" => "\x40\x00\x03\x01\x04\n__END__\n ".b,
        "sd_ctrlz.bin" => "\x40\x00\x03\x01\x1a\n__END__\n ".b,
        "sd_end_cpool_ok.bin" => "\x40\x00\x03\x01foo_bar = :sym_const\n__END__\nextra_data_tail\n".b,
        "sd_unclosed_def_end_ok.bin" => "\x40\x00\x03\x01def foo\n__END__\nextra_data_tail\n".b,
        "sd_deep_spine_ok.bin" => ("\x40\x00\x03\x01e\n" + ("|" * 7168) + "\n").b,
        "mixed_enc_unicode_ok.bin" => "\x00\x00\x03\x01#encoding:ascii\n\"\\u{de}\"\n".b,
        "mixed_enc_unicode_vtab.bin" => "\x00\x00\x03\x01#encoding:ascii\n\"\\u{41\vde}\"\n".b,
        "mixed_enc_unicode_ff.bin" => "\x00\x00\x03\x01#encoding:ascii\n\"\\u{41\fde}\"\n".b,
        "mixed_enc_unicode_cr.bin" => "\x00\x00\x03\x01#encoding:ascii\n\"\\u{41\rde}\"\n".b,
        "rec_depth_alt_ok.bin" => "\x00\x00\x03\x01case 1; in ".b + (["a"] * 140).join("|").b + "; end\n".b,
        "er_lookahead_ok.bin" => "\x00\x00\x03\x01[,\n".b
      }
      ok_inputs.each do |name, bytes|
        path = File.join(workdir, name)
        File.binwrite(path, bytes)
        assert_cmd(harness_slow, path, msg: "expected #{name} not to trigger parse/stream_diff invariant")
      end

      sd_midline = File.join(workdir, "sd_midline.bin")
      zero_er_fail = File.join(workdir, "zero_er_fail.bin")
      File.binwrite(sd_midline, "\x40\x00\x03\x01MOCK_SPURIOUS_STOP   ".b)
      File.binwrite(zero_er_fail, "\x00\x00\x03\x01MOCK_ZERO_ER\n".b)

      _out, err, st = run_cmd(harness_slow, sd_midline)
      refute st.success?, "expected spurious_stop mock to abort"
      assert_includes err, "INVARIANT[stream_diff]: kind=spurious_stop"

      _out2, err2, st2 = run_cmd(harness_slow, zero_er_fail)
      refute st2.success?, "expected zero-error ErrorRecoveryNode mock to abort"
      assert_includes err2, "INVARIANT[error_recovery]: kind=zero_errors"
    end
  end

  def test_sub_location_fast_check_and_legacy_missing_field_fallback
    prism_a = require_prism_a!
    artifacts = self.class.prism_test_artifacts(prism_a, cc: c_compiler, root_dir: root_dir, gen_dir_candidate: prism_a_gen_dir)

    with_tmpdir("triage-repro-") do |workdir|
      sub_loc_c = File.join(workdir, "sub_loc_fast_test.c")
      sub_loc_bin = File.join(workdir, "sub_loc_fast_test")
      File.write(sub_loc_c, <<~'C')
        #include "parse.c"

        int main(void) {
            pm_call_node_t call = {
                .base = {
                    .type = PM_CALL_NODE,
                    .location = { .start = 0, .length = 10 },
                },
                .message_loc = { .start = 8, .length = 4294967292U },
            };
            fuzz_node_check_t ctx = {
                .source = (const uint8_t *) "<<H\n#{\"\"[e* =k&until",
                .parsed_size = 20,
                .parent_type = PM_STATEMENTS_NODE,
                .parser = NULL,
                .depth = 1,
            };
            fuzz_check_node_sub_locations(&call.base, &ctx);
            return 0;
        }
      C

      assert_cmd(
        c_compiler, "-O1", "-std=c99", "-DPRISM_DEPTH_MAXIMUM=128",
        "-Wno-gnu-statement-expression-from-macro-expansion", "-Wno-switch",
        "-fsanitize=address,undefined",
        "-I#{File.join(prism_a, 'include')}",
        "-I#{artifacts[:gen_dir]}",
        "-I#{repo_path('harnesses/prism')}",
        sub_loc_c, artifacts[:lib],
        "-o", sub_loc_bin
      )
      _out, err, st = run_cmd(sub_loc_bin)
      refute st.success?, "expected fast sub-location checker to abort on PM_CALL_NODE.message_loc length_underflow"
      assert_includes err, "INVARIANT[node_sub_location]: type=PM_CALL_NODE field=message_loc kind=length_underflow"

      # Verify historical header probe falls back cleanly to -DPRISM_FUZZ_NO_SUB_LOCATIONS when node_locations.inc references a field absent from ast.h.
      mock_fuzz_root = File.join(workdir, "mock_fuzz_root")
      FileUtils.mkdir_p(mock_fuzz_root)
      %w[harnesses triage runtime].each do |dir_name|
        FileUtils.cp_r(repo_path(dir_name), File.join(mock_fuzz_root, dir_name), preserve: true)
      end

      gen_rb = File.join(mock_fuzz_root, "harnesses/prism/gen_node_locations.rb")
      File.write(gen_rb, File.read(gen_rb) + <<~'RB')
        File.write(out_path, File.read(out_path) + <<~'C')
            case PM_CALL_NODE: {
                const pm_call_node_t *cast = (const pm_call_node_t *) node;
                fuzz_check_sub_location(node, "legacy_missing_loc", cast->legacy_missing_loc, ctx);
                break;
            }
        C
      RB

      verify_build_dir = File.join(workdir, "sub_loc_compat_verify_build")
      out, _err = assert_cmd(
        repo_path("triage/verify_bucket.sh"),
        "--repo-root", prism_a,
        "--fuzz-root", mock_fuzz_root,
        "--profile", "asan_ubsan",
        "--build-only",
        env: {
          "VERIFY_BUILD_DIR" => verify_build_dir,
          "FUZZ_BUILD_DIR" => File.join(workdir, "ws_build")
        }
      )
      legacy_runner = out.strip
      assert File.file?(legacy_runner) && File.executable?(legacy_runner),
             "expected verify_bucket.sh to compile cleanly with missing sub-location field via -DPRISM_FUZZ_NO_SUB_LOCATIONS, got #{legacy_runner.inspect}"
      assert_includes File.read(File.join(verify_build_dir, "node_locations.inc")), "legacy_missing_loc"
    end
  end

  def test_corpus_8k_makefile_run_and_fuzz_flags_macro_overrides
    with_tmpdir("triage-repro-") do |workdir|
      corpus_8k = File.join(workdir, "corpus_8k")
      assert_ruby_cmd(
        repo_path("runtime/corpus.rb"), "--no-minimize", corpus_8k,
        env: {
          "FUZZ_MAX_INPUT_SIZE" => "8192",
          "PRISM_A_DIR" => prism_a_dir,
          "CORPUS_FIXTURES_DIR" => nil
        }
      )
      long_seed = File.join(corpus_8k, "opt_stream_long_line.rb")
      assert_path_exists long_seed, "expected opt_stream_long_line.rb when FUZZ_MAX_INPUT_SIZE=8192"
      assert File.binread(long_seed).start_with?("\x40\x00\x03\x01".b)
      assert_path_exists File.join(corpus_8k, "opt_stream_fgets_split_end.rb")
      assert_equal 1028, File.size(File.join(corpus_8k, "opt_buffer_1024_boundary.rb"))
      assert_equal 2053, File.size(File.join(corpus_8k, "opt_arena_2049_boundary.rb"))

      # FUZZ_MAX_INPUT_SIZE=4096 accounts for the 4-byte option header (4096 payload + 4 header = 4100 B).
      corpus_4k = File.join(workdir, "corpus_4k")
      assert_ruby_cmd(
        repo_path("runtime/corpus.rb"), "--no-minimize", corpus_4k,
        env: { "FUZZ_MAX_INPUT_SIZE" => "4096", "PRISM_A_DIR" => prism_a_dir, "CORPUS_FIXTURES_DIR" => nil }
      )
      long_4k = File.join(corpus_4k, "opt_stream_long_line.rb")
      assert_path_exists long_4k
      assert_equal 4100, File.size(long_4k), "expected 4-byte header + 4096-byte fgets boundary payload"

      # FUZZ_MAX_INPUT_SIZE=256 splits multi-statement + heredoc fixtures along AST boundaries (<= 260 B wire)
      # and keeps multi-encoding seeds intact without mid-line truncation.
      mini_fix = File.join(workdir, "mini_fixtures")
      FileUtils.mkdir_p(mini_fix)
      heredoc_multi = ([
        "a = <<~EOF + 1\n  hello_heredoc\nEOF\n",
        "def alpha(x)\n  x * 2\nend\n",
        "class Beta\n  y = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]\nend\n"
      ] * 3).join("\n")
      assert_operator heredoc_multi.bytesize, :>, 256
      File.binwrite(File.join(mini_fix, "heredoc_multi.txt"), heredoc_multi)

      corpus_256 = File.join(workdir, "corpus_256")
      assert_ruby_cmd(
        repo_path("runtime/corpus.rb"), "--no-minimize", "--fixtures-dir", mini_fix, corpus_256,
        env: { "FUZZ_MAX_INPUT_SIZE" => "256" }
      )
      parts = Dir.glob(File.join(corpus_256, "heredoc_multi.txt.part*.rb")).sort
      require "prism"
      assert_operator parts.size, :>=, 2
      parts.each do |pt|
        raw = File.binread(pt)
        assert_operator raw.bytesize, :<=, 260, "expected <= 256 payload + 4 header on #{pt}"
        assert ::Prism.parse_success?(raw.byteslice(4..)), "expected AST-split chunk to stay valid Ruby: #{raw.byteslice(4..).inspect}"
      end
      utf8_seed = File.binread(File.join(corpus_256, "corpus_UTF-8.rb")).byteslice(4..)
      assert_includes utf8_seed, "puts [foo, bar, baz, qux]"
      assert ::Prism.parse_success?(utf8_seed)

      # Per-worker max_input_size + 4-byte header in AFL -G + compiled max_input_size ceiling:
      mixed_ws = File.join(workdir, "mixed_max_ws")
      mixed_camp = File.join(workdir, "mixed_max_campaign.rb")
      File.write(mixed_camp, <<~RB)
        PrismFuzzer.campaign "mixed-max-input" do
          workspace #{mixed_ws.inspect}
          defaults max_input_size: 256, max_allocated_mb: 128
          prism :prism_a, dir: #{(prism_a_dir || root_dir).inspect}, patches: "none", templates: "never"
          grammar_generator :grammar, source: :prism_a, fuzzer: "fuzz", sync_group: :afl
          fuzzer "fuzz", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
          fuzzer "fuzz.slow", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :slow, afl: :lto
          sync_group :afl, dir: "afl", primary: true
          worker :main, fuzzer: "fuzz", sync_group: :afl, afl_role: :main do
            foreign_sync :grammar
          end
          worker :grammar, kind: :generator, generator: :grammar
          worker :slow, fuzzer: "fuzz.slow", sync_group: :afl, afl_role: :secondary do
            max_input_size 4096
          end
        end
      RB
      mixed_ir, = PrismFuzzer::Topology.load_ir(mixed_camp, fuzz_root: root_dir)
      mixed_plan = PrismFuzzer::Topology.compile_plan(mixed_ir, fuzz_root: root_dir, build_dir: File.join(mixed_ws, "build"))
      assert_equal 4096, PrismFuzzer::Topology.effective_compiled_max_input_size(mixed_plan)
      lp = PrismFuzzer::Topology.plan_launch(mixed_plan, fuzz_root: root_dir)
      main_w = lp["workers"].find { |w| w["id"] == "main" }
      slow_w = lp["workers"].find { |w| w["id"] == "slow" }
      gram_w = lp["workers"].find { |w| w["id"] == "grammar" }
      main_inner = Shellwords.split(main_w["cmd"]).last
      slow_inner = Shellwords.split(slow_w["cmd"]).last
      assert_includes main_inner, "-G 260 "
      assert_includes slow_inner, "-G 4100 "
      assert_equal "256", gram_w.dig("env", "FUZZ_MAX_INPUT_SIZE")

      # Verify verify_bucket.sh auto-detects topology.json defaults.max_input_size and clamps up to
      # large (> 1024 B) bucket payloads when FUZZ_MAX_INPUT_SIZE is unset in ENV:
      if prism_a_dir && File.directory?(File.join(prism_a_dir, "src"))
        cc_log = File.join(workdir, "cc_args.log")
        fake_cc = File.join(workdir, "fake_cc.sh")
        File.write(fake_cc, <<~SH)
          #!/usr/bin/env bash
          printf '%s\\n' "$*" >> #{Shellwords.escape(cc_log)}
          for prev in "$@"; do
            if [ "${want_out:-0}" = "1" ]; then
              printf '#!/bin/sh\\nexit 0\\n' > "$prev"
              chmod +x "$prev"
              exit 0
            fi
            [ "$prev" = "-o" ] && want_out=1
          done
          exit 0
        SH
        File.chmod(0o755, fake_cc)

        big_bucket = File.join(workdir, "big_bucket")
        FileUtils.mkdir_p(big_bucket)
        File.binwrite(File.join(big_bucket, "input.min"), "\x00\x00\x03\x01".b + ("x" * 1500))
        assert_cmd(
          repo_path("triage/verify_bucket.sh"),
          "--repo-root", prism_a_dir,
          "--fuzz-root", root_dir,
          "--bucket-dir", big_bucket,
          "--profile", "asan_ubsan",
          "--build-only",
          env: {
            "CC" => fake_cc,
            "VERIFY_BUILD_DIR" => File.join(workdir, "big_vdir"),
            "FUZZ_BUILD_DIR" => File.join(workdir, "no_topo_build"),
            "FUZZ_MAX_INPUT_SIZE" => nil
          }
        )
        assert_includes File.read(cc_log), "-DFUZZ_MAX_INPUT_SIZE=1500"

        File.write(cc_log, "")
        topo_ws = File.join(workdir, "topo_auto_ws")
        FileUtils.mkdir_p(File.join(topo_ws, "build"))
        File.write(File.join(topo_ws, "topology.json"), JSON.generate({ "defaults" => { "max_input_size" => 16_384 } }))
        assert_cmd(
          repo_path("triage/verify_bucket.sh"),
          "--repo-root", prism_a_dir,
          "--fuzz-root", root_dir,
          "--bucket-dir", big_bucket,
          "--profile", "asan_ubsan",
          "--build-only",
          env: {
            "CC" => fake_cc,
            "VERIFY_BUILD_DIR" => File.join(workdir, "topo_vdir"),
            "FUZZ_BUILD_DIR" => File.join(topo_ws, "build"),
            "FUZZ_MAX_INPUT_SIZE" => nil
          }
        )
        assert_includes File.read(cc_log), "-DFUZZ_MAX_INPUT_SIZE=16384"
      end

      run_plan, = assert_cmd(
        "make", "-n", "IN_DOCKER=", "-o", "./build/.fuzz.docker.stamp",
        "run", "FUZZ_MAX_INPUT_SIZE=8192", "FUZZ_MAX_ALLOCATED=256",
        chdir: root_dir,
        env: UNMAKE_ENV
      )
      assert_includes run_plan, "FUZZ_MAX_INPUT_SIZE=8192 -e FUZZ_MAX_ALLOCATED=256",
                      "make run failed to forward raw FUZZ_MAX_INPUT_SIZE/FUZZ_MAX_ALLOCATED:\n#{run_plan}"

      # Also verify campaigns/default.rb define computation in-memory without touching $ROOT_DIR.
      default_ir, = PrismFuzzer::Topology.load_ir(repo_path("campaigns/default.rb"), fuzz_root: root_dir)
      default_plan = PrismFuzzer::Topology.compile_plan(default_ir, fuzz_root: root_dir, build_dir: File.join(workdir, "default_plan_build"))
      fuzz_flags = "-DFUZZ_MAX_INPUT_SIZE=8192 -D PRISM_DEPTH_MAXIMUM=64 -DFUZZ_MAX_ALLOCATED=256"
      with_env("FUZZ_FLAGS" => fuzz_flags) do
        defs_norm = normalize_define_tokens(PrismFuzzer::Topology.common_define_flags(default_plan))
        refute_includes defs_norm, "-DFUZZ_MAX_INPUT_SIZE=1024"
        refute_includes defs_norm, "-DPRISM_DEPTH_MAXIMUM=128"
        refute_includes defs_norm, "-DFUZZ_MAX_ALLOCATED=128"
        assert_includes defs_norm, "-DFUZZ_MAX_INPUT_SIZE=8192"
        assert_includes defs_norm, "-DPRISM_DEPTH_MAXIMUM=64"
        assert_includes defs_norm, "-DFUZZ_MAX_ALLOCATED=256"
      end

      prism_a = require_prism_a!
      artifacts = self.class.prism_test_artifacts(prism_a, cc: c_compiler, root_dir: root_dir, gen_dir_candidate: prism_a_gen_dir)

      # Verify bin/topology.rb build --dry-run in an isolated workspace dir (never writing to $ROOT_DIR).
      ws_dir = File.join(workdir, "override_ws")
      ws_build = File.join(ws_dir, "build")
      FileUtils.mkdir_p(ws_build)
      campaign_rb = File.join(workdir, "override_campaign.rb")
      File.write(campaign_rb, <<~RB)
        PrismFuzzer.campaign "fuzz-flags-override" do
          workspace #{ws_dir.inspect}
          defaults max_input_size: 1024, max_allocated_mb: 128
          prism :prism_a, dir: #{prism_a.inspect}, patches: "none", templates: "never"
          fuzzer "fuzz.slow", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :slow, afl: :lto
          sync_group :afl, dir: "afl", primary: true
          worker :slow, fuzzer: "fuzz.slow", sync_group: :afl, afl_role: :main
        end
      RB
      File.write(File.join(ws_build, "topology.resolved.json"), JSON.generate({
        "sources" => {
          "prism_a" => { "kind" => "prism", "path" => prism_a, "gen_dir" => artifacts[:gen_dir] }
        }
      }))

      dry_out, = assert_ruby_cmd(
        repo_path("bin/topology.rb"), "build", "--dry-run",
        "--topology", campaign_rb,
        "--build-dir", ws_build,
        env: CLEAN_TOPOLOGY_ENV.merge("FUZZ_FLAGS" => fuzz_flags)
      )
      override_cmd = dry_out.lines.find { |line| line.match?(%r{ -o \S*/fuzz\.slow }) }
      refute_nil override_cmd, "expected fuzz.slow dry-run command in:\n#{dry_out}"

      %w[-DFUZZ_MAX_INPUT_SIZE=1024 -DPRISM_DEPTH_MAXIMUM=128 -DFUZZ_MAX_ALLOCATED=128].each do |dup_def|
        refute_includes override_cmd, dup_def, "emitted duplicate default macro define #{dup_def} alongside FUZZ_FLAGS override: #{override_cmd}"
      end

      override_defs = normalize_define_tokens(Shellwords.split(override_cmd))
      assert_includes override_defs, "-DFUZZ_MAX_INPUT_SIZE=8192"
      assert_includes override_defs, "-DPRISM_DEPTH_MAXIMUM=64"
      assert_includes override_defs, "-DFUZZ_MAX_ALLOCATED=256"

      assert_cmd(
        c_compiler, "-c", "-O1", "-std=c99", "-Wall", "-Werror",
        *override_defs,
        "-I#{File.join(prism_a, 'include')}",
        "-I#{artifacts[:gen_dir]}",
        repo_path("harnesses/prism/parse.c"),
        "-o", File.join(workdir, "parse_override.o")
      )
    end
  end

  def test_ijon_allow_stream_fast_and_slow_dispatch
    prism_a = require_prism_a!
    artifacts = self.class.prism_test_artifacts(prism_a, cc: c_compiler, root_dir: root_dir, gen_dir_candidate: prism_a_gen_dir)

    with_tmpdir("triage-repro-") do |workdir|
      driver_c = File.join(workdir, "ijon_stream_driver.c")
      File.write(driver_c, <<~'C')
        #include <prism.h>
        #include <stdint.h>
        #include <stdio.h>
        #include <stdlib.h>

        extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
        extern pm_node_t *__real_pm_parse(pm_parser_t *parser);
        extern pm_node_t *__real_pm_parse_stream(pm_parser_t **parser, pm_arena_t *arena, pm_source_t *source, const pm_options_t *options);

        static int g_parse_calls = 0;
        static int g_stream_calls = 0;

        void ijon_set(uint32_t addr, uint32_t val) { (void) addr; (void) val; }
        void ijon_max(uint32_t addr, uint64_t val) { (void) addr; (void) val; }
        uint32_t ijon_hashstr(uint32_t old, const char *val) { (void) val; return old ^ 1u; }

        pm_node_t *__wrap_pm_parse(pm_parser_t *parser) {
            g_parse_calls++;
            return __real_pm_parse(parser);
        }

        pm_node_t *__wrap_pm_parse_stream(pm_parser_t **parser, pm_arena_t *arena, pm_source_t *source, const pm_options_t *options) {
            g_stream_calls++;
            return __real_pm_parse_stream(parser, arena, source, options);
        }

        int main(void) {
            static const uint8_t input[] = { 0x40, 0x00, 0x03, 0x01, '1', ' ', '+', ' ', '2', '\n' };
            LLVMFuzzerTestOneInput(input, sizeof(input));
            printf("parse=%d stream=%d\n", g_parse_calls, g_stream_calls);
            return 0;
        }
      C

      inc_flags = [
        "-I#{File.join(prism_a, 'include')}",
        "-I#{artifacts[:gen_dir]}",
        "-I#{repo_path('harnesses/prism')}",
        "-I#{repo_path('harnesses/prism/include')}"
      ]
      wrap_flags = ["-Wl,--wrap=pm_parse", "-Wl,--wrap=pm_parse_stream"]
      srcs = [driver_c, repo_path("harnesses/prism/parse.c"), repo_path("harnesses/prism/fuzz.c"), artifacts[:lib]]

      no_stream_bin = File.join(workdir, "ijon_no_stream")
      assert_cmd(
        c_compiler, *COMMON_HARNESS_FLAGS, *inc_flags,
        "-DPRISM_EXCLUDE_JSON", "-DPRISM_EXCLUDE_PRETTYPRINT", "-DPRISM_FUZZ_IJON",
        *srcs, *wrap_flags, "-o", no_stream_bin
      )
      out_off, = assert_cmd(no_stream_bin)
      assert_equal "parse=1 stream=0", out_off.strip

      stream_fast_bin = File.join(workdir, "ijon_stream_fast")
      assert_cmd(
        c_compiler, *COMMON_HARNESS_FLAGS, *inc_flags,
        "-Wall", "-Werror", "-DPRISM_EXCLUDE_JSON", "-DPRISM_EXCLUDE_PRETTYPRINT",
        "-DPRISM_FUZZ_IJON", "-DPRISM_FUZZ_ALLOW_STREAM_WITH_IJON",
        *srcs, *wrap_flags, "-o", stream_fast_bin
      )
      out_fast, = assert_cmd(stream_fast_bin)
      assert_equal "parse=0 stream=1", out_fast.strip

      stream_slow_bin = File.join(workdir, "ijon_stream_slow")
      assert_cmd(
        c_compiler, *COMMON_HARNESS_FLAGS, *inc_flags,
        "-Wall", "-Werror", "-DSLOW", "-DPRISM_EXCLUDE_JSON", "-DPRISM_EXCLUDE_PRETTYPRINT",
        "-DPRISM_FUZZ_IJON", "-DPRISM_FUZZ_ALLOW_STREAM_WITH_IJON",
        *srcs, *wrap_flags, "-o", stream_slow_bin
      )
      out_slow, = assert_cmd(stream_slow_bin)
      assert_equal "parse=1 stream=1", out_slow.strip
    end
  end

  def test_legacy_c_api_shim_probes_and_shared_invariants_parity
    prism_a = require_prism_a!
    artifacts = self.class.prism_test_artifacts(prism_a, cc: c_compiler, root_dir: root_dir, gen_dir_candidate: prism_a_gen_dir)

    with_tmpdir("triage-repro-") do |workdir|
      iter_stub_h = File.join(workdir, "iter_objs_stub.h")
      File.write(iter_stub_h, <<~'H')
        #include <prism.h>
        typedef struct pm_diagnostics_iter_t pm_diagnostics_iter_t;
        typedef struct pm_comments_iter_t pm_comments_iter_t;
        typedef struct pm_magic_comments_iter_t pm_magic_comments_iter_t;
        pm_diagnostics_iter_t *pm_parser_errors(const pm_parser_t *);
        const pm_diagnostic_t *pm_diagnostics_iter_next(pm_diagnostics_iter_t *);
        void pm_diagnostics_iter_free(pm_diagnostics_iter_t *);
        pm_diagnostics_iter_t *pm_parser_warnings(const pm_parser_t *);
        pm_comments_iter_t *pm_parser_comments(const pm_parser_t *);
        const pm_comment_t *pm_comments_iter_next(pm_comments_iter_t *);
        void pm_comments_iter_free(pm_comments_iter_t *);
        pm_magic_comments_iter_t *pm_parser_magic_comments(const pm_parser_t *);
        const pm_magic_comment_t *pm_magic_comments_iter_next(pm_magic_comments_iter_t *);
        void pm_magic_comments_iter_free(pm_magic_comments_iter_t *);
      H

      base_inc = ["-I#{File.join(prism_a, 'include')}", "-I#{artifacts[:gen_dir]}", "-I#{repo_path('harnesses/prism')}"]
      parse_c = repo_path("harnesses/prism/parse.c")

      assert_cmd(
        c_compiler, "-c", "-O1", "-std=c99", "-Wall", "-Werror",
        "-DPRISM_FUZZ_ITER_OBJS", "-include", iter_stub_h, *base_inc,
        parse_c, "-o", File.join(workdir, "parse_iter_objs.o")
      )
      assert_cmd(
        c_compiler, "-c", "-O1", "-std=c99", "-Wall", "-Werror",
        "-DPRISM_FUZZ_NO_VISIT_NODE", *base_inc,
        parse_c, "-o", File.join(workdir, "parse_no_visit.o")
      )
      assert_cmd(
        c_compiler, "-c", "-O1", "-std=c99", "-Wall", "-Werror",
        "-DPRISM_FUZZ_NO_NODE_RELATIONS", *base_inc,
        parse_c, "-o", File.join(workdir, "parse_no_rel.o")
      )

      ptr_loc_inc = File.join(workdir, "ptr_loc_inc")
      FileUtils.mkdir_p(ptr_loc_inc)
      File.write(File.join(ptr_loc_inc, "prism.h"), <<~'H')
        #include <stdbool.h>
        #include <stddef.h>
        #include <stdint.h>
        typedef struct pm_arena_t pm_arena_t;
        typedef struct { const uint8_t *source; size_t length; } pm_string_t;
        typedef struct pm_options_t pm_options_t;
        typedef struct pm_options_scope_t pm_options_scope_t;
        typedef void (*pm_options_shebang_callback_t)(pm_options_t *, const uint8_t *, size_t, void *);
        #define PM_OPTIONS_COMMAND_LINE_X 0x20
        #define PM_OPTIONS_SCOPE_FORWARDING_NONE 0x0
        typedef struct { const uint8_t *start; const uint8_t *end; } pm_location_t;
        typedef uint16_t pm_node_type_t;
        typedef struct { pm_node_type_t type; pm_location_t location; } pm_node_t;
        typedef struct { pm_node_t base; pm_location_t opening_loc; pm_location_t closing_loc; } pm_string_node_t;
        typedef pm_string_node_t pm_interpolated_string_node_t;
        typedef pm_string_node_t pm_x_string_node_t;
        typedef pm_string_node_t pm_interpolated_x_string_node_t;
        typedef struct { pm_node_t base; pm_location_t opening_loc; } pm_array_node_t;
        enum {
            PM_STRING_NODE = 1, PM_INTERPOLATED_STRING_NODE, PM_X_STRING_NODE, PM_INTERPOLATED_X_STRING_NODE,
            PM_SYMBOL_NODE, PM_INTERPOLATED_SYMBOL_NODE, PM_REGULAR_EXPRESSION_NODE, PM_INTERPOLATED_REGULAR_EXPRESSION_NODE,
            PM_MATCH_LAST_LINE_NODE, PM_INTERPOLATED_MATCH_LAST_LINE_NODE, PM_ARRAY_NODE
        };
        #define PM_NODE_TYPE(n) ((n)->type)
        #define PM_COMMENT_EMBDOC 1
        typedef struct { size_t size; size_t capacity; uint32_t *offsets; } pm_line_offset_list_t;
        typedef struct pm_parser_t pm_parser_t;
        typedef struct pm_diagnostic_t pm_diagnostic_t;
        typedef struct pm_comment_t pm_comment_t;
        typedef struct pm_magic_comment_t pm_magic_comment_t;
        typedef struct pm_source_t pm_source_t;
        typedef char *(pm_source_stream_fgets_t)(char *, int, void *);
        typedef int (pm_source_stream_feof_t)(void *);
        typedef enum { PM_VISIT_DESCEND = 0, PM_VISIT_SKIP = 1 } pm_visit_result_t;
        pm_arena_t *pm_arena_new(void);
        void pm_arena_free(pm_arena_t *);
        void pm_string_init(pm_string_t *, const uint8_t *, size_t);
        pm_options_t *pm_options_new(void);
        void pm_options_free(pm_options_t *);
        void pm_options_line_set(pm_options_t *, int32_t);
        void pm_options_command_line_set(pm_options_t *, uint8_t);
        void pm_options_main_script_set(pm_options_t *, bool);
        void pm_options_freeze_set(pm_options_t *, bool);
        void pm_options_partial_script_set(pm_options_t *, bool);
        void pm_options_attach_comments_set(pm_options_t *, bool);
        void pm_options_encoding_locked_set(pm_options_t *, bool);
        bool pm_options_version_set(pm_options_t *, const char *, size_t);
        void pm_options_frozen_string_literal_set(pm_options_t *, bool);
        void pm_options_encoding_set(pm_options_t *, const char *);
        void pm_options_filepath_set(pm_options_t *, const char *);
        void pm_options_shebang_callback_set(pm_options_t *, pm_options_shebang_callback_t, void *);
        void pm_options_stack_budget_set(pm_options_t *, size_t);
        bool pm_options_scopes_init(pm_options_t *, size_t);
        pm_options_scope_t *pm_options_scope_mut(pm_options_t *, size_t);
        void pm_options_scope_init(pm_options_scope_t *, size_t);
        void pm_options_scope_forwarding_set(pm_options_scope_t *, uint8_t);
        pm_string_t *pm_options_scope_local_mut(pm_options_scope_t *, size_t);
        pm_source_t *pm_source_stream_new(void *, pm_source_stream_fgets_t *, pm_source_stream_feof_t *);
        size_t pm_source_length(const pm_source_t *);
        void pm_source_free(pm_source_t *);
        pm_node_t *pm_parse_stream(pm_parser_t **, pm_arena_t *, pm_source_t *, const pm_options_t *);
        pm_parser_t *pm_parser_new(pm_arena_t *, const uint8_t *, size_t, const pm_options_t *);
        void pm_parser_free(pm_parser_t *);
        pm_node_t *pm_parse(pm_parser_t *);
        const pm_line_offset_list_t *pm_parser_line_offsets(const pm_parser_t *);
        const pm_location_t *pm_parser_data_loc(const pm_parser_t *);
        size_t pm_parser_errors_size(const pm_parser_t *);
        const pm_diagnostic_t *pm_parser_errors_first(const pm_parser_t *);
        const pm_diagnostic_t *pm_parser_warnings_first(const pm_parser_t *);
        const pm_diagnostic_t *pm_diagnostic_next(const pm_diagnostic_t *);
        pm_location_t pm_diagnostic_location(const pm_diagnostic_t *);
        const char *pm_diagnostic_type(const pm_diagnostic_t *);
        unsigned pm_diagnostic_error_level(const pm_diagnostic_t *);
        unsigned pm_diagnostic_warning_level(const pm_diagnostic_t *);
        const pm_comment_t *pm_parser_comments_first(const pm_parser_t *);
        const pm_comment_t *pm_comment_next(const pm_comment_t *);
        pm_location_t pm_comment_location(const pm_comment_t *);
        int pm_comment_type(const pm_comment_t *);
        const pm_magic_comment_t *pm_parser_magic_comments_first(const pm_parser_t *);
        const pm_magic_comment_t *pm_magic_comment_next(const pm_magic_comment_t *);
        pm_location_t pm_magic_comment_key(const pm_magic_comment_t *);
        pm_location_t pm_magic_comment_value(const pm_magic_comment_t *);
        void pm_visit_node(const pm_node_t *, pm_visit_result_t (*)(const pm_node_t *, void *), void *);
        void pm_visit_child_nodes(const pm_node_t *, pm_visit_result_t (*)(const pm_node_t *, void *), void *);
        const char *pm_node_type(pm_node_type_t);
      H

      ptr_loc_gen = File.join(workdir, "ptr_loc_gen")
      assert_ruby_cmd(
        repo_path("harnesses/prism/gen_api_compat.rb"),
        "--include-dir", ptr_loc_inc,
        "--output", File.join(ptr_loc_gen, "prism_fuzz_compat.h")
      )
      compat_text = File.read(File.join(ptr_loc_gen, "prism_fuzz_compat.h"))
      assert_includes compat_text, "#define PRISM_FUZZ_POINTER_LOCATIONS 1"
      assert_includes compat_text, "#define PRISM_FUZZ_LEGACY_ENCODING_SET_2ARG 1"
      assert_includes compat_text, "#define PRISM_FUZZ_LEGACY_FILEPATH_SET_2ARG 1"

      assert_cmd(
        c_compiler, "-c", "-O1", "-std=c99", "-Wall", "-Werror",
        "-DPRISM_FUZZ_NO_PARSER_ERRORS_SIZE",
        "-I#{ptr_loc_inc}", "-I#{ptr_loc_gen}", "-I#{repo_path('harnesses/prism')}",
        parse_c, "-o", File.join(workdir, "parse_ptr_locs.o")
      )

      modern_inc = File.join(workdir, "modern_3arg_inc")
      modern_gen = File.join(workdir, "modern_3arg_gen")
      FileUtils.mkdir_p(modern_inc)
      File.write(
        File.join(modern_inc, "prism.h"),
        File.read(File.join(ptr_loc_inc, "prism.h"))
          .sub("void pm_options_encoding_set(pm_options_t *, const char *);", "void pm_options_encoding_set(pm_options_t *, const char *, size_t);")
          .sub("void pm_options_filepath_set(pm_options_t *, const char *);", "void pm_options_filepath_set(pm_options_t *, const char *, size_t);")
      )
      assert_ruby_cmd(
        repo_path("harnesses/prism/gen_api_compat.rb"),
        "--include-dir", modern_inc,
        "--output", File.join(modern_gen, "prism_fuzz_compat.h")
      )
      modern_compat = File.read(File.join(modern_gen, "prism_fuzz_compat.h"))
      refute_includes modern_compat, "PRISM_FUZZ_LEGACY_ENCODING_SET_2ARG"
      refute_includes modern_compat, "PRISM_FUZZ_LEGACY_FILEPATH_SET_2ARG"
      assert_cmd(
        c_compiler, "-c", "-O1", "-std=c99", "-Wall", "-Werror",
        "-I#{modern_inc}", "-I#{modern_gen}", "-I#{repo_path('harnesses/prism')}",
        parse_c, "-o", File.join(workdir, "parse_modern_3arg.o")
      )

      iter_runtime_c = File.join(workdir, "iter_objs_runtime.c")
      File.write(iter_runtime_c, <<~'C')
        #include <stdlib.h>

        struct pm_diagnostics_iter_t { const pm_diagnostic_t *cur; };
        struct pm_comments_iter_t { const pm_comment_t *cur; };
        struct pm_magic_comments_iter_t { const pm_magic_comment_t *cur; };

        pm_diagnostics_iter_t *pm_parser_errors(const pm_parser_t *p) {
            pm_diagnostics_iter_t *it = malloc(sizeof(*it));
            it->cur = pm_parser_errors_first(p);
            return it;
        }
        pm_diagnostics_iter_t *pm_parser_warnings(const pm_parser_t *p) {
            pm_diagnostics_iter_t *it = malloc(sizeof(*it));
            it->cur = pm_parser_warnings_first(p);
            return it;
        }
        const pm_diagnostic_t *pm_diagnostics_iter_next(pm_diagnostics_iter_t *it) {
            const pm_diagnostic_t *d = it->cur;
            if (d != NULL) it->cur = pm_diagnostic_next(d);
            return d;
        }
        void pm_diagnostics_iter_free(pm_diagnostics_iter_t *it) { free(it); }

        pm_comments_iter_t *pm_parser_comments(const pm_parser_t *p) {
            pm_comments_iter_t *it = malloc(sizeof(*it));
            it->cur = pm_parser_comments_first(p);
            return it;
        }
        const pm_comment_t *pm_comments_iter_next(pm_comments_iter_t *it) {
            const pm_comment_t *c = it->cur;
            if (c != NULL) it->cur = pm_comment_next(c);
            return c;
        }
        void pm_comments_iter_free(pm_comments_iter_t *it) { free(it); }

        pm_magic_comments_iter_t *pm_parser_magic_comments(const pm_parser_t *p) {
            pm_magic_comments_iter_t *it = malloc(sizeof(*it));
            it->cur = pm_parser_magic_comments_first(p);
            return it;
        }
        const pm_magic_comment_t *pm_magic_comments_iter_next(pm_magic_comments_iter_t *it) {
            const pm_magic_comment_t *mc = it->cur;
            if (mc != NULL) it->cur = pm_magic_comment_next(mc);
            return mc;
        }
        void pm_magic_comments_iter_free(pm_magic_comments_iter_t *it) { free(it); }
      C

      driver_c = write_harness_driver(File.join(workdir, "harness_driver.c"))
      iter_bin = File.join(workdir, "harness_iter_objs")
      assert_cmd(
        c_compiler, "-O1", "-std=c99", "-Wall", "-Werror", "-fsanitize=address,undefined",
        "-DPRISM_FUZZ_ITER_OBJS", "-include", iter_stub_h, *base_inc,
        driver_c, parse_c, iter_runtime_c, artifacts[:lib],
        "-o", iter_bin
      )

      {
        "mixed_enc_unicode_ok.bin" => "\x00\x00\x03\x01#encoding:ascii\n\"\\u{de}\"\n".b,
        "mixed_enc_unicode_vtab.bin" => "\x00\x00\x03\x01#encoding:ascii\n\"\\u{41\vde}\"\n".b,
        "mixed_enc_unicode_ff.bin" => "\x00\x00\x03\x01#encoding:ascii\n\"\\u{41\fde}\"\n".b,
        "mixed_enc_unicode_cr.bin" => "\x00\x00\x03\x01#encoding:ascii\n\"\\u{41\rde}\"\n".b
      }.each do |name, bytes|
        path = File.join(workdir, name)
        File.binwrite(path, bytes)
        assert_cmd(iter_bin, path, msg: "expected PRISM_FUZZ_ITER_OBJS parse.c to pass #{name}")
      end

      parity_c = File.join(workdir, "invariants_parity_test.c")
      parity_bin = File.join(workdir, "invariants_parity_test")
      File.write(parity_c, <<~'C')
        #include <assert.h>
        #include <prism.h>
        #include <string.h>
        #define PRISM_FUZZ_NO_STREAM 1
        #include "include/fuzz_invariants.h"
        #include "include/fuzz_options.h"

        int main(void) {
            static const char ws_chars[] = { ' ', '\t', '\v', '\f', '\r' };
            for (size_t i = 0; i < sizeof(ws_chars); i++) {
                char buf[32];
                buf[0] = '\\'; buf[1] = 'u'; buf[2] = '{';
                buf[3] = '4'; buf[4] = '1'; buf[5] = ws_chars[i];
                buf[6] = 'd'; buf[7] = 'e'; buf[8] = '}';
                assert(fuzz_is_unicode_escape_mixed_encoding_span((const uint8_t *) buf, 6, 2));
            }

            assert(strcmp(fuzz_span_violation_kind(8U, 4294967292U, 20U, false), "length_underflow") == 0);
            assert(strcmp(fuzz_span_violation_kind(8U, 4294967292U, 20U, true), "length_underflow") == 0);
            assert(strcmp(fuzz_span_violation_kind(0x80000000U, 0x80000000U, (size_t) 0x90000000ULL, false), "length_underflow") == 0);
            assert(strcmp(fuzz_span_violation_kind(0x80000000U, 0x80000000U, (size_t) 0x90000000ULL, true), "end_overflow") == 0);
            assert(strcmp(fuzz_span_violation_kind(0x80000000U, 4U, 20U, false), "start_underflow") == 0);
            assert(strcmp(fuzz_span_violation_kind(25U, 1U, 20U, true), "start_oob") == 0);
            assert(strcmp(fuzz_span_violation_kind(15U, 10U, 20U, true), "end_oob") == 0);
            assert(fuzz_span_violation_kind(10U, 10U, 20U, false) == NULL);

            assert(strcmp(fuzz_option_encoding_name(0x01), "ASCII-8BIT") == 0);
            assert(fuzz_option_extreme_line(0x00) == INT32_MAX);
            assert(strcmp(fuzz_option_stack_budget_name(0x80), "512") == 0);
            const uint8_t hdr[4] = { 0x80, 0x80, 0x0c, 0x80 };
            fuzz_options_t opts;
            fuzz_options_decode(hdr, &opts);
            assert(fuzz_option_forwarding_scope(&opts) == 2U);
            return 0;
        }
      C

      assert_cmd(
        c_compiler, "-O1", "-std=c99", "-Wall", "-Werror", "-Wextra", "-Wpedantic", "-Wundef", "-Wconversion",
        "-fsanitize=address,undefined",
        *base_inc, parity_c, "-o", parity_bin
      )
      assert_cmd(parity_bin)
    end
  end

  private

  def require_prism_a!
    pa = prism_a_dir
    skip "missing Prism A target (run 'make targets-sync' first)" unless pa && File.directory?(File.join(pa, "src"))
    pa
  end

  def c_compiler
    cc = ENV.fetch("CC", "").strip
    cc.empty? ? "clang" : cc
  end

  def normalize_define_tokens(tokens)
    out = []
    i = 0
    while i < tokens.length
      t = tokens[i]
      if t == "-D" && i + 1 < tokens.length
        out << "-D#{tokens[i + 1]}"
        i += 2
      elsif t.start_with?("-D")
        out << t
        i += 1
      else
        i += 1
      end
    end
    out
  end

  def write_harness_driver(path)
    File.write(path, <<~'C')
      #include <stdint.h>
      #include <stdio.h>
      #include <stdlib.h>

      extern void harness(const uint8_t *input, size_t size);

      int main(int argc, char **argv) {
          if (argc != 2) return 2;
          FILE *f = fopen(argv[1], "rb");
          if (!f) return 2;
          if (fseek(f, 0, SEEK_END) != 0) {
              fclose(f);
              return 2;
          }
          long len = ftell(f);
          if (len < 0 || fseek(f, 0, SEEK_SET) != 0) {
              fclose(f);
              return 2;
          }
          uint8_t *buf = len > 0 ? malloc((size_t) len) : NULL;
          if (len > 0 && (!buf || fread(buf, 1, (size_t) len, f) != (size_t) len)) {
              free(buf);
              fclose(f);
              return 2;
          }
          fclose(f);
          harness(buf, (size_t) len);
          free(buf);
          return 0;
      }
    C
    path
  end
end
