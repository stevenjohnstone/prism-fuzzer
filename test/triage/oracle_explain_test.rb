# frozen_string_literal: true

require_relative "../lib/autorun"

require "fileutils"
require "json"
require "rubygems/package"
require "zlib"

require_relative "../../runtime/provenance"
require_relative "../../triage/match"
require_relative "../../triage/retriage"
require_relative "../../triage/verify"

# Isolated tests for 32-bit vs 64-bit cross-oracle (arm32/ppc) triage,
# clustering, provenance, verify_bucket.sh, explain.c diagnostics/JSON/UTF-8,
# and mutator_oracle64.c allocation/stream NULL-return checks.
class TriageOracleExplainTest < Minitest::Test
  CROSS_SPECS = [
    {
      kind: "arm32",
      qemu: "/usr/bin/qemu-arm",
      sysroot: "/usr/arm-linux-gnueabihf",
      profile: "arm32_oracle",
      namespace: "oracle_arm32",
      len_key: "arm32_len",
      gcc: "arm-linux-gnueabihf-gcc",
      extra_build: []
    },
    {
      kind: "ppc",
      qemu: "/usr/bin/qemu-ppc",
      sysroot: "/usr/powerpc-linux-gnu",
      profile: "ppc_oracle",
      namespace: "oracle_ppc",
      len_key: "ppc_len",
      gcc: "powerpc-linux-gnu-gcc",
      extra_build: %w[-msecure-plt -latomic]
    }
  ].freeze

  CLEAN_TRIAGE_ENV = {
    "FUZZ_DIR" => nil,
    "FUZZ_BUILD_DIR" => nil,
    "TRIAGE_DIR" => nil,
    "TRIAGE_OUTPUT_DIRS" => nil,
    "TRIAGE_COVERAGE_BIN" => nil,
    "TRIAGE_COVERAGE_IDS" => nil,
    "TRIAGE_DIFF_COVERAGE_BIN" => nil,
    "TRIAGE_DIFF_COVERAGE_IDS" => nil,
    "TRIAGE_CORPUS_DIR" => nil,
    "TRIAGE_RECOUNT" => nil,
    "TRIAGE_MINIMIZE" => nil,
    "TRIAGE_THREADS" => nil,
    "HALFEMPTY_THREADS" => nil,
    "TRIAGE_EXPLAIN_BIN" => nil,
    "TRIAGE_DIGEST" => nil,
    "AFL_SHOWMAP" => nil
  }.freeze

  def test_provenance_clustering_and_cross_oracle_triage
    %w[fuzz.arm32 fuzz.arm32.repro fuzz.ppc fuzz.ppc.repro].each do |bin|
      assert_includes FuzzProvenance::BINARIES, bin
    end
    assert_includes FuzzProvenance::AUX_FILES, "mutator_oracle64.so"
    assert_includes FuzzProvenance::AUX_FILES, "fuzz.explain"
    assert_includes FuzzClustering::BOILERPLATE_FUNCTIONS, "fuzz_oracle32_fail"

    with_tmpdir("oracle-triage-") do |workdir|
      with_env(CLEAN_TRIAGE_ENV) do
        Dir.chdir(root_dir) do
          CROSS_SPECS.each do |spec|
            verify_cross_oracle_spec(workdir, spec)
          end
        end
      end
    end
  end

  def test_cross_verify_bucket_arm32_oracle
    verify_cross_oracle_bucket(CROSS_SPECS.fetch(0))
  end

  def test_cross_verify_bucket_ppc_oracle
    verify_cross_oracle_bucket(CROSS_SPECS.fetch(1))
  end

  def test_explain_c_diagnostics_stream_compare_and_json_utf8
    prism_a = require_prism_a!

    with_tmpdir("oracle-explain-") do |workdir|
      gen_dir = ensure_node_locations_inc(prism_a, workdir)
      explain_bin = compile_explain_asan_bin(prism_a, gen_dir, workdir)

      explain_raw = File.join(workdir, "explain_raw.bin")
      File.binwrite(explain_raw, "\x40\x08\x03\x01puts 1\n".b)
      explain_out, = assert_cmd(explain_bin, "--compare-stream", "--serialize", explain_raw)
      assert_includes explain_out, "header:      40080301"
      assert_includes explain_out, "stream_mode=true"
      assert_includes explain_out, "cmd=-n"
      assert_match(/serialize:.*bytes/, explain_out)
      assert_includes explain_out, "serialize:   EQUAL"

      explain_warn, = assert_cmd(explain_bin, "-e", "if /a/; end", "--no-ast")
      assert_includes explain_warn, "warnings:"

      explain_json, = assert_cmd(explain_bin, "--snippet", "--json", "--no-ast", "-", input: "1 + 2\n")
      assert_includes explain_json, '"ProgramNode"'

      explain_clean, = assert_cmd(explain_bin, "-e", "<<~A + 1\n  \#{1 + 2}\nA")
      refute_match(/^anomalies:|<-- \[!/, explain_clean)

      %w[0b 0c 0d].each do |ws_hex|
        ws_payload = "#encoding:ascii\n\"\\u{41".b + [ws_hex].pack("H*") + "de}\"\n".b
        ws_digest, = assert_cmd(explain_bin, "--snippet", "--digest", "-", input: ws_payload)
        parsed = JSON.parse(utf8_string(ws_digest))
        assert_equal 0, parsed["anomaly_count"], "expected anomaly_count=0 for ws=0x#{ws_hex}: #{parsed.inspect}"
      end

      underflow_snippet = "<<C<\n\#{y=>{ "
      explain_underflow, = assert_cmd(explain_bin, "-e", underflow_snippet)
      assert_includes explain_underflow, "node_location: kind=length_underflow"
      assert_match(/@ EmbeddedStatementsNode .*<-- \[! length_underflow:/, explain_underflow)
      assert_match(/\+-- closing_loc: .*<-- \[! closing_before_opening:/, explain_underflow)

      explain_raw_ast, = assert_cmd(explain_bin, "--no-anomalies", "-e", underflow_snippet)
      refute_match(/^anomalies:|<-- \[!/, explain_raw_ast)

      explain_overlap, = assert_cmd(explain_bin, "-e", "<<e\"\n\#{<<B B\n\#{y=>{ ")
      assert_match(/@ StringNode .*<-- \[! .*sibling_overlap:/, explain_overlap)
      assert_match(/@ ConstantReadNode .*<-- \[! sibling_out_of_order:/, explain_overlap)

      explain_subloc_oob, = assert_cmd(explain_bin, "-e", "<<C-\n\#{[?[[O{<<y=>{\n\#{{3}s")
      assert_includes explain_subloc_oob, "safe fallback: skipped pm_prettyprint"
      assert_match(/sub_location: kind=length_underflow PM_CALL_NODE\.message_loc/, explain_subloc_oob)

      digest_stream_out, = assert_cmd(explain_bin, "--digest", "--compare-stream", "--serialize", explain_raw)
      digest_clean_out, = assert_cmd(explain_bin, "--digest", "-e", "puts 1")
      digest_anom_out, = assert_cmd(explain_bin, "--digest", "-e", underflow_snippet)

      ds = JSON.parse(utf8_string(digest_stream_out))
      dc = JSON.parse(utf8_string(digest_clean_out))
      da = JSON.parse(utf8_string(digest_anom_out))
      assert_equal true, ds["stream_mode"]
      assert_equal 7, ds["parsed_size"]
      assert_equal true, ds.dig("stream_compare", "serialize_equal")
      assert_equal 6, dc["parsed_size"]
      assert_equal 0, dc["anomaly_count"]
      kinds = Array(da["anomalies"]).map { |a| a["kind"] }
      assert_operator da["anomaly_count"], :>=, 2
      assert_includes kinds, "length_underflow"
      assert_includes kinds, "closing_before_opening"

      explain_end_out, = assert_cmd(explain_bin, "--digest", "-e", "1 + 2\n__END__\nextra_trailing_text")
      dend = JSON.parse(utf8_string(explain_end_out))
      assert_operator dend["parsed_size"], :>, 0
      assert_operator dend["parsed_size"], :<, 34

      utf8_src = File.join(workdir, "café_😀.rb")
      File.write(utf8_src, "1 + 2\n")
      explain_utf8_out, = assert_cmd(explain_bin, "--digest", "--snippet", utf8_src)
      du = JSON.parse(utf8_string(explain_utf8_out))
      assert du["label"].end_with?("/café_😀.rb"), "expected UTF-8 label in JSON digest: #{du.inspect}"

      verify_fuzz_json_and_runner_utf8(workdir)
    end
  end

  def test_mutator_oracle64_null_checks
    skip "GNU ld --wrap requires Linux" unless linux?
    prism_a = require_prism_a!

    with_tmpdir("oracle64-null-") do |workdir|
      gen_dir = ensure_node_locations_inc(prism_a, workdir)
      test_c = File.join(workdir, "oracle64_null_test.c")
      File.write(test_c, <<~'C')
        #include <prism.h>
        #include <assert.h>
        #include <stdint.h>
        #include <stdio.h>
        #include <stdlib.h>

        extern void *afl_custom_init(void *afl, unsigned int seed);
        extern size_t afl_custom_post_process(void *data, unsigned char *buf, size_t buf_size, unsigned char **out_buf);
        extern void afl_custom_deinit(void *data);

        extern pm_options_t *__real_pm_options_new(void);
        extern pm_arena_t *__real_pm_arena_new(void);
        extern pm_source_t *__real_pm_source_stream_new(void *stream, void *fgets_fn, void *feof_fn);
        extern pm_parser_t *__real_pm_parser_new(pm_arena_t *arena, const uint8_t *source, size_t size, const pm_options_t *options);

        static int fail_mode = 0;

        pm_options_t *__wrap_pm_options_new(void) {
            return fail_mode == 1 ? NULL : __real_pm_options_new();
        }

        pm_arena_t *__wrap_pm_arena_new(void) {
            return fail_mode == 2 ? NULL : __real_pm_arena_new();
        }

        pm_source_t *__wrap_pm_source_stream_new(void *stream, void *fgets_fn, void *feof_fn) {
            return fail_mode == 3 ? NULL : __real_pm_source_stream_new(stream, fgets_fn, feof_fn);
        }

        pm_parser_t *__wrap_pm_parser_new(pm_arena_t *arena, const uint8_t *source, size_t size, const pm_options_t *options) {
            return fail_mode == 4 ? NULL : __real_pm_parser_new(arena, source, size, options);
        }

        int main(void) {
            void *st = afl_custom_init(NULL, 0);
            assert(st != NULL);
            unsigned char buf_input[] = { 0x00, 0x00, 0x03, 0x01, '1', '+', '2', '\n' };
            unsigned char strm_input[] = { 0x40, 0x00, 0x03, 0x01, '1', '+', '2', '\n' };
            unsigned char *out = NULL;

            fail_mode = 1;
            assert(afl_custom_post_process(st, buf_input, sizeof(buf_input), &out) == 0 && out == NULL);
            fail_mode = 2;
            assert(afl_custom_post_process(st, buf_input, sizeof(buf_input), &out) == 0 && out == NULL);
            fail_mode = 3;
            assert(afl_custom_post_process(st, strm_input, sizeof(strm_input), &out) == 0 && out == NULL);
            fail_mode = 4;
            assert(afl_custom_post_process(st, buf_input, sizeof(buf_input), &out) == 0 && out == NULL);

            fail_mode = 0;
            assert(afl_custom_post_process(st, buf_input, sizeof(buf_input), &out) > 0 && out != NULL);
            assert(afl_custom_post_process(st, strm_input, sizeof(strm_input), &out) > 0 && out != NULL);
            afl_custom_deinit(st);
            printf("ORACLE64_NULL_CHECKS_OK\n");
            return 0;
        }
      C

      objs_dir = File.join(workdir, "oracle64_prism_objs")
      FileUtils.mkdir_p(objs_dir)
      prism_srcs = Dir.glob(File.join(prism_a, "src", "**", "*.c")).sort
      refute_empty prism_srcs, "missing Prism C sources under #{prism_a}/src"

      assert_cmd(
        c_compiler, "-O1", "-std=c99", "-fsanitize=address,undefined",
        "-I#{File.join(prism_a, 'include')}",
        "-I#{File.join(prism_a, 'src')}",
        *prism_srcs, "-c",
        chdir: objs_dir
      )

      lib_path = File.join(workdir, "libprism_oracle64_test.a")
      objs = Dir.glob(File.join(objs_dir, "*.o")).sort
      assert_cmd("ar", "rcs", lib_path, *objs)

      bin_path = File.join(workdir, "oracle64_null_test")
      assert_cmd(
        c_compiler, "-O1", "-std=c99", "-fsanitize=address,undefined",
        "-Wno-gnu-statement-expression-from-macro-expansion", "-Wno-switch",
        "-I#{File.join(prism_a, 'include')}",
        "-I#{gen_dir}",
        "-I#{repo_path('harnesses/prism')}",
        "-I#{repo_path('harnesses/prism/include')}",
        "-DPRISM_EXCLUDE_JSON", "-DPRISM_EXCLUDE_PRETTYPRINT", "-DFUZZ_MAX_INPUT_SIZE=1024",
        test_c, repo_path("harnesses/prism/mutator_oracle64.c"), lib_path,
        "-Wl,--wrap=pm_options_new",
        "-Wl,--wrap=pm_arena_new",
        "-Wl,--wrap=pm_source_stream_new",
        "-Wl,--wrap=pm_parser_new",
        "-o", bin_path
      )

      o64_out, = assert_cmd(bin_path)
      assert_equal "ORACLE64_NULL_CHECKS_OK", o64_out.strip
    end
  end

  private

  def c_compiler
    cc = ENV.fetch("CC", "").strip
    cc.empty? ? "clang" : cc
  end

  def require_prism_a!
    pa = prism_a_dir
    skip "missing Prism A target (run 'make targets-sync' first)" unless pa && File.directory?(File.join(pa, "src"))
    pa
  end

  def utf8_string(text)
    text.dup.force_encoding(Encoding::UTF_8)
  end

  def ensure_node_locations_inc(prism_a, workdir)
    cand = prism_a_gen_dir
    return cand if cand && File.file?(File.join(cand, "node_locations.inc"))

    local_gen = File.join(workdir, "gen")
    FileUtils.mkdir_p(local_gen)
    assert_ruby_cmd(
      repo_path("harnesses/prism/gen_node_locations.rb"),
      File.join(prism_a, "config.yml"),
      File.join(local_gen, "node_locations.inc")
    )
    local_gen
  end

  def compile_explain_asan_bin(prism_a, gen_dir, workdir)
    explain_bin = File.join(workdir, "fuzz.explain")
    prism_srcs = Dir.glob(File.join(prism_a, "src", "**", "*.c")).sort
    explain_sub_srcs = Dir.glob(repo_path("harnesses/prism/explain/*.c")).sort
    refute_empty prism_srcs, "missing Prism C sources under #{prism_a}/src"
    refute_empty explain_sub_srcs, "missing explain/*.c sources"

    assert_cmd(
      c_compiler, "-O1", "-std=c99",
      "-Wall", "-Werror", "-Wextra", "-Wpedantic", "-Wundef", "-Wconversion", "-Wno-missing-braces",
      "-fsanitize=address,undefined",
      "-I#{File.join(prism_a, 'include')}",
      "-I#{gen_dir}",
      "-I#{repo_path('harnesses/prism')}",
      "-DPRISM_DEPTH_MAXIMUM=128",
      "-DPM_INTEGER_DIVIDE_THRESHOLD=8",
      *prism_srcs,
      repo_path("harnesses/prism/explain.c"),
      *explain_sub_srcs,
      "-o", explain_bin
    )
    explain_bin
  end

  def verify_cross_oracle_spec(workdir, spec)
    k = spec[:kind]
    ns = spec[:namespace]
    prof_expected = spec[:profile]

    raw_cmd = "#{spec[:qemu]}\n-L\n#{spec[:sysroot]}\n/prism/tmp/fuzz/bin/fuzz.#{k}\n"
    resolved = FuzzTriage.resolve_cmdline_executable(raw_cmd)
    assert_equal "/prism/tmp/fuzz/bin/fuzz.#{k}", resolved

    inv_out = "INVARIANT[#{ns}]: kind=ast_size_mismatch stream=0 [detail: #{spec[:len_key]}=120 oracle64_len=24]\n"
    assert_equal k, FuzzTriage.cross_oracle_kind(executable: "/tmp/bin/fuzz.#{k}", crash_output: "")
    assert_equal k, FuzzTriage.cross_oracle_kind(executable: "./build/fuzz.#{k}.repro", crash_output: "")
    assert_equal k, FuzzTriage.cross_oracle_kind(executable: "./build/fuzz", crash_output: inv_out)
    assert FuzzTriage.arm32_bucket?(executable: "./build/fuzz.arm32", crash_output: "") if k == "arm32"
    assert FuzzTriage.ppc_bucket?(executable: "./build/fuzz.ppc", crash_output: "") if k == "ppc"

    prof = FuzzTriage.bucket_verify_profile(reason: "ABRT", executable: "./build/fuzz.#{k}.repro", crash_output: inv_out)
    assert_equal prof_expected, prof
    assert_equal prof_expected, FuzzTriage.bucket_verify_profile(reason: "ABRT", executable: "fuzz", crash_output: inv_out)
    assert_equal prof_expected, FuzzVerify.infer_bucket_profile(workdir, { "reproduced_by" => "fuzz.#{k}.repro" })
    assert_equal "./tmp/fuzz/build/fuzz.#{k}.repro", FuzzRetriage.resolve_reclassify_executable({}, prof_expected)
    assert_equal "./tmp/fuzz/build/fuzz.#{k}.repro", FuzzRetriage.resolve_reclassify_executable({ "reproduced_by" => "fuzz.#{k}" }, "asan_ubsan")
    assert_includes FuzzMatcher::DEFAULT_FUZZER_ORDER, "fuzz.#{k}.repro"

    ora_bucket = {
      "verify_profile" => prof_expected,
      "symptom" => { "headline" => inv_out.strip, "invariant" => { "namespace" => ns } }
    }
    assert_equal ns, FuzzClustering.oracle_family(ora_bucket)

    v_sh = FuzzTriage.verify_script(reason: "ABRT", executable: "./build/fuzz.#{k}.repro", crash_output: inv_out)
    assert_includes v_sh, "--profile \"#{prof_expected}\""

    mock_bucket = File.join(workdir, "#{k}_mock_bucket")
    FileUtils.mkdir_p(mock_bucket)
    File.write(File.join(mock_bucket, "verify.sh"), v_sh)
    assert_equal prof_expected, FuzzVerify.infer_bucket_profile(mock_bucket, {})

    # Simulate AFL++ cross-arch crash directory and verify pipeline unwraps qemu cmdline -> fuzz.<k>.repro,
    # falls back when 64-bit fuzz does not crash, minimizes to raw bytes, and writes <k>_oracle metadata.
    sim_dir = File.join(workdir, "sim_#{k}_triage")
    sim_bin = File.join(sim_dir, "bin")
    sim_afl = File.join(sim_dir, "afl", k)
    sim_crashes = File.join(sim_afl, "crashes")
    sim_triage = File.join(sim_dir, "triage")
    FileUtils.mkdir_p([sim_bin, sim_crashes, sim_triage])

    write_executable(File.join(sim_bin, "fuzz"), "#!/bin/sh\nexit 0\n")
    write_executable(File.join(sim_bin, "fuzz.#{k}.repro"), <<~SH)
      #!/bin/sh
      if grep -q "BUG32" "$1" 2>/dev/null; then
        echo "INVARIANT[#{ns}]: kind=ast_size_mismatch stream=0 [detail: #{spec[:len_key]}=99 oracle64_len=11]" >&2
        exit 134
      fi
      exit 0
    SH
    worker_bin = write_executable(File.join(sim_bin, "fuzz.#{k}"), "#!/bin/sh\nexit 0\n")

    File.write(File.join(sim_afl, "cmdline"), "#{spec[:qemu]}\n-L\n#{spec[:sysroot]}\n#{worker_bin}\n")
    crash_file = File.join(sim_crashes, "id:000000,sig:06,src:000000,time:100,execs:1,op:havoc,rep:1")
    File.binwrite(crash_file, "\x00\x00\x03\x01x = 1\nBUG32\ny = 2\n".b)

    capture_io do
      FuzzTriage.run_triage_pipeline(output_dirs: [File.join(sim_dir, "afl")], testcases_dir: sim_triage, coverage_bin: "")
    end

    meta_files = Dir.glob(File.join(sim_triage, "ABRT", "*", "meta.json"))
    assert_equal 1, meta_files.size, "expected single ABRT bucket from simulated #{k} triage, got #{meta_files.inspect}"

    meta = JSON.parse(File.read(meta_files.first))
    assert_equal prof_expected, meta["verify_profile"]
    assert_equal "fuzz.#{k}.repro", meta["reproduced_by"]
    bdir = File.dirname(meta_files.first)
    refute_path_exists File.join(bdir, "testcase.c")
    refute_path_exists File.join(bdir, "build.sh")
    assert File.executable?(File.join(bdir, "verify.sh")), "missing executable verify.sh in #{bdir}"

    min_bytes = File.binread(File.join(bdir, "input.min"))
    assert_includes min_bytes, "BUG32".b
    refute min_bytes.start_with?("PM64".b, "46MP".b), "expected raw header without PM64 in input.min: #{min_bytes.inspect}"
  end

  def verify_cross_oracle_bucket(spec)
    profile = spec[:profile]
    cross_gcc = spec[:gcc]
    qemu_bin = spec[:qemu]
    oracle_ns = spec[:namespace]

    skip "#{profile} requires Linux" unless linux?
    skip "#{profile} requires #{cross_gcc}" if find_executable(cross_gcc).nil?
    skip "#{profile} requires #{qemu_bin}" unless File.executable?(qemu_bin) || !find_executable(File.basename(qemu_bin)).nil?
    prism_a = require_prism_a!

    with_tmpdir("cross-verify-#{profile}-") do |workdir|
      # 1) Compile verify_runner against real Prism tree and verify passing raw inputs.
      pass_bucket = File.join(workdir, "#{profile}_verify_pass")
      FileUtils.mkdir_p(pass_bucket)
      File.binwrite(File.join(pass_bucket, "input.min"), "\x00\x00\x03\x01puts 1 + 2\n".b)
      File.binwrite(
        File.join(pass_bucket, "id:000001"),
        "\x40\x00\x03\x01def foo(x); a = 1.5; b = 99999999999999999999999999; x + 1; end\n__END__\nrest\n".b
      )

      real_vdir = File.join(workdir, "real_#{profile}_verify_build")
      FileUtils.mkdir_p(real_vdir)
      verify_sh = repo_path("triage/verify_bucket.sh")
      pass_out, = assert_cmd(
        verify_sh,
        "--repo-root", prism_a,
        "--fuzz-root", root_dir,
        "--bucket-dir", pass_bucket,
        "--profile", profile,
        "--json",
        env: { "VERIFY_BUILD_DIR" => real_vdir, "ASAN_OPTIONS" => nil, "UBSAN_OPTIONS" => nil },
        chdir: root_dir
      )
      pass_rep = JSON.parse(pass_out)
      assert_equal 2, pass_rep["total"], "unexpected pass report: #{pass_rep.inspect}"
      assert_equal 2, pass_rep["passed"], "unexpected pass report: #{pass_rep.inspect}"
      assert_equal 0, pass_rep["failed"], "unexpected pass report: #{pass_rep.inspect}"

      # 2) Mock fuzz_root with a deliberate 32-bit mismatch trigger ("BUG32") and verify FAIL,
      # JSON raw size_bytes, --extract-survivors raw byte preservation, and --tar streaming.
      mock_fuzz = build_mock_oracle_fuzz_root(File.join(workdir, "mock_#{profile}_fuzz_root"))

      fail_bucket = File.join(workdir, "#{profile}_verify_fail")
      extract_dir = File.join(workdir, "#{profile}_extract")
      FileUtils.mkdir_p(fail_bucket)
      File.binwrite(File.join(fail_bucket, "input.min"), "\x00\x00\x03\x01puts 1\n".b)
      bug_bytes = "\x00\x00\x03\x01BUG32\n".b
      write_tar_gz(File.join(fail_bucket, "inputs.tar.gz"), [["id:000001", bug_bytes]])

      mock_vdir = File.join(workdir, "mock_#{profile}_verify_build")
      FileUtils.mkdir_p(mock_vdir)
      fail_out, fail_err, fail_st = run_cmd(
        verify_sh,
        "--repo-root", prism_a,
        "--fuzz-root", mock_fuzz,
        "--bucket-dir", fail_bucket,
        "--profile", profile,
        "--extract-survivors", extract_dir,
        "--json",
        env: { "VERIFY_BUILD_DIR" => mock_vdir, "ASAN_OPTIONS" => nil, "UBSAN_OPTIONS" => nil },
        chdir: root_dir
      )
      assert_equal 1, fail_st.exitstatus,
                   "expected #{profile} FAIL exit 1, got #{fail_st.exitstatus}\nstdout=#{fail_out}\nstderr=#{fail_err}"

      fail_rep = JSON.parse(fail_out)
      assert_equal 2, fail_rep["total"], "unexpected fail report: #{fail_rep.inspect}"
      assert_equal 1, fail_rep["passed"], "unexpected fail report: #{fail_rep.inspect}"
      assert_equal 1, fail_rep["failed"], "unexpected fail report: #{fail_rep.inspect}"

      failure = fail_rep["failures"].first
      assert_equal 10, failure["size_bytes"], "expected raw size_bytes=10 (not PM64 envelope), got #{failure.inspect}"
      assert_includes failure["headline"].to_s, "INVARIANT[#{oracle_ns}]"
      assert_equal bug_bytes, File.binread(File.join(extract_dir, "id:000001"))
    end
  end

  def build_mock_oracle_fuzz_root(mock_fuzz)
    inc_dst = File.join(mock_fuzz, "harnesses/prism/include")
    harness_dst = File.join(mock_fuzz, "harnesses/prism")
    triage_dst = File.join(mock_fuzz, "triage")
    FileUtils.mkdir_p([inc_dst, triage_dst])

    %w[fuzz_invariants.h fuzz_options.h fuzz_json.h].each do |hdr|
      FileUtils.cp(repo_path("harnesses/prism/include", hdr), File.join(inc_dst, hdr))
    end
    %w[parse.c mutator_oracle64.c fuzz.c].each do |src|
      FileUtils.cp(repo_path("harnesses/prism", src), File.join(harness_dst, src))
    end
    %w[gen_serialize_walk.rb gen_node_locations.rb].each do |gen_rb|
      src = repo_path("harnesses/prism", gen_rb)
      FileUtils.cp(src, File.join(harness_dst, gen_rb)) if File.file?(src)
    end
    FileUtils.cp(repo_path("triage/verify_runner.c"), File.join(triage_dst, "verify_runner.c"))

    parse32_src = File.read(repo_path("harnesses/prism/parse32.c"))
    target = "    pm_serialize(parser, node, ast_buf);\n"
    assert_includes parse32_src, target
    hook = target +
           "    if (has_oracle && src_len >= 5 && memcmp(source_buf, \"BUG32\", 5) == 0) {\n" \
           "        fuzz_oracle32_fail(\"INVARIANT[\" FUZZ_ORACLE_NAMESPACE \"]: kind=ast_size_mismatch stream=0 [detail: mock=1]\\n\");\n" \
           "    }\n"
    File.write(File.join(harness_dst, "parse32.c"), parse32_src.sub(target, hook))
    mock_fuzz
  end

  def verify_fuzz_json_and_runner_utf8(workdir)
    json_utf8_c = File.join(workdir, "json_utf8_test.c")
    json_utf8_bin = File.join(workdir, "json_utf8_test")
    File.write(json_utf8_c, <<~'C')
      #define _POSIX_C_SOURCE 200809L
      #include <stdio.h>
      #include <stdlib.h>
      #include <string.h>
      #include "include/fuzz_json.h"

      int main(void) {
          char *buf = NULL;
          size_t sz = 0;
          FILE *mem = open_memstream(&buf, &sz);
          const char input[] = { 'c', 'a', 'f', (char)0xc3, (char)0xa9, ' ', (char)0xf0, (char)0x9f, (char)0x98, (char)0x80, ' ', (char)0xff, '\0' };
          fuzz_json_write_string(mem, input, sizeof(input) - 1);
          fclose(mem);
          printf("OUT=%s\n", buf);
          free(buf);
          return 0;
      }
    C
    assert_cmd(
      c_compiler, "-O1", "-std=c99", "-Wall", "-Werror",
      "-I#{repo_path('harnesses/prism')}",
      json_utf8_c, "-o", json_utf8_bin
    )
    json_mem_out, = assert_cmd(json_utf8_bin)
    assert_equal 'OUT="café 😀 \u00ff"', utf8_string(json_mem_out).chomp

    vr_utf8_c = File.join(workdir, "vr_utf8_target.c")
    vr_utf8_bin = File.join(workdir, "vr_utf8_bin")
    File.write(vr_utf8_c, <<~'C')
      #include <stdint.h>
      #include <stdio.h>
      #include <stdlib.h>
      int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
          (void) data; (void) size;
          fprintf(stderr, "ERR utf8=caf\xc3\xa9_\xf0\x9f\x98\x80 raw=\xff\n");
          abort();
      }
    C
    assert_cmd(
      c_compiler, "-O1", "-std=c99", "-Wall", "-Wextra",
      "-I#{repo_path('harnesses/prism/include')}",
      repo_path("triage/verify_runner.c"), vr_utf8_c, "-o", vr_utf8_bin
    )

    utf8_bin_in = File.join(workdir, "café_😀.bin")
    File.write(utf8_bin_in, "x")
    vr_out, vr_err, vr_st = run_cmd(vr_utf8_bin, "--json", utf8_bin_in)
    assert_equal 1, vr_st.exitstatus, "expected aborting verify_runner to exit 1\nstdout=#{vr_out}\nstderr=#{vr_err}"

    parsed = JSON.parse(utf8_string(vr_out))
    failure = parsed.fetch("failures").first
    assert_equal "café_😀.bin", failure["name"]
    assert_includes failure["headline"].to_s, "café_😀"
  end

  def write_tar_gz(path, entries)
    Zlib::GzipWriter.open(path) do |gz|
      Gem::Package::TarWriter.new(gz) do |tar|
        entries.each do |name, body|
          bytes = body.b
          tar.add_file_simple(name, 0o644, bytes.bytesize) { |io| io.write(bytes) }
        end
      end
    end
  end
end
