# frozen_string_literal: true

require "yaml"
require_relative "lib/autorun"

class OssFuzzTest < Minitest::Test
  TARGETS = %w[prism_parse_fuzzer prism_full_fuzzer].freeze
  ASAN_CFLAGS = [
    "-O1",
    "-fno-omit-frame-pointer",
    "-gline-tables-only",
    "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION",
    "-fsanitize=address,undefined",
    "-fno-sanitize-recover=all",
    "-fsanitize=fuzzer-no-link"
  ].join(" ").freeze
  REPLAY_ENV = {
    "ASAN_OPTIONS" => "detect_leaks=1:handle_abort=1:abort_on_error=1",
    "UBSAN_OPTIONS" => "abort_on_error=1:print_stacktrace=1"
  }.freeze
  REMOVED_DOCKER_PACKAGES_RE = /(?:^|[ \t])(?:default-jre|valgrind|bsdmainutils|uuid-dev|clang-format|rake-compiler|ruby_memcheck|bundler)(?:[ \t]|\\|$)/.freeze
  REQUIRED_DOCKER_PACKAGES = %w[
    libglib2.0-dev xxhash tmux python3 unzip libyaml-dev libz-dev libssl-dev autoconf bison gperf bsdextrautils
  ].freeze

  def test_dockerfiles_invariants
    oss_df_path = File.join(oss_dir, "Dockerfile")
    assert_path_exists oss_df_path, "missing oss-fuzz/Dockerfile"
    oss_df = File.read(oss_df_path)
    assert_match(%r{^FROM gcr\.io/oss-fuzz-base/base-builder}, oss_df,
                 "oss-fuzz/Dockerfile must build FROM gcr.io/oss-fuzz-base/base-builder")
    assert_includes oss_df, "--no-install-recommends",
                    "oss-fuzz/Dockerfile must pass --no-install-recommends to apt-get install"
    assert_includes oss_df, "rm -rf /var/lib/apt/lists/*",
                    "oss-fuzz/Dockerfile must clean /var/lib/apt/lists/*"
    assert_match(/^COPY build\.sh \*\.options \$SRC\//, oss_df,
                 "oss-fuzz/Dockerfile must COPY build.sh *.options $SRC/")
    assert_includes oss_df, "PRISM_FUZZER_REPO",
                    "oss-fuzz/Dockerfile must support PRISM_FUZZER_REPO checkout when prism lacks test/fuzz"

    main_df_path = repo_path("docker", "Dockerfile")
    assert_path_exists main_df_path, "missing docker/Dockerfile"
    main_df = File.read(main_df_path)
    assert_match(/^ARG HALFEMPTY_COMMIT=[0-9a-f]{40}$/, main_df,
                 "docker/Dockerfile must pin HALFEMPTY_COMMIT to a 40-char git SHA")
    assert_includes main_df, 'git checkout "${HALFEMPTY_COMMIT}"',
                    "docker/Dockerfile must checkout HALFEMPTY_COMMIT"
    assert_includes main_df, "grep -qF 'g_close(task->fd, NULL);' tree.c",
                    "docker/Dockerfile must verify pre-patch g_close(task->fd, NULL); in tree.c"
    assert_includes main_df,
                    "sed -i 's/g_close(task->fd, NULL);/if (task->fd != -1) g_close(task->fd, NULL);/' tree.c",
                    "docker/Dockerfile must patch g_close(task->fd, NULL); in tree.c"
    assert_includes main_df, "grep -qF 'if (task->fd != -1) g_close(task->fd, NULL);' tree.c",
                    "docker/Dockerfile must verify post-patch g_close guard in tree.c"
    assert_match(/^RUN gem install .*--no-document/, main_df,
                 "docker/Dockerfile must pass --no-document to gem install")
    %w[concurrent-ruby lrama lrama-fuzz].each do |gem_name|
      assert_match(/#{Regexp.escape(gem_name)}:\d+\.\d+\.\d+/, main_df,
                   "docker/Dockerfile must pin #{gem_name} gem version")
    end
    refute_match REMOVED_DOCKER_PACKAGES_RE, main_df,
                 "docker/Dockerfile still references removed unused package or gem"
    REQUIRED_DOCKER_PACKAGES.each do |pkg|
      assert_match(/(?:^|[ \t])#{Regexp.escape(pkg)}(?:[ \t]|\\|$)/, main_df,
                   "docker/Dockerfile missing required package #{pkg}")
    end
    main_df.gsub(/\\\n/, " ").lines.each do |line|
      next unless line.match?(/^\s*RUN\b/) && line.include?("apt-get install")

      assert_includes line, "rm -rf /var/lib/apt/lists/*",
                      "docker/Dockerfile apt-get layer missing rm -rf /var/lib/apt/lists/*: #{line.strip}"
    end

    assert_cmd("bash", "-n", File.join(oss_dir, "build.sh"))
    assert_ruby_cmd("-c", repo_path("runtime", "corpus.rb"))
  end

  def test_oss_fuzz_metadata_and_missing_harness_exit
    skip_if_docker_only!

    # Standalone copied build.sh without test/fuzz or prism-fuzzer must fail cleanly instead of probing //harnesses/prism.
    with_tmpdir("oss-fuzz-no-harness-") do |dir|
      no_harness_src = File.join(dir, "src")
      no_harness_out = File.join(dir, "out")
      no_harness_work = File.join(dir, "work")
      FileUtils.mkdir_p([File.join(no_harness_src, "prism"), no_harness_out, no_harness_work])
      FileUtils.cp(File.join(oss_dir, "build.sh"), no_harness_src, preserve: true)
      Dir.glob(File.join(oss_dir, "*.options")).each { |opt| FileUtils.cp(opt, no_harness_src) }

      out, err, st = run_cmd(
        File.join(no_harness_src, "build.sh"),
        env: {
          "SRC" => no_harness_src,
          "OUT" => no_harness_out,
          "WORK" => no_harness_work,
          "FUZZ_ROOT" => nil
        }
      )
      combined = out + err
      assert_equal 2, st.exitstatus, "expected exit 2 when harness missing, got #{st.exitstatus}: #{combined}"
      assert_includes combined, "cannot locate Prism fuzz harness",
                      "unexpected missing-harness error message: #{combined}"
    end

    project_yaml = YAML.safe_load_file(File.join(oss_dir, "project.yaml"))
    assert_equal "c", project_yaml["language"]
    engines = Array(project_yaml["fuzzing_engines"])
    %w[libfuzzer afl honggfuzz centipede].each do |eng|
      assert_includes engines, eng, "missing engine #{eng}"
    end
    sanitizers = Array(project_yaml["sanitizers"])
    %w[address undefined memory].each do |san|
      assert_includes sanitizers, san, "missing sanitizer #{san}"
    end

    TARGETS.each do |target|
      opt_path = File.join(oss_dir, "#{target}.options")
      assert_path_exists opt_path, "missing options file: #{opt_path}"
      content = File.read(opt_path)
      assert_match(/^\[libfuzzer\]/, content, "#{opt_path} missing [libfuzzer]")
      assert_match(/^dict = #{Regexp.escape(target)}\.dict$/, content, "#{opt_path} missing dict = #{target}.dict")
      assert_match(/^max_len = \d+$/, content, "#{opt_path} missing max_len")
    end
  end

  def test_corpus_no_minimize_standalone_fixtures_and_fuzz_c_guards
    skip_if_docker_only!
    prism_dir = require_prism_dir!

    with_tmpdir("oss-fuzz-corpus-") do |dir|
      corpus_dir = File.join(dir, "corpus_nomin")
      assert_ruby_cmd(
        repo_path("runtime", "corpus.rb"), "--no-minimize", corpus_dir,
        env: {
          "PRISM_A_DIR" => prism_dir,
          "FUZZ_MAX_INPUT_SIZE" => "1024",
          "CORPUS_FIXTURES_DIR" => nil
        }
      )
      seed_count = Dir.children(corpus_dir).count { |f| File.file?(File.join(corpus_dir, f)) }
      assert_operator seed_count, :>, 100, "expected >100 generated seeds, got #{seed_count}"

      encoding_checks = {
        "corpus_UTF-8.rb" => ["ü".b, "€".b, "あ".b],
        "corpus_EUC-JP.rb" => ["あ".encode("EUC-JP").b],
        "corpus_ISO-8859-1.rb" => ["ü".encode("ISO-8859-1").b],
        "corpus_Windows-31J.rb" => ["あ".encode("Windows-31J").b]
      }
      encoding_checks.each do |fname, expected_tokens|
        path = File.join(corpus_dir, fname)
        assert_path_exists path, "missing generated seed #{path}"
        payload = File.binread(path).byteslice(4..) || "".b
        expected_tokens.each do |tok|
          assert payload.include?(tok),
                 "expected #{fname} to preserve multibyte sequence #{tok.bytes.map { |b| format('0x%02x', b) }.join(' ')}"
        end
      end

      # Verify oss-fuzz/build.sh discovers $SRC/prism/test/prism/fixtures even when $FUZZ_ROOT/tmp does not exist.
      standalone_src = File.join(dir, "standalone_src")
      standalone_out = File.join(dir, "standalone_out")
      standalone_work = File.join(dir, "standalone_work")
      stub_bin = File.join(dir, "stub_bin")
      FileUtils.mkdir_p([standalone_src, standalone_out, standalone_work, stub_bin])
      FileUtils.cp_r(prism_dir, File.join(standalone_src, "prism"), preserve: true)
      fixtures_dir = File.join(standalone_src, "prism", "test", "prism", "fixtures")
      FileUtils.mkdir_p(fixtures_dir)
      File.write(File.join(fixtures_dir, "oss_fuzz_standalone_canary.txt"), "oss_fuzz_standalone_canary = 42\n")
      FileUtils.cp(File.join(oss_dir, "build.sh"), standalone_src, preserve: true)
      Dir.glob(File.join(oss_dir, "*.options")).each { |opt| FileUtils.cp(opt, standalone_src) }
      stage_standalone_prism_fuzzer(File.join(standalone_src, "prism-fuzzer"))
      refute_path_exists File.join(standalone_src, "prism-fuzzer", "tmp"), "standalone prism-fuzzer unexpectedly has tmp/"

      cc_stub = write_executable(File.join(stub_bin, "cc"), <<~'SH')
        #!/bin/sh
        out=""
        prev=""
        for arg in "$@"; do
          if [ "$prev" = "-o" ]; then
            out="$arg"
            break
          fi
          prev="$arg"
        done
        [ -n "$out" ] && : > "$out"
      SH
      cxx_stub = write_executable(File.join(stub_bin, "cxx"), <<~'SH')
        #!/bin/sh
        out=""
        prev=""
        for arg in "$@"; do
          if [ "$prev" = "-o" ]; then
            out="$arg"
            break
          fi
          prev="$arg"
        done
        if [ -n "$out" ]; then
          printf '#!/bin/sh\nexit 0\n' > "$out"
          chmod +x "$out"
        fi
      SH

      assert_cmd(
        File.join(standalone_src, "build.sh"),
        env: {
          "CORPUS_FIXTURES_DIR" => nil,
          "PRISM_A_DIR" => nil,
          "PRISM_DIR" => nil,
          "FUZZ_ROOT" => nil,
          "AFL_LLVM_CMPLOG" => nil,
          "SRC" => standalone_src,
          "OUT" => standalone_out,
          "WORK" => standalone_work,
          "CC" => cc_stub,
          "CXX" => cxx_stub,
          "CFLAGS" => "",
          "CXXFLAGS" => "",
          "LIB_FUZZING_ENGINE" => ""
        }
      )

      TARGETS.each do |target|
        assert_path_exists File.join(standalone_out, "#{target}.options"),
                           "standalone build missing #{target}.options"
        zip_path = File.join(standalone_out, "#{target}_seed_corpus.zip")
        assert_path_exists zip_path, "standalone build missing #{target}_seed_corpus.zip"
        zip_list, = assert_cmd("unzip", "-Z1", zip_path)
        assert_includes zip_list.lines.map(&:strip), "oss_fuzz_standalone_canary.txt.rb",
                        "standalone #{target}_seed_corpus.zip missed $SRC/prism/test/prism/fixtures canary seed"
      end

      fuzz_c = repo_path("harnesses", "prism", "fuzz.c")
      fuzz_oss_o = File.join(dir, "fuzz_oss.o")
      assert_cmd(
        cc_bin, "-std=c99", "-O1", "-DPRISM_OSS_FUZZ", "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION",
        "-c", fuzz_c, "-o", fuzz_oss_o
      )
      fuzz_oss_syms, = assert_cmd("nm", fuzz_oss_o)
      refute_match(/ T (?:__asan_default_options|__ubsan_default_options)$/, fuzz_oss_syms,
                   "fuzz.c with -DPRISM_OSS_FUZZ must not define __asan_default_options or __ubsan_default_options")
      assert_match(/ T LLVMFuzzerTestOneInput$/, fuzz_oss_syms,
                   "fuzz.c missing LLVMFuzzerTestOneInput symbol")

      fuzz_local_o = File.join(dir, "fuzz_local.o")
      assert_cmd(
        cc_bin, "-std=c99", "-O1", "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION",
        "-c", fuzz_c, "-o", fuzz_local_o
      )
      fuzz_local_syms, = assert_cmd("nm", fuzz_local_o)
      assert_match(/ T __asan_default_options$/, fuzz_local_syms,
                   "local fuzz.c build must retain __asan_default_options even with FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION")
    end
  end

  def test_oss_fuzz_asan_build_corpus_replay
    skip_if_docker_only!
    prism_dir = require_prism_dir!

    with_tmpdir("oss-fuzz-asan-") do |dir|
      out_dir = resolve_or_build_out_dir(
        dir: dir,
        prism_dir: prism_dir,
        override_env_key: "OSS_FUZZ_OUT_DIR",
        build_subdir: "out",
        extra_env: { "AFL_LLVM_CMPLOG" => nil }
      )

      fixtures_root = File.join(prism_dir, "test", "prism", "fixtures")
      has_txt_fixtures = File.directory?(fixtures_root) &&
                         !Dir.glob(File.join(fixtures_root, "**", "*.txt")).empty?

      TARGETS.each do |target|
        bin_path = File.join(out_dir, target)
        dict_path = File.join(out_dir, "#{target}.dict")
        opt_path = File.join(out_dir, "#{target}.options")
        zip_path = File.join(out_dir, "#{target}_seed_corpus.zip")

        assert File.file?(bin_path) && File.executable?(bin_path), "missing executable #{bin_path}"
        assert_path_exists dict_path, "missing #{dict_path}"
        assert_path_exists opt_path, "missing #{opt_path}"
        assert_path_exists zip_path, "missing #{zip_path}"

        target_syms, = assert_cmd("nm", bin_path)
        refute_match(/ T (?:__asan_default_options|__ubsan_default_options)$/, target_syms,
                     "#{target} unexpectedly exported strong __asan_default_options or __ubsan_default_options")
        assert_match(/ T pm_strncasecmp$/, target_syms,
                     "#{target} expected pm_strncasecmp when AFL_LLVM_CMPLOG is unset")

        unzip_dir = File.join(dir, "unzip-#{target}")
        FileUtils.mkdir_p(unzip_dir)
        assert_cmd("unzip", "-q", zip_path, "-d", unzip_dir)

        seed_files = Dir.children(unzip_dir).map { |f| File.join(unzip_dir, f) }.select { |p| File.file?(p) }
        refute_empty seed_files, "#{target} empty unzipped seed corpus"
        if has_txt_fixtures
          txt_seeds = seed_files.select { |p| (b = File.basename(p)) && b.include?(".txt") && b.end_with?(".rb") }
          refute_empty txt_seeds, "#{target} seed corpus missing Prism fixture .txt seeds"
        end
        min_seed_bytes = seed_files.map { |p| File.size(p) }.min
        assert_operator min_seed_bytes, :>=, 4,
                        "#{target} seed smaller than 4-byte option header: #{min_seed_bytes}"

        replay_seed_corpus(
          bin_path: bin_path,
          opt_path: opt_path,
          dict_path: dict_path,
          unzip_dir: unzip_dir,
          artifact_prefix: dir
        )
      end
    end
  end

  def test_oss_fuzz_msan_compilation
    skip_if_docker_only!
    prism_dir = require_prism_dir!

    with_tmpdir("oss-fuzz-msan-") do |dir|
      msan_dir = File.join(dir, "msan")
      msan_gen_dir = File.join(dir, "msan_gen")
      FileUtils.mkdir_p([msan_dir, msan_gen_dir])

      inc_path = File.join(msan_gen_dir, "node_locations.inc")
      compat_path = File.join(msan_gen_dir, "prism_fuzz_compat.h")
      assert_ruby_cmd(
        repo_path("harnesses", "prism", "gen_node_locations.rb"),
        File.join(prism_dir, "config.yml"),
        inc_path
      )
      assert_ruby_cmd(
        repo_path("harnesses", "prism", "gen_api_compat.rb"),
        "--include-dir", File.join(prism_dir, "include"),
        "--subloc-inc", inc_path,
        "--output", compat_path
      )
      assert_path_exists inc_path
      assert_path_exists compat_path

      %w[fuzz.c parse.c].each do |src_name|
        obj_path = File.join(msan_dir, "#{src_name}.o")
        assert_cmd(
          cc_bin, "-std=c99",
          "-I#{File.join(prism_dir, 'include')}",
          "-I#{msan_gen_dir}",
          "-I#{repo_path('harnesses', 'prism')}",
          "-O1", "-fno-omit-frame-pointer",
          "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION",
          "-fsanitize=memory", "-fsanitize-memory-track-origins", "-fsanitize=fuzzer-no-link",
          "-DPRISM_OSS_FUZZ", "-DPM_ARENA_INITIAL_SIZE=0", "-DPM_INTEGER_DIVIDE_THRESHOLD=8",
          "-DPRISM_DEPTH_MAXIMUM=128", "-DSLOW",
          "-c", repo_path("harnesses", "prism", src_name),
          "-o", obj_path
        )
        assert_path_exists obj_path
      end
    end
  end

  def test_oss_fuzz_cmplog_strncasecmp_swap
    skip_if_docker_only!
    prism_dir = require_prism_dir!

    with_tmpdir("oss-fuzz-cmplog-") do |dir|
      cmplog_out = resolve_or_build_out_dir(
        dir: dir,
        prism_dir: prism_dir,
        override_env_key: "OSS_FUZZ_CMPLOG_OUT_DIR",
        build_subdir: "cmplog_out",
        extra_env: { "AFL_LLVM_CMPLOG" => "1" }
      )

      TARGETS.each do |target|
        bin_path = File.join(cmplog_out, target)
        dict_path = File.join(cmplog_out, "#{target}.dict")
        opt_path = File.join(cmplog_out, "#{target}.options")
        zip_path = File.join(cmplog_out, "#{target}_seed_corpus.zip")

        assert File.file?(bin_path) && File.executable?(bin_path), "missing cmplog executable #{bin_path}"
        assert_path_exists zip_path, "missing #{zip_path}"

        cmplog_syms, = assert_cmd("nm", bin_path)
        refute_match(/ pm_strncasecmp$/, cmplog_syms,
                     "#{target} unexpectedly kept pm_strncasecmp under AFL_LLVM_CMPLOG=1")
        assert_includes cmplog_syms, "strncasecmp",
                        "#{target} missing strncasecmp reference under AFL_LLVM_CMPLOG=1"

        unzip_dir = File.join(dir, "unzip-#{target}")
        FileUtils.mkdir_p(unzip_dir)
        assert_cmd("unzip", "-q", zip_path, "-d", unzip_dir)

        replay_seed_corpus(
          bin_path: bin_path,
          opt_path: opt_path,
          dict_path: dict_path,
          unzip_dir: unzip_dir,
          artifact_prefix: dir
        )
      end
    end
  end

  def test_oss_fuzz_docker_build_and_compile
    unless ENV["TEST_OSS_FUZZ_DOCKER"] == "1"
      skip "set TEST_OSS_FUZZ_DOCKER=1 (or pass --docker-only) on host to run"
    end

    assert find_executable("docker"), "TEST_OSS_FUZZ_DOCKER=1 requires docker on PATH"
    assert_cmd("docker", "info", msg: "TEST_OSS_FUZZ_DOCKER=1 requires a reachable Docker daemon")

    oss_docker_tag = "prism-fuzzer-oss-fuzz-test:#{Process.pid}-#{object_id}"
    with_tmpdir("oss-fuzz-docker-") do |dir|
      docker_out = File.join(dir, "oss_docker_out")
      docker_rf = File.join(dir, "oss_docker_prism_fuzzer")
      FileUtils.mkdir_p(docker_out)
      stage_standalone_prism_fuzzer(docker_rf)

      prism_fuzzer_repo = ENV["PRISM_FUZZER_REPO"]
      prism_fuzzer_ref = ENV["PRISM_FUZZER_REF"]
      build_args = ["docker", "build", "-f", File.join(oss_dir, "Dockerfile"), "-t", oss_docker_tag]
      build_args.push("--build-arg", "PRISM_FUZZER_REPO=#{prism_fuzzer_repo}") if prism_fuzzer_repo && !prism_fuzzer_repo.empty?
      build_args.push("--build-arg", "PRISM_FUZZER_REF=#{prism_fuzzer_ref}") if prism_fuzzer_ref && !prism_fuzzer_ref.empty?
      build_args << oss_dir
      assert_cmd(*build_args)

      run_args = [
        "docker", "run", "--rm",
        "-e", "FUZZING_LANGUAGE=c",
        "-e", "SANITIZER=address",
        "-e", "FUZZING_ENGINE=libfuzzer",
        "-e", "ARCHITECTURE=x86_64",
        "-v", "#{docker_out}:/out"
      ]
      run_args.push("-v", "#{docker_rf}:/src/prism-fuzzer:ro") if prism_fuzzer_repo.nil? || prism_fuzzer_repo.empty?
      run_args.push(oss_docker_tag, "compile")
      assert_cmd(*run_args)

      TARGETS.each do |target|
        assert_path_exists File.join(docker_out, target), "Docker compile missing #{target}"
        assert_path_exists File.join(docker_out, "#{target}.dict"), "Docker compile missing #{target}.dict"
        assert_path_exists File.join(docker_out, "#{target}.options"), "Docker compile missing #{target}.options"
        zip_path = File.join(docker_out, "#{target}_seed_corpus.zip")
        assert_path_exists zip_path, "Docker compile missing #{target}_seed_corpus.zip"

        zip_list, = assert_cmd("unzip", "-Z1", zip_path)
        txt_seed_count = zip_list.lines.count { |line| line.strip.match?(/\.txt(?:\.part\d+)?\.rb$/) }
        assert_operator txt_seed_count, :>, 50,
                        "Docker #{target}_seed_corpus.zip expected >50 Prism fixture seeds, got #{txt_seed_count}"
      end

      replay_script = <<~'BASH'
        set -euo pipefail
        for target in prism_parse_fuzzer prism_full_fuzzer; do
          unzip_dir="$(mktemp -d)"
          unzip -q "/out/${target}_seed_corpus.zip" -d "$unzip_dir"
          max_len="$(awk -F'= *' '/^max_len/{print $2}' "/out/${target}.options")"
          ASAN_OPTIONS=detect_leaks=1:handle_abort=1:abort_on_error=1 \
            UBSAN_OPTIONS=abort_on_error=1:print_stacktrace=1 \
            "/out/$target" -dict="/out/${target}.dict" -max_len="$max_len" -runs=0 "$unzip_dir" >/dev/null
          rm -rf "$unzip_dir"
        done
      BASH
      assert_cmd(
        "docker", "run", "--rm",
        "-v", "#{docker_out}:/out",
        oss_docker_tag, "bash", "-lc", replay_script
      )
    ensure
      run_cmd("docker", "rmi", "-f", oss_docker_tag) if oss_docker_tag && find_executable("docker")
    end
  end

  private

  def docker_only?
    ENV["TEST_OSS_FUZZ_DOCKER_ONLY"] == "1"
  end

  def skip_if_docker_only!
    skip "skipped under TEST_OSS_FUZZ_DOCKER_ONLY=1" if docker_only?
  end

  def oss_dir
    repo_path("oss-fuzz")
  end

  def cc_bin
    val = ENV["CC"]
    val && !val.empty? ? val : "clang"
  end

  def cxx_bin
    val = ENV["CXX"]
    val && !val.empty? ? val : "clang++"
  end

  def require_prism_dir!
    dir = prism_a_dir
    assert dir && File.directory?(File.join(dir, "src")),
           "missing Prism target (run 'make targets-sync' first)"
    dir
  end

  def stage_standalone_prism_fuzzer(dst)
    FileUtils.rm_rf(dst)
    FileUtils.mkdir_p(dst)
    %w[harnesses dict runtime oss-fuzz campaigns lib].each do |sub|
      FileUtils.cp_r(repo_path(sub), File.join(dst, sub), preserve: true)
    end
    FileUtils.cp(repo_path("topology.schema.json"), File.join(dst, "topology.schema.json"))
  end

  def stage_oss_fuzz_src(src_dir, prism_dir)
    FileUtils.mkdir_p(src_dir)
    FileUtils.cp_r(prism_dir, File.join(src_dir, "prism"), preserve: true)
    FileUtils.cp(File.join(oss_dir, "build.sh"), src_dir, preserve: true)
    Dir.glob(File.join(oss_dir, "*.options")).each { |opt| FileUtils.cp(opt, src_dir) }
    stage_standalone_prism_fuzzer(File.join(src_dir, "prism-fuzzer"))
  end

  def resolve_or_build_out_dir(dir:, prism_dir:, override_env_key:, build_subdir:, extra_env:)
    override = ENV[override_env_key]
    return override if ENV["OSS_FUZZ_SKIP_BUILD"] == "1" && override && File.directory?(override)

    out_dir = File.join(dir, build_subdir)
    work_dir = File.join(dir, "#{build_subdir}_work")
    src_dir = File.join(dir, "src")
    FileUtils.mkdir_p([out_dir, work_dir])
    stage_oss_fuzz_src(src_dir, prism_dir)

    build_env = {
      "CC" => cc_bin,
      "CXX" => cxx_bin,
      "CFLAGS" => ASAN_CFLAGS,
      "CXXFLAGS" => ASAN_CFLAGS,
      "LIB_FUZZING_ENGINE" => "-fsanitize=fuzzer",
      "OUT" => out_dir,
      "WORK" => work_dir,
      "SRC" => src_dir,
      "FUZZ_ROOT" => nil,
      "CORPUS_FIXTURES_DIR" => nil
    }.merge(extra_env)

    assert_cmd(File.join(src_dir, "build.sh"), env: build_env)
    out_dir
  end

  def replay_seed_corpus(bin_path:, opt_path:, dict_path:, unzip_dir:, artifact_prefix:)
    max_len = File.read(opt_path)[/^max_len\s*=\s*(\d+)/, 1]
    refute_nil max_len, "missing max_len in #{opt_path}"

    out, err, st = run_cmd(
      bin_path,
      "-artifact_prefix=#{artifact_prefix}/",
      "-dict=#{dict_path}",
      "-max_len=#{max_len}",
      "-runs=0",
      unzip_dir,
      env: REPLAY_ENV
    )
    assert st.success?, lambda {
      tail = (out + err).lines.last(40).join
      "Corpus replay failed (status=#{st.exitstatus || st.termsig}) for #{bin_path}:\n#{tail}"
    }
  end
end
