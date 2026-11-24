# frozen_string_literal: true

require_relative "../lib/autorun"
require_relative "../lib/fixtures"

require "fileutils"
require "json"
require "open3"
require "shellwords"

require_relative "../../runtime/topology"
require_relative "../../runtime/campaign"

class BuildAndCrossTest < Minitest::Test
  UNMAKE_ENV = {
    "MAKEFLAGS" => nil,
    "MFLAGS" => nil,
    "MAKELEVEL" => nil,
    "FUZZ_DIR" => nil,
    "FUZZ_BUILD_DIR" => nil,
    "FUZZ_AFL_DIR" => nil,
    "FUZZ_MAX_INPUT_SIZE" => nil,
    "FUZZ_MAX_ALLOCATED" => nil
  }.freeze

  DEAD_MAKEFILE_PATTERN = /^(FUZZ_AFL_IJON_DIR|FUZZ_FAST_FLAGS|FUZZ_SLOW_FLAGS|FUZZ_SOURCES|FUZZ_ARM32_DEPS|_EXTRA_PRISM_B_TARGETS|define BUILD_CROSS_ORACLE_TARGET|define BUILD_CROSS_EXPLAIN_TARGET)\b/.freeze

  def test_makefile_in_container_run_and_workspace_aware_debug_histfile
    with_tmpdir("make-rel-histfile-") do |workdir|
      up = PrismFuzzerTest::Fixtures.build_synthetic_upstream_prism(File.join(workdir, "upstream"))
      campaign_path = File.join(workdir, "make_rel_campaign.rb")
      File.write(campaign_path, <<~RB)
        PrismFuzzer.campaign "make-rel-histfile" do
          workspace "tmp/examples/make_debug_ws"
          prism :prism_a, repo: #{up[:repo].inspect}, ref: #{up[:v1].inspect}, patches: "none", templates: "never"
          fuzzer "fuzz", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
          sync_group :afl, dir: "afl", primary: true
          worker :w1, fuzzer: "fuzz", sync_group: :afl, afl_role: :main, schedule: "fast"
        end
      RB

      make_run_plan, = assert_cmd(
        "make", "-C", root_dir, "-n",
        "IN_DOCKER=1",
        "TOPOLOGY=#{campaign_path}",
        "CAMPAIGN=#{campaign_path}",
        "run",
        env: UNMAKE_ENV
      )
      assert_includes make_run_plan, "make build",
                      "in-container make run plan must run make build (targets-sync + _build-all): #{make_run_plan}"
      assert_match %r{mkdir -p .*tmp/examples/make_debug_ws/afl .*tmp/examples/make_debug_ws/bin}, make_run_plan,
                   "in-container make run plan missing workspace afl/bin mkdir: #{make_run_plan}"
      assert_includes make_run_plan, "exec ./runtime/run.sh",
                      "in-container make run plan should exec ./runtime/run.sh: #{make_run_plan}"

      make_dbg_plan, = assert_cmd(
        "make", "-C", root_dir, "-n",
        "-o", "./build/.fuzz.docker.stamp",
        "TOPOLOGY=#{campaign_path}",
        "CAMPAIGN=#{campaign_path}",
        "debug",
        env: UNMAKE_ENV
      )
      assert_includes make_dbg_plan, "HISTFILE=/prism-fuzzer/tmp/examples/make_debug_ws/.bash_history",
                      "make debug failed to track custom workspace HISTFILE: #{make_dbg_plan}"
    end
  end

  def test_pm_arena_initial_size_compile_flag_for_xallocator_and_overrides
    with_tmpdir("arena-flag-") do |workdir|
      up = PrismFuzzerTest::Fixtures.build_synthetic_upstream_prism(File.join(workdir, "upstream"))
      ws = File.join(workdir, "arena_flag_ws")
      gen_dir = File.join(ws, "build", "targets", "gen", "prism_a")
      FileUtils.mkdir_p(gen_dir)
      FileUtils.touch(File.join(gen_dir, "node_locations.inc"))

      campaign_path = File.join(workdir, "arena_flag_campaign.rb")
      File.write(campaign_path, <<~RB)
        PrismFuzzer.campaign "arena-flag-test" do
          workspace #{ws.inspect}
          prism :prism_a, repo: #{up[:repo].inspect}, ref: #{up[:v1].inspect}, patches: "none", templates: "never"
          fuzzer "f_xalloc",   shape: :prism_parse, source: :prism_a, sanitizers: [],            xallocator: true
          fuzzer "f_plain",    shape: :prism_parse, source: :prism_a, sanitizers: [],            xallocator: false
          fuzzer "f_san",      shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], xallocator: false
          fuzzer "f_override", shape: :prism_parse, source: :prism_a, sanitizers: [],            xallocator: true, defines: { PM_ARENA_INITIAL_SIZE: 64 }
          sync_group :afl, dir: "afl", primary: true
          worker :w1, fuzzer: "f_xalloc", sync_group: :afl, afl_role: :main
        end
      RB

      ir, = PrismFuzzer::Topology.load_ir(campaign_path, fuzz_root: root_dir)
      build_dir = File.join(ws, "build")
      plan = PrismFuzzer::Topology.compile_plan(ir, fuzz_root: root_dir, build_dir: build_dir)
      plan["sources"]["prism_a"]["path"] = up[:repo]
      plan["sources"]["prism_a"]["gen_dir"] = gen_dir

      dry_out = with_env("FUZZ_FLAGS" => nil, "DEBUG_FLAGS" => nil, "CPPFLAGS" => nil, "CFLAGS" => nil) do
        out, _err = capture_io do
          PrismFuzzer::Topology.build_plan!(plan, fuzz_root: root_dir, build_dir: build_dir, dry_run: true)
        end
        out
      end

      lines = dry_out.lines.map(&:strip)
      by_out = lines.each_with_object({}) do |line, acc|
        if (m = line.match(/\s-o\s+\S*\/(f_\w+)/))
          acc[m[1]] = line
        end
      end

      assert_equal %w[f_override f_plain f_san f_xalloc], by_out.keys.sort,
                   "expected 4 dry-run build lines, got #{lines.inspect}"

      assert_includes by_out["f_xalloc"], "-DPM_ARENA_INITIAL_SIZE=0"
      assert_includes by_out["f_xalloc"], "-DPRISM_XALLOCATOR"
      assert_includes by_out["f_xalloc"], "-DPRISM_FUZZ_INLINE_ASSERTS"
      refute_includes by_out["f_plain"], "-DPM_ARENA_INITIAL_SIZE=0"
      assert_includes by_out["f_plain"], "-DPRISM_FUZZ_INLINE_ASSERTS"
      assert_includes by_out["f_san"], "-DPM_ARENA_INITIAL_SIZE=0"
      assert_includes by_out["f_san"], "-DPRISM_FUZZ_INLINE_ASSERTS"
      assert_includes by_out["f_override"], "-DPM_ARENA_INITIAL_SIZE=64"
      refute_includes by_out["f_override"], "-DPM_ARENA_INITIAL_SIZE=0"
    end
  end

  def test_non_parse_flags_defines_fuzz_flags_sanitizers_and_bkey_invalidation
    ex2_ir, = PrismFuzzer::Topology.load_ir(repo_path("examples/02_cross_arch_endian_gauntlet.rb"), fuzz_root: root_dir)
    %w[fuzz.arm32 fuzz.arm32.ijon fuzz.ppc fuzz.ppc.ijon].each do |fid|
      assert_equal %w[asan ubsan], ex2_ir.dig("fuzzers", fid, "sanitizers"),
                   "expected #{fid} sanitizers=['asan','ubsan'] in example 02"
    end

    with_tmpdir("nonparse-flags-") do |workdir|
      up = PrismFuzzerTest::Fixtures.build_synthetic_upstream_prism(File.join(workdir, "upstream"))
      good_ruby = PrismFuzzerTest::Fixtures.build_good_ruby_dir(File.join(workdir, "good_ruby"))
      ws = File.join(workdir, "nonparse_ws")
      build_dir = File.join(ws, "build")

      FileUtils.mkdir_p([
        File.join(build_dir, "targets/gen/prism_a"),
        File.join(build_dir, "targets/gen/prism_b"),
        File.join(ws, "corpus")
      ])
      File.write(File.join(ws, "corpus/seed.rb"), "1 + 2\n")
      FileUtils.touch([
        File.join(build_dir, "targets/gen/prism_a/node_locations.inc"),
        File.join(build_dir, "targets/gen/prism_a/node_serialize_walk.inc"),
        File.join(build_dir, "targets/gen/prism_b/node_locations.inc"),
        File.join(build_dir, ".fuzz.afl.stamp")
      ])

      campaign_path = File.join(workdir, "nonparse_campaign.rb")
      File.write(campaign_path, <<~RB)
        PrismFuzzer.campaign "nonparse-flags-test" do
          workspace #{ws.inspect}
          prism :prism_a, repo: #{up[:repo].inspect}, ref: #{up[:v1].inspect}, patches: "none", templates: "never"
          prism :prism_b, repo: #{up[:repo].inspect}, ref: #{up[:v2].inspect}, patches: "none", templates: "never"
          ruby  :ruby,    repo: "https://example.invalid/ruby.git", dir: #{good_ruby.inspect}

          fuzzer "f_diff_san",    shape: :prism_diff_ruby,    prism: :prism_a, ruby: :ruby, sanitizers: %i[asan ubsan], afl: :pcguard, ijon: true, cflags: ["-O1"], defines: { PM_INTEGER_DIVIDE_THRESHOLD: 16, PRISM_ACCEL_SWAR: true }
          fuzzer "f_diff_plain",  shape: :prism_diff_ruby,    prism: :prism_a, ruby: :ruby, sanitizers: [], afl: :pcguard
          fuzzer "f_pdiff_san",   shape: :prism_diff_prism,   prism_a: :prism_a, prism_b: :prism_b, sanitizers: %i[asan ubsan], afl: :pcguard, cflags: ["-O2"], defines: { PRISM_DEPTH_MAXIMUM: 16 }
          fuzzer "f_pdiff_plain", shape: :prism_diff_prism,   prism_a: :prism_a, prism_b: :prism_b, sanitizers: [], afl: :pcguard, defines: { PRISM_ACCEL_SWAR: true }
          fuzzer "f_arm_san",     shape: :prism_cross_oracle, source: :prism_a, arch: :arm32, sanitizers: %i[asan ubsan], afl: :pcguard, mutator: "mutator_arm.so", repro: "f_arm_san.repro", defines: { PRISM_ACCEL_SWAR: true }
          fuzzer "f_ppc_nosan",   shape: :prism_cross_oracle, source: :prism_a, arch: :ppc,   sanitizers: [], afl: :pcguard, mutator: "mutator_ppc.so", repro: "f_ppc_nosan.repro", cflags: ["-O2"], defines: { PM_ARENA_INITIAL_SIZE: 64 }

          sync_group :afl, dir: "afl", primary: true
          worker :w_diff_san,  fuzzer: "f_diff_san",  sync_group: :afl, afl_role: :main
          worker :w_arm_san,   fuzzer: "f_arm_san",   sync_group: :afl, afl_role: :secondary
          worker :w_ppc_nosan, fuzzer: "f_ppc_nosan", sync_group: :afl, afl_role: :secondary
        end
      RB

      ir, = PrismFuzzer::Topology.load_ir(campaign_path, fuzz_root: root_dir)
      plan = PrismFuzzer::Topology.compile_plan(ir, fuzz_root: root_dir, build_dir: build_dir)
      %w[prism_a prism_b].each do |sid|
        plan["sources"][sid]["path"] = up[:repo]
        plan["sources"][sid]["gen_dir"] = File.join(build_dir, "targets", "gen", sid)
      end

      with_env("FUZZ_FLAGS" => "-DPRISM_CUSTOM_TEST=7", "DEBUG_FLAGS" => nil, "CPPFLAGS" => nil, "CFLAGS" => nil) do
        dry_out, _err = capture_io do
          PrismFuzzer::Topology.build_plan!(plan, fuzz_root: root_dir, build_dir: build_dir, dry_run: true)
        end
        lines = dry_out.lines.map(&:strip)
        by_id = {}
        lines.each do |ln|
          if (m = ln.match(/--output\s+\S*\/(f_\w+)/))
            by_id[m[1]] = ln
          end
        end
        assert_equal %w[f_arm_san f_diff_plain f_diff_san f_pdiff_plain f_pdiff_san f_ppc_nosan], by_id.keys.sort,
                     "expected 6 dry-run lines, got #{lines.inspect}"

        d_san = by_id.fetch("f_diff_san")
        %w[
          AFL_USE_ASAN=1 AFL_USE_UBSAN=1 AFL_LLVM_IJON=1
          -DPM_ARENA_INITIAL_SIZE=0 -DPRISM_CUSTOM_TEST=7 -O1
          -DPM_INTEGER_DIVIDE_THRESHOLD=16 -DPRISM_ACCEL_SWAR
        ].each do |tok|
          assert_includes d_san, tok, "f_diff_san dry-run missing #{tok}: #{d_san}"
        end
        refute_includes by_id.fetch("f_diff_plain"), "AFL_USE_ASAN=1"
        refute_includes by_id.fetch("f_diff_plain"), "-DPM_ARENA_INITIAL_SIZE=0"

        p_san = by_id.fetch("f_pdiff_san")
        %w[
          AFL_UBSAN_VERBOSE=1 -fsanitize=address,undefined -fno-sanitize-recover=all
          -DPM_ARENA_INITIAL_SIZE=0 -DPRISM_CUSTOM_TEST=7 -O2 -DPRISM_DEPTH_MAXIMUM=16
        ].each do |tok|
          assert_includes p_san, tok, "f_pdiff_san dry-run missing #{tok}: #{p_san}"
        end
        p_plain = by_id.fetch("f_pdiff_plain")
        refute_includes p_plain, "-fsanitize="
        refute_includes p_plain, "-DPM_ARENA_INITIAL_SIZE=0"
        assert_includes p_plain, "-DPRISM_ACCEL_SWAR"
        assert_includes p_plain, "-DPRISM_CUSTOM_TEST=7"

        a_san = by_id.fetch("f_arm_san")
        %w[
          -fsanitize=address,undefined -fno-sanitize-recover=all
          -DPM_ARENA_INITIAL_SIZE=0 -DPRISM_ACCEL_SWAR -DPRISM_CUSTOM_TEST=7
        ].each do |tok|
          assert_includes a_san, tok, "f_arm_san dry-run missing #{tok}: #{a_san}"
        end
        ppc_no = by_id.fetch("f_ppc_nosan")
        refute_includes ppc_no, "-fsanitize="
        refute_includes ppc_no, "-DPM_ARENA_INITIAL_SIZE=0"
        assert_includes ppc_no, "-O2"
        assert_includes ppc_no, "-DPM_ARENA_INITIAL_SIZE=64"
        assert_includes ppc_no, "-DPRISM_CUSTOM_TEST=7"

        recorded = []
        stub_run_cmd_recording(recorded) do
          with_stubbed_method(PrismFuzzer::Topology, :build_ruby_ext_for_source!, ->(*_args, **_kw) { nil }) do
            capture_io do
              PrismFuzzer::Topology.build_plan!(plan, fuzz_root: root_dir, build_dir: build_dir)
            end

            pdiff_call = recorded.find do |r|
              r[:cmd].first.to_s.end_with?("build_prism_diff.sh") && r[:cmd].include?(File.join(build_dir, "f_pdiff_san"))
            end
            refute_nil pdiff_call, "missing build_prism_diff.sh call for f_pdiff_san"
            assert_includes pdiff_call[:cmd], "-fsanitize=address,undefined"
            assert_includes pdiff_call[:cmd], "-DPRISM_DEPTH_MAXIMUM=16"

            arm_link = recorded.find { |r| r[:cmd].first == "arm-linux-gnueabihf-gcc" }
            ppc_link = recorded.find { |r| r[:cmd].first == "powerpc-linux-gnu-gcc" }
            refute_nil arm_link, "expected arm link command"
            assert_includes arm_link[:cmd], "-fsanitize=address,undefined"
            refute_nil ppc_link, "expected ppc link command"
            refute ppc_link[:cmd].any? { |c| c.to_s.start_with?("-fsanitize=") },
                   "expected ppc link without -fsanitize=: #{ppc_link.inspect}"

            stamp_before = JSON.parse(File.read(File.join(build_dir, ".stamps", "f_diff_san.json")))["key"]
            pdiff_stamp_before = JSON.parse(File.read(File.join(build_dir, ".stamps", "f_pdiff_san.json")))["key"]

            recorded.clear
            capture_io do
              PrismFuzzer::Topology.build_plan!(plan, fuzz_root: root_dir, build_dir: build_dir)
            end
            assert_empty recorded, "expected stamp cache hit with unchanged FUZZ_FLAGS, got #{recorded.size} calls"

            with_env("FUZZ_FLAGS" => "-DPRISM_CUSTOM_TEST=8") do
              capture_io do
                PrismFuzzer::Topology.build_plan!(plan, fuzz_root: root_dir, build_dir: build_dir)
              end
              stamp_after = JSON.parse(File.read(File.join(build_dir, ".stamps", "f_diff_san.json")))["key"]
              pdiff_stamp_after = JSON.parse(File.read(File.join(build_dir, ".stamps", "f_pdiff_san.json")))["key"]
              refute_equal stamp_before, stamp_after, "expected FUZZ_FLAGS change to invalidate f_diff_san stamp"
              refute_equal pdiff_stamp_before, pdiff_stamp_after, "expected FUZZ_FLAGS change to invalidate f_pdiff_san stamp"
              refute_empty recorded, "expected rebuild calls after FUZZ_FLAGS change"
            end

            bad_plan = Marshal.load(Marshal.dump(plan))
            bad_plan["fuzzers"]["f_arm_san"]["sanitizers"] = ["msan"]
            err = assert_raises(PrismFuzzer::Topology::TopologyError) do
              PrismFuzzer::Topology.build_prism_cross_oracle!(
                "f_arm_san",
                bad_plan["fuzzers"]["f_arm_san"],
                plan: bad_plan,
                fuzz_root: root_dir,
                build_dir: build_dir,
                afl_path: File.join(build_dir, "afl"),
                afl_stamp: File.join(build_dir, ".fuzz.afl.stamp")
              )
            end
            assert_includes err.message, "supports only asan/ubsan"
          end
        end
      end
    end
  end

  def test_cross_oracle_plan_launch_honors_afl_role_and_sanitizer_env
    with_tmpdir("cross-role-launch-") do |workdir|
      up = PrismFuzzerTest::Fixtures.build_synthetic_upstream_prism(File.join(workdir, "upstream"))
      ws = File.join(workdir, "cross_role_ws")
      FileUtils.mkdir_p([File.join(ws, "bin"), File.join(ws, "corpus"), File.join(ws, "afl")])
      File.write(File.join(ws, "corpus/seed.rb"), "1 + 2\n")
      write_executable(File.join(ws, "bin/f_arm_main"), "#!/bin/sh\nexit 0\n")
      write_executable(File.join(ws, "bin/f_ppc_sec"), "#!/bin/sh\nexit 0\n")

      campaign_path = File.join(workdir, "cross_role_campaign.rb")
      File.write(campaign_path, <<~RB)
        PrismFuzzer.campaign "cross-role-launch-test" do
          workspace #{ws.inspect}
          prism :prism_a, repo: #{up[:repo].inspect}, ref: #{up[:v1].inspect}, patches: "none", templates: "never"
          fuzzer "f_arm_main", shape: :prism_cross_oracle, source: :prism_a, arch: :arm32, sanitizers: %i[asan ubsan], afl: :pcguard
          fuzzer "f_ppc_sec",  shape: :prism_cross_oracle, source: :prism_a, arch: :ppc,   sanitizers: [], afl: :pcguard
          sync_group :afl, dir: "afl", primary: true
          worker :t6_arm_master, fuzzer: "f_arm_main", sync_group: :afl, afl_role: :main, schedule: "exploit"
          worker :t6_ppc_worker, fuzzer: "f_ppc_sec",  sync_group: :afl, afl_role: :secondary, schedule: "fast"
        end
      RB

      ir, = PrismFuzzer::Topology.load_ir(campaign_path, fuzz_root: root_dir)
      plan = PrismFuzzer::Topology.compile_plan(ir, fuzz_root: root_dir, build_dir: File.join(ws, "build"))

      orig_capture2 = Open3.method(:capture2)
      cap_impl = lambda do |*args, **kwargs|
        if args.any? { |a| a.to_s.include?("qemu-") }
          ["65536\n", Struct.new(:success?).new(true)]
        elsif kwargs.empty?
          orig_capture2.call(*args)
        else
          orig_capture2.call(*args, **kwargs)
        end
      end
      launch = nil
      begin
        with_stubbed_method(Open3, :capture2, cap_impl) do
          launch = PrismFuzzer::Topology.plan_launch!(
            plan,
            fuzz_dir: ws,
            bin_dir: File.join(ws, "bin"),
            corpus_dir: File.join(ws, "corpus"),
            fuzz_root: root_dir
          )
        end
      ensure
        Dir.glob("/tmp/afl-tmpdir/t6_*").each { |d| FileUtils.rm_rf(d) }
      end

      by_wid = launch.fetch("workers").to_h { |w| [w["id"], w] }
      arm_cmd = by_wid.fetch("t6_arm_master").fetch("cmd")
      ppc_cmd = by_wid.fetch("t6_ppc_worker").fetch("cmd")
      arm_toks = Shellwords.shellsplit(Shellwords.shellsplit(arm_cmd).last)
      ppc_toks = Shellwords.shellsplit(Shellwords.shellsplit(ppc_cmd).last)

      assert arm_toks.each_cons(2).include?(["-M", "t6_arm_master"]),
             "expected cross_oracle main worker to pass -M t6_arm_master, got: #{arm_cmd}"
      refute arm_toks.each_cons(2).include?(["-S", "t6_arm_master"]),
             "did not expect -S t6_arm_master on main worker, got: #{arm_cmd}"
      assert_includes arm_cmd, "ASAN_OPTIONS\\="
      assert_includes arm_cmd, "UBSAN_OPTIONS\\="
      assert_equal "65536", by_wid.fetch("t6_arm_master").dig("cross_oracle", "map_size")

      assert ppc_toks.each_cons(2).include?(["-S", "t6_ppc_worker"]),
             "expected cross_oracle secondary worker to pass -S t6_ppc_worker, got: #{ppc_cmd}"
      refute ppc_toks.each_cons(2).include?(["-M", "t6_ppc_worker"]),
             "did not expect -M t6_ppc_worker on secondary worker, got: #{ppc_cmd}"
      refute_includes ppc_cmd, "ASAN_OPTIONS"
      refute_includes ppc_cmd, "UBSAN_OPTIONS"
    end
  end

  def test_cross_oracle_repro_wrapper_target_names_mocked
    with_tmpdir("repro-custom-") do |workdir|
      up = PrismFuzzerTest::Fixtures.build_synthetic_upstream_prism(File.join(workdir, "upstream"))
      ws = File.join(workdir, "repro_custom_ws")
      bdir = File.join(ws, "build")
      gen_dir = File.join(bdir, "targets/gen/prism_a")
      FileUtils.mkdir_p(gen_dir)
      FileUtils.touch(File.join(gen_dir, "node_locations.inc"))

      campaign_path = build_custom_repro_campaign(workdir, ws, up)
      ir, = PrismFuzzer::Topology.load_ir(campaign_path, fuzz_root: root_dir)
      plan = PrismFuzzer::Topology.compile_plan(ir, fuzz_root: root_dir, build_dir: bdir)
      plan["sources"]["prism_a"]["path"] = up[:repo]
      plan["sources"]["prism_a"]["gen_dir"] = gen_dir

      recorded = []
      stub_run_cmd_recording(recorded) do
        capture_io do
          %w[fuzz.arm32.ijon fuzz.ppc.ijon fuzz.arm32.auto].each do |fid|
            fspec = plan.fetch("fuzzers").fetch(fid)
            PrismFuzzer::Topology.build_oracle64_helpers!(
              plan["sources"]["prism_a"], fspec,
              plan: plan, fuzz_root: root_dir, build_dir: bdir
            )
          end
        end
      end

      calls = recorded.map { |r| r[:cmd] }
      repro_calls = calls.select { |c| c.include?("-DORACLE64_REPLAY_MAIN") }
      assert_equal 3, repro_calls.size, "expected 3 oracle_repro compile invocations, got #{repro_calls.inspect}"

      prism_c_count = PrismFuzzer::Topology.prism_c_sources(up[:repo]).size
      prism_obj_compiles = calls.count { |c| c.include?("-c") && c.any? { |tok| tok.to_s.start_with?(File.join(up[:repo], "src/")) } }
      assert_equal prism_c_count, prism_obj_compiles,
                   "expected 64-bit Prism C sources compiled once across all 3 oracle helpers (#{prism_c_count}), got #{prism_obj_compiles}"

      arm_ijon_call = repro_calls.find { |c| c.last.start_with?(File.join(bdir, "fuzz.arm32.ijon.repro")) }
      ppc_ijon_call = repro_calls.find { |c| c.last.start_with?(File.join(bdir, "fuzz.ppc.ijon.repro")) }
      auto_call = repro_calls.find { |c| c.last.start_with?(File.join(bdir, "fuzz.arm32.auto.repro")) }

      refute_nil arm_ijon_call, "missing fuzz.arm32.ijon.repro compile call: #{repro_calls.inspect}"
      refute_nil ppc_ijon_call, "missing fuzz.ppc.ijon.repro compile call: #{repro_calls.inspect}"
      refute_nil auto_call, "missing default fuzz.arm32.auto.repro compile call: #{repro_calls.inspect}"

      assert_includes arm_ijon_call, '-DORACLE_REPLAY_TARGET_NAME="fuzz.arm32.ijon"'
      ppc_target_flags = ppc_ijon_call.select { |tok| tok.start_with?("-DORACLE_REPLAY_TARGET_NAME=") }
      assert_equal ['-DORACLE_REPLAY_TARGET_NAME="fuzz.ppc.ijon"'], ppc_target_flags
      assert_includes auto_call, '-DORACLE_REPLAY_TARGET_NAME="fuzz.arm32.auto"'
    end
  end

  def test_cross_oracle_repro_wrapper_resolves_sibling_arm32_binary
    pa = prism_a_dir
    pa_gen = prism_a_gen_dir
    qemu_arm = find_executable("qemu-arm")
    arm_gcc = find_executable("arm-linux-gnueabihf-gcc")
    skip "requires prism_a checkout, gen_dir, qemu-arm, and arm-linux-gnueabihf-gcc" unless
      pa && Dir.exist?(File.join(pa, "src")) && pa_gen && qemu_arm && arm_gcc

    with_tmpdir("real-repro-") do |workdir|
      ws = File.join(workdir, "real_repro_ws")
      bdir = File.join(ws, "build")
      FileUtils.mkdir_p(bdir)

      campaign_path = build_custom_repro_campaign(
        workdir, ws, { repo: "https://example.invalid/prism.git", v1: "deadbeef" * 5 }
      )
      ir, = PrismFuzzer::Topology.load_ir(campaign_path, fuzz_root: root_dir)
      plan = PrismFuzzer::Topology.compile_plan(ir, fuzz_root: root_dir, build_dir: bdir)
      plan["sources"]["prism_a"]["path"] = pa
      plan["sources"]["prism_a"]["gen_dir"] = pa_gen

      with_env("FUZZ_FLAGS" => nil, "CPPFLAGS" => nil, "CFLAGS" => nil) do
        capture_io do
          fspec = plan.fetch("fuzzers").fetch("fuzz.arm32.ijon")
          PrismFuzzer::Topology.build_oracle64_helpers!(
            plan["sources"]["prism_a"], fspec,
            plan: plan, fuzz_root: root_dir, build_dir: bdir
          )
        end
      end

      repro_bin = File.join(bdir, "fuzz.arm32.ijon.repro")
      assert_path_exists repro_bin
      assert File.executable?(repro_bin), "expected executable #{repro_bin}"

      arm_stub_c = File.join(workdir, "arm_stub.c")
      File.write(arm_stub_c, <<~C)
        #include <stdio.h>
        int main(int argc, char **argv) {
            printf("ARM32_IJON_OK %s\\n", argc > 1 ? argv[1] : "");
            return 42;
        }
      C
      arm_target = File.join(bdir, "fuzz.arm32.ijon")
      assert_cmd(arm_gcc, "-static", arm_stub_c, "-o", arm_target)

      probe_rb = File.join(workdir, "repro_probe.rb")
      File.binwrite(probe_rb, seed_bytes("1 + 2\n"))

      out, err, st = run_cmd(repro_bin, probe_rb)
      combined = out + err
      assert_equal 42, st.exitstatus,
                   "expected fuzz.arm32.ijon exit 42 via fuzz.arm32.ijon.repro, got #{st.exitstatus}: #{combined}"
      assert_includes combined, "ARM32_IJON_OK"
    end
  end

  def test_ensure_docker_image_invalidates_caches_on_image_id_change
    with_tmpdir("docker-inv-") do |workdir|
      root = File.join(workdir, "docker_inv_root")
      ext_ws = File.join(workdir, "ext_diff_ws")
      ext_build = File.join(ext_ws, "build")

      FileUtils.mkdir_p([
        File.join(root, "docker"),
        File.join(root, "build/diff-oracle"),
        File.join(root, "build/targets/prism_a"),
        File.join(root, "tmp/fuzz/build/diff-oracle"),
        File.join(root, "tmp/examples/demo/build/diff-oracle"),
        File.join(ext_build, "diff-oracle"),
        File.join(ext_build, "targets/prism_a")
      ])
      File.write(File.join(root, "docker/Dockerfile"), "FROM ubuntu:24.04\n")
      FileUtils.touch([
        File.join(root, "build/.fuzz.afl.stamp"),
        File.join(ext_build, ".fuzz.afl.stamp"),
        File.join(root, "build/targets/prism_a/keep.txt"),
        File.join(ext_build, "targets/prism_a/keep.txt"),
        File.join(root, "build/diff-oracle/libcruby_oracle.a"),
        File.join(root, "tmp/fuzz/build/diff-oracle/libcruby_oracle.a"),
        File.join(root, "tmp/examples/demo/build/diff-oracle/libcruby_oracle.a"),
        File.join(ext_build, "diff-oracle/libcruby_oracle.a")
      ])

      seq = nil
      fake_stage = Object.new
      def fake_stage.exec_stream(*, **); end

      with_env("RUBY_GIT_REF" => nil) do
        with_stubbed_method(PrismFuzzer::Campaign, :in_docker?, -> { false }) do
          with_stubbed_method(PrismFuzzer::Campaign, :docker_image_id, ->(_img = nil) { seq.shift }) do
            with_stubbed_method(PrismFuzzer::Progress, :stage, ->(_t, **_kw, &blk) { blk&.call(fake_stage); true }) do
              # Same image ID after forced rebuild preserves diff-oracle & AFL stamps.
              seq = %w[sha256:old sha256:old]
              PrismFuzzer::Campaign.ensure_docker_image!(fuzz_root: root, build_dir: ext_build, force: true)
              assert_path_exists File.join(root, "build", ".fuzz.afl.stamp")
              assert Dir.exist?(File.join(ext_build, "diff-oracle")),
                     "expected ext_build/diff-oracle preserved when image ID unchanged"

              # Changed image ID removes AFL stamps and all diff-oracle caches while preserving targets/.
              seq = %w[sha256:old sha256:new]
              PrismFuzzer::Campaign.ensure_docker_image!(fuzz_root: root, build_dir: ext_build, force: true)
              refute_path_exists File.join(root, "build", ".fuzz.afl.stamp")
              refute_path_exists File.join(ext_build, ".fuzz.afl.stamp")
              [
                File.join(root, "build", "diff-oracle"),
                File.join(root, "tmp", "fuzz", "build", "diff-oracle"),
                File.join(root, "tmp", "examples", "demo", "build", "diff-oracle"),
                File.join(ext_build, "diff-oracle")
              ].each do |odir|
                refute File.exist?(odir), "expected #{odir} invalidated on image change"
              end
              assert_path_exists File.join(root, "build/targets/prism_a/keep.txt")
              assert_path_exists File.join(ext_build, "targets/prism_a/keep.txt")

              # Even if docker image was previously removed (existing_id=nil), recorded prev_id triggers invalidation.
              FileUtils.mkdir_p(File.join(ext_build, "diff-oracle"))
              File.write(File.join(ext_build, "diff-oracle", "libcruby_oracle.a"), "stale")
              seq = [nil, "sha256:rebuilt"]
              PrismFuzzer::Campaign.ensure_docker_image!(fuzz_root: root, build_dir: ext_build, force: false)
              refute File.exist?(File.join(ext_build, "diff-oracle")),
                     "expected diff-oracle invalidated when rebuilt from missing image ID"
            end
          end
        end
      end
    end
  end

  def test_build_diff_oracle_stamp_changes_with_fuzz_image_id
    pa = prism_a_dir
    skip "requires prism_a checkout and /opt/ruby static tree" unless
      pa && File.file?("/opt/ruby/libruby-static.a") && File.file?("/opt/ruby/parse.c")

    with_tmpdir("fp-oracle-") do |workdir|
      fp_oracle = File.join(workdir, "fp_oracle")
      FileUtils.mkdir_p(fp_oracle)
      build_diff = repo_path("harnesses/prism/build_diff.sh")

      assert_cmd(
        build_diff,
        "--mode", "verify",
        "--prism-root", pa,
        "--fuzz-root", root_dir,
        "--oracle-dir", fp_oracle,
        "--output", File.join(fp_oracle, "v1"),
        env: { "FUZZ_IMAGE_ID" => "img_one" }
      )
      fp1 = File.read(File.join(fp_oracle, ".oracle.stamp")).strip

      assert_cmd(
        build_diff,
        "--mode", "verify",
        "--prism-root", pa,
        "--fuzz-root", root_dir,
        "--oracle-dir", fp_oracle,
        "--output", File.join(fp_oracle, "v2"),
        env: { "FUZZ_IMAGE_ID" => "img_two" }
      )
      fp2 = File.read(File.join(fp_oracle, ".oracle.stamp")).strip

      refute_empty fp1
      refute_equal fp1, fp2, "expected build_diff.sh .oracle.stamp to change with FUZZ_IMAGE_ID (#{fp1})"
    end
  end

  def test_makefile_dead_variables_eliminated_and_dry_run_contracts
    makefile_text = File.read(repo_path("Makefile"))
    refute_match DEAD_MAKEFILE_PATTERN, makefile_text,
                 "Makefile still contains eliminated dead variables or cross-compile macros"

    mk_run_n, = assert_cmd(
      "make", "-C", root_dir, "-n", "IN_DOCKER=",
      "-o", "./build/.fuzz.docker.stamp",
      "run", "FUZZ_MAX_INPUT_SIZE=8192", "FUZZ_MAX_ALLOCATED=256",
      env: UNMAKE_ENV
    )
    assert_includes mk_run_n, "make build", "make -n run missing make build: #{mk_run_n}"
    assert_includes mk_run_n, "mkdir -p", "make -n run missing mkdir -p: #{mk_run_n}"
    assert_includes mk_run_n, "FUZZ_MAX_INPUT_SIZE=8192 -e FUZZ_MAX_ALLOCATED=256",
                    "make -n run missing limits: #{mk_run_n}"
    assert_includes mk_run_n, "triage.rb", "make -n run missing default post-run triage: #{mk_run_n}"
    assert_includes mk_run_n, "report.rb", "make -n run missing default post-run report: #{mk_run_n}"

    mk_run_nopost_n, = assert_cmd(
      "make", "-C", root_dir, "-n", "IN_DOCKER=",
      "-o", "./build/.fuzz.docker.stamp",
      "run", "FUZZ_NO_POST=1",
      env: UNMAKE_ENV
    )
    refute_match(/triage\.rb|report\.rb/, mk_run_nopost_n,
                 "make -n run FUZZ_NO_POST=1 must skip post-run triage/report: #{mk_run_nopost_n}")

    mk_dbg_n, = assert_cmd(
      "make", "-C", root_dir, "-n",
      "-o", "./build/.fuzz.docker.stamp", "debug",
      env: UNMAKE_ENV
    )
    assert_includes mk_dbg_n, "HISTFILE=", "make -n debug missing HISTFILE: #{mk_dbg_n}"

    mk_rep_n, = assert_cmd(
      "make", "-C", root_dir, "-n",
      "-o", "./build/.fuzz.docker.stamp", "report",
      env: UNMAKE_ENV
    )
    refute_includes mk_rep_n, "_build-all", "make -n report must not invoke _build-all: #{mk_rep_n}"
    assert_includes mk_rep_n, "TRIAGE_LIVE_SCRIPTS", "make -n report missing TRIAGE_LIVE_SCRIPTS: #{mk_rep_n}"
    assert_includes mk_rep_n, "snapshot/triage/triage.rb", "make -n report missing snapshot/triage/triage.rb: #{mk_rep_n}"

    mk_oss_n, = assert_cmd(
      "make", "-C", root_dir, "-n", "test-oss-fuzz-docker",
      env: UNMAKE_ENV
    )
    assert_includes mk_oss_n, "TEST_OSS_FUZZ_DOCKER=1 ruby test/run.rb --docker-only --suite oss_fuzz",
                    "make -n test-oss-fuzz-docker mismatch: #{mk_oss_n}"

    mk_afl_n, = assert_cmd(
      "make", "-C", root_dir, "-n",
      "-W", "patches/afl/aflplusplus.patch", "./build/.fuzz.afl.stamp",
      env: UNMAKE_ENV
    )
    assert_includes mk_afl_n, "bin/campaign.rb ensure-afl-passes",
                    "make -n ./build/.fuzz.afl.stamp should delegate to bin/campaign.rb ensure-afl-passes: #{mk_afl_n}"

    mk_doc_n, = assert_cmd(
      "make", "-C", root_dir, "-n",
      "-W", "docker/Dockerfile", "./build/.fuzz.docker.stamp",
      env: UNMAKE_ENV
    )
    assert_includes mk_doc_n, "bin/campaign.rb docker-build",
                    "make -n ./build/.fuzz.docker.stamp should delegate to bin/campaign.rb docker-build: #{mk_doc_n}"
  end

  def test_makefile_clean_preserves_build_and_triage
    with_tmpdir("mk-clean-") do |workdir|
      mk_clean_dir = File.join(workdir, "mk_clean_ws")
      FileUtils.mkdir_p([
        File.join(mk_clean_dir, "afl/w"),
        File.join(mk_clean_dir, "build"),
        File.join(mk_clean_dir, "bin"),
        File.join(mk_clean_dir, "report/triage/ABRT/b1"),
        File.join(mk_clean_dir, "report/coverage")
      ])
      FileUtils.touch([
        File.join(mk_clean_dir, ".dot"),
        File.join(mk_clean_dir, "build/keep.bin"),
        File.join(mk_clean_dir, "bin/fuzz"),
        File.join(mk_clean_dir, "report/triage/ABRT/b1/meta.json"),
        File.join(mk_clean_dir, "report/index.html"),
        File.join(mk_clean_dir, "report/coverage/coverage.json")
      ])

      assert_cmd("make", "-C", root_dir, "clean", "FUZZ_DIR=#{mk_clean_dir}", env: UNMAKE_ENV)

      assert_path_exists File.join(mk_clean_dir, "build/keep.bin")
      assert_path_exists File.join(mk_clean_dir, "report/triage/ABRT/b1/meta.json")
      %w[afl bin .dot report/index.html report/coverage].each do |removed|
        refute File.exist?(File.join(mk_clean_dir, removed)), "make clean failed to remove #{removed}"
      end
    end
  end

  def test_makefile_afl_stamp_builds_in_isolated_sandbox
    skip "requires /AFLplusplus and /usr/local/lib/afl inside container" unless
      Dir.exist?("/AFLplusplus") && Dir.exist?("/usr/local/lib/afl")

    with_tmpdir("afl-make-sandbox-") do |workdir|
      sandbox = File.join(workdir, "afl_make_sandbox")
      FileUtils.mkdir_p([File.join(sandbox, "harnesses/prism"), File.join(sandbox, "test")])
      FileUtils.cp([repo_path("Makefile"), repo_path("topology.schema.json")], sandbox)
      FileUtils.cp(repo_path("test/tests.mk"), File.join(sandbox, "test/tests.mk"))
      %w[bin runtime lib campaigns patches].each do |dir|
        FileUtils.cp_r(repo_path(dir), sandbox)
      end
      File.write(File.join(sandbox, "harnesses/prism/parse.c"), "")

      assert_cmd("make", "-C", sandbox, "./build/.fuzz.afl.stamp", env: UNMAKE_ENV)

      assert_path_exists File.join(sandbox, "build/.fuzz.afl.stamp")
      %w[SanitizerCoverageLTO.so SanitizerCoveragePCGUARD.so].each do |so|
        so_path = File.join(sandbox, "build/afl", so)
        assert_path_exists so_path, "missing build/afl/#{so}"
        refute File.symlink?(so_path), "build/afl/#{so} must be a copied regular file, not a symlink"
      end
      %w[afl-compiler-rt-armhf.o aflpp_driver-armhf.o afl-compiler-rt-ppc.o aflpp_driver-ppc.o].each do |rt|
        assert_path_exists File.join(sandbox, "build/afl", rt), "missing cross runtime #{rt}"
      end
    end
  end

  def test_topology_cli_gen_inc_and_build_explain_host_and_arm32
    pa = prism_a_dir
    skip "requires prism_a checkout with src/" unless pa && Dir.exist?(File.join(pa, "src"))

    with_tmpdir("explain-cli-") do |workdir|
      topo_cli = repo_path("bin/topology.rb")
      bdir = File.join(workdir, "build")
      gen_dir = File.join(workdir, "explain_cli_gen")
      host_bin = File.join(workdir, "explain_cli_bin")

      assert_ruby_cmd(topo_cli, "gen-inc", "--prism-dir", pa, "--gen-dir", gen_dir, "--build-dir", bdir)
      assert_path_exists File.join(gen_dir, "node_locations.inc")
      assert_path_exists File.join(gen_dir, "node_serialize_walk.inc")

      assert_ruby_cmd(
        topo_cli, "build-explain",
        "--prism-dir", pa, "--gen-dir", gen_dir, "--build-dir", bdir, "--output", host_bin
      )
      assert_path_exists host_bin
      assert File.executable?(host_bin), "expected executable host explain binary at #{host_bin}"

      host_out, = assert_cmd(host_bin, "-e", "1 + 2")
      assert_includes host_out, "ProgramNode", "build-explain host binary did not parse snippet: #{host_out}"

      arm_gcc = find_executable("arm-linux-gnueabihf-gcc")
      qemu_arm = find_executable("qemu-arm")
      if arm_gcc && qemu_arm
        arm_bin = File.join(workdir, "explain_cli_arm32")
        assert_ruby_cmd(
          topo_cli, "build-explain",
          "--arch", "arm32", "--prism-dir", pa, "--gen-dir", gen_dir, "--build-dir", bdir, "--output", arm_bin
        )
        assert_path_exists arm_bin
        assert File.executable?(arm_bin), "expected executable arm32 explain binary at #{arm_bin}"

        arm_out, = assert_cmd(qemu_arm, "-L", "/usr/arm-linux-gnueabihf", arm_bin, "-e", "1 + 2")
        assert_includes arm_out, "ProgramNode", "build-explain arm32 binary failed under qemu-arm: #{arm_out}"
      end
    end
  end

  def test_build_pool_concurrency_cap_and_ccache_namespace_isolation
    pool = PrismFuzzer::Topology::BuildPool.new(3)
    active = 0
    peak = 0
    mu = Mutex.new
    out = pool.parallel_map((1..12).to_a, max_threads: 8) do |n|
      pool.with_slot do
        mu.synchronize do
          active += 1
          peak = active if active > peak
        end
        sleep 0.01
        mu.synchronize { active -= 1 }
        n * 2
      end
    end
    assert_equal((1..12).map { |n| n * 2 }, out)
    assert_operator peak, :<=, 3, "BuildPool exceeded slot limit (peak=#{peak})"
    assert_operator peak, :>=, 2, "BuildPool did not execute concurrently (peak=#{peak})"

    with_tmpdir("ccache-ns-") do |workdir|
      fake_bin = File.join(workdir, "bin")
      cdir = File.join(workdir, "ccache")
      afl_stamp = File.join(workdir, ".fuzz.afl.stamp")
      FileUtils.mkdir_p([fake_bin, cdir])
      write_executable(File.join(fake_bin, "ccache"), "#!/bin/sh\nexec \"$@\"\n")
      File.write(afl_stamp, "stamp\n")

      with_env("PATH" => "#{fake_bin}:#{ENV['PATH']}", "CCACHE_DIR" => cdir, "FUZZ_CCACHE" => nil, "FUZZ_IMAGE_ID" => "sha256:abc123456789") do
        PrismFuzzer::Topology.instance_variable_set(:@ccache_cached_path_env, nil)
        cmd_msan, env_msan = PrismFuzzer::Topology.ccache_compile_wrapper(
          "afl-clang-lto", { "AFL_USE_MSAN" => "1", "AFL_LLVM_IJON" => "1" },
          fuzz_root: root_dir, afl_stamp: afl_stamp
        )
        cmd_lsan, env_lsan = PrismFuzzer::Topology.ccache_compile_wrapper(
          "afl-clang-lto", { "AFL_USE_LSAN" => "1", "AFL_LLVM_IJON" => "1" },
          fuzz_root: root_dir, afl_stamp: afl_stamp
        )
        assert_equal [File.join(fake_bin, "ccache"), "afl-clang-lto"], cmd_msan
        assert_equal [File.join(fake_bin, "ccache"), "afl-clang-lto"], cmd_lsan
        assert_equal cdir, env_msan["CCACHE_DIR"]
        assert_equal "1", env_msan["CCACHE_NOHASHDIR"]
        refute_equal env_msan["CCACHE_NAMESPACE"], env_lsan["CCACHE_NAMESPACE"],
                     "MSan and LSan must have distinct CCACHE_NAMESPACE values"
        assert_includes env_msan["CCACHE_NAMESPACE"], "AFL_USE_MSAN=1"
        assert_includes env_lsan["CCACHE_NAMESPACE"], "AFL_USE_LSAN=1"
      end

      with_env("FUZZ_CCACHE" => "0") do
        cmd_off, = PrismFuzzer::Topology.ccache_compile_wrapper("clang", nil, fuzz_root: root_dir)
        assert_equal ["clang"], cmd_off
      end
      PrismFuzzer::Topology.instance_variable_set(:@ccache_cached_path_env, nil)

      ctx = PrismFuzzer::Campaign.resolve_context(campaign_path: repo_path("campaigns/default.rb"), fuzz_root: root_dir)
      with_env("FUZZ_CCACHE" => nil, "CCACHE_DIR" => nil) do
        dcmd = PrismFuzzer::Campaign.docker_cmd_for(ctx, ["true"])
        assert_includes dcmd, "prism-fuzzer-ccache:/ccache"
      end
      with_env("FUZZ_CCACHE" => "0") do
        dcmd_off = PrismFuzzer::Campaign.docker_cmd_for(ctx, ["true"])
        refute dcmd_off.any? { |t| t.include?(":/ccache") }
      end
    end
  end

  private

  def build_custom_repro_campaign(workdir, ws, up)
    path = File.join(workdir, "repro_custom_campaign.rb")
    File.write(path, <<~RB)
      PrismFuzzer.campaign "custom-repro-name-test" do
        workspace #{ws.inspect}
        prism :prism_a, repo: #{up[:repo].inspect}, ref: #{up[:v1].inspect}, patches: "none", templates: "never"
        fuzzer "fuzz.arm32.ijon", shape: :prism_cross_oracle, source: :prism_a, arch: :arm32, sanitizers: %i[asan ubsan], ijon: true, mutator: "mutator_oracle64.so", repro: "fuzz.arm32.ijon.repro"
        fuzzer "fuzz.ppc.ijon",   shape: :prism_cross_oracle, source: :prism_a, arch: :ppc,   sanitizers: %i[asan ubsan], ijon: true, mutator: "mutator_oracle64.so", repro: "fuzz.ppc.ijon.repro"
        fuzzer "fuzz.arm32.auto", shape: :prism_cross_oracle, source: :prism_a, arch: :arm32, sanitizers: %i[asan ubsan]
        sync_group :afl, dir: "afl", primary: true
        worker :w1, fuzzer: "fuzz.arm32.ijon", sync_group: :afl, afl_role: :main
      end
    RB
    path
  end

  def stub_run_cmd_recording(recorded, &block)
    rec_lock = Mutex.new
    impl = lambda do |*cmd, env: nil, chdir: nil, allow_fail: false|
      o_idx = cmd.index("--output") || cmd.index("-o")
      if o_idx && cmd[o_idx + 1]
        FileUtils.mkdir_p(File.dirname(cmd[o_idx + 1]))
        File.write(cmd[o_idx + 1], "stub\n")
      end
      rec_lock.synchronize do
        recorded << { cmd: cmd, env: env || {}, chdir: chdir, allow_fail: allow_fail }
      end
      ["", "", nil]
    end
    with_stubbed_method(PrismFuzzer::Topology, :run_cmd, impl, &block)
  end

  def with_stubbed_method(target, method_name, impl)
    sc = target.singleton_class
    had_orig = sc.method_defined?(method_name) || sc.private_method_defined?(method_name)
    orig = target.method(method_name) if had_orig
    sc.define_method(method_name, impl)
    yield
  ensure
    if had_orig
      sc.define_method(method_name, orig)
    elsif sc.method_defined?(method_name) || sc.private_method_defined?(method_name)
      sc.remove_method(method_name)
    end
  end
end
