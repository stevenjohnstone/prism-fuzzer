# frozen_string_literal: true

require_relative "../lib/autorun"
require_relative "../lib/fixtures"

require "fileutils"
require "json"
require "securerandom"

class TargetsSyncAndPatchesTest < Minitest::Test
  def test_synthetic_upstream_prism_and_sync_v1_patches_templates
    with_tmpdir("targets-sync-") do |workdir|
      ws = prepare_dsl_workspace(workdir)
      upstream = ws[:upstream]

      assert_equal 3, [upstream[:v1], upstream[:v2], upstream[:v3]].uniq.size
      [upstream[:v1], upstream[:v2], upstream[:v3]].each do |sha|
        assert_match(/\A[0-9a-f]{40}\z/, sha)
      end

      sync_out, = assert_topo(
        "sync",
        "--topology", ws[:topo_path],
        "--build-dir", ws[:build_dir],
        "--cache-dir", ws[:cache_dir],
        "--json"
      )
      d = JSON.parse(sync_out)

      a = d.dig("sources", "prism_a")
      refute_nil a, "missing sources.prism_a: #{d.inspect}"
      assert_equal upstream[:v1], a["commit"]

      applied = Array(a.dig("resolved", "applied_patches"))
      assert_equal 5, applied.size, "expected all 5 patches applied, got #{applied.inspect}"
      assert_empty Array(a.dig("resolved", "skipped_patches"))
      assert a.dig("resolved", "templates_generated"), "expected templates_generated=true"

      gen = a["gen_dir"]
      refute_nil gen, "missing prism_a gen_dir"
      assert_path_exists File.join(gen, "node_locations.inc")
      assert_path_exists File.join(gen, "node_serialize_walk.inc")

      refute d.dig("sources", "prism_b"), "prism_b should be inactive"
      refute d.dig("fuzzers", "fuzz.prism_diff"), "fuzz.prism_diff should be inactive"
      refute d["workers"].any? { |w| w["id"] == "pdiff" }, "worker pdiff should be inactive"

      refute_path_exists File.join(ws[:build_dir], "targets", "prism_b.json"),
                         "prism_b.json must not exist when prism_b.ref is null"
      assert_path_exists File.join(ws[:build_dir], "topology.resolved.json"),
                         "missing topology.resolved.json"
    end
  end

  def test_incremental_offline_reuse_prism_b_ref_activation_and_cleanup
    with_tmpdir("targets-sync-") do |workdir|
      ws = prepare_dsl_workspace(workdir)
      v2_sha = ws[:upstream][:v2]

      assert_topo(
        "sync",
        "--topology", ws[:topo_path],
        "--build-dir", ws[:build_dir],
        "--cache-dir", ws[:cache_dir],
        "--json"
      )

      sentinel = File.join(ws[:build_dir], "targets", "prism_a", "src", "node.c")
      assert_path_exists sentinel
      mtime_before = File.mtime(sentinel)
      sent_mtime_before = mtime_before.nsec
      sleep 0.05

      assert_topo(
        "sync",
        "--topology", ws[:topo_path],
        "--build-dir", ws[:build_dir],
        "--cache-dir", ws[:cache_dir],
        "--json",
        env: { "TARGETS_OFFLINE" => "1" }
      )
      mtime_after = File.mtime(sentinel)
      assert_equal sent_mtime_before, mtime_after.nsec,
                   "expected unchanged incremental worktree reuse (mtime nsec changed)"
      assert_equal mtime_before, mtime_after,
                   "expected unchanged incremental worktree reuse (mtime changed)"

      sync_ab_out, = assert_topo(
        "sync",
        "--topology", ws[:topo_path],
        "--build-dir", ws[:build_dir],
        "--cache-dir", ws[:cache_dir],
        "--json",
        env: { "TARGETS_OFFLINE" => "1", "PRISM_B_REF" => v2_sha }
      )
      d = JSON.parse(sync_ab_out)

      b = d.dig("sources", "prism_b")
      refute_nil b, "missing prism_b"
      assert_equal v2_sha, b["commit"]

      applied = Array(b.dig("resolved", "applied_patches"))
      skipped = Array(b.dig("resolved", "skipped_patches"))
      assert_equal 4, applied.size,
                   "expected 4 applied patches, got applied=#{applied.inspect} skipped=#{skipped.inspect}"
      assert_equal 1, skipped.size,
                   "expected 1 skipped patch, got applied=#{applied.inspect} skipped=#{skipped.inspect}"
      assert_includes skipped[0]["patch"], "0002"
      assert_equal "already_upstream", skipped[0]["reason"]

      assert d.dig("fuzzers", "fuzz.prism_diff"), "expected fuzz.prism_diff active"
      assert d["workers"].any? { |w| w["id"] == "pdiff" }, "expected worker pdiff active"
      assert_equal File.join(ws[:build_dir], "fuzz.explain.b"),
                   d.dig("explain_binaries", "prism_b"),
                   "expected fuzz.explain.b in explain_binaries"
      assert_path_exists File.join(ws[:build_dir], "targets", "prism_b.json")

      env_ab, = assert_topo(
        "env",
        "--topology", ws[:topo_path],
        "--build-dir", ws[:build_dir],
        "--cache-dir", ws[:cache_dir],
        env: { "PRISM_B_REF" => v2_sha }
      )
      assert_match(/^TOPOLOGY_RESOLVED=/, env_ab, "env missing TOPOLOGY_RESOLVED")
      assert_match(/^PRISM_A_DIR=/, env_ab, "env missing PRISM_A_DIR")
      assert_match(/^PRISM_B_DIR=/, env_ab, "env missing PRISM_B_DIR")
      assert_match(/^PRISM_A_GEN_DIR=/, env_ab, "env missing PRISM_A_GEN_DIR")

      assert_topo(
        "sync",
        "--topology", ws[:topo_path],
        "--build-dir", ws[:build_dir],
        "--cache-dir", ws[:cache_dir],
        env: { "TARGETS_OFFLINE" => "1", "PRISM_B_REF" => nil }
      )
      refute_path_exists File.join(ws[:build_dir], "targets", "prism_b.json"),
                         "expected prism_b.json removal when PRISM_B_REF is cleared"
    end
  end

  def test_ruby_dir_validation_and_external_docker_args
    with_tmpdir("targets-sync-") do |workdir|
      ws = prepare_dsl_workspace(workdir)
      bad_ruby = File.join(workdir, "bad_ruby")
      FileUtils.mkdir_p(bad_ruby)
      good_ruby = PrismFuzzerTest::Fixtures.build_good_ruby_dir(File.join(workdir, "good_ruby"))

      out_bad, err_bad, st_bad = run_topo(
        "sync-ruby",
        "--topology", ws[:topo_path],
        "--build-dir", ws[:build_dir],
        "--cache-dir", ws[:cache_dir],
        env: { "RUBY_DIR" => bad_ruby }
      )
      refute st_bad.success?, "expected invalid RUBY_DIR to fail (stdout=#{out_bad}, stderr=#{err_bad})"
      assert_includes err_bad, "Invalid RUBY_DIR"

      ruby_state_out, = assert_topo(
        "sync-ruby",
        "--topology", ws[:topo_path],
        "--build-dir", ws[:build_dir],
        "--cache-dir", ws[:cache_dir],
        "--json",
        env: { "RUBY_DIR" => good_ruby }
      )
      r = JSON.parse(ruby_state_out)
      assert_equal "local_dir", r["mode"], "expected mode=local_dir, got #{r.inspect}"
      assert_equal File.expand_path(good_ruby), r["oracle_dir"]

      d_args, = assert_topo(
        "docker-args",
        "--topology", ws[:topo_path],
        env: { "RUBY_DIR" => good_ruby }
      )
      assert_includes d_args, "/external/campaign.rb:ro", "missing external campaign bind mount: #{d_args}"
      assert_includes d_args, "/external/src_ruby:ro", "missing external ruby bind mount: #{d_args}"
    end
  end

  def test_multi_source_pr_matrix_topology_and_plan_launch_without_grammar
    with_tmpdir("targets-sync-") do |workdir|
      upstream = PrismFuzzerTest::Fixtures.build_synthetic_upstream_prism(File.join(workdir, "upstream_prism"))
      cache_dir = File.join(workdir, "cache")
      matrix_build = File.join(workdir, "matrix_build")
      matrix_topo = File.join(workdir, "pr_matrix.json")

      uid = "#{Process.pid}-#{SecureRandom.hex(4)}"
      wid_pr = "pr-main-#{uid}"
      wid_rel = "rel-diff-#{uid}"
      wid_cur = "cur-diff-#{uid}"
      wid_none = "none-diff-#{uid}"

      matrix_ir = {
        "schema_version" => 2,
        "name" => "pr-matrix-test",
        "sources" => {
          "release" => { "kind" => "prism", "repo" => upstream[:repo], "ref" => upstream[:v1], "patches" => "auto", "templates" => "auto" },
          "main" => { "kind" => "prism", "repo" => upstream[:repo], "ref" => upstream[:v2], "patches" => "auto", "templates" => "auto" },
          "pr" => { "kind" => "prism", "repo" => upstream[:repo], "ref" => upstream[:v3], "patches" => "auto", "templates" => "auto" }
        },
        "coverage" => { "source" => "pr", "fuzzer" => "pr_fast" },
        "generators" => {
          "corpus" => { "kind" => "corpus", "source" => "pr", "dir" => "corpus", "fuzzer" => "pr_fast" }
        },
        "fuzzers" => {
          "pr_fast" => { "shape" => "prism_parse", "source" => "pr", "sanitizers" => %w[asan ubsan], "mode" => "fast", "afl" => "lto", "document_ids" => true },
          "vs_release" => { "shape" => "prism_diff_prism", "prism_a" => "release", "prism_b" => "pr", "sanitizers" => %w[asan ubsan], "afl" => "pcguard", "document_ids" => true },
          "vs_main" => { "shape" => "prism_diff_prism", "prism_a" => "main", "prism_b" => "pr", "sanitizers" => %w[asan ubsan], "afl" => "pcguard", "document_ids" => true }
        },
        "sync_groups" => {
          "san" => { "dir" => "afl-san", "primary" => true },
          "rel" => { "dir" => "afl-rel" },
          "cur" => { "dir" => "afl-main" }
        },
        "workers" => [
          {
            "id" => wid_pr,
            "kind" => "afl",
            "fuzzer" => "pr_fast",
            "sync_group" => "san",
            "afl_role" => "main",
            "schedule" => "exploit",
            "seeds" => { "from" => "corpus" },
            "color" => "#60a5fa"
          },
          {
            "id" => wid_rel,
            "kind" => "afl",
            "fuzzer" => "vs_release",
            "sync_group" => "rel",
            "afl_role" => "main",
            "schedule" => "explore",
            "seeds" => { "from" => "corpus", "filter" => "self_pass", "cache_key" => "rel" },
            "peer_imports" => [{ "group" => "san", "worker" => wid_pr, "alias" => "san_peer" }],
            "color" => "#f97316"
          },
          {
            "id" => wid_cur,
            "kind" => "afl",
            "fuzzer" => "vs_main",
            "sync_group" => "cur",
            "afl_role" => "main",
            "schedule" => "fast",
            "seeds" => { "from" => "corpus", "shard_group" => "g" },
            "color" => "#facc15"
          }
        ]
      }
      File.write(matrix_topo, JSON.pretty_generate(matrix_ir))

      sync_out, = assert_topo(
        "sync",
        "--topology", matrix_topo,
        "--build-dir", matrix_build,
        "--cache-dir", cache_dir,
        "--json"
      )
      d = JSON.parse(sync_out)

      %w[release main pr].each do |sid|
        src_path = d.dig("sources", sid, "path")
        refute_nil src_path, "missing source #{sid}"
        assert_path_exists File.join(src_path, "include", "prism.h")
        assert_equal File.join(matrix_build, "fuzz.explain.#{sid}"), d.dig("explain_binaries", sid)
      end
      assert_empty d["grammar_ext_sources"], "expected no grammar_ext_sources when grammar generator is omitted"

      # Re-sync offline using populated cache to match offline multi-source reuse.
      assert_topo(
        "sync",
        "--topology", matrix_topo,
        "--build-dir", matrix_build,
        "--cache-dir", cache_dir,
        "--json",
        env: { "TARGETS_OFFLINE" => "1" }
      )

      matrix_fuzz = File.join(workdir, "matrix_fuzz")
      matrix_bin = File.join(matrix_fuzz, "bin")
      matrix_corpus = File.join(matrix_fuzz, "corpus")
      FileUtils.mkdir_p([matrix_bin, matrix_corpus])
      FileUtils.cp(File.join(matrix_build, "topology.resolved.json"), File.join(matrix_bin, "topology.json"))

      write_executable(File.join(matrix_bin, "pr_fast"), "#!/bin/sh\nexit 0\n")
      write_executable(File.join(matrix_bin, "vs_release"), "#!/bin/sh\ngrep -q \"PASS_REL\" \"$1\"\n")
      write_executable(File.join(matrix_bin, "vs_main"), "#!/bin/sh\nexit 0\n")

      seed_pass = File.join(matrix_corpus, "seed_pass")
      seed_drop = File.join(matrix_corpus, "seed_drop")
      File.binwrite(seed_pass, seed_bytes("PASS_REL\n"))
      File.binwrite(seed_drop, seed_bytes("DROP_REL\n"))

      afl_tmpdirs = [wid_pr, wid_rel, wid_cur, wid_none].map { |wid| File.join("/tmp/afl-tmpdir", wid) }

      begin
        launch_out, = assert_topo(
          "plan-launch",
          "--topology", matrix_topo,
          "--build-dir", matrix_build,
          "--fuzz-dir", matrix_fuzz,
          "--corpus-dir", matrix_corpus,
          "--bin-dir", matrix_bin
        )
        lp = JSON.parse(launch_out)

        assert_equal [wid_pr, wid_rel, wid_cur], lp["worker_names"]
        assert_empty lp["generator_seeds_dirs"]
        assert_equal true, lp["staged"]

        w_pr = lp["workers"].find { |w| w["id"] == wid_pr }
        w_rel = lp["workers"].find { |w| w["id"] == wid_rel }
        w_cur = lp["workers"].find { |w| w["id"] == wid_cur }
        refute_nil w_pr
        refute_nil w_rel
        refute_nil w_cur

        assert_equal true, w_pr["staged"]
        assert_equal true, w_pr.dig("seeds", "staged")
        assert_equal matrix_corpus, w_pr["input_dir"]

        assert_equal true, w_rel["staged"]
        assert_equal "self_pass", w_rel.dig("seeds", "filter")
        assert_equal true, w_rel.dig("seeds", "staged")
        assert_equal [seed_pass], w_rel.dig("seeds", "selected_files")
        assert_equal File.join("/tmp/afl-tmpdir", wid_rel, "seeds"), w_rel["input_dir"]

        assert_equal true, w_cur["staged"]
        assert_equal true, w_cur.dig("seeds", "staged")
        assert_equal 0, w_cur.dig("seeds", "shard_index")
        assert_equal 1, w_cur.dig("seeds", "shard_total")
        assert_equal [seed_drop, seed_pass].sort, w_cur.dig("seeds", "selected_files").sort
        assert_equal File.join("/tmp/afl-tmpdir", wid_cur, "seeds"), w_cur["input_dir"]

        san_peer_queue = File.join(matrix_fuzz, "afl-rel", "san_peer", "queue")
        assert File.symlink?(san_peer_queue), "expected shadow peer queue symlink afl-rel/san_peer/queue"

        assert_path_exists File.join("/tmp/afl-tmpdir", wid_rel, "seeds", "seed_pass"),
                           "expected self_pass filter to keep seed_pass"
        refute_path_exists File.join("/tmp/afl-tmpdir", wid_rel, "seeds", "seed_drop"),
                           "expected self_pass filter to drop seed_drop"
        assert_path_exists File.join("/tmp/afl-tmpdir", wid_cur, "seeds", "seed_pass")
        assert_path_exists File.join("/tmp/afl-tmpdir", wid_cur, "seeds", "seed_drop")

        # Verify plan-launch fails clearly when self_pass rejects all corpus seeds.
        empty_fuzz = File.join(workdir, "empty_pass_fuzz")
        empty_build = File.join(workdir, "empty_pass_build")
        empty_bin = File.join(empty_fuzz, "bin")
        FileUtils.mkdir_p([empty_bin, empty_build])
        vs_none = write_executable(File.join(empty_bin, "vs_none"), "#!/bin/sh\nexit 1\n")

        empty_topo = File.join(workdir, "empty_pass.json")
        empty_ir = {
          "schema_version" => 2,
          "name" => "empty-pass",
          "sources" => { "prism_a" => { "kind" => "prism", "repo" => upstream[:repo], "ref" => upstream[:v1] } },
          "generators" => { "corpus" => { "kind" => "corpus", "source" => "prism_a", "fuzzer" => "vs_none" } },
          "fuzzers" => { "vs_none" => { "shape" => "prism_parse", "source" => "prism_a", "binary" => vs_none } },
          "sync_groups" => { "main" => { "dir" => "afl", "primary" => true } },
          "workers" => [
            {
              "id" => wid_none,
              "kind" => "afl",
              "fuzzer" => "vs_none",
              "sync_group" => "main",
              "afl_role" => "main",
              "seeds" => { "from" => "corpus", "filter" => "self_pass" }
            }
          ]
        }
        File.write(empty_topo, JSON.pretty_generate(empty_ir))

        err_out, err_err, err_st = run_topo(
          "plan-launch",
          "--topology", empty_topo,
          "--build-dir", empty_build,
          "--fuzz-dir", empty_fuzz,
          "--corpus-dir", matrix_corpus,
          "--bin-dir", empty_bin
        )
        refute err_st.success?, "expected plan-launch to fail when self_pass matches 0 seeds"
        assert_includes(err_out + err_err, "matched 0 of")
      ensure
        afl_tmpdirs.each { |d_path| FileUtils.rm_rf(d_path) }
      end
    end
  end

  def test_three_way_patch_fallback_uses_mirror_object_alternates
    with_tmpdir("targets-3way-") do |workdir|
      ws = prepare_dsl_workspace(workdir)
      repo = ws[:upstream][:repo]

      # Checkout v1 in synthetic upstream and:
      # 1. Tweak outer context in include/prism/internal/arena.h so 0001 exercises `-C1 --index`.
      # 2. Tweak immediate 1-line context in include/prism/compiler/inline.h (whose v1 blob
      #    matches 0004's exact preimage SHA in the cached mirror) so 0004 MUST fall back to
      #    `git apply --3way` via GIT_ALTERNATE_OBJECT_DIRECTORIES *after* 0003 has already
      #    modified src/integer.c (which 0004 also patches).
      arena_h = File.join(repo, "include/prism/internal/arena.h")
      inline_h = File.join(repo, "include/prism/compiler/inline.h")
      run_cmd("git", "-C", repo, "checkout", "-q", ws[:upstream][:v1])
      File.write(
        arena_h,
        File.read(arena_h).sub(
          "    /* The number of bytes consumed so far. */",
          "    /* Bytes consumed so far (upstream doc tweak shifting 0001 context). */"
        )
      )
      File.write(
        inline_h,
        File.read(inline_h).sub(
          "#   define PRISM_INLINE inline\n#endif\n",
          "#   define PRISM_INLINE inline\n#endif /* _MSC_VER */\n"
        )
      )
      run_cmd("git", "-C", repo, "add", "include/prism/internal/arena.h", "include/prism/compiler/inline.h")
      run_cmd("git", "-C", repo, "commit", "-q", "-m", "Upstream context tweaks requiring -C1 and chained 3-way")
      v4_sha, = run_cmd("git", "-C", repo, "rev-parse", "HEAD")
      v4_sha = v4_sha.strip

      sync_out, = assert_topo(
        "sync",
        "--topology", ws[:topo_path],
        "--build-dir", ws[:build_dir],
        "--cache-dir", ws[:cache_dir],
        "--json",
        env: { "PRISM_B_REF" => v4_sha }
      )
      d = JSON.parse(sync_out)
      b = d.dig("sources", "prism_b")
      refute_nil b
      assert_equal v4_sha, b["commit"]
      assert_equal 5, Array(b.dig("resolved", "applied_patches")).size
      merged_arena = File.read(File.join(b["path"], "include/prism/internal/arena.h"))
      assert_includes merged_arena, "pm_arena_align_t"
      assert_includes merged_arena, "upstream doc tweak shifting 0001 context"
      merged_inline = File.read(File.join(b["path"], "include/prism/compiler/inline.h"))
      assert_includes merged_inline, "#endif /* _MSC_VER */"
      assert_includes merged_inline, "#include \"prism/internal/ijon.h\""
      merged_integer = File.read(File.join(b["path"], "src/integer.c"))
      assert_includes merged_integer, "#ifndef PM_INTEGER_DIVIDE_THRESHOLD"
      assert_includes merged_integer, "PM_IJON_MAX(0x601u, level);"
    end
  end

  private

  def topo_cli
    repo_path("bin", "topology.rb")
  end

  def base_topo_env(overrides = {})
    {
      "PRISM_B_REF" => nil,
      "RUBY_DIR" => nil,
      "TARGETS_OFFLINE" => nil,
      "FUZZ_DIR" => nil,
      "FUZZ_BUILD_DIR" => nil,
      "TRIAGE_CORPUS_DIR" => nil
    }.merge(overrides)
  end

  def run_topo(*args, env: {})
    run_cmd(RbConfig.ruby, topo_cli, *args, env: base_topo_env(env), chdir: root_dir)
  end

  def assert_topo(*args, env: {}, msg: nil)
    assert_ruby_cmd(topo_cli, *args, env: base_topo_env(env), chdir: root_dir, msg: msg)
  end

  def prepare_dsl_workspace(workdir)
    upstream = PrismFuzzerTest::Fixtures.build_synthetic_upstream_prism(File.join(workdir, "upstream_prism"))
    build_dir = File.join(workdir, "build")
    cache_dir = File.join(workdir, "cache")
    topo_path = File.join(workdir, "topology.rb")

    ruby_ref = File.read(repo_path("docker/Dockerfile"))[/^ARG RUBY_GIT_REF=([0-9a-f]+)/, 1] || "495f3778a4020ecc828083239e945e60c51245ae"

    File.write(topo_path, <<~RUBY)
      b_ref = ENV["PRISM_B_REF"].to_s.strip
      b_ref = nil if b_ref.empty?

      PrismFuzzer.campaign "test-default-topo" do
        prism :prism_a, repo: #{upstream[:repo].inspect}, ref: #{upstream[:v1].inspect}, patches: "auto", templates: "auto"
        if b_ref
          prism :prism_b, repo: #{upstream[:repo].inspect}, ref: b_ref, patches: "auto", templates: "auto"
        end
        ruby :ruby, repo: "https://example.invalid/ruby.git",
                    ref: #{ruby_ref.inspect},
                    dir: ENV["RUBY_DIR"]

        fuzzer "fuzz", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto, document_ids: true
        if b_ref
          fuzzer "fuzz.prism_diff", shape: :prism_diff_prism, prism_a: :prism_a, prism_b: :prism_b, sanitizers: %i[asan ubsan], afl: :pcguard
        end

        sync_group :afl, dir: "afl", primary: true

        worker_specs = [
          { id: :main, fuzzer: "fuzz", afl_role: :main, schedule: "exploit" }
        ]
        if b_ref
          worker_specs << { id: :pdiff, fuzzer: "fuzz.prism_diff", afl_role: :secondary }
        end
        workers worker_specs, kind: :afl, sync_group: :afl do |w, cfg|
          w.color(cfg[:afl_role] == :main ? "#60a5fa" : "#facc15")
        end
      end
    RUBY

    { upstream: upstream, build_dir: build_dir, cache_dir: cache_dir, topo_path: topo_path }
  end
end
