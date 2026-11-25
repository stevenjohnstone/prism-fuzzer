# frozen_string_literal: true

require_relative "../lib/autorun"

require "digest"
require "json"
require "set"

require_relative "../../triage/triage"

class TriagePipelineTest < Minitest::Test
  CLEAN_TRIAGE_ENV = {
    "FUZZ_DIR" => nil,
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
    "HALFEMPTY_MAX_TIME" => nil,
    "TRIAGE_HANG_MINIMIZE_MAX_TIME" => nil,
    "TRIAGE_EXPLAIN_BIN" => nil,
    "TRIAGE_DIGEST" => nil,
    "AFL_SHOWMAP" => nil
  }.freeze

  def c_compiler
    cc = ENV.fetch("CC", "").strip
    cc.empty? ? "clang" : cc
  end

  def compile_synth_target(workdir)
    src = File.join(workdir, "synth_target.c")
    bin = File.join(workdir, "synth_target")
    File.write(src, <<~'C')
      #define _GNU_SOURCE
      #include <signal.h>
      #include <stdint.h>
      #include <stdio.h>
      #include <stdlib.h>
      #include <string.h>

      __attribute__((noreturn, noinline))
      static void fail_invariant_at_shared_site(const char *diag_type, size_t start, size_t parsed_size) {
          fprintf(
              stderr,
              "INVARIANT[diagnostic]: list=error type=%s kind=end_oob [detail: level=0 start=%zu length=4 parsed_size=%zu]\n"
              "    #0 0x1000 in fail_invariant_at_shared_site /prism/harnesses/prism/parse.c:90:5\n"
              "    #1 0x1010 in harness_parse /prism/harnesses/prism/parse.c:550:13\n",
              diag_type,
              start,
              parsed_size
          );
          fflush(stderr);
          abort();
      }

      int main(int argc, char **argv) {
          if (argc < 2) return 0;
          FILE *f = fopen(argv[1], "rb");
          if (!f) return 0;
          if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 0; }
          long n = ftell(f);
          if (n < 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return 0; }
          uint8_t *buf = malloc((size_t)(n > 0 ? n : 1));
          if (!buf) { fclose(f); return 0; }
          if (n > 0 && fread(buf, 1, (size_t)n, f) != (size_t)n) {
              free(buf);
              fclose(f);
              return 0;
          }
          fclose(f);

          if (n < 4) {
              free(buf);
              return 0;
          }

          const uint8_t *body = buf + 4;
          size_t body_len = (size_t)(n - 4);

          if ((buf[0] & 0x08) && body_len == 0) {
              fprintf(stderr, "fuzz: src/prism.c:11: empty_body: Assertion `0' failed.\n");
              free(buf);
              abort();
          }
          if ((buf[0] & 0x02) && body_len >= 4 && memmem(body, body_len, "BOOM", 4) != NULL) {
              fprintf(stderr, "fuzz: src/prism.c:42: bug_a: Assertion `0' failed.\n");
              free(buf);
              abort();
          }
          if (body_len >= 9 && memmem(body, body_len, "ALT_CRASH", 9) != NULL) {
              fprintf(stderr, "fuzz: src/prism.c:84: bug_b: Assertion `0' failed.\n");
              free(buf);
              abort();
          }
          if ((buf[0] & 0x04) && body_len >= 4 && memmem(body, body_len, "SEGV", 4) != NULL) {
              free(buf);
              raise(SIGSEGV);
          }
          if (buf[0] & 0x10) {
              const uint8_t *target = body_len >= 10 ? (const uint8_t *)memmem(body, body_len, "INV_TARGET", 10) : NULL;
              if (target != NULL) {
                  size_t off = (size_t)(target - body);
                  free(buf);
                  fail_invariant_at_shared_site("heredoc_term", off, body_len);
              }
              const uint8_t *decoy = body_len >= 9 ? (const uint8_t *)memmem(body, body_len, "INV_DECOY", 9) : NULL;
              if (decoy != NULL) {
                  size_t off = (size_t)(decoy - body);
                  free(buf);
                  fail_invariant_at_shared_site("escape_invalid_meta", off, body_len);
              }
          }

          free(buf);
          return 0;
      }
    C
    assert_cmd(c_compiler, "-O2", "-std=c99", src, "-o", bin)
    bin
  end

  def write_pipeline_crash_fixtures(afl_dir, synth_bin)
    FileUtils.mkdir_p([
      File.join(afl_dir, "w1", "crashes"),
      File.join(afl_dir, "w2", "crashes"),
      File.join(afl_dir, "w1", "hangs")
    ])
    File.write(File.join(afl_dir, "w1", "cmdline"), "#{synth_bin}\n")
    File.write(File.join(afl_dir, "w2", "cmdline"), "#{synth_bin}\n")

    hdr = "\x2a\x11\x22\x33".b
    4.times do |i|
      body = ("x_#{i} = 123\n".b * 10) + "BOOM\n".b + ("y_#{i} = 456\n".b * 10)
      File.binwrite(File.join(afl_dir, "w1", "crashes", "id:00000#{i},sig:06"), hdr + body)
    end

    # Byte-identical duplicate across workers
    dup = File.binread(File.join(afl_dir, "w1", "crashes", "id:000000,sig:06"))
    File.binwrite(File.join(afl_dir, "w2", "crashes", "id:000000,sig:06"), dup)

    # Two distinct INVARIANT[...] crashes sharing an identical C call stack (plus a shifted-offset duplicate)
    inv_hdr = "\x10\x44\x55\x66".b
    inv_first_path = File.join(afl_dir, "w1", "crashes", "id:000010,sig:06,time:42100")
    inv_later_path = File.join(afl_dir, "w2", "crashes", "id:000011,sig:06,time:95000")
    File.binwrite(inv_first_path, inv_hdr + ("a = 1\n".b * 8) + "INV_TARGET\n".b)
    File.binwrite(inv_later_path, inv_hdr + ("b = 222\n".b * 20) + "INV_TARGET\n".b)
    t_now = Time.now
    File.utime(t_now - 60, t_now - 60, inv_first_path)
    File.utime(t_now - 10, t_now - 10, inv_later_path)
    File.binwrite(File.join(afl_dir, "w1", "crashes", "id:000012,sig:06"), inv_hdr + ("c = 3\n".b * 8) + "INV_DECOY\n".b)

    # Unreproducible crash (sig:06, exits 0 on replay)
    unrepro_bytes = "\x00\x00\x03\x011 + 1\n".b
    File.binwrite(File.join(afl_dir, "w1", "crashes", "id:000098,sig:06"), unrepro_bytes)

    # External OOM SIGKILL (sig:09, exits 0 on replay -> skipped)
    sig09_bytes = "\x00\x00\x03\x01ok\n".b
    File.binwrite(File.join(afl_dir, "w1", "crashes", "id:000099,sig:09"), sig09_bytes)

    # Transient timeout in hangs/ (exits 0 on replay -> skipped)
    hang_bytes = "\x00\x00\x03\x01ok_hang\n".b
    File.binwrite(File.join(afl_dir, "w1", "hangs", "id:000000,src:000001"), hang_bytes)

    {
      sig09_sha: Digest::SHA2.hexdigest(sig09_bytes),
      hang_sha: Digest::SHA2.hexdigest(hang_bytes)
    }
  end

  def verify_abrt_buckets(triage_dir, log)
    abrt_dirs = Dir.glob(File.join(triage_dir, "ABRT", "*")).sort
    assert_equal 3, abrt_dirs.size,
                 "expected 3 ABRT dirs (BOOM + heredoc_term + escape_invalid_meta), got #{abrt_dirs.inspect}\nlog:\n#{log}"

    tokens_found = []
    counts_by_token = {}
    abrt_dirs.each do |abrt_dir|
      mode = File.stat(abrt_dir).mode & 0o777
      assert_equal 0o755, mode & 0o755, "expected world-readable/traversable dir mode, got #{format('%#o', mode)}"

      refute_path_exists File.join(abrt_dir, "testcase.c"), "unexpected testcase.c in #{abrt_dir}"
      refute_path_exists File.join(abrt_dir, "build.sh"), "unexpected build.sh in #{abrt_dir}"

      verify_path = File.join(abrt_dir, "verify.sh")
      assert_path_exists verify_path, "missing verify.sh in #{abrt_dir}"
      assert File.executable?(verify_path), "verify.sh is not executable in #{abrt_dir}"
      assert_includes File.read(verify_path), '--profile "asan_ubsan"'
      assert_cmd("bash", "-n", verify_path)

      archive_path = File.join(abrt_dir, "inputs.tar.gz")
      assert File.file?(archive_path), "missing inputs.tar.gz in #{abrt_dir}"
      refute_path_exists File.join(abrt_dir, ".inputs.pending"), "unexpected leftover .inputs.pending in #{abrt_dir}"
      meta_path = File.join(abrt_dir, "meta.json")
      assert File.file?(meta_path), "missing meta.json in #{abrt_dir}"
      assert File.file?(File.join(abrt_dir, "occurrences.jsonl")), "missing occurrences.jsonl in #{abrt_dir}"

      meta = JSON.parse(File.read(meta_path))
      assert_equal meta.dig("occurrences", "count"), meta.dig("archive", "count"),
                   "archive count != occurrences count in #{abrt_dir}"
      assert_equal meta.dig("occurrences", "count"),
                   FuzzTriage.read_tar_gz_entries(archive_path, include_bytes: false)[:entries].size,
                   "inputs.tar.gz entry count mismatch in #{abrt_dir}"
      assert_equal "asan_ubsan", meta["verify_profile"]
      assert_equal false, meta.dig("coverage", "available"),
                   "expected coverage disabled in uninstrumented test, got #{meta['coverage'].inspect}"

      min_data = File.binread(File.join(abrt_dir, "input.min"))
      body = min_data.byteslice(4..)
      if body.include?("BOOM".b)
        assert_equal "\x02\x00\x03\x01".b, min_data.byteslice(0, 4)
        assert_operator min_data.bytesize, :<=, 12, "unexpected BOOM input.min size: #{min_data.dump}"
        assert_equal true, meta.dig("options", "partial_script")
        assert_equal "4.1", meta.dig("options", "ruby_version")
        assert_equal [], meta.dig("options", "command_line_flags")
        assert_equal 0, meta.dig("options", "scopes_count")
        assert_includes meta.dig("input", "loupe_url").to_s, "&partial=1"
        assert_equal "0", meta.dig("symptom", "assertion", "expr")
        assert_equal Digest::SHA256.hexdigest(body), meta.dig("input", "payload_sha256")
        assert_includes meta.dig("input", "source_preview").to_s, "BOOM"
        tokens_found << "BOOM"
        counts_by_token["BOOM"] = meta.dig("occurrences", "count")
      elsif body.include?("INV_TARGET".b)
        assert_equal "\x10\x00\x03\x01".b, min_data.byteslice(0, 4)
        assert_operator min_data.bytesize, :<=, 18, "unexpected INV_TARGET input.min size: #{min_data.dump}"
        assert_equal false, meta.dig("options", "frozen_string_literal")
        assert_equal "diagnostic", meta.dig("symptom", "invariant", "namespace")
        assert_equal "heredoc_term", meta.dig("symptom", "invariant", "fields", "type")
        assert_equal 2, meta["frames"].size
        assert_equal "fail_invariant_at_shared_site", meta["frames"][0]["func"]
        assert_equal({ "w1" => 1, "w2" => 1 }, meta.dig("occurrences", "by_worker"))
        assert_equal 42_100, meta.dig("occurrences", "first_elapsed_ms")
        tokens_found << "INV_TARGET"
        counts_by_token["INV_TARGET"] = meta.dig("occurrences", "count")
      elsif body.include?("INV_DECOY".b)
        assert_equal "\x10\x00\x03\x01".b, min_data.byteslice(0, 4)
        assert_operator min_data.bytesize, :<=, 18, "unexpected INV_DECOY input.min size: #{min_data.dump}"
        assert_equal "escape_invalid_meta", meta.dig("symptom", "invariant", "fields", "type")
        tokens_found << "INV_DECOY"
        counts_by_token["INV_DECOY"] = meta.dig("occurrences", "count")
      else
        flunk "unexpected minimized body in #{abrt_dir}: #{min_data.dump}"
      end
    end

    assert_equal %w[BOOM INV_DECOY INV_TARGET], tokens_found.sort
    assert_equal({ "BOOM" => 4, "INV_TARGET" => 2, "INV_DECOY" => 1 }, counts_by_token)
    abrt_dirs
  end

  def verify_coalescing_races(workdir)
    race_root = File.join(workdir, "coalesce_race")
    triage1 = File.join(race_root, "triage1")
    triage2 = File.join(race_root, "triage2")
    FileUtils.mkdir_p([
      File.join(race_root, "w1", "crashes"),
      File.join(race_root, "w2", "crashes"),
      File.join(race_root, "w3", "crashes"),
      File.join(triage1, ".processed"),
      File.join(triage2, ".processed")
    ])

    race_bin = write_executable(File.join(race_root, "race_fuzz"), <<~SH)
      #!/usr/bin/env bash
      echo "Assertion \\`race_boom' failed." >&2
      echo "SUMMARY: AddressSanitizer: ABRT race.c:10" >&2
      exit 134
    SH

    bytes1 = "\x00\x00\x03\x01race_one\n".b
    bytes2 = "\x00\x00\x03\x01race_two\n".b
    h2 = Digest::SHA2.hexdigest(bytes2)
    c1 = File.join(race_root, "w1", "crashes", "id:000000,sig:06,time:100")
    c2 = File.join(race_root, "w2", "crashes", "id:000000,sig:06,time:200")
    c2_dup = File.join(race_root, "w3", "crashes", "id:000000,sig:06,time:300")
    File.binwrite(c1, bytes1)
    File.binwrite(c2, bytes2)
    File.binwrite(c2_dup, bytes2)

    race_triage = Module.new
    race_triage.extend(FuzzTriage)
    orig_classify = FuzzTriage.method(:classify_crash_execution)
    classify_calls = Hash.new(0)
    min_hook = nil

    race_triage.define_singleton_method(:classify_crash_execution) do |*args, **kwargs|
      classify_calls[args[1]] += 1
      orig_classify.call(*args, **kwargs)
    end
    race_triage.define_singleton_method(:minimize) do |*args, **kwargs|
      if min_hook
        min_hook.call(*args, **kwargs)
      else
        FileUtils.cp(args[0], args[2])
      end
    end

    capture_io do
      # Scenario 1: duplicate h2 from w3 arrives mid-minimization after w2 returned
      entered_min = Queue.new
      release_min = Queue.new
      sem1 = Mutex.new
      in_prog1 = Set.new
      ps1 = {}; po1 = {}; pi1 = {}; ph1 = {}; pr1 = {}
      rec1 = Set.new; arch1 = Set.new
      min_hook = lambda do |src, _r, dst, _e, _sl|
        FileUtils.cp(src, dst)
        if src == c1
          entered_min.push(true)
          release_min.pop
        end
      end

      t_leader = Thread.new do
        race_triage.process_crash(
          File.dirname(c1), c1, race_bin, sem1, in_prog1, ps1, po1, pi1, rec1, arch1,
          testcases_dir: triage1, pending_hashes: ph1, pending_retries: pr1
        )
      rescue StandardError => e
        entered_min.push(e)
        raise
      end

      gate1 = entered_min.pop
      raise gate1 if gate1.is_a?(Exception)

      # c2 coalesces while t_leader is paused in minimize
      race_triage.process_crash(
        File.dirname(c2), c2, race_bin, sem1, in_prog1, ps1, po1, pi1, rec1, arch1,
        testcases_dir: triage1, pending_hashes: ph1, pending_retries: pr1
      )
      assert_includes in_prog1, h2, "expected h2 to stay in in_progress after coalescing"

      # Identical c2_dup arrives while t_leader is still in minimize -> must NOT re-classify or duplicate pending
      race_triage.process_crash(
        File.dirname(c2_dup), c2_dup, race_bin, sem1, in_prog1, ps1, po1, pi1, rec1, arch1,
        testcases_dir: triage1, pending_hashes: ph1, pending_retries: pr1
      )
      assert_equal 0, classify_calls[c2_dup],
                   "expected c2_dup not to re-run classify_crash_execution, count=#{classify_calls[c2_dup]}"

      release_min.push(true)
      t_leader.join
      assert_empty in_prog1, "expected empty in_progress after leader published, got #{in_prog1.to_a.inspect}"

      race_triage.finalize_triage_metadata(triage1, coverage_bin: "", diff_coverage_bin: "")
      meta1 = JSON.parse(File.read(File.join(triage1, "metadata.json")))
      b1 = meta1["buckets"].first
      refute_nil b1
      assert_equal 2, b1.dig("occurrences", "count"), "expected 2 unique occurrences (h1, h2), got #{b1.inspect}"
      assert_equal 2, b1.dig("archive", "count"), "expected 2 archived inputs (h1, h2), got #{b1.inspect}"

      # Scenario 2: leader raises exception during minimization -> orphaned c2 must still be published
      sem2 = Mutex.new
      in_prog2 = Set.new
      ps2 = {}; po2 = {}; pi2 = {}; ph2 = {}; pr2 = {}
      rec2 = Set.new; arch2 = Set.new
      entered_fail_min = Queue.new
      release_fail_min = Queue.new
      entered_ok = false
      min_hook = lambda do |src, _r, dst, _e, _sl|
        if src == c1
          entered_ok = true
          entered_fail_min.push(true)
          release_fail_min.pop
          raise "simulated minimize exception for c1"
        end
        FileUtils.cp(src, dst)
      end

      t_fail = Thread.new do
        race_triage.process_crash(
          File.dirname(c1), c1, race_bin, sem2, in_prog2, ps2, po2, pi2, rec2, arch2,
          testcases_dir: triage2, pending_hashes: ph2, pending_retries: pr2
        )
      rescue StandardError => e
        unless entered_ok && e.message == "simulated minimize exception for c1"
          entered_fail_min.push(e) unless entered_ok
          raise
        end
      end

      gate2 = entered_fail_min.pop
      raise gate2 if gate2.is_a?(Exception)

      race_triage.process_crash(
        File.dirname(c2), c2, race_bin, sem2, in_prog2, ps2, po2, pi2, rec2, arch2,
        testcases_dir: triage2, pending_hashes: ph2, pending_retries: pr2
      )
      release_fail_min.push(true)
      t_fail.join

      assert_empty in_prog2, "expected empty in_progress after leader exception recovery, got #{in_prog2.to_a.inspect}"
      assert File.file?(File.join(triage2, ".processed", h2)),
             "expected sentinel for coalesced sibling c2 after leader exception"
      race_triage.finalize_triage_metadata(triage2, coverage_bin: "", diff_coverage_bin: "")
      meta2 = JSON.parse(File.read(File.join(triage2, "metadata.json")))
      assert_equal 1, meta2.dig("summary", "bucket_count"), "expected orphaned sibling bucket in #{meta2.inspect}"
      assert_equal 1, meta2.dig("summary", "total_occurrences"), "expected orphaned sibling occurrence in #{meta2.inspect}"
    end
  end

  def test_concurrent_triage_dedup_minimization_coalescing_and_metadata
    with_tmpdir("triage-pipe-") do |workdir|
      with_env(CLEAN_TRIAGE_ENV) do
        synth_bin = compile_synth_target(workdir)
        afl_dir = File.join(workdir, "afl")
        triage_dir = File.join(workdir, "triage")
        fixture_info = write_pipeline_crash_fixtures(afl_dir, synth_bin)

        log, _err = capture_io do
          FuzzTriage.run_triage_pipeline(
            output_dirs: [afl_dir],
            testcases_dir: triage_dir,
            coverage_bin: "",
            diff_coverage_bin: "",
            threads: [FuzzTriage.env_triage_threads, 2].max
          )
        end

        abrt_dirs = verify_abrt_buckets(triage_dir, log)

        unrepro_dirs = Dir.glob(File.join(triage_dir, "unreproducible", "*"))
        assert_equal 1, unrepro_dirs.size, "expected 1 unreproducible dir, got #{unrepro_dirs.inspect}"
        refute_path_exists File.join(unrepro_dirs.first, "testcase.c")
        refute_path_exists File.join(unrepro_dirs.first, "build.sh")
        assert File.executable?(File.join(unrepro_dirs.first, "verify.sh"))
        assert File.file?(File.join(unrepro_dirs.first, "meta.json"))

        refute_path_exists File.join(triage_dir, "hang"), "transient hang should not create hang dir"
        min_runs = log.scan(/^minimizing /).size
        assert_equal 3, min_runs, "expected exactly 3 minimization runs across duplicates, got #{min_runs}:\n#{log}"

        sentinels = Dir.glob(File.join(triage_dir, ".processed", "*"))
        assert_equal 10, sentinels.size,
                     "expected 10 .processed sentinels (4 BOOM + 2 INV_TARGET + 1 INV_DECOY + 1 unrepro + 1 sig:09 + 1 hang)"
        assert_equal "#skip", File.read(File.join(triage_dir, ".processed", fixture_info[:sig09_sha])).strip
        assert_equal "#skip", File.read(File.join(triage_dir, ".processed", fixture_info[:hang_sha])).strip

        index_path = File.join(triage_dir, "metadata.json")
        assert File.file?(index_path), "missing consolidated metadata.json"
        index = JSON.parse(File.read(index_path))
        assert_equal 4, index.dig("summary", "bucket_count")
        assert_equal 8, index.dig("summary", "total_occurrences")

        clusters_path = File.join(triage_dir, "clusters.json")
        assert File.file?(clusters_path), "missing consolidated clusters.json"
        clusters = JSON.parse(File.read(clusters_path))
        assert_equal 1, clusters["schema_version"]
        refute_empty clusters.dig("summary", "first_seen").to_s
        inv_cluster = clusters["clusters"].find do |c|
          c["buckets"].any? { |b| b["headline"].to_s.include?("heredoc_term") }
        end
        refute_nil inv_cluster, "expected INV_TARGET cluster in #{clusters.inspect}"
        assert_equal 42_100, inv_cluster["first_elapsed_ms"]
        refute_empty inv_cluster["first_seen"].to_s

        # Verify format_source_preview safety and legacy meta.json payload backfill in finalize_triage_metadata
        p_ctrl = FuzzTriage.format_source_preview("a\nb\0\xff\u{1f600}".b)
        assert_equal "a\\nb\\0\\xff\u{1f600}", p_ctrl
        assert p_ctrl.valid_encoding?

        p_long = FuzzTriage.format_source_preview("x" * 200, max_chars: 20)
        assert_operator p_long.length, :<=, 20
        assert p_long.end_with?("...")

        first_meta_path = File.join(abrt_dirs.first, "meta.json")
        stale_meta = JSON.parse(File.read(first_meta_path))
        stale_meta["input"].delete("payload_sha256")
        stale_meta["input"].delete("source_preview")
        File.write(first_meta_path, JSON.pretty_generate(stale_meta))
        capture_io do
          FuzzTriage.finalize_triage_metadata(triage_dir, coverage_bin: "", diff_coverage_bin: "")
        end
        refreshed_meta = JSON.parse(File.read(first_meta_path))
        assert refreshed_meta.dig("input", "payload_sha256"), "expected finalize_triage_metadata to backfill payload_sha256"
        assert refreshed_meta.dig("input", "source_preview"), "expected finalize_triage_metadata to backfill source_preview"

        verify_coalescing_races(workdir)
        verify_topology_max_allocated_and_heartbeat(workdir)
      end
    end
  end

  def verify_topology_max_allocated_and_heartbeat(workdir)
    ws_256 = File.join(workdir, "ws_256_alloc")
    triage_256 = File.join(ws_256, "report", "triage")
    FileUtils.mkdir_p(triage_256)
    File.write(File.join(ws_256, "topology.json"), JSON.generate({
      "schema_version" => 2,
      "name" => "alloc-256-test",
      "workspace" => { "dir" => ws_256, "build_dir" => File.join(ws_256, "build"), "triage_dir" => triage_256 },
      "defaults" => { "max_input_size" => 8192, "max_allocated_mb" => 256 },
      "sources" => { "prism_a" => { "kind" => "prism", "repo" => "https://example.invalid/prism.git", "ref" => "main" } },
      "fuzzers" => { "fuzz" => { "shape" => "prism_parse", "source" => "prism_a", "sanitizers" => %w[asan ubsan] } },
      "sync_groups" => { "afl" => { "dir" => "afl" } },
      "workers" => []
    }))

    with_env("FUZZ_MAX_ALLOCATED" => nil) do
      FuzzTriage.with_cached_topology do
        assert_equal 256, FuzzTriage.env_max_allocated_mb(triage_dir: triage_256)
        san_env = FuzzTriage.env_sanitizer_env(triage_dir: triage_256)
        assert_includes san_env.fetch("MSAN_OPTIONS"), "max_allocation_size_mb=256"
        assert_includes san_env.fetch("ASAN_OPTIONS"), "max_allocation_size_mb=256"
      end
    end

    # Also verify fallback when topology.json is a minimal partial stub without full schema fields.
    ws_partial = File.join(workdir, "ws_partial_alloc")
    triage_partial = File.join(ws_partial, "report", "triage")
    FileUtils.mkdir_p(triage_partial)
    File.write(File.join(ws_partial, "topology.json"), JSON.generate({ "defaults" => { "max_allocated_mb" => 384 } }))
    with_env("FUZZ_MAX_ALLOCATED" => nil) do
      assert_equal 384, FuzzTriage.env_max_allocated_mb(triage_dir: triage_partial)
    end

    require_relative "../../runtime/campaign"
    camp_rb = File.join(workdir, "camp_alloc_256.rb")
    File.write(camp_rb, <<~RB)
      PrismFuzzer.campaign "camp-alloc-256" do
        workspace #{ws_256.inspect}
        defaults max_input_size: 8192, max_allocated_mb: 256
        prism :prism_a, repo: "https://example.invalid/prism.git", ref: "main"
        fuzzer "fuzz", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan]
        sync_group :afl, dir: "afl", primary: true
        worker :w1, fuzzer: "fuzz", sync_group: :afl, afl_role: :main
      end
    RB
    with_env("FUZZ_MAX_ALLOCATED" => nil) do
      ctx = PrismFuzzer::Campaign.resolve_context(campaign_path: camp_rb, cli: {})
      captured_env = nil
      sc = PrismFuzzer::Campaign.singleton_class
      orig_ric = PrismFuzzer::Campaign.method(:run_in_container!)
      orig_edi = PrismFuzzer::Campaign.method(:ensure_docker_image!)
      begin
        sc.undef_method(:ensure_docker_image!)
        sc.define_method(:ensure_docker_image!) { |**_kw| true }
        sc.undef_method(:run_in_container!)
        sc.define_method(:run_in_container!) do |c, cmd_args, **kw|
          captured_env = kw[:extra_env]
          puts PrismFuzzer::Campaign.docker_cmd_for(c, cmd_args, extra_env: kw[:extra_env] || {}).join(" ")
          true
        end
        dry_triage, = capture_io { PrismFuzzer::Campaign.run_triage!(ctx, dry_run: true) }
      ensure
        sc.undef_method(:run_in_container!) if sc.method_defined?(:run_in_container!)
        sc.define_method(:run_in_container!, orig_ric)
        sc.undef_method(:ensure_docker_image!) if sc.method_defined?(:ensure_docker_image!)
        sc.define_method(:ensure_docker_image!, orig_edi)
      end
      assert_equal "256", captured_env&.fetch("FUZZ_MAX_ALLOCATED", nil)
      assert_includes dry_triage, "-e FUZZ_MAX_ALLOCATED=256",
                      "expected Campaign.run_triage! to forward defaults.max_allocated_mb=256:\n#{dry_triage}"
    end

    # Verify in-flight minimization heartbeat emits live progress lines when a slow minimization is running.
    hb_root = File.join(workdir, "hb_triage")
    hb_afl = File.join(hb_root, "afl", "w1", "crashes")
    hb_out_dir = File.join(hb_root, "triage")
    FileUtils.mkdir_p([hb_afl, hb_out_dir])
    hb_bin = write_executable(File.join(hb_root, "hb_fuzz"), "#!/bin/sh\necho 'Assertion `hb' failed.' >&2\nexit 134\n")
    File.write(File.join(hb_root, "afl", "w1", "cmdline"), "#{hb_bin}\n")
    File.binwrite(File.join(hb_afl, "id:000000,sig:06"), "\x00\x00\x03\x01hb_boom\n".b)

    hb_mod = Module.new
    hb_mod.extend(FuzzTriage)
    hb_mod.define_singleton_method(:minimize) do |src, _r, dst, _e, _sl|
      sleep 0.12
      FileUtils.cp(src, dst)
    end
    hb_log, = capture_io do
      with_env("TRIAGE_HEARTBEAT_SECONDS" => "0.04") do
        hb_mod.run_triage_pipeline(
          output_dirs: [File.join(hb_root, "afl")],
          testcases_dir: hb_out_dir,
          coverage_bin: "",
          diff_coverage_bin: "",
          threads: 2
        )
      end
    end
    assert_includes hb_log, "[triage] still minimizing 1 bucket(s):"
    verify_bounded_hang_minimization(workdir)
  end

  def verify_bounded_hang_minimization(workdir)
    hang_dir = File.join(workdir, "hang_min_bound")
    bin_dir = File.join(hang_dir, "bin")
    FileUtils.mkdir_p(bin_dir)
    raw_hang = File.join(hang_dir, "raw_hang.bin")
    File.binwrite(raw_hang, ("\x00\x00\x03\x01" + ("@" * 4096)).b)
    target_exe = write_executable(File.join(hang_dir, "dummy_target"), "#!/bin/sh\nexit 0\n")

    # 1) afl-tmin catches SIGINT on timeout and flushes its best partial candidate to -o.
    write_executable(File.join(bin_dir, "afl-tmin"), <<~'RB')
      #!/usr/bin/env ruby
      out_idx = ARGV.index("-o")
      out_path = out_idx ? ARGV[out_idx + 1] : nil
      Signal.trap("INT") do
        File.binwrite(out_path, "\x00\x00\x03\x01@@@\n".b) if out_path
        exit 130
      end
      sleep 30
    RB

    min_int = File.join(hang_dir, "min_int.bin")
    t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    with_env("PATH" => "#{bin_dir}:#{ENV.fetch('PATH', '')}", "TRIAGE_HANG_MINIMIZE_MAX_TIME" => "0.15") do
      capture_io { FuzzTriage.minimize(raw_hang, "hang", min_int, target_exe, 10) }
    end
    dt_int = Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0
    assert_operator dt_int, :<, 3.0, "expected SIGINT-bounded hang minimization to finish promptly (got #{dt_int}s)"
    assert_equal "\x00\x00\x03\x01@@@\n".b, File.binread(min_int)

    # 2) Wedged afl-tmin ignoring SIGINT is SIGKILLed after grace window and falls back to raw crash bytes.
    write_executable(File.join(bin_dir, "afl-tmin"), <<~'RB')
      #!/usr/bin/env ruby
      Signal.trap("INT", "IGNORE")
      sleep 30
    RB

    min_kill = File.join(hang_dir, "min_kill.bin")
    t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    with_env("PATH" => "#{bin_dir}:#{ENV.fetch('PATH', '')}") do
      _, _, timed_out = FuzzTriage.run_bounded_pgroup(
        {}, File.join(bin_dir, "afl-tmin"),
        max_time_sec: 0.1, stop_signal: "INT", grace_sec: 0.15
      )
      assert timed_out, "expected wedged afl-tmin to report timed_out"
    end
    dt_kill = Process.clock_gettime(Process::CLOCK_MONOTONIC) - t1
    assert_operator dt_kill, :<, 3.0, "expected SIGKILL escalation to terminate wedged afl-tmin promptly (got #{dt_kill}s)"

    with_env("PATH" => "#{bin_dir}:#{ENV.fetch('PATH', '')}", "TRIAGE_HANG_MINIMIZE_MAX_TIME" => "0.1") do
      capture_io { FuzzTriage.minimize(raw_hang, "hang", min_kill, target_exe, 10) }
    end
    assert_equal File.binread(raw_hang), File.binread(min_kill),
                 "expected fallback copy of raw hang when afl-tmin exits without writing -o"
  end

  def test_afl_showmap_bucket_coverage_edge_df_document_ids_cache_and_recount
    skip "afl-clang-lto / afl-showmap / build/afl unavailable" unless afl_lto_ready?

    with_tmpdir("triage-pipe-") do |workdir|
      with_env(CLEAN_TRIAGE_ENV) do
        cov_src = File.join(workdir, "cov_target.c")
        cov_bin = File.join(workdir, "cov_target")
        cov_ids = File.join(workdir, "cov_target.ids")

        File.write(cov_src, <<~'C')
          #include <stdint.h>
          #include <stdio.h>
          #include <stdlib.h>

          __attribute__((noinline)) static void common_path(void) { asm volatile(""); }
          __attribute__((noinline)) static void rare_corpus_path(void) { asm volatile(""); }
          __attribute__((noinline)) static void bug_recovery_helper(void) {
              fprintf(stderr, "INVARIANT[node_location]: type=PM_CALL_NODE kind=length_underflow [detail: start=1 length=9 parsed_size=2]\n");
              abort();
          }

          int main(int argc, char **argv) {
              if (argc < 2) return 0;
              FILE *f = fopen(argv[1], "rb");
              if (!f) return 0;
              uint8_t buf[64];
              size_t n = fread(buf, 1, sizeof(buf), f);
              fclose(f);
              if (n < 5) return 0;
              uint8_t op = buf[4];
              common_path();
              if (op == 'R') rare_corpus_path();
              if (op == 'B') bug_recovery_helper();
              return 0;
          }
        C

        FileUtils.rm_f(cov_ids)
        assert_cmd(
          "afl-clang-lto", "-O1", "-g", cov_src, "-o", cov_bin,
          env: { "AFL_PATH" => afl_build_dir, "AFL_LLVM_DOCUMENT_IDS" => cov_ids }
        )
        assert File.file?(cov_ids), "expected AFL_LLVM_DOCUMENT_IDS output at #{cov_ids}"

        corpus_dir = File.join(workdir, "corpus")
        afl_cov_dir = File.join(workdir, "afl_cov")
        triage_dir = File.join(workdir, "triage_cov")
        FileUtils.mkdir_p([
          corpus_dir,
          File.join(afl_cov_dir, "m1", "crashes"),
          File.join(afl_cov_dir, "m2", "crashes")
        ])

        File.binwrite(File.join(corpus_dir, "c1.rb"), "\x00\x00\x03\x01cccc".b)
        File.binwrite(File.join(corpus_dir, "c2.rb"), "\x00\x00\x03\x01dddd".b)
        File.binwrite(File.join(corpus_dir, "r1.rb"), "\x00\x00\x03\x01Rrrr".b)

        File.write(File.join(afl_cov_dir, "m1", "cmdline"), "#{cov_bin}\n")
        File.write(File.join(afl_cov_dir, "m2", "cmdline"), "#{cov_bin}\n")
        File.binwrite(File.join(afl_cov_dir, "m1", "crashes", "id:000001,sig:06"), "\x00\x00\x03\x01Bxyz".b)
        File.binwrite(File.join(afl_cov_dir, "m2", "crashes", "id:000002,sig:06"), "\x00\x00\x03\x01B123".b)

        out1, _err1 = capture_io do
          FuzzTriage.run_triage_pipeline(
            output_dirs: [afl_cov_dir],
            testcases_dir: triage_dir,
            coverage_bin: cov_bin,
            coverage_ids: cov_ids,
            corpus_dir: corpus_dir,
            threads: [FuzzTriage.env_triage_threads, 2].max
          )
        end

        assert_includes out1, "Collecting afl-showmap prism corpus baseline"
        cache_path = File.join(triage_dir, ".corpus-coverage.json")
        assert File.file?(cache_path), "expected corpus coverage cache at #{cache_path}"

        index = JSON.parse(File.read(File.join(triage_dir, "metadata.json")))
        assert index.dig("reference_binary", "available"), "expected reference binary available"
        assert index.dig("reference_binary", "ids_available"), "expected reference binary DOCUMENT_IDS available"
        assert_equal 3, index.dig("corpus", "corpus_count")

        edge_df = index.dig("corpus", "edge_df") || {}
        edge_fns = index.dig("corpus", "edge_functions") || {}
        refute_empty edge_df, "expected non-empty edge_df"
        refute_empty edge_fns, "expected non-empty edge_functions"
        assert_includes edge_fns.values, "main", "expected DOCUMENT_IDS to record main: #{edge_fns.inspect}"
        assert_includes edge_fns.values, "common_path", "expected DOCUMENT_IDS to record common_path: #{edge_fns.inspect}"
        assert_includes edge_fns.values, "rare_corpus_path", "expected DOCUMENT_IDS to record rare_corpus_path: #{edge_fns.inspect}"
        common_eid = edge_fns.key("common_path")
        rare_eid = edge_fns.key("rare_corpus_path")
        assert_equal 3, edge_df[common_eid], "expected common_path df==3 across all corpus inputs: #{edge_df.inspect}"
        assert_equal 1, edge_df[rare_eid], "expected rare_corpus_path df==1 for r1.rb only: #{edge_df.inspect}"
        assert_includes edge_df.values, 3, "expected at least one df==3 edge in corpus: #{edge_df.inspect}"
        assert_includes edge_df.values, 1, "expected at least one df==1 rare edge in corpus: #{edge_df.inspect}"

        assert_equal 1, index.dig("summary", "bucket_count")
        assert_equal 2, index.dig("summary", "total_occurrences")
        bucket = index["buckets"].first
        edges = bucket.dig("coverage", "edges") || {}
        assert bucket.dig("coverage", "available"), "expected available bucket coverage: #{bucket['coverage'].inspect}"
        refute_empty edges, "expected non-empty bucket edges"
        unseen_edges = edges.keys.reject { |e| edge_df.key?(e) }
        refute_empty unseen_edges, "expected bug-specific edge unseen in corpus (#{edges.keys.inspect} vs #{edge_df.keys.inspect})"

        # Second run with no corpus changes must reuse .corpus-coverage.json cache, and
        # TRIAGE_RECOUNT=1 on a pre-existing sentinel without occurrences must backfill it.
        late_crash = File.join(afl_cov_dir, "m2", "crashes", "id:000003,sig:06")
        File.binwrite(late_crash, "\x00\x00\x03\x01B999".b)
        late_sentinel = File.join(triage_dir, ".processed", Digest::SHA2.hexdigest(File.binread(late_crash)))
        File.write(late_sentinel, "")

        out2, _err2 = capture_io do
          with_env("TRIAGE_RECOUNT" => "1") do
            FuzzTriage.run_triage_pipeline(
              output_dirs: [afl_cov_dir],
              testcases_dir: triage_dir,
              coverage_bin: cov_bin,
              coverage_ids: cov_ids,
              corpus_dir: corpus_dir,
              threads: [FuzzTriage.env_triage_threads, 2].max
            )
          end
        end

        refute_includes out2, "Collecting afl-showmap", "expected second run to hit .corpus-coverage.json cache"
        index2 = JSON.parse(File.read(File.join(triage_dir, "metadata.json")))
        assert_equal 3, index2.dig("summary", "total_occurrences"),
                     "expected recount to raise total_occurrences to 3"
        b2 = index2["buckets"].first
        assert_equal 3, b2.dig("occurrences", "count"),
                     "expected recounted occurrences count == 3, got #{b2['occurrences'].inspect}"
        assert_equal 3, b2.dig("archive", "count"),
                     "expected recounted archive to contain all 3 inputs, got #{b2['archive'].inspect}"
        assert_equal 3,
                     FuzzTriage.read_tar_gz_entries(File.join(triage_dir, b2["bucket_id"], "inputs.tar.gz"), include_bytes: false)[:entries].size
        assert_equal b2["bucket_id"], File.read(late_sentinel).strip
      end
    end
  end
end
