# frozen_string_literal: true

require_relative "../lib/autorun"
require_relative "../lib/fixtures"

require "base64"
require "cgi"
require "fileutils"
require "json"
require "rbconfig"
require "stringio"

require_relative "../../runtime/common"
require_relative "../../runtime/fuzz_header"
require_relative "../../runtime/json_schema"
require_relative "../../runtime/provenance"
require_relative "../../runtime/topology"
require_relative "../../runtime/campaign"
require_relative "../../triage/cluster"
require_relative "../../triage/explain"
require_relative "../../triage/triage"

# Migrated integration and unit tests covering section [6/8] downstream
# consumers (cluster.rb, sankey.rb, report.rb, publish.rb, FuzzHeader/LoupeUrl/
# atomic JSON parity) of test/test_targets.sh.
class ConsumersIntegrationTest < Minitest::Test
  def test_matrix_consumers_cluster_sankey_report_and_publish
    with_tmpdir("consumers-matrix-") do |workdir|
      upstream_dir = File.join(workdir, "upstream_prism")
      upstream = PrismFuzzerTest::Fixtures.build_synthetic_upstream_prism(upstream_dir)

      cache_dir = File.join(workdir, "cache")
      matrix_build = File.join(workdir, "matrix_build")
      matrix_fuzz = File.join(workdir, "matrix_fuzz")
      matrix_bin = File.join(matrix_fuzz, "bin")
      matrix_topo = File.join(workdir, "pr_matrix.json")
      FileUtils.mkdir_p(matrix_bin)

      File.write(matrix_topo, JSON.pretty_generate(build_pr_matrix_spec(upstream)))

      sync_out, = assert_ruby_cmd(
        repo_path("bin/topology.rb"),
        "sync",
        "--topology", matrix_topo,
        "--build-dir", matrix_build,
        "--cache-dir", cache_dir,
        "--json",
        env: { "TARGETS_OFFLINE" => nil }
      )
      resolved = JSON.parse(sync_out)
      assert_equal %w[main pr release], resolved.fetch("sources").keys.sort

      resolved_topo_path = File.join(matrix_build, "topology.resolved.json")
      assert_path_exists resolved_topo_path
      FileUtils.cp(resolved_topo_path, File.join(matrix_bin, "topology.json"))

      stats_text = <<~TXT
        fuzzer_pid : 1
        corpus_count : 1
        execs_per_sec : 100.0
        execs_done : 10
        edges_found : 5
        total_edges : 100
        bitmap_cvg : 5.00%
      TXT
      plot_text = "0, 0, 0, 1, 0, 0, 5.00%, 0, 0, 1, 100.0, 10, 5, 0\n"

      [
        File.join(matrix_fuzz, "afl-san", "pr-main"),
        File.join(matrix_fuzz, "afl-rel", "rel-diff"),
        File.join(matrix_fuzz, "afl-main", "cur-diff")
      ].each do |wdir|
        FileUtils.mkdir_p(File.join(wdir, "queue"))
        File.write(File.join(wdir, "fuzzer_stats"), stats_text)
        File.write(File.join(wdir, "plot_data"), plot_text)
      end

      triage_dir = File.join(matrix_fuzz, "triage")
      FileUtils.mkdir_p([
        File.join(triage_dir, "ABRT", "b_rel"),
        File.join(triage_dir, "ABRT", "b_main")
      ])
      metadata = {
        "schema_version" => 1,
        "versions" => {
          "fuzz" => {
            "prism" => { "version" => "1.9.0", "git_short" => "abc123456" },
            "ruby_parse_y" => { "version" => "4.1.0dev", "revision" => "72d4cf2e9a1234567890" }
          }
        },
        "buckets" => [
          {
            "bucket_id" => "ABRT/b_rel",
            "reason" => "ABRT",
            "signature" => "b_rel",
            "reproducible" => true,
            "timed_out" => false,
            "reproduced_by" => "vs_release",
            "verify_profile" => "diff_prism",
            "target" => { "id" => "vs_release", "shape" => "prism_diff_prism", "sources" => { "prism_a" => "release", "prism_b" => "pr" } },
            "occurrences" => { "count" => 2, "first_seen" => "2026-11-21T10:00:00Z", "last_seen" => "2026-11-21T10:01:00Z", "by_worker" => { "rel-diff" => 2 } },
            "input" => { "min_path" => "input.min", "min_size_bytes" => 10, "source_preview" => "1 + 2" },
            "options" => { "header_hex" => "00000301", "ruby_version" => "4.1" },
            "symptom" => { "headline" => "INVARIANT[diff_prism]: kind=error_mismatch sub=count a=0 b=1", "invariant" => { "namespace" => "diff_prism", "fields" => { "kind" => "error_mismatch", "sub" => "count" } } },
            "frames" => [{ "depth" => 0, "scope" => "harness", "func" => "prism_diff_fail", "file" => "harnesses/prism/prism_diff.c", "line" => 25 }]
          },
          {
            "bucket_id" => "ABRT/b_main",
            "reason" => "ABRT",
            "signature" => "b_main",
            "reproducible" => true,
            "timed_out" => false,
            "reproduced_by" => "vs_main",
            "verify_profile" => "diff_prism",
            "target" => { "id" => "vs_main", "shape" => "prism_diff_prism", "sources" => { "prism_a" => "main", "prism_b" => "pr" } },
            "occurrences" => { "count" => 2, "first_seen" => "2026-11-21T10:00:00Z", "last_seen" => "2026-11-21T10:01:00Z", "by_worker" => { "cur-diff" => 2 } },
            "input" => { "min_path" => "input.min", "min_size_bytes" => 10, "source_preview" => "1 + 2" },
            "options" => { "header_hex" => "00000301", "ruby_version" => "4.1" },
            "symptom" => { "headline" => "INVARIANT[diff_prism]: kind=error_mismatch sub=count a=0 b=1", "invariant" => { "namespace" => "diff_prism", "fields" => { "kind" => "error_mismatch", "sub" => "count" } } },
            "frames" => [{ "depth" => 0, "scope" => "harness", "func" => "prism_diff_fail", "file" => "harnesses/prism/prism_diff.c", "line" => 25 }]
          }
        ]
      }
      File.write(File.join(triage_dir, "metadata.json"), JSON.pretty_generate(metadata))

      clusters_path = File.join(triage_dir, "clusters.json")
      assert_ruby_cmd(
        repo_path("triage/cluster.rb"),
        "--metadata", File.join(triage_dir, "metadata.json"),
        "--output", clusters_path,
        "--quiet"
      )
      clusters_doc = JSON.parse(File.read(clusters_path))
      assert_equal 2, clusters_doc.fetch("clusters").size, "expected distinct diff_prism pairs (release..pr vs main..pr) to remain in 2 clusters"
      assert_equal "abc123456", clusters_doc.dig("versions", "fuzz", "prism", "git_short")
      assert_equal "72d4cf2e9a1234567890", clusters_doc.dig("versions", "fuzz", "ruby_parse_y", "revision")

      sankey_html_path = File.join(workdir, "sankey.html")
      assert_ruby_cmd(
        repo_path("report/sankey.rb"),
        "--triage-dir", triage_dir,
        "--afl-dir", File.join(matrix_fuzz, "afl-san"),
        "-o", sankey_html_path
      )
      sankey_html = File.read(sankey_html_path)
      assert_includes sankey_html, "rel-diff"
      assert_includes sankey_html, "cur-diff"

      report_out = File.join(workdir, "report_out")
      cov_out = File.join(workdir, "cov_out")
      FileUtils.mkdir_p([report_out, cov_out])
      report_html_path = File.join(report_out, "index.html")
      assert_ruby_cmd(
        repo_path("report/report.rb"),
        File.join(matrix_fuzz, "afl-san"),
        report_html_path,
        File.join(workdir, "nonexistent_cov.json"),
        "--triage-dir", triage_dir
      )
      report_html = File.read(report_html_path)
      assert_includes report_html, "rel-diff"
      assert_includes report_html, 'id="tab-triage"'
      assert_includes report_html, "triage-clusters-tbody"
      assert_includes report_html, "4.1.0dev (72d4cf2e9a)"
      triage_sec = report_html[/<section id="tab-triage" class="tab-panel">.*?<\/section>/m]
      refute_nil triage_sec, "missing tab-triage section"
      assert_includes triage_sec, "<code>rel-diff</code> <strong>2</strong>"
      assert_includes triage_sec, "<code>cur-diff</code> <strong>2</strong>"
      assert_includes report_html, 'id="tab-sankey"'
      assert_includes report_html, "sankey-root"

      FileUtils.cp(sankey_html_path, File.join(report_out, "sankey.html"))
      reports_dir = File.join(workdir, "reports")
      assert_ruby_cmd(
        repo_path("bin/publish.rb"),
        "--run-id", "matrix-01",
        "--report-dir", report_out,
        "--triage-dir", triage_dir,
        "--coverage-dir", cov_out,
        "--bin-dir", matrix_bin,
        "--out-dir", reports_dir
      )
      manifest_path = File.join(reports_dir, "runs", "matrix-01", "manifest.json")
      manifest = JSON.parse(File.read(manifest_path))
      topo_manifest = manifest.dig("versions", "topology")
      refute_nil topo_manifest, "missing versions.topology in manifest.json: #{manifest.inspect}"
      assert_equal "pr-matrix-test", topo_manifest["name"]
      assert_equal %w[main pr release], topo_manifest.fetch("sources").keys.sort
      assert_equal "report/index.html", manifest.dig("artifacts", "report")
      assert_equal "report/triage/clusters.json", manifest.dig("artifacts", "clusters")

      # Regression (Bug #38): publish.rb encodes run_id path segments with %20 (ERB::Util.url_encode), not + (CGI.escape)
      reports_space = File.join(workdir, "reports_space")
      assert_ruby_cmd(
        repo_path("bin/publish.rb"),
        "--run-id", "matrix 01 space",
        "--report-dir", report_out,
        "--triage-dir", triage_dir,
        "--coverage-dir", cov_out,
        "--bin-dir", matrix_bin,
        "--out-dir", reports_space
      )
      space_index = File.read(File.join(reports_space, "index.html"))
      assert_includes space_index, %(href="runs/matrix%2001%20space/report/index.html")
      assert_includes space_index, %(href="runs/matrix%2001%20space/manifest.json")
      refute_includes space_index, "runs/matrix+01+space/"
      assert_path_exists File.join(reports_space, "runs", "matrix 01 space", "manifest.json")
    end
  end

  def test_publish_copies_all_artifacts_and_manages_gh_pages_worktree
    with_tmpdir("publish-gh-pages-") do |workdir|
      upstream = File.join(workdir, "origin.git")
      repo_a = File.join(workdir, "repo_a")
      repo_b = File.join(workdir, "repo_b")
      assert_cmd("git", "init", "--bare", "-q", upstream)
      assert_cmd("git", "init", "-q", "-b", "main", repo_a)
      assert_cmd("git", "-C", repo_a, "config", "user.email", "test@example.com")
      assert_cmd("git", "-C", repo_a, "config", "user.name", "Test")
      assert_cmd("git", "-C", repo_a, "config", "commit.gpgsign", "false")
      File.write(File.join(repo_a, ".gitignore"), "tmp/\nreports/\n")
      File.write(File.join(repo_a, "README.md"), "repo\n")
      assert_cmd("git", "-C", repo_a, "add", ".gitignore", "README.md")
      assert_cmd("git", "-C", repo_a, "commit", "-qm", "init main")
      assert_cmd("git", "-C", repo_a, "remote", "add", "origin", upstream)
      assert_cmd("git", "-C", repo_a, "push", "-q", "-u", "origin", "main")

      rep_src = File.join(repo_a, "tmp", "ws", "report")
      cov_src = File.join(rep_src, "coverage")
      tri_src = File.join(rep_src, "triage")
      FileUtils.mkdir_p([
        File.join(cov_src, "pairs", "prism_a__native", "report", "coverage"),
        File.join(tri_src, "ABRT", "deadbeef")
      ])
      File.write(File.join(rep_src, "index.html"), "<html>main report</html>\n")
      File.write(File.join(rep_src, "sankey.html"), "<html>sankey</html>\n")
      File.write(File.join(cov_src, "coverage.json"), '{"pairs":[{"id":"prism_a__native","totals":{"regions":{"covered":8,"count":10,"percent":80.0}}}]}')
      File.write(File.join(cov_src, "summary.txt"), "TOTAL 10 2 80.00% 1 0 100.00% 10 2 80.00%\n")
      File.write(File.join(cov_src, "lcov.info"), "SF:src/prism.c\nend_of_record\n")
      File.write(File.join(cov_src, "pairs", "prism_a__native", "summary.txt"), "pair summary\n")
      File.write(File.join(cov_src, "pairs", "prism_a__native", "lcov.info"), "end_of_record\n")
      File.write(File.join(cov_src, "pairs", "prism_a__native", "report", "index.html"), "<html>cov</html>\n")
      File.write(File.join(cov_src, "pairs", "prism_a__native", "report", "coverage", "prism.c.html"), "<html>prism.c</html>\n")
      File.write(File.join(tri_src, "clusters.json"), '{"clusters":[],"summary":{"cluster_count":0,"bucket_count":1,"total_occurrences":2}}')
      File.write(File.join(tri_src, "metadata.json"), '{"summary":{"bucket_count":1,"total_occurrences":2}}')
      File.write(File.join(tri_src, "ABRT", "deadbeef", "meta.json"), "{\"bucket_id\":\"ABRT/deadbeef\"}\n")
      File.write(File.join(tri_src, "ABRT", "deadbeef", "input.min"), "crash()\n")
      File.write(File.join(tri_src, "ABRT", "deadbeef", "verify.sh"), "#!/bin/sh\nexit 1\n")
      File.write(File.join(tri_src, "ABRT", "deadbeef", "id:000001,sig:06"), "raw\n")

      reports_a = File.join(repo_a, "reports")
      assert_ruby_cmd(
        repo_path("bin/publish.rb"),
        "--fuzz-root", repo_a,
        "--report-dir", rep_src,
        "--triage-dir", tri_src,
        "--coverage-dir", cov_src,
        "--out-dir", reports_a,
        "--run-id", "run-all",
        "--commit",
        "--push"
      )

      main_status, = assert_cmd("git", "-C", repo_a, "status", "--porcelain")
      assert_equal "", main_status.strip
      main_tree, = assert_cmd("git", "-C", repo_a, "ls-tree", "-r", "--name-only", "main")
      refute_includes main_tree, "reports"

      wt_branch, = assert_cmd("git", "-C", reports_a, "symbolic-ref", "--short", "HEAD")
      assert_equal "gh-pages", wt_branch.strip
      wt_status, = assert_cmd("git", "-C", reports_a, "status", "--porcelain")
      assert_equal "", wt_status.strip

      run_rep = File.join(reports_a, "runs", "run-all", "report")
      assert_path_exists File.join(reports_a, ".nojekyll")
      assert_path_exists File.join(run_rep, "index.html")
      assert_path_exists File.join(run_rep, "sankey.html")
      assert_path_exists File.join(run_rep, "coverage", "pairs", "prism_a__native", "report", "coverage", "prism.c.html")
      assert_path_exists File.join(run_rep, "triage", "ABRT", "deadbeef", "input.min")
      assert_path_exists File.join(run_rep, "triage", "ABRT", "deadbeef", "verify.sh")
      assert_path_exists File.join(run_rep, "triage", "ABRT", "deadbeef", "meta.json")
      assert_path_exists File.join(run_rep, "triage", "ABRT", "deadbeef", "id:000001,sig:06")

      idx_html = File.read(File.join(reports_a, "index.html"))
      assert_includes idx_html, "runs/run-all/report/coverage/pairs/prism_a__native/report/index.html"

      remote_gh, = assert_cmd("git", "--git-dir", upstream, "rev-parse", "--verify", "refs/heads/gh-pages")
      refute_empty remote_gh.strip

      # Fresh clone attaches to existing origin/gh-pages worktree and preserves run-all
      assert_cmd("git", "clone", "-q", upstream, repo_b)
      assert_cmd("git", "-C", repo_b, "config", "user.email", "test@example.com")
      assert_cmd("git", "-C", repo_b, "config", "user.name", "Test")
      assert_cmd("git", "-C", repo_b, "config", "commit.gpgsign", "false")
      reports_b = File.join(repo_b, "reports")
      assert_ruby_cmd(
        repo_path("bin/publish.rb"),
        "--fuzz-root", repo_b,
        "--report-dir", rep_src,
        "--triage-dir", tri_src,
        "--coverage-dir", cov_src,
        "--out-dir", reports_b,
        "--run-id", "run-two",
        "--commit"
      )
      runs_idx = JSON.parse(File.read(File.join(reports_b, "runs", "index.json")))
      assert_equal %w[run-two run-all], runs_idx.map { |r| r["run_id"] }
    end
  end

  def test_report_custom_worker_colors_override_palette
    # Regression (Bug #33): custom DSL worker color in PLOT_COLORS overrides PALETTE across report charts & SVG cards
    with_tmpdir("report-colors-") do |color_ws|
      write_minimal_afl_worker(File.join(color_ws, "afl", "w_alpha"))
      write_minimal_afl_worker(File.join(color_ws, "afl", "w_beta"))

      topo_path = File.join(color_ws, "topology.json")
      File.write(topo_path, JSON.pretty_generate(
        "schema_version" => 2,
        "name" => "color-test",
        "workspace" => { "dir" => color_ws, "build_dir" => File.join(color_ws, "build") },
        "sources" => { "prism_a" => { "kind" => "prism", "repo" => "https://example.invalid/prism.git", "ref" => "main" } },
        "fuzzers" => { "fuzz" => { "shape" => "prism_parse", "source" => "prism_a" } },
        "sync_groups" => { "afl" => { "dir" => "afl", "primary" => true } },
        "workers" => [
          { "id" => "w_alpha", "kind" => "afl", "fuzzer" => "fuzz", "sync_group" => "afl", "afl_role" => "main", "color" => "#12abcd" },
          { "id" => "w_beta",  "kind" => "afl", "fuzzer" => "fuzz", "sync_group" => "afl", "afl_role" => "secondary", "color" => "#fe9876" }
        ]
      ))

      out_html = File.join(color_ws, "report", "index.html")
      assert_ruby_cmd(
        repo_path("report/report.rb"),
        File.join(color_ws, "afl"),
        out_html,
        File.join(color_ws, "none.json"),
        "--triage-dir", File.join(color_ws, "triage"),
        env: { "TOPOLOGY" => topo_path }
      )
      html = File.read(out_html)
      assert_includes html, "#12abcd"
      assert_includes html, "#fe9876"
      refute_includes html, %("name":"w_alpha","color":"#60a5fa")
      refute_includes html, %("name":"w_beta","color":"#34d399")
    end
  end

  def test_report_xss_escaping
    # Regression (Bug #35): XSS escaping for chart tooltips/badges and selectTab onclick args
    with_tmpdir("report-xss-") do |xss_ws|
      xss_worker = "w'<img src=x onerror=alert(1)>"
      write_minimal_afl_worker(File.join(xss_ws, "afl", "main"))
      write_minimal_afl_worker(File.join(xss_ws, "afl", xss_worker))
      FileUtils.mkdir_p(File.join(xss_ws, "afl", "main", "queue"))
      FileUtils.mkdir_p(File.join(xss_ws, "afl", xss_worker, "queue"))
      File.write(File.join(xss_ws, "afl", "main", "queue", "id:000000,sync:#{xss_worker},src:000000"), "")

      out_html = File.join(xss_ws, "report", "index.html")
      assert_ruby_cmd(
        repo_path("report/report.rb"),
        File.join(xss_ws, "afl"),
        out_html,
        File.join(xss_ws, "none.json"),
        "--triage-dir", File.join(xss_ws, "triage")
      )
      html = File.read(out_html)
      refute_includes html, "<img src=x"
      refute(html.include?("selectTab('") && html.match?(/selectTab\('[^']*&#39;/), "unexpected single-quoted selectTab break-out")
      assert_includes html, "selectTab(&quot;w&#39;&lt;img src=x onerror=alert(1)&gt;&quot;)"
      assert_includes html, "function escapeHtml("
      assert_includes html, "escapeHtml(activeInfo.series.name)"
      assert_includes html, "escapeHtml(s.name)"
    end
  end

  def test_report_loupe_san_flag_and_diff_url_lineage
    # Regression (Wave 1C): report.rb &san=1 on sanitizer lineage crashes vs non-san INVARIANT ABRT and diff_parse_y URLs
    with_tmpdir("report-loupe-") do |ws|
      FileUtils.mkdir_p(File.join(ws, "corpus"))
      File.binwrite(File.join(ws, "corpus", "seed_0"), "\x00\x00\x03\x01seed_src".b)

      %w[w_asan_bt w_asan_short w_segv w_inv_abrt w_diff_py].each do |w|
        wdir = File.join(ws, "afl", w)
        FileUtils.mkdir_p([File.join(wdir, "queue"), File.join(wdir, "crashes")])
        write_minimal_afl_worker(wdir, saved_crashes: 1)
        File.binwrite(File.join(wdir, "queue", "id:000000,time:0,execs:0,orig:seed_0"), "\x00\x00\x03\x01seed_src".b)
      end

      File.binwrite(File.join(ws, "afl", "w_asan_bt", "crashes", "id:000000,sig:06,src:000000,time:10"), "\x00\x00\x03\x01asan_bt_src".b)
      File.write(
        File.join(ws, "afl", "w_asan_bt", "crashes", "id:000000,sig:06,src:000000,time:10.bt"),
        "==123==ERROR: AddressSanitizer: heap-buffer-overflow\nSUMMARY: AddressSanitizer: heap-buffer-overflow src/prism.c:1\n"
      )

      File.binwrite(File.join(ws, "afl", "w_asan_short", "crashes", "id:000000,sig:06,src:000000,time:10"), "\x00\x00\x03\x01asan_short_src".b)
      File.write(
        File.join(ws, "afl", "w_asan_short", "crashes", "id:000000,sig:06,src:000000,time:10.bt"),
        "ASAN: stack-buffer-overflow at src/prism.c:2\n"
      )

      File.binwrite(File.join(ws, "afl", "w_segv", "crashes", "id:000000,sig:11,src:000000,time:10"), "\x00\x00\x03\x01segv_src".b)

      File.binwrite(File.join(ws, "afl", "w_inv_abrt", "crashes", "id:000000,sig:06,src:000000,time:10"), "\x00\x00\x03\x01inv_abrt_src".b)
      File.write(
        File.join(ws, "afl", "w_inv_abrt", "crashes", "id:000000,sig:06,src:000000,time:10.bt"),
        "INVARIANT[node_location]: type=PM_WHILE_NODE kind=length_underflow\n"
      )

      File.binwrite(File.join(ws, "afl", "w_diff_py", "crashes", "id:000000,sig:06,src:000000,time:10"), "\x00\x00\x03\x01diff_py_src".b)
      File.write(
        File.join(ws, "afl", "w_diff_py", "crashes", "id:000000,sig:06,src:000000,time:10.bt"),
        "INVARIANT[diff_parse_y]: kind=syntax_mismatch\n"
      )

      out_html = File.join(ws, "report", "index.html")
      assert_ruby_cmd(
        repo_path("report/report.rb"),
        File.join(ws, "afl"),
        out_html,
        File.join(ws, "none.json"),
        "--triage-dir", File.join(ws, "triage")
      )

      html = File.read(out_html)
      urls = html.scan(/href="(https:\/\/stevenjohnstone\.github\.io\/prism-loupe\/\?[^"]+)"/).flatten.map { |u| CGI.unescapeHTML(u) }
      find_url = ->(src) do
        b64 = Base64.strict_encode64(src)
        urls.find { |u| u.include?("code=#{CGI.escape(b64)}") }
      end

      u_asan_bt = find_url.call("asan_bt_src")
      u_asan_short = find_url.call("asan_short_src")
      u_segv = find_url.call("segv_src")
      u_inv_abrt = find_url.call("inv_abrt_src")
      u_diff_py = find_url.call("diff_py_src")

      assert u_asan_bt && u_asan_bt.include?("&san=1"), "missing AddressSanitizer &san=1 Loupe URL in #{urls.inspect}"
      assert u_asan_short && u_asan_short.include?("&san=1"), "missing ASAN &san=1 Loupe URL in #{urls.inspect}"
      assert u_segv && u_segv.include?("&san=1"), "missing SEGV &san=1 Loupe URL in #{urls.inspect}"
      assert u_inv_abrt, "missing INVARIANT ABRT Loupe URL in #{urls.inspect}"
      refute_includes u_inv_abrt, "san=1"
      assert_equal PrismFuzzer::LoupeUrl.diff_url("diff_py_src"), u_diff_py
    end
  end

  def test_report_custom_generator_zero_crashes_and_provenance_json
    with_tmpdir("report-gen-zero-") do |ws|
      afl_dir = File.join(ws, "afl")
      gen_dir = File.join(afl_dir, "gram_custom")
      zero_dir = File.join(afl_dir, "w_zero")
      crash_dir = File.join(afl_dir, "w_crash")
      triage_dir = File.join(ws, "triage")
      FileUtils.mkdir_p([
        File.join(gen_dir, "queue"),
        File.join(zero_dir, "queue"),
        File.join(crash_dir, "queue"),
        File.join(crash_dir, "crashes"),
        File.join(triage_dir, "ABRT", "b1")
      ])

      File.write(File.join(gen_dir, "fuzzer_stats"), <<~TXT)
        fuzzer_pid        : 101
        fuzzer_role       : generator
        run_time          : 20
        files_created     : 18
        pending_files     : 2
        max_pending_files : 500
        files_pruned      : 1
        duplicates_skipped: 3
        files_per_sec     : 0.9
        avg_files_per_sec : 0.9
        attempts_done     : 24
        files_valid       : 18
        files_invalid     : 6
        afl_banner        : ./custom_grammar_gen
        command_line      : ./custom_grammar_gen --schedule custom-lrama
      TXT
      File.write(File.join(gen_dir, "plot_data"), <<~TXT)
        # relative_time, files_created, files_per_sec, avg_files_per_sec, attempts_done, files_valid, files_invalid
        0, 0, 0.0, 0.0, 0, 0, 0
        20, 18, 0.9, 0.9, 24, 18, 6
      TXT

      write_minimal_afl_worker(zero_dir, saved_crashes: 0)
      File.write(File.join(zero_dir, "queue", "id:000000,sync:gram_custom,src:000000"), "\x00\x00\x03\x01x = 1".b)

      write_minimal_afl_worker(crash_dir, saved_crashes: 1)
      crash_file = File.join(crash_dir, "crashes", "id:000000,sig:06,src:000000,time:10")
      File.binwrite(crash_file, "\x00\x00\x03\x01y = 2".b)
      File.write(File.join(crash_dir, "queue", "id:000000,time:0,execs:0,orig:seed_0"), "\x00\x00\x03\x01y = 2".b)

      topo_path = File.join(ws, "topology.json")
      File.write(topo_path, JSON.pretty_generate(
        "schema_version" => 2,
        "name" => "custom-gen-zero-crash",
        "workspace" => { "dir" => ws, "build_dir" => File.join(ws, "build") },
        "sources" => { "prism_a" => { "kind" => "prism", "repo" => "https://example.invalid/prism.git", "ref" => "main" } },
        "generators" => { "gram_custom" => { "kind" => "grammar", "source" => "prism_a", "schedule" => "custom-lrama" } },
        "fuzzers" => { "fuzz" => { "shape" => "prism_parse", "source" => "prism_a" } },
        "sync_groups" => { "afl" => { "dir" => "afl", "primary" => true } },
        "workers" => [
          { "id" => "gram_custom", "kind" => "generator", "generator" => "gram_custom", "color" => "#34d399" },
          { "id" => "w_zero", "kind" => "afl", "fuzzer" => "fuzz", "sync_group" => "afl", "afl_role" => "main", "foreign_sync" => ["gram_custom"], "color" => "#60a5fa" },
          { "id" => "w_crash", "kind" => "afl", "fuzzer" => "fuzz", "sync_group" => "afl", "afl_role" => "secondary", "color" => "#f472b6" }
        ]
      ))

      File.write(File.join(triage_dir, "ABRT", "b1", "occurrences.jsonl"), "#{JSON.generate("worker" => "w_crash", "path" => crash_file, "time_ms" => 10, "mtime" => "2026-11-21T10:00:10Z")}\n")
      File.write(File.join(triage_dir, "metadata.json"), JSON.pretty_generate(
        "schema_version" => 1,
        "versions" => {
          "fuzz" => {
            "prism" => { "version" => "1.9.0", "git_short" => "feedbeef12" },
            "ruby_parse_y" => { "version" => "4.1.0dev", "revision" => "abcdef012345" }
          }
        },
        "buckets" => [
          {
            "bucket_id" => "ABRT/b1",
            "reason" => "ABRT",
            "signature" => "b1",
            "reproducible" => true,
            "timed_out" => false,
            "verify_profile" => "asan_ubsan",
            "occurrences" => { "count" => 1, "by_worker" => { "w_crash" => 1 } },
            "input" => { "min_path" => "input.min", "min_size_bytes" => 5, "source_preview" => "y = 2" },
            "symptom" => { "headline" => "SUMMARY: AddressSanitizer: ABRT src/prism.c:1", "invariant" => nil }
          }
        ]
      ))

      assert_ruby_cmd(
        repo_path("triage/cluster.rb"),
        "--metadata", File.join(triage_dir, "metadata.json"),
        "--output", File.join(triage_dir, "clusters.json"),
        "--quiet"
      )

      sankey_json_path = File.join(ws, "sankey.json")
      assert_ruby_cmd(
        repo_path("report/sankey.rb"),
        "--triage-dir", triage_dir,
        "--afl-dir", afl_dir,
        "--format", "json",
        "-o", sankey_json_path,
        env: { "TOPOLOGY" => topo_path }
      )
      sankey_data = JSON.parse(File.read(sankey_json_path))
      assert_equal ["w_zero"], sankey_data["zero_crash_workers"]

      report_html_path = File.join(ws, "report", "index.html")
      assert_ruby_cmd(
        repo_path("report/report.rb"),
        afl_dir,
        report_html_path,
        File.join(ws, "none.json"),
        "--triage-dir", triage_dir,
        env: { "TOPOLOGY" => topo_path }
      )
      html = File.read(report_html_path)
      assert_includes html, "Seed Generator"
      assert_includes html, "gram_custom"
      assert_includes html, "0-Crash Workers"
      assert_includes html, "w_zero"
      assert_includes html, "feedbeef12"
      assert_includes html, "4.1.0dev (abcdef0123)"
    end
  end

  def test_common_fuzz_header_loupe_url_and_atomic_json_parity
    # Check Object namespace isolation and parity across Common, Topology, FuzzProvenance,
    # FuzzClustering, FuzzTriage, FuzzExplain, FuzzHeader, and LoupeUrl.
    with_env("TRIAGE_LIB_ONLY" => "1") do
      %i[write_json_atomic encode_fuzz_header build_prism_loupe_url build_diff_loupe_url].each do |meth|
        refute(
          Object.private_method_defined?(meth) || Object.method_defined?(meth),
          "Object leaked #{meth}"
        )
      end

      with_tmpdir("parity-") do |dir|
        payload = { "ok" => true, "n" => 42 }
        expected_mode = 0o666 & ~File.umask

        [
          [File.join(dir, "atomic", "common.json"), PrismFuzzer::Common.method(:write_json_atomic), true],
          [File.join(dir, "atomic", "topo.json"), PrismFuzzer::Topology.method(:write_json_atomic), true],
          [File.join(dir, "atomic", "prov.json"), FuzzProvenance.method(:write_json_atomic), false],
          [File.join(dir, "atomic", "clus.json"), FuzzClustering.method(:write_json_atomic), false],
          [File.join(dir, "atomic", "triage.json"), FuzzTriage.method(:write_json_atomic), false]
        ].each do |path, fn, check_ret|
          ret = fn.call(path, payload)
          assert_equal payload, ret if check_ret
          assert_equal payload, JSON.parse(File.read(path))
          mode = File.stat(path).mode & 0o777
          assert_equal expected_mode, mode, "expected mode #{format('%#o', expected_mode)}, got #{format('%#o', mode)}"
        end
      end

      assert_nil PrismFuzzer::FuzzHeader.format_summary("abc".b)

      raw_hdr = FuzzTriage.encode_fuzz_header(
        ruby_version: "3.5",
        encoding: "ASCII-8BIT",
        frozen_string_literal: true,
        partial_script: true,
        command_line: "aelnpx",
        scopes_count: 2,
        forwarding: "pk"
      )
      raw_inp = raw_hdr + "puts 1".b
      sum = PrismFuzzer::FuzzHeader.format_summary(raw_inp)
      assert_includes sum, "v3.5"
      assert_includes sum, "enc=ASCII-8BIT"
      assert_includes sum, "fwd[1]=0x3"
      assert_includes sum, "-a-e-l-n-p-x"

      stripped_body, stripped_flags = FuzzExplain.strip_fuzz_header(raw_inp)
      assert_equal "puts 1".b, stripped_body
      assert_equal %w[a e l n p x], stripped_flags

      assert_equal(
        PrismFuzzer::LoupeUrl.prism_url(raw_inp, sanitize: true),
        FuzzTriage.build_prism_loupe_url(raw_inp, sanitize: true)
      )
      assert_equal(
        PrismFuzzer::LoupeUrl.diff_url("1 + 2"),
        FuzzTriage.build_diff_loupe_url("1 + 2")
      )
    end
  end

  private

  def write_minimal_afl_worker(wdir, saved_crashes: 0)
    FileUtils.mkdir_p(wdir)
    File.write(File.join(wdir, "fuzzer_stats"), <<~TXT)
      start_time        : 1700000000
      last_update       : 1700000010
      run_time          : 10
      execs_done        : 50
      execs_per_sec     : 5.00
      corpus_count      : 3
      edges_found       : 10
      total_edges       : 100
      bitmap_cvg        : 10.00%
      saved_crashes     : #{saved_crashes}
      afl_banner        : ./fuzz
      command_line      : ./fuzz
    TXT
    File.write(
      File.join(wdir, "plot_data"),
      "# relative_time, cycles_done, cur_item, corpus_count, pending_total, pending_favs, map_size, saved_crashes, saved_hangs, max_depth, execs_per_sec, total_execs, edges_found, total_crashes, servers_count\n" \
      "0, 0, 0, 1, 0, 0, 10.00%, #{saved_crashes}, 0, 1, 5.0, 10, 5, #{saved_crashes}, 1\n" \
      "10, 0, 0, 3, 0, 0, 10.00%, #{saved_crashes}, 0, 1, 5.0, 50, 10, #{saved_crashes}, 1\n"
    )
  end

  def build_pr_matrix_spec(upstream)
    {
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
        { "id" => "pr-main", "kind" => "afl", "fuzzer" => "pr_fast", "sync_group" => "san", "afl_role" => "main", "schedule" => "exploit", "seeds" => { "from" => "corpus" }, "color" => "#60a5fa" },
        { "id" => "rel-diff", "kind" => "afl", "fuzzer" => "vs_release", "sync_group" => "rel", "afl_role" => "main", "schedule" => "explore", "seeds" => { "from" => "corpus", "filter" => "self_pass", "cache_key" => "rel" }, "peer_imports" => [{ "group" => "san", "worker" => "pr-main", "alias" => "san_peer" }], "color" => "#f97316" },
        { "id" => "cur-diff", "kind" => "afl", "fuzzer" => "vs_main", "sync_group" => "cur", "afl_role" => "main", "schedule" => "fast", "seeds" => { "from" => "corpus", "shard_group" => "g" }, "color" => "#facc15" }
      ]
    }
  end
end

# Migrated integration and unit tests covering section [7/8] Ruby Campaign DSL,
# topology schema validation, lifecycle schema, autorun, in-memory vs file
# compilation, CLI subcommands, and stop/TTY/detach lifecycle behavior.
class CampaignDslAndSchemaTest < Minitest::Test
  def test_default_campaign_validate_and_compile_against_schema
    val_out, = assert_cmd(repo_path("campaigns/default.rb"), "validate", "--json")
    v = JSON.parse(val_out)
    assert_equal true, v["valid"]
    assert_equal 2, v["schema_version"]
    assert_equal 14, v.fetch("workers").size
    assert File.file?(v.fetch("schema")), "missing topology.schema.json at #{v['schema'].inspect}"
    assert PrismFuzzer::Campaign.step_enabled?(v.fetch("lifecycle"), :report),
           "expected campaigns/default.rb to enable report by default: #{v['lifecycle'].inspect}"
    assert PrismFuzzer::Campaign.any_post_steps?(v.fetch("lifecycle"))

    dry_default_out, = assert_cmd(repo_path("campaigns/default.rb"), "run", "--skip-build", "--dry-run")
    assert_includes dry_default_out, "triage.rb"
    assert_includes dry_default_out, "report.rb"

    dry_nopost_out, = assert_cmd(repo_path("campaigns/default.rb"), "run", "--skip-build", "--no-post", "--dry-run")
    refute_match(/triage\.rb|coverage\.sh|report\.rb|publish\.rb/, dry_nopost_out)

    dry_pub_out, = assert_cmd(repo_path("campaigns/default.rb"), "publish", "--dry-run", "--", "--run-id", "cli-01", "--commit")
    assert_includes dry_pub_out, "--run-id"
    assert_includes dry_pub_out, "cli-01"
    assert_includes dry_pub_out, "--commit"

    comp_out, = assert_cmd(
      repo_path("campaigns/default.rb"),
      "compile",
      env: { "PRISM_B_REF" => "deadbeef" }
    )
    ir = JSON.parse(comp_out)
    schema = JSON.parse(File.read(repo_path("topology.schema.json")))
    PrismFuzzer::JsonSchema.validate!(schema, ir)
    assert_equal 15, ir.fetch("workers").size
    refute ir.key?("workers_policy")
    refute ir.fetch("sources").values.any? { |s| s.key?("optional") }
    refute ir.fetch("workers").any? { |w| w.key?("when") || w.key?("when_lt_4_workers") }
  end

  def test_lifecycle_schema_timer_and_post_steps
    with_tmpdir("dsl-lifecycle-") do |dir|
      upstream = PrismFuzzerTest::Fixtures.build_synthetic_upstream_prism(File.join(dir, "upstream"))
      camp_path = File.join(dir, "lifecycle_campaign.rb")
      File.write(camp_path, <<~RB)
        PrismFuzzer.campaign "lifecycle-test" do
          duration "30m"
          after_run do
            report threads: 2, minimize: true, top: 10
            publish run_id: "camp-01", title: "Camp"
          end

          prism :prism_a, repo: #{upstream[:repo].dump}, ref: #{upstream[:v1].dump}, patches: "auto", templates: "auto"
          fuzzer "fuzz", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
          sync_group :afl, dir: "afl", primary: true
          worker :w1, fuzzer: "fuzz", sync_group: :afl, afl_role: :main, schedule: "fast"
        end
      RB

      comp_out, = assert_ruby_cmd(repo_path("bin/campaign.rb"), "compile", "--campaign", camp_path)
      ir = JSON.parse(comp_out)
      schema = JSON.parse(File.read(repo_path("topology.schema.json")))
      PrismFuzzer::JsonSchema.validate!(schema, ir)

      lc = ir["lifecycle"]
      refute_nil lc, "missing lifecycle in compiled IR"
      assert_equal 1800, lc["duration_seconds"]
      refute lc.key?("triage"), "unexpected separate triage lifecycle key: #{lc.inspect}"
      assert_equal 2, lc.dig("report", "threads")
      assert_equal true, lc.dig("report", "minimize")
      assert_equal 10, lc.dig("report", "top")
      assert_equal "camp-01", lc.dig("publish", "run_id")
      assert_equal "Camp", lc.dig("publish", "title")

      # Duration parser unit assertions (timer)
      assert_equal 1800, PrismFuzzer::CampaignDSL.parse_duration("30m")
      assert_equal 7200, PrismFuzzer::CampaignDSL.parse_duration("2h")
      assert_equal 5400, PrismFuzzer::CampaignDSL.parse_duration("1h 30m")
      assert_equal 45, PrismFuzzer::CampaignDSL.parse_duration("45")
      assert_raises(PrismFuzzer::CampaignDSL::Error) { PrismFuzzer::CampaignDSL.parse_duration("0s") }
      assert_raises(PrismFuzzer::CampaignDSL::Error) { PrismFuzzer::CampaignDSL.parse_duration("") }
      assert_raises(PrismFuzzer::CampaignDSL::Error) { PrismFuzzer::CampaignDSL.parse_duration("10z") }

      # Lifecycle post_steps helpers & CLI merge overrides
      assert PrismFuzzer::Campaign.any_post_steps?(lc)
      assert PrismFuzzer::Campaign.step_enabled?(lc, :report)
      assert PrismFuzzer::Campaign.step_enabled?(lc, :publish)
      merged_no_post = PrismFuzzer::Campaign.merge_lifecycle(lc, no_post: true)
      refute PrismFuzzer::Campaign.any_post_steps?(merged_no_post)
      merged_timer_clear = PrismFuzzer::Campaign.merge_lifecycle(lc, duration_seconds: nil)
      refute merged_timer_clear.key?("duration_seconds")
      merged_override = PrismFuzzer::Campaign.merge_lifecycle(
        { "duration_seconds" => 60 },
        post: true,
        publish_run_id: "ovr-99",
        publish_title: "Override"
      )
      assert_equal true, merged_override["report"]
      assert_equal "ovr-99", merged_override.dig("publish", "run_id")
      assert_equal "Override", merged_override.dig("publish", "title")
    end
  end

  def test_topology_validation_accepts_valid_matrix_and_rejects_all_invalid_specs
    with_tmpdir("topo-validate-") do |dir|
      upstream = PrismFuzzerTest::Fixtures.build_synthetic_upstream_prism(File.join(dir, "upstream"))
      good_ruby = PrismFuzzerTest::Fixtures.build_good_ruby_dir(File.join(dir, "good_ruby"))
      up = upstream[:repo]
      v1 = upstream[:v1]

      valid_topo = File.join(dir, "valid_matrix.json")
      File.write(valid_topo, JSON.pretty_generate(
        "schema_version" => 2,
        "name" => "pr-matrix-test",
        "sources" => {
          "release" => { "kind" => "prism", "repo" => up, "ref" => upstream[:v1] },
          "main" => { "kind" => "prism", "repo" => up, "ref" => upstream[:v2] },
          "pr" => { "kind" => "prism", "repo" => up, "ref" => upstream[:v3] }
        },
        "fuzzers" => {
          "pr_fast" => { "shape" => "prism_parse", "source" => "pr", "afl" => "lto" },
          "vs_release" => { "shape" => "prism_diff_prism", "prism_a" => "release", "prism_b" => "pr", "afl" => "pcguard" }
        },
        "sync_groups" => { "san" => { "dir" => "afl-san", "primary" => true } },
        "workers" => [
          { "id" => "pr-main", "kind" => "afl", "fuzzer" => "pr_fast", "sync_group" => "san", "afl_role" => "main" }
        ]
      ))
      assert_ruby_cmd(repo_path("bin/topology.rb"), "validate", "--topology", valid_topo)

      base_src = { "prism_a" => { "kind" => "prism", "repo" => up, "ref" => v1 } }
      base_fuzz = { "fuzz" => { "shape" => "prism_parse", "source" => "prism_a" } }
      base_sg = { "afl" => { "dir" => "afl" } }

      invalid_cases = [
        [
          "bad schema_version",
          { "schema_version" => 99, "name" => "bad", "sources" => base_src, "fuzzers" => base_fuzz, "sync_groups" => base_sg, "workers" => [] },
          /expected 2, got 99/
        ],
        [
          "bogus_flag on fuzzer",
          { "schema_version" => 2, "name" => "bad", "sources" => base_src, "fuzzers" => { "fuzz" => { "shape" => "prism_parse", "source" => "prism_a", "bogus_flag" => true } }, "sync_groups" => base_sg, "workers" => [] },
          /additional property 'bogus_flag'/
        ],
        [
          "legacy workers_policy",
          { "schema_version" => 2, "name" => "bad", "sources" => base_src, "fuzzers" => base_fuzz, "sync_groups" => base_sg, "workers_policy" => { "default" => "auto_half_cpus_min_9" }, "workers" => [] },
          /additional property 'workers_policy'/
        ],
        [
          "legacy optional on source",
          { "schema_version" => 2, "name" => "bad", "sources" => { "prism_a" => { "kind" => "prism", "repo" => up, "ref" => v1, "optional" => true } }, "fuzzers" => base_fuzz, "sync_groups" => base_sg, "workers" => [] },
          /additional property 'optional'/
        ],
        [
          "diff_ruby missing ruby",
          { "schema_version" => 2, "name" => "bad", "sources" => base_src, "fuzzers" => { "fuzz.diff" => { "shape" => "prism_diff_ruby", "prism" => "prism_a" } }, "sync_groups" => base_sg, "workers" => [] },
          /missing required property 'ruby'/
        ],
        [
          "invalid cross_oracle arch",
          { "schema_version" => 2, "name" => "bad", "sources" => base_src, "fuzzers" => { "fuzz.cross" => { "shape" => "prism_cross_oracle", "source" => "prism_a", "arch" => "sparc64" } }, "sync_groups" => base_sg, "workers" => [] },
          /expected one of/
        ],
        [
          "unknown prism source",
          { "schema_version" => 2, "name" => "bad", "sources" => base_src, "fuzzers" => { "fuzz" => { "shape" => "prism_parse", "source" => "missing_src" } }, "sync_groups" => base_sg, "workers" => [] },
          /unknown prism source 'missing_src'/
        ],
        [
          "duplicate worker IDs",
          {
            "schema_version" => 2, "name" => "bad", "sources" => base_src, "fuzzers" => base_fuzz, "sync_groups" => base_sg,
            "workers" => [
              { "id" => "w1", "kind" => "afl", "fuzzer" => "fuzz", "sync_group" => "afl" },
              { "id" => "w1", "kind" => "afl", "fuzzer" => "fuzz", "sync_group" => "afl" }
            ]
          },
          /Duplicate worker IDs: w1/
        ],
        [
          "legacy when on fuzzer",
          { "schema_version" => 2, "name" => "bad", "sources" => base_src, "fuzzers" => { "fuzz" => { "shape" => "prism_parse", "source" => "prism_a", "when" => { "source_active" => "prism_a" } } }, "sync_groups" => base_sg, "workers" => [] },
          /additional property 'when'/
        ],
        [
          "zero duration_seconds",
          { "schema_version" => 2, "name" => "bad", "lifecycle" => { "duration_seconds" => 0 }, "sources" => base_src, "fuzzers" => base_fuzz, "sync_groups" => base_sg, "workers" => [] },
          /minimum 1/
        ],
        [
          "shared grammar across multiple foreign_sync consumers",
          {
            "schema_version" => 2, "name" => "bad-shared-grammar", "sources" => base_src,
            "generators" => { "grammar" => { "kind" => "grammar", "source" => "prism_a" } },
            "fuzzers" => base_fuzz,
            "sync_groups" => { "g1" => { "dir" => "afl1" }, "g2" => { "dir" => "afl2" } },
            "workers" => [
              { "id" => "gram", "kind" => "generator", "generator" => "grammar" },
              { "id" => "m1", "kind" => "afl", "fuzzer" => "fuzz", "sync_group" => "g1", "afl_role" => "main", "foreign_sync" => ["grammar"] },
              { "id" => "m2", "kind" => "afl", "fuzzer" => "fuzz", "sync_group" => "g2", "afl_role" => "main", "foreign_sync" => ["grammar"] }
            ]
          },
          /cannot be shared across multiple foreign_sync consumers/
        ],
        [
          "secondary worker with foreign_sync",
          {
            "schema_version" => 2, "name" => "bad-secondary-foreign-sync", "sources" => base_src,
            "generators" => { "grammar" => { "kind" => "grammar", "source" => "prism_a" } },
            "fuzzers" => base_fuzz, "sync_groups" => base_sg,
            "workers" => [
              { "id" => "gram", "kind" => "generator", "generator" => "grammar" },
              { "id" => "sec", "kind" => "afl", "fuzzer" => "fuzz", "sync_group" => "afl", "afl_role" => "secondary", "foreign_sync" => ["grammar"] }
            ]
          },
          /must set afl_role=main/
        ],
        [
          "cross_oracle with foreign_sync",
          {
            "schema_version" => 2, "name" => "bad-cross-foreign-sync", "sources" => base_src,
            "generators" => { "grammar" => { "kind" => "grammar", "source" => "prism_a" } },
            "fuzzers" => { "fuzz.arm32" => { "shape" => "prism_cross_oracle", "source" => "prism_a", "arch" => "arm32" } },
            "sync_groups" => base_sg,
            "workers" => [
              { "id" => "gram", "kind" => "generator", "generator" => "grammar" },
              { "id" => "arm", "kind" => "afl", "fuzzer" => "fuzz.arm32", "sync_group" => "afl", "afl_role" => "main", "foreign_sync" => ["grammar"] }
            ]
          },
          /not supported on prism_cross_oracle/
        ],
        [
          "seeds.from referencing grammar generator",
          {
            "schema_version" => 2, "name" => "bad-seeds-from-grammar", "sources" => base_src,
            "generators" => { "grammar" => { "kind" => "grammar", "source" => "prism_a" } },
            "fuzzers" => base_fuzz, "sync_groups" => base_sg,
            "workers" => [
              { "id" => "m1", "kind" => "afl", "fuzzer" => "fuzz", "sync_group" => "afl", "afl_role" => "main", "seeds" => { "from" => "grammar" } }
            ]
          },
          /seeds\.from cannot reference grammar generator/
        ],
        [
          "multiple generator workers sharing generator",
          {
            "schema_version" => 2, "name" => "bad-dup-gen-workers", "sources" => base_src,
            "generators" => { "corpus" => { "kind" => "corpus", "source" => "prism_a" }, "grammar" => { "kind" => "grammar", "source" => "prism_a" } },
            "fuzzers" => base_fuzz, "sync_groups" => base_sg,
            "workers" => [
              { "id" => "g1", "kind" => "generator", "generator" => "grammar" },
              { "id" => "g2", "kind" => "generator", "generator" => "grammar" }
            ]
          },
          /cannot be shared by multiple generator workers/
        ],
        [
          "generator worker referencing corpus generator",
          {
            "schema_version" => 2, "name" => "bad-corpus-gen-worker", "sources" => base_src,
            "generators" => { "corpus" => { "kind" => "corpus", "source" => "prism_a" } },
            "fuzzers" => base_fuzz, "sync_groups" => base_sg,
            "workers" => [
              { "id" => "cg", "kind" => "generator", "generator" => "corpus" }
            ]
          },
          /must reference a kind=grammar generator/
        ],
        [
          "shared seeds_dir across grammar generators",
          {
            "schema_version" => 2, "name" => "bad-shared-seeds-dir", "sources" => base_src,
            "generators" => {
              "g1" => { "kind" => "grammar", "source" => "prism_a", "seeds_dir" => "/tmp/shared-grammar-seeds" },
              "g2" => { "kind" => "grammar", "source" => "prism_a", "seeds_dir" => "/tmp/shared-grammar-seeds" }
            },
            "fuzzers" => base_fuzz, "sync_groups" => base_sg, "workers" => []
          },
          /cannot share seeds_dir/
        ],
        [
          "unwired grammar worker without foreign_sync consumer",
          {
            "schema_version" => 2, "name" => "bad-unwired-grammar", "sources" => base_src,
            "generators" => { "grammar" => { "kind" => "grammar", "source" => "prism_a" } },
            "fuzzers" => base_fuzz, "sync_groups" => base_sg,
            "workers" => [
              { "id" => "grammar", "kind" => "generator", "generator" => "grammar" },
              { "id" => "main", "kind" => "afl", "fuzzer" => "fuzz", "sync_group" => "afl", "afl_role" => "main" }
            ]
          },
          /has no foreign_sync consumer/
        ],
        [
          "legacy afl=ijon",
          { "schema_version" => 2, "name" => "bad-legacy-afl-ijon", "sources" => base_src, "fuzzers" => { "fuzz" => { "shape" => "prism_parse", "source" => "prism_a", "afl" => "ijon" } }, "sync_groups" => base_sg, "workers" => [] },
          /Topology schema validation failed/
        ],
        [
          "ijon with afl=sand",
          { "schema_version" => 2, "name" => "bad-ijon-on-sand", "sources" => base_src, "fuzzers" => { "fuzz_sand" => { "shape" => "prism_parse", "source" => "prism_a", "afl" => "sand", "ijon" => true } }, "sync_groups" => base_sg, "workers" => [] },
          /cannot enable ijon with non-coverage-guided afl mode 'sand'/
        ],
        [
          "ijon with afl=cmplog",
          { "schema_version" => 2, "name" => "bad-ijon-on-cmplog", "sources" => base_src, "fuzzers" => { "fuzz_cmplog" => { "shape" => "prism_parse", "source" => "prism_a", "afl" => "cmplog", "ijon" => true } }, "sync_groups" => base_sg, "workers" => [] },
          /cannot enable ijon with non-coverage-guided afl mode 'cmplog'/
        ],
        [
          "afl=lto on prism_diff_ruby",
          {
            "schema_version" => 2, "name" => "bad-lto-on-diff",
            "sources" => {
              "prism_a" => { "kind" => "prism", "repo" => up, "ref" => v1 },
              "ruby" => { "kind" => "ruby", "repo" => "https://example.invalid/ruby.git", "dir" => good_ruby }
            },
            "fuzzers" => { "fuzz_diff" => { "shape" => "prism_diff_ruby", "prism" => "prism_a", "ruby" => "ruby", "afl" => "lto" } },
            "sync_groups" => base_sg, "workers" => []
          },
          /does not support afl='lto'/
        ]
      ]

      invalid_cases.each do |label, spec, pattern|
        err = assert_raises(PrismFuzzer::Topology::TopologyError, "expected #{label} to fail validation") do
          PrismFuzzer::Topology.validate_ir!(spec, fuzz_root: root_dir, source_label: label)
        end
        assert_match pattern, err.message, "mismatch for #{label}"
      end

      # Verify CLI exit status & error reporting for invalid topology files
      bad_topo = File.join(dir, "bad_topology.json")
      [invalid_cases.first, invalid_cases.last].each do |label, spec, pattern|
        File.write(bad_topo, JSON.pretty_generate(spec))
        out, err, st = run_cmd(RbConfig.ruby, repo_path("bin/topology.rb"), "validate", "--topology", bad_topo)
        refute st.success?, "expected bin/topology.rb validate to fail for #{label}"
        assert_match pattern, "#{out}\n#{err}", "CLI error mismatch for #{label}"
      end
    end
  end

  def test_ijon_all_shapes_validate_plan_and_dry_run_build
    with_tmpdir("ijon-shapes-") do |dir|
      upstream = PrismFuzzerTest::Fixtures.build_synthetic_upstream_prism(File.join(dir, "upstream"))
      good_ruby = PrismFuzzerTest::Fixtures.build_good_ruby_dir(File.join(dir, "good_ruby"))
      ijon_ws = File.join(dir, "ijon_ws")
      camp_path = File.join(dir, "ijon_shapes_campaign.rb")

      File.write(camp_path, <<~RB)
        #!/usr/bin/env ruby
        require #{repo_path("lib/prism_fuzzer").dump}

        PrismFuzzer.campaign "ijon-all-shapes-test" do
          workspace #{ijon_ws.dump}
          prism :prism_a, repo: #{upstream[:repo].dump}, ref: #{upstream[:v1].dump}, dir: #{upstream[:repo].dump}, patches: "none", templates: "never"
          prism :prism_b, repo: #{upstream[:repo].dump}, ref: #{upstream[:v2].dump}, dir: #{upstream[:repo].dump}, patches: "none", templates: "never"
          ruby  :ruby,    repo: "https://example.invalid/ruby.git", dir: #{good_ruby.dump}

          fuzzer "p_lto",     shape: :prism_parse,        source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto, ijon: true
          fuzzer "p_pcguard", shape: :prism_parse,        source: :prism_a, sanitizers: [], mode: :fast, afl: :pcguard, ijon: true, xallocator: true
          fuzzer "p_diff",    shape: :prism_diff_ruby,    prism: :prism_a, ruby: :ruby, afl: :pcguard, ijon: true
          fuzzer "p_pdiff",   shape: :prism_diff_prism,   prism_a: :prism_a, prism_b: :prism_b, afl: :pcguard, ijon: true
          fuzzer "p_arm",     shape: :prism_cross_oracle, source: :prism_a, arch: :arm32, afl: :pcguard, ijon: true
          fuzzer "p_ppc",     shape: :prism_cross_oracle, source: :prism_a, arch: :ppc,   afl: :pcguard, ijon: true

          sync_group :afl, dir: "afl", primary: true
          worker :w1, fuzzer: "p_lto", sync_group: :afl, afl_role: :main
        end
      RB

      assert_ruby_cmd(repo_path("bin/topology.rb"), "validate", "--topology", camp_path)

      plan_out, = assert_ruby_cmd(repo_path("bin/topology.rb"), "plan", "--topology", camp_path)
      fuzzers = JSON.parse(plan_out).fetch("fuzzers")
      expected_profiles = {
        "p_lto" => "asan_ubsan",
        "p_pcguard" => "xallocator",
        "p_diff" => "diff_parse_y",
        "p_pdiff" => "diff_prism",
        "p_arm" => "arm32_oracle",
        "p_ppc" => "ppc_oracle"
      }
      expected_profiles.each do |fid, prof|
        assert_equal true, fuzzers.dig(fid, "ijon"), "expected ijon=true on #{fid}"
        assert_equal prof, fuzzers.dig(fid, "verify_profile"), "unexpected verify_profile on #{fid}"
      end

      dry_build, = assert_ruby_cmd(repo_path("bin/topology.rb"), "build", "--topology", camp_path, "--dry-run")
      [
        /AFL_LLVM_IJON=1 afl-clang-lto .*-DPRISM_FUZZ_IJON.*-o .*p_lto /,
        /AFL_LLVM_INSTRUMENT=PCGUARD .*AFL_LLVM_IJON=1 afl-clang-fast .*-DPRISM_FUZZ_IJON.*-o .*p_pcguard /,
        /AFL_LLVM_IJON=1 build_diff\.sh --mode fuzz .* --cflag -DPRISM_FUZZ_IJON .*p_diff/,
        /AFL_LLVM_IJON=1 build_prism_diff\.sh --mode fuzz --cflag -DPRISM_FUZZ_IJON .*p_pdiff/,
        /AFL_LLVM_IJON=1 cross_oracle arm32 -DPRISM_FUZZ_IJON .*p_arm/,
        /AFL_LLVM_IJON=1 cross_oracle ppc -DPRISM_FUZZ_IJON .*p_ppc/
      ].each do |pat|
        assert_match pat, dry_build
      end
    end
  end

  def test_in_memory_vs_file_compilation_and_compiling_dsl_guard
    with_tmpdir("dsl-compile-") do |dir|
      ws_dir = File.join(dir, "ws")
      source = <<~RB
        require "/nonexistent/host/prism-fuzzer/lib/prism_fuzzer"

        c = PrismFuzzer.campaign "mem-vs-file-test" do
          workspace #{ws_dir.dump}
          duration "15m"
          after_run { report threads: 2 }
          prism :prism_a, repo: "https://example.invalid/prism.git", ref: "deadbeef", patches: "none", templates: "never"
          fuzzer "fuzz", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
          sync_group :afl, dir: "afl", primary: true
          worker :w1, fuzzer: "fuzz", sync_group: :afl, afl_role: :main
        end

        raise "expected Thread.current[:prism_fuzzer_compiling_dsl] == true" unless Thread.current[:prism_fuzzer_compiling_dsl]
        # Imperative invocations inside DSL file must become safe no-ops when compiling DSL.
        c.validate!
        raise "expected start! to be safe no-op returning self" unless c.start!(detach: true).equal?(c)
        raise "expected stop! to be safe no-op returning false" unless c.stop! == false
        c
      RB

      camp_file = File.join(dir, "camp.rb")
      File.write(camp_file, source)

      assert_nil Thread.current[:prism_fuzzer_compiling_dsl]
      ir_mem = PrismFuzzer::CampaignDSL.compile_source(source, path: "(in-memory)", fuzz_root: root_dir)
      assert_nil Thread.current[:prism_fuzzer_compiling_dsl]
      ir_file = PrismFuzzer::CampaignDSL.compile_file(camp_file, fuzz_root: root_dir)
      assert_nil Thread.current[:prism_fuzzer_compiling_dsl]

      assert_equal ir_mem, ir_file
      assert_equal 900, ir_mem.dig("lifecycle", "duration_seconds")

      # Ensure Thread.current[:prism_fuzzer_compiling_dsl] is restored even when DSL raises
      assert_raises(RuntimeError) do
        PrismFuzzer::CampaignDSL.compile_source('raise "boom"', path: "(boom)")
      end
      assert_nil Thread.current[:prism_fuzzer_compiling_dsl]

      assert_raises(PrismFuzzer::CampaignDSL::Error) do
        PrismFuzzer::CampaignDSL.compile_file(File.join(dir, "missing_campaign.rb"))
      end
    end
  end

  def test_executable_script_autorun_false_imperative_and_execute_flag
    with_tmpdir("dsl-autorun-") do |dir|
      upstream = PrismFuzzerTest::Fixtures.build_synthetic_upstream_prism(File.join(dir, "upstream"))
      ws_auto = File.join(dir, "ws_auto")
      ws_imp = File.join(dir, "ws_imp")
      ws_exec = File.join(dir, "ws_exec")
      exec_marker = File.join(dir, "executed.marker")

      # 1. Direct executable campaign script (autorun: true default) responds to validate/compile/plan
      auto_script = File.join(dir, "auto_camp.rb")
      write_executable(auto_script, <<~RB)
        #!/usr/bin/env ruby
        # frozen_string_literal: true

        require #{repo_path("lib/prism_fuzzer").dump}

        PrismFuzzer.campaign "auto-script-test" do
          workspace #{ws_auto.dump}
          prism :prism_a, repo: #{upstream[:repo].dump}, ref: #{upstream[:v1].dump}, patches: "none", templates: "never"
          fuzzer "fuzz", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
          sync_group :afl, dir: "afl", primary: true
          worker :w1, fuzzer: "fuzz", sync_group: :afl, afl_role: :main
        end
      RB

      v_out, = assert_cmd(auto_script, "validate", "--json")
      assert_equal true, JSON.parse(v_out)["valid"]
      c_out, = assert_cmd(auto_script, "compile")
      assert_equal "auto-script-test", JSON.parse(c_out)["name"]
      p_out, = assert_cmd(auto_script, "plan")
      assert_equal "asan_ubsan", JSON.parse(p_out).dig("fuzzers", "fuzz", "verify_profile")

      # 2. Multiple PrismFuzzer.campaign blocks with autorun: true fail safely on direct execution
      multi_script = File.join(dir, "multi_camp.rb")
      write_executable(multi_script, <<~RB)
        #!/usr/bin/env ruby
        require #{repo_path("lib/prism_fuzzer").dump}

        PrismFuzzer.campaign("one") do
          prism :prism_a, repo: #{upstream[:repo].dump}, ref: #{upstream[:v1].dump}
          fuzzer "fuzz", shape: :prism_parse, source: :prism_a
          sync_group :afl, dir: "afl", primary: true
          worker :w1, fuzzer: "fuzz", sync_group: :afl
        end
        PrismFuzzer.campaign("two") do
          prism :prism_a, repo: #{upstream[:repo].dump}, ref: #{upstream[:v1].dump}
          fuzzer "fuzz", shape: :prism_parse, source: :prism_a
          sync_group :afl, dir: "afl", primary: true
          worker :w1, fuzzer: "fuzz", sync_group: :afl
        end
      RB
      _mo, me, mst = run_cmd(multi_script, "validate")
      refute mst.success?
      assert_includes me, "Multiple PrismFuzzer.campaign blocks"

      # 3. Imperative script (c = PrismFuzzer.campaign ...; c.validate!) suppresses at_exit autorun
      imp_script = File.join(dir, "imperative_camp.rb")
      write_executable(imp_script, <<~RB)
        #!/usr/bin/env ruby
        require #{repo_path("lib/prism_fuzzer").dump}

        c = PrismFuzzer.campaign "imperative-test" do
          workspace #{ws_imp.dump}
          duration "15m"
          after_run { report threads: 2 }
          prism :prism_a, repo: #{upstream[:repo].dump}, ref: #{upstream[:v1].dump}, patches: "auto", templates: "auto"
          fuzzer "ws_fuzz", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
          sync_group :afl, dir: "afl", primary: true
          worker :w1, fuzzer: "ws_fuzz", sync_group: :afl, afl_role: :main, schedule: "fast"
        end

        c.validate!
        raise "expected distinct container_name" unless c.container_name.start_with?("prism-fuzzer-imperative-test-")
        puts JSON.generate("campaign" => c.stats["campaign"], "ws" => c.workspace[:fuzz_dir])
      RB
      imp_out, = assert_cmd(imp_script)
      imp_json = JSON.parse(imp_out)
      assert_equal "imperative-test", imp_json["campaign"]
      assert_equal File.expand_path(ws_imp), imp_json["ws"]

      # 4. autorun: false + --execute gate + compiling_dsl guard (examples/06_imperative_orchestrator.rb pattern)
      no_auto_script = File.join(dir, "autorun_false_exec.rb")
      write_executable(no_auto_script, <<~RB)
        #!/usr/bin/env ruby
        require #{repo_path("lib/prism_fuzzer").dump}

        phase1 = PrismFuzzer.campaign "imperative-phase-1", autorun: false do
          workspace #{ws_exec.dump}
          duration "10m"
          after_run { report threads: 2 }
          prism :prism_a, repo: #{upstream[:repo].dump}, ref: #{upstream[:v1].dump}, patches: "none", templates: "never"
          fuzzer "fuzz.fast", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
          sync_group :afl, dir: "afl", primary: true
          worker :scout, fuzzer: "fuzz.fast", sync_group: :afl, afl_role: :main, schedule: "explore"
        end

        if __FILE__ == $PROGRAM_NAME && !Thread.current[:prism_fuzzer_compiling_dsl]
          phase1.validate!
          if ARGV.include?("--execute")
            File.write(#{exec_marker.dump}, "executed")
            puts JSON.generate("mode" => "execute", "name" => phase1.ir["name"])
          else
            st = phase1.stats
            puts JSON.generate("mode" => "inspect", "name" => phase1.ir["name"], "execs" => st.dig("fleet", "total_execs") || 0)
          end
        end
      RB

      # Default invocation without --execute neither triggers autorun CLI nor runs --execute branch
      inspect_out, = assert_cmd(no_auto_script, "validate")
      assert_equal({ "mode" => "inspect", "name" => "imperative-phase-1", "execs" => 0 }, JSON.parse(inspect_out))
      refute_path_exists exec_marker

      # --execute triggers imperative execution path
      exec_out, = assert_cmd(no_auto_script, "--execute")
      assert_equal({ "mode" => "execute", "name" => "imperative-phase-1" }, JSON.parse(exec_out))
      assert_path_exists exec_marker

      # Compiling via bin/campaign.rb honors Thread.current[:prism_fuzzer_compiling_dsl] without running script body
      FileUtils.rm_f(exec_marker)
      compiled_out, = assert_ruby_cmd(repo_path("bin/campaign.rb"), "compile", "--campaign", no_auto_script)
      assert_equal "imperative-phase-1", JSON.parse(compiled_out)["name"]
      refute_path_exists exec_marker

      # Legacy `require "ruby_fuzz"` and `RubyFuzz.campaign` shims remain supported for external scripts.
      legacy_script = write_executable(File.join(dir, "legacy_ruby_fuzz_camp.rb"), <<~RB)
        #!/usr/bin/env ruby
        require #{repo_path("lib/ruby_fuzz").dump}

        c = RubyFuzz.campaign "legacy-shim-test", autorun: false do
          workspace #{File.join(dir, "legacy_ws").dump}
          prism :prism_a, repo: "https://example.invalid/prism.git", ref: "deadbeef", patches: "none", templates: "never"
          fuzzer "ws_fuzz", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
          sync_group :afl, dir: "afl", primary: true
          worker :w1, fuzzer: "ws_fuzz", sync_group: :afl, afl_role: :main
        end
        puts JSON.generate("name" => c.stats["campaign"], "same_mod" => (RubyFuzz == PrismFuzzer))
      RB
      legacy_out, = assert_cmd(legacy_script)
      assert_equal({ "name" => "legacy-shim-test", "same_mod" => true }, JSON.parse(legacy_out))
    end
  end

  def test_cli_subcommands_and_stop_lifecycle_tty_detach_stubs
    with_tmpdir("stop-lifecycle-") do |dir|
      camp = File.join(dir, "stop_lifecycle_camp.rb")
      ws_dir = File.join(dir, "stop_lifecycle_ws")
      File.write(camp, <<~RB)
        require #{repo_path("lib/prism_fuzzer").dump}

        PrismFuzzer.campaign "stop-lifecycle-test" do
          workspace #{ws_dir.dump}
          after_run { report threads: 2 }
          prism :prism_a, repo: "https://example.invalid/prism.git", ref: "deadbeef", patches: "none", templates: "never"
          fuzzer "ws_fuzz", shape: :prism_parse, source: :prism_a, sanitizers: %i[asan ubsan], mode: :fast, afl: :lto
          sync_group :afl, dir: "afl", primary: true
          worker :w1, fuzzer: "ws_fuzz", sync_group: :afl, afl_role: :main, schedule: "fast"
        end
      RB

      # CLI subcommands: validate, compile, plan, and stop --dry-run / --no-post
      val_out, = assert_ruby_cmd(repo_path("bin/campaign.rb"), "validate", "--campaign", camp, "--json")
      assert_equal true, JSON.parse(val_out)["valid"]
      comp_out, = assert_ruby_cmd(repo_path("bin/campaign.rb"), "compile", "--campaign", camp)
      assert_equal "stop-lifecycle-test", JSON.parse(comp_out)["name"]
      plan_out, = assert_ruby_cmd(repo_path("bin/campaign.rb"), "plan", "--campaign", camp)
      assert_equal "asan_ubsan", JSON.parse(plan_out).dig("fuzzers", "ws_fuzz", "verify_profile")
      dry_stop_out, = assert_ruby_cmd(repo_path("bin/campaign.rb"), "stop", "--campaign", camp, "--dry-run")
      assert_includes dry_stop_out, "docker stop -t 30 "
      assert_includes dry_stop_out, "report.rb"
      dry_stop_nopost, = assert_ruby_cmd(repo_path("bin/campaign.rb"), "stop", "--campaign", camp, "--no-post", "--dry-run")
      assert_includes dry_stop_nopost, "docker stop -t 30 "
      refute_match(/triage\.rb|coverage\.sh|report\.rb|publish\.rb/, dry_stop_nopost)

      # 1. Detached launch with CLI overrides (--publish --run-id) persists lifecycle for `stop`
      ctx_det = PrismFuzzer::Campaign.resolve_context(
        campaign_path: camp,
        cli: { post: true, publish: true, publish_run_id: "det-01" },
        fuzz_root: root_dir
      )
      PrismFuzzer::Campaign.write_run_state!(ctx_det, lifecycle: ctx_det[:lifecycle], post_handled: false)
      stop_ctx = PrismFuzzer::Campaign.resolve_stop_context(
        PrismFuzzer::Campaign.resolve_context(campaign_path: camp, fuzz_root: root_dir),
        {}
      )
      assert_equal "det-01", stop_ctx[:lifecycle].dig("publish", "run_id")
      nopost_stop_ctx = PrismFuzzer::Campaign.resolve_stop_context(stop_ctx, { no_post: true })
      refute PrismFuzzer::Campaign.any_post_steps?(nopost_stop_ctx[:lifecycle])

      # 2. Stub container stop & post pipeline to verify stop_campaign! runs post once and avoids duplicate runs
      post_calls = []
      running = true
      with_stubbed_singleton_methods(
        PrismFuzzer::Campaign,
        stop_container!: ->(_name, timeout: 30) { running ? (running = false; true) : false },
        run_post_pipeline!: ->(c, dry_run: false) { post_calls << [c[:lifecycle].dup, dry_run] },
        print_stats_summary: ->(_c, _s = nil) { nil }
      ) do
        base_ctx = PrismFuzzer::Campaign.resolve_context(campaign_path: camp, fuzz_root: root_dir)
        out1, = capture_io { assert_equal true, PrismFuzzer::Campaign.stop_campaign!(base_ctx) }
        assert_includes out1, "Stopped '"
        assert_equal 1, post_calls.size
        assert_equal "det-01", post_calls[0][0].dig("publish", "run_id")

        # Repeated stop when container is already stopped must not re-run post steps
        out2, = capture_io { assert_equal false, PrismFuzzer::Campaign.stop_campaign!(base_ctx) }
        assert_includes out2, "is not running"
        assert_equal 1, post_calls.size

        # Active foreground watcher holding flock suppresses duplicate post execution in stop_campaign!
        running = true
        PrismFuzzer::Campaign.write_run_state!(base_ctx, lifecycle: base_ctx[:lifecycle], post_handled: false)
        lock_ready_r, lock_ready_w = IO.pipe
        lock_done_r, lock_done_w = IO.pipe
        pid = Process.fork do
          lock_ready_r.close
          lock_done_w.close
          PrismFuzzer::Campaign.with_watcher_lock(base_ctx, blocking: true) do
            lock_ready_w.write("1")
            lock_ready_w.close
            lock_done_r.read
          end
          exit!(0)
        end
        lock_ready_w.close
        lock_done_r.close
        lock_ready_r.read(1)
        lock_ready_r.close
        out_locked = nil
        begin
          out_locked, = capture_io { PrismFuzzer::Campaign.stop_campaign!(base_ctx) }
        ensure
          lock_done_w.close
          Process.wait(pid)
        end
        assert_includes out_locked, "Active foreground runner will complete post-run steps"
        assert_equal 1, post_calls.size, "expected active watcher lock to prevent duplicate post call"

        # Imperative start! preserves after_run (run_post: false) and stop! invokes it when stopped
        with_stubbed_singleton_methods(
          PrismFuzzer::Campaign,
          run_campaign!: lambda do |c, detach: false, dry_run: false, skip_sync: false, skip_build: false, run_post: true|
            raise "expected start! to pass run_post: false" unless run_post == false
            raise "expected start! to preserve report lifecycle" unless PrismFuzzer::Campaign.any_post_steps?(c[:lifecycle])

            PrismFuzzer::Campaign.write_run_state!(c, lifecycle: c[:lifecycle], post_handled: false)
            0
          end
        ) do
          inst = PrismFuzzer::Campaign::Instance.new(
            PrismFuzzer::CampaignDSL.compile_file(camp, fuzz_root: root_dir),
            source_path: camp
          )
          inst.start!(detach: true, skip_sync: true, skip_build: true)
          running = true
          capture_io { assert_equal true, inst.stop! }
          assert_equal 2, post_calls.size
        end
      end

      # 3. Timed interactive TTY campaigns must attach to tmux and honor both expiry and Ctrl-B d detach
      attach_calls = []
      timed_post_calls = []
      tmux_alive = false
      timed_ctx = PrismFuzzer::Campaign.resolve_context(
        campaign_path: camp,
        cli: { duration_seconds: 60 },
        fuzz_root: root_dir
      )

      with_stubbed_singleton_methods(
        PrismFuzzer::Campaign,
        in_docker?: -> { false },
        interactive_tty?: ->(**) { true },
        build!: ->(*_a, **_kw) { nil },
        start_detached_container!: ->(c) { ["deadbeef0001", PrismFuzzer::Campaign.write_run_state!(c, lifecycle: c[:lifecycle], post_handled: false)] },
        attach_tmux_session!: lambda do |_c, duration_seconds: nil|
          attach_calls << duration_seconds
          { expired: !tmux_alive, interrupted: false }
        end,
        tmux_session_alive?: ->(_n) { tmux_alive },
        wait_for_container_exit: ->(_n, **_kw) { nil },
        run_post_pipeline!: ->(c, dry_run: false) { timed_post_calls << [c[:lifecycle].dup, dry_run] },
        print_stats_summary: ->(_c, _s = nil) { nil }
      ) do
        # Case A: Timer expires while attached -> triggers post pipeline
        tmux_alive = false
        out_exp, = capture_io { PrismFuzzer::Campaign.run_campaign!(timed_ctx, skip_sync: true, skip_build: true) }
        assert_includes out_exp, "Timer expired (60s)"
        assert_equal [60], attach_calls
        assert_equal 1, timed_post_calls.size

        # Case B: User detaches with Ctrl-B d while timed -> returns to shell leaving post_handled=false
        tmux_alive = true
        out_det, = capture_io { PrismFuzzer::Campaign.run_campaign!(timed_ctx, skip_sync: true, skip_build: true) }
        assert_includes out_det, "Detached from campaign"
        assert_equal [60, 60], attach_calls
        assert_equal 1, timed_post_calls.size
        st_after_det = PrismFuzzer::Campaign.read_run_state(timed_ctx)
        assert_equal false, st_after_det["post_handled"]
      end
    end
  end

  def test_topology_read_json_toctou_resilience_idempotent_ir_write_and_triage_cache
    with_tmpdir("topo-toctou-") do |workdir|
      ir_path = File.join(workdir, "build", "topology.ir.json")
      bin_topo = File.join(workdir, "bin", "topology.json")
      triage_dir = File.join(workdir, "report", "triage")
      FileUtils.mkdir_p([File.dirname(ir_path), File.dirname(bin_topo), triage_dir])

      sample_topo = {
        "schema_version" => 2,
        "name" => "toctou-test",
        "sources" => { "prism_a" => { "kind" => "prism", "dir" => workdir } },
        "fuzzers" => { "fuzz" => { "shape" => "prism_parse", "source" => "prism_a", "binary" => File.join(workdir, "bin", "fuzz") } },
        "sync_groups" => { "afl" => { "dir" => "afl", "primary" => true } },
        "workers" => [{ "id" => "main", "kind" => "afl", "fuzzer" => "fuzz", "sync_group" => "afl", "afl_role" => "main" }],
        "explain_binaries" => {}
      }
      PrismFuzzer::Topology.write_json_atomic(ir_path, sample_topo)
      PrismFuzzer::Topology.write_json_atomic(bin_topo, sample_topo)

      # 1. Transient ENOENT between File.file? and File.read retries and succeeds cleanly.
      orig_read = File.method(:read)
      flaky_calls = 0
      with_stubbed_singleton_methods(File, read: lambda do |path, *args, **kwargs|
        if path == ir_path && (flaky_calls += 1) == 1
          raise Errno::ENOENT, path
        end
        orig_read.call(path, *args, **kwargs)
      end) do
        parsed = PrismFuzzer::Topology.read_json(ir_path)
        assert_equal "toctou-test", parsed["name"]
        assert_equal 2, flaky_calls
      end

      # 2. Persistent ENOENT after File.file? returns nil without raising, allowing discover fallback to bin/topology.json.
      saved_camp = ENV["CAMPAIGN"]
      begin
        ENV["CAMPAIGN"] = ir_path
        with_stubbed_singleton_methods(File, read: lambda do |path, *args, **kwargs|
          raise Errno::ENOENT, path if path == ir_path
          orig_read.call(path, *args, **kwargs)
        end) do
          discovered = PrismFuzzer::Topology.discover(triage_dir: triage_dir, bin_dir: File.dirname(bin_topo))
          assert_equal "toctou-test", discovered["name"]
        end
      ensure
        ENV["CAMPAIGN"] = saved_camp
      end

      # 3. write_container_ir! skips atomic rename churn when serialized IR is unchanged.
      camp_rb = File.join(workdir, "camp.rb")
      File.write(camp_rb, <<~RUBY)
        PrismFuzzer.campaign "idempotent-ir" do
          workspace #{workdir.inspect}, build_dir: #{File.join(workdir, "build").inspect}
          prism :prism_a, dir: #{workdir.inspect}
          fuzzer "fuzz", shape: :prism_parse, source: :prism_a
          sync_group :afl, dir: "afl", primary: true
          worker :main, kind: :afl, fuzzer: "fuzz", sync_group: :afl, afl_role: :main
        end
      RUBY
      ctx = PrismFuzzer::Campaign.resolve_context(campaign_path: camp_rb)
      written = PrismFuzzer::Campaign.write_container_ir!(ctx)
      stat1 = File.stat(written)
      sleep 0.02
      PrismFuzzer::Campaign.write_container_ir!(ctx)
      stat2 = File.stat(written)
      assert_equal stat1.ino, stat2.ino, "expected unchanged topology.ir.json inode when IR is identical"
      assert_equal stat1.mtime, stat2.mtime

      # 4. FuzzTriage#with_cached_topology memoizes discover across concurrent worker lookups.
      discover_calls = 0
      orig_discover = PrismFuzzer::Topology.method(:discover)
      with_stubbed_singleton_methods(PrismFuzzer::Topology, discover: lambda do |**kw|
        discover_calls += 1
        orig_discover.call(**kw)
      end) do
        FuzzTriage.with_cached_topology do
          threads = Array.new(6) do
            Thread.new { FuzzTriage.resolve_topology(triage_dir: triage_dir) }
          end
          results = threads.map(&:value)
          assert(results.all? { |r| r && r["name"] == "toctou-test" })
        end
        assert_operator discover_calls, :<=, 6

        before = discover_calls
        FuzzTriage.with_cached_topology do
          first = FuzzTriage.resolve_topology(triage_dir: triage_dir)
          assert_equal "toctou-test", first["name"]
          assert_equal before + 1, discover_calls
          5.times { FuzzTriage.resolve_topology(triage_dir: triage_dir) }
          assert_equal before + 1, discover_calls, "expected cached resolve_topology to avoid repeated disk discovery"
        end
      end
    end
  end

  private

  def with_stubbed_singleton_methods(target, stubs)
    sc = target.singleton_class
    saved = stubs.keys.each_with_object({}) do |name, h|
      had = sc.method_defined?(name) || sc.private_method_defined?(name)
      h[name] = had ? target.method(name) : :__absent__
    end
    stubs.each { |name, impl| sc.define_method(name, impl) }
    yield
  ensure
    saved&.each do |name, orig|
      if orig == :__absent__
        sc.remove_method(name) if sc.method_defined?(name) || sc.private_method_defined?(name)
      else
        sc.define_method(name, orig)
      end
    end
  end
end
