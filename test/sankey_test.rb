# frozen_string_literal: true

require_relative "lib/autorun"
require "rexml/document"
require_relative "../report/sankey"

class SankeyTest < Minitest::Test
  def test_sankey_extraction_origin_tracing_buckets_and_tail_collapse
    with_tmpdir("sankey-test-") do |workdir|
      tdir = File.join(workdir, "triage")
      afl_dir = File.join(workdir, "afl")
      ijon_dir = File.join(workdir, "afl-ijon")

      FileUtils.mkdir_p([
        File.join(tdir, "ABRT", "b1"),
        File.join(tdir, "ABRT", "b2"),
        File.join(tdir, "SEGV", "b3"),
        File.join(afl_dir, "main", "queue"),
        File.join(afl_dir, "msan", "queue"),
        File.join(afl_dir, "diff", "queue"),
        File.join(afl_dir, "ppc"),
        File.join(afl_dir, "main", "crashes"),
        File.join(afl_dir, "msan", "crashes"),
        File.join(afl_dir, "diff", "crashes"),
        File.join(ijon_dir, "ijon", "queue")
      ])

      %w[main msan diff ppc].each do |worker|
        FileUtils.touch(File.join(afl_dir, worker, "fuzzer_stats"))
      end

      [
        File.join(afl_dir, "main", "queue", "id:000000,time:0,execs:0,orig:seed_0001_fixture"),
        File.join(ijon_dir, "ijon", "queue", "id:000001,sync:seeds_0,src:seed_9999"),
        File.join(afl_dir, "main", "queue", "id:000002,sync:ijon_peer,src:000001"),
        File.join(afl_dir, "msan", "queue", "id:000003,sync:main,src:000002"),
        File.join(afl_dir, "diff", "queue", "id:000004,time:0,execs:0,orig:sample.rb")
      ].each { |path| File.write(path, "") }

      c_main = File.join(afl_dir, "main", "crashes", "id:000000,sig:06,src:000002,time:100")
      c_msan = File.join(afl_dir, "msan", "crashes", "id:000000,sig:06,src:000003,time:500")
      c_diff = File.join(afl_dir, "diff", "crashes", "id:000000,sig:06,src:000004,time:250")
      [c_main, c_msan, c_diff].each { |path| File.write(path, "") }

      b1_entries = Array.new(10) do
        { "worker" => "msan", "path" => c_msan, "time_ms" => 500, "mtime" => "2026-11-20T00:08:20Z" }
      end + Array.new(2) do
        { "worker" => "main", "path" => c_main, "time_ms" => 100, "mtime" => "2026-11-20T00:01:40Z" }
      end
      write_occurrences(tdir, "ABRT/b1", b1_entries)

      b2_entries = Array.new(5) do
        { "worker" => "diff", "path" => c_diff, "time_ms" => 250, "mtime" => "2026-11-20T00:04:10Z" }
      end
      write_occurrences(tdir, "ABRT/b2", b2_entries)

      buckets = primary_triage_buckets
      clusters = primary_clusters(buckets)
      write_json(File.join(tdir, "metadata.json"), { "buckets" => buckets })
      write_json(File.join(tdir, "clusters.json"), { "clusters" => clusters })

      occ_json = File.join(workdir, "occ.json")
      buckets_json = File.join(workdir, "buckets.json")
      cap2_json = File.join(workdir, "cap2.json")
      svg_path = File.join(workdir, "sankey.svg")
      html_path = File.join(workdir, "sankey.html")

      assert_ruby_cmd(sankey_rb, "--triage-dir", tdir, "--afl-dir", afl_dir, "--format", "json", "-o", occ_json)
      assert_ruby_cmd(sankey_rb, "--triage-dir", tdir, "--afl-dir", afl_dir, "--metric", "buckets", "--format", "json", "-o", buckets_json)
      assert_ruby_cmd(sankey_rb, "--triage-dir", tdir, "--afl-dir", afl_dir, "--max-clusters", "2", "--format", "json", "-o", cap2_json)
      assert_ruby_cmd(sankey_rb, "--triage-dir", tdir, "--afl-dir", afl_dir, "--format", "svg", "-o", svg_path)
      assert_ruby_cmd(sankey_rb, "--triage-dir", tdir, "--afl-dir", afl_dir, "--max-clusters", "2", "--format", "html", "-o", html_path)

      occ = JSON.parse(File.read(occ_json))
      assert_equal 20, occ["total_weight"]
      assert_equal %w[origin worker category cluster], occ["layers"]
      assert_equal ["ppc"], occ["zero_crash_workers"]
      assert_conservation(occ)

      # Verify grammar origin resolved via AFL queue lineage (ijon_peer -> seeds_0)
      orig_links = occ["links"].select { |l| l["column"] == 0 }.to_h { |l| [[l["from"], l["to"]], l["value"]] }
      assert_equal 2, orig_links[%w[grammar main]]
      assert_equal 10, orig_links[%w[grammar msan]]
      assert_equal 5, orig_links[%w[corpus diff]]

      # Verify buckets metric counts unique worker x bucket pairs (4 pairs: main/ABRT-b1, msan/ABRT-b1, diff/ABRT-b2, main/SEGV-b3)
      buckets_report = JSON.parse(File.read(buckets_json))
      assert_conservation(buckets_report)
      assert_equal 4, buckets_report["total_weight"]

      w_links = buckets_report["links"].select { |l| l["column"] == 1 }.to_h { |l| [[l["from"], l["to"]], l["value"]] }
      assert_equal 1, w_links[%w[main stream_diff]]
      assert_equal 1, w_links[%w[msan stream_diff]]

      # Verify tail cluster collapse (--max-clusters 2 keeps top 1 + __other__)
      cap2 = JSON.parse(File.read(cap2_json))
      assert_conservation(cap2)
      c_ids = cap2["nodes"].select { |n| n["layer"] == "cluster" }.map { |n| n["id"] }.sort
      assert_equal %w[__other__ cluster-01], c_ids

      doc = REXML::Document.new(File.read(svg_path))
      assert_equal "svg", doc.root&.name

      html = File.read(html_path)
      assert_includes html, "Prism Fuzzing Flow"
      refute_includes html, "&amp;rarr;"
      refute_includes html, "First Discoverer"
      refute_includes html, "first_finds"
      assert_includes html, "Worker &times; Bucket Pairs"
      assert_includes html, "Other clusters (2)"
    end
  end

  def test_sankey_fallback_when_clusters_json_omitted
    with_tmpdir("sankey-test-") do |workdir|
      tdir = File.join(workdir, "triage")
      FileUtils.mkdir_p(tdir)
      write_json(File.join(tdir, "metadata.json"), { "buckets" => primary_triage_buckets })

      no_clus_path = File.join(workdir, "no_clus.json")
      assert_ruby_cmd(sankey_rb, "--triage-dir", tdir, "--no-origins", "--format", "json", "-o", no_clus_path)

      report = JSON.parse(File.read(no_clus_path))
      assert_equal %w[worker category cluster], report["layers"]
      assert_equal 20, report["total_weight"]
    end
  end

  def test_sankey_empty_triage_handling
    assert_equal "cluster-01 · node_location: CASE_MATCH",
                 FuzzSankey.concise_cluster_title({
                   "cluster_id" => "cluster-01",
                   "representative" => {
                     "headline" => "INVARIANT[node_location]: site=pm_case_match_node_create op=tokens_length kind=length_underflow [detail: length=4294967292]"
                   }
                 })
    assert_equal "#34d399", FuzzSankey.color_for("node_sub_location", layer_kind: :category)
    with_tmpdir("sankey-test-") do |workdir|
      empty_dir = File.join(workdir, "empty_triage")
      FileUtils.mkdir_p(empty_dir)
      File.write(File.join(empty_dir, "metadata.json"), "{\"buckets\":[]}\n")
      File.write(File.join(empty_dir, "clusters.json"), "{\"clusters\":[]}\n")

      empty_svg = File.join(workdir, "empty.svg")
      empty_html = File.join(workdir, "empty.html")
      assert_ruby_cmd(sankey_rb, "--triage-dir", empty_dir, "--no-origins", "--format", "svg", "-o", empty_svg)
      assert_ruby_cmd(sankey_rb, "--triage-dir", empty_dir, "--no-origins", "--format", "html", "-o", empty_html)

      doc = REXML::Document.new(File.read(empty_svg))
      assert_equal "svg", doc.root&.name
      assert_path_exists empty_html

      require_relative "../report/lib/sankey/extract"
      mk_cluster = ->(hl) { { "cluster_id" => "c1", "representative" => { "bucket_id" => "ABRT/x", "headline" => hl } } }
      assert_equal "c1 · diff: prism_err_cruby_ok (return)",
                   FuzzSankey.concise_cluster_title(mk_cluster.call("INVARIANT[diff_parse_y]: kind=syntax_mismatch sub=prism_err_cruby_ok ctx=return prism=void_expression cruby=ok [detail: nul=0]"))
      assert_equal "c1 · diff: preexe_order",
                   FuzzSankey.concise_cluster_title(mk_cluster.call("INVARIANT[diff_parse_y]: kind=ast_preexe_order_mismatch sub=tree [detail: idx=1]"))
      assert_equal "c1 · diff: tree TARGET vs MTARGET",
                   FuzzSankey.concise_cluster_title(mk_cluster.call("INVARIANT[diff_parse_y]: kind=ast_tree_mismatch sub=tag ctx=FOR.idx prism=TARGET cruby=MTARGET [detail: idx=7]"))
      assert_equal "c1 · stream_diff: error_loc (array_term)",
                   FuzzSankey.concise_cluster_title(mk_cluster.call("INVARIANT[stream_diff]: kind=ast_mismatch sub=error_loc type=array_term [detail: size=11]"))
      assert_equal "c1 · oracle_arm32: ast: INTEGER",
                   FuzzSankey.concise_cluster_title(mk_cluster.call("INVARIANT[oracle_arm32]: kind=ast_size_mismatch section=ast type=PM_INTEGER_NODE stream=0 [detail: first_diff=30]"))
      assert_equal "c1 · diff_prism: ast: STRING",
                   FuzzSankey.concise_cluster_title(mk_cluster.call("INVARIANT[diff_prism]: kind=serialize_mismatch sub=bytes section=ast type=PM_STRING_NODE [detail: a_len=40]"))
      assert_equal "c1 · stack-overflow (parser_lex)",
                   FuzzSankey.concise_cluster_title(mk_cluster.call("ERROR: AddressSanitizer: stack-overflow in parser_lex (src/prism.c:10179)"))
      assert_equal "c1 · stack-overflow (parser_lex)",
                   FuzzSankey.concise_cluster_title({
                     "cluster_id" => "c1",
                     "representative" => {
                       "bucket_id" => "stack-overflow/abc",
                       "headline" => "==7==ERROR: AddressSanitizer: stack-overflow on address 0xffffc19be9f0",
                       "top_prism_frame" => "parser_lex@src/prism.c:10179"
                     }
                   })
      assert_equal "c1 · SEGV (fuzz.ijon.diff)",
                   FuzzSankey.concise_cluster_title({
                     "cluster_id" => "c1",
                     "reasons" => { "SEGV" => 1 },
                     "representative" => {
                       "bucket_id" => "SEGV/ef46db3751d8e999",
                       "reproduced_by" => "fuzz.ijon.diff",
                       "headline" => ""
                     }
                   })
    end
  end

  def test_sankey_html_and_tooltip_xss_escaping
    with_tmpdir("sankey-test-") do |workdir|
      xss_dir = File.join(workdir, "xss_triage")
      xss_afl = File.join(workdir, "xss_afl")
      xss_worker = "w'xss<img src=x>"

      FileUtils.mkdir_p([
        File.join(xss_dir, "ABRT", "b_xss"),
        File.join(xss_afl, xss_worker, "crashes"),
        File.join(xss_afl, "main", "crashes")
      ])
      FileUtils.touch([
        File.join(xss_afl, xss_worker, "fuzzer_stats"),
        File.join(xss_afl, "main", "fuzzer_stats")
      ])

      xss_crash = File.join(xss_afl, xss_worker, "crashes", "id:000000,sig:06,time:10")
      File.write(xss_crash, "")
      write_occurrences(xss_dir, "ABRT/b_xss", [
        { "worker" => xss_worker, "path" => xss_crash, "time_ms" => 10, "mtime" => "2026-11-20T00:00:10Z" }
      ])

      headline = "boom </script><img src=x onerror=alert(1)> ' \" &"
      buckets = [
        {
          "bucket_id" => "ABRT/b_xss",
          "reason" => "ABRT",
          "signature" => "b_xss",
          "reproducible" => true,
          "reproduced_by" => "fuzz",
          "verify_profile" => "asan_ubsan",
          "occurrences" => { "count" => 1, "by_worker" => { xss_worker => 1 } },
          "symptom" => { "headline" => headline, "invariant" => nil },
          "input" => {}
        }
      ]
      clusters = [
        {
          "cluster_id" => "cluster-xss",
          "group" => "prism_flaw",
          "bucket_count" => 1,
          "occurrences" => 1,
          "representative" => { "bucket_id" => "ABRT/b_xss", "headline" => headline },
          "buckets" => [{ "bucket_id" => "ABRT/b_xss" }]
        }
      ]
      write_json(File.join(xss_dir, "metadata.json"), { "buckets" => buckets })
      write_json(File.join(xss_dir, "clusters.json"), { "clusters" => clusters })

      xss_html = File.join(workdir, "xss.html")
      assert_ruby_cmd(sankey_rb, "--triage-dir", xss_dir, "--afl-dir", xss_afl, "--no-origins", "--format", "html", "-o", xss_html)

      html = File.read(xss_html)
      assert_equal 1, html.scan(/<\/script>/i).size, "unexpected unescaped </script> inside inline JSON"
      refute_includes html, "<img src=x"
      assert_includes html, "function escapeHtml("
      assert_includes html, "escapeHtml(meta.headline)"
      assert_includes html, "escapeHtml(meta.label || rect.dataset.rawId)"
      assert_includes html, "escapeHtml(sl)"
      assert_includes html, "escapeHtml(dl)"
    end
  end

  def test_sankey_cruby_crash_and_diff_prism_filters_badges_help
    with_tmpdir("sankey-test-") do |workdir|
      grp_dir = File.join(workdir, "groups_triage")
      grp_afl = File.join(workdir, "groups_afl")

      FileUtils.mkdir_p([
        File.join(grp_dir, "SEGV", "b_flaw"),
        File.join(grp_dir, "ABRT", "b_cruby"),
        File.join(grp_dir, "ABRT", "b_diff"),
        File.join(grp_dir, "ABRT", "b_pdiff"),
        File.join(grp_afl, "main", "crashes"),
        File.join(grp_afl, "diff", "crashes"),
        File.join(grp_afl, "pdiff", "crashes")
      ])
      %w[main diff pdiff].each do |worker|
        FileUtils.touch(File.join(grp_afl, worker, "fuzzer_stats"))
      end

      write_occurrences(grp_dir, "SEGV/b_flaw", [
        { "worker" => "main", "path" => File.join(grp_afl, "main", "crashes", "c1"), "time_ms" => 10, "mtime" => "2026-11-20T00:00:10Z" }
      ])
      write_occurrences(grp_dir, "ABRT/b_cruby", [
        { "worker" => "diff", "path" => File.join(grp_afl, "diff", "crashes", "c2"), "time_ms" => 20, "mtime" => "2026-11-20T00:00:20Z" }
      ])
      write_occurrences(grp_dir, "ABRT/b_diff", [
        { "worker" => "diff", "path" => File.join(grp_afl, "diff", "crashes", "c3"), "time_ms" => 30, "mtime" => "2026-11-20T00:00:30Z" }
      ])
      write_occurrences(grp_dir, "ABRT/b_pdiff", [
        { "worker" => "pdiff", "path" => File.join(grp_afl, "pdiff", "crashes", "c4"), "time_ms" => 40, "mtime" => "2026-11-20T00:00:40Z" }
      ])

      buckets = [
        {
          "bucket_id" => "SEGV/b_flaw",
          "reason" => "SEGV",
          "signature" => "b_flaw",
          "reproducible" => true,
          "verify_profile" => "asan_ubsan",
          "occurrences" => { "count" => 2, "by_worker" => { "main" => 2 } },
          "symptom" => { "headline" => "SUMMARY: AddressSanitizer: SEGV src/prism.c:1", "invariant" => nil },
          "input" => {}
        },
        {
          "bucket_id" => "ABRT/b_cruby",
          "reason" => "ABRT",
          "signature" => "b_cruby",
          "reproducible" => true,
          "verify_profile" => "diff_parse_y",
          "occurrences" => { "count" => 3, "by_worker" => { "diff" => 3 } },
          "symptom" => { "headline" => "CRASH[diff_parse_y]: oracle=cruby_crash compile.c:99", "invariant" => nil },
          "input" => {}
        },
        {
          "bucket_id" => "ABRT/b_diff",
          "reason" => "ABRT",
          "signature" => "b_diff",
          "reproducible" => true,
          "verify_profile" => "diff_parse_y",
          "occurrences" => { "count" => 4, "by_worker" => { "diff" => 4 } },
          "symptom" => { "headline" => "INVARIANT[diff_parse_y]: kind=syntax_mismatch sub=prism_ok_cruby_err", "invariant" => { "namespace" => "diff_parse_y", "fields" => { "kind" => "syntax_mismatch" } } },
          "input" => {}
        },
        {
          "bucket_id" => "ABRT/b_pdiff",
          "reason" => "ABRT",
          "signature" => "b_pdiff",
          "reproducible" => true,
          "verify_profile" => "diff_prism",
          "occurrences" => { "count" => 5, "by_worker" => { "pdiff" => 5 } },
          "symptom" => { "headline" => "INVARIANT[diff_prism]: kind=ast_mismatch", "invariant" => { "namespace" => "diff_prism", "fields" => { "kind" => "ast_mismatch" } } },
          "input" => {}
        }
      ]
      clusters = [
        { "cluster_id" => "c-flaw", "group" => "prism_flaw", "bucket_count" => 1, "occurrences" => 2, "representative" => { "bucket_id" => "SEGV/b_flaw", "headline" => "flaw" }, "buckets" => [{ "bucket_id" => "SEGV/b_flaw" }] },
        { "cluster_id" => "c-cruby", "group" => "cruby_crash", "bucket_count" => 1, "occurrences" => 3, "representative" => { "bucket_id" => "ABRT/b_cruby", "headline" => "cruby" }, "buckets" => [{ "bucket_id" => "ABRT/b_cruby" }] },
        { "cluster_id" => "c-diff", "group" => "diff_parse_y", "bucket_count" => 1, "occurrences" => 4, "representative" => { "bucket_id" => "ABRT/b_diff", "headline" => "diff" }, "buckets" => [{ "bucket_id" => "ABRT/b_diff" }] },
        { "cluster_id" => "c-pdiff", "group" => "diff_prism", "bucket_count" => 1, "occurrences" => 5, "representative" => { "bucket_id" => "ABRT/b_pdiff", "headline" => "pdiff" }, "buckets" => [{ "bucket_id" => "ABRT/b_pdiff" }] }
      ]
      write_json(File.join(grp_dir, "metadata.json"), { "buckets" => buckets })
      write_json(File.join(grp_dir, "clusters.json"), { "clusters" => clusters })

      groups_html = File.join(workdir, "groups.html")
      groups_cruby = File.join(workdir, "groups_cruby.json")
      groups_pdiff = File.join(workdir, "groups_pdiff.json")

      help_txt, _err = assert_ruby_cmd(sankey_rb, "--help")
      assert_ruby_cmd(sankey_rb, "--triage-dir", grp_dir, "--afl-dir", grp_afl, "--no-origins", "--format", "html", "-o", groups_html)
      assert_ruby_cmd(sankey_rb, "--triage-dir", grp_dir, "--afl-dir", grp_afl, "--no-origins", "--group", "cruby_crash", "--format", "json", "-o", groups_cruby)
      assert_ruby_cmd(sankey_rb, "--triage-dir", grp_dir, "--afl-dir", grp_afl, "--no-origins", "--group", "diff_prism", "--format", "json", "-o", groups_pdiff)

      assert_includes help_txt, "all | prism_flaw | cruby_crash | diff_parse_y | diff_prism"

      html = File.read(groups_html)
      assert_includes html, 'data-val="cruby_crash">CRuby Crashes</button>'
      assert_includes html, 'data-val="diff_prism">Diff Prism</button>'
      assert_includes html, '<span class="badge-cruby">cruby_crash</span>'
      cruby_row = html[/<tr data-cluster-id="c-cruby">.*?<\/tr>/m]
      refute_nil cruby_row, "expected table row for c-cruby"
      refute_includes cruby_row, "badge-flaw"

      cruby_j = JSON.parse(File.read(groups_cruby))
      pdiff_j = JSON.parse(File.read(groups_pdiff))
      cruby_ids = cruby_j["nodes"].select { |n| n["layer"] == "cluster" }.map { |n| n["id"] }
      assert_equal ["c-cruby"], cruby_ids
      pdiff_ids = pdiff_j["nodes"].select { |n| n["layer"] == "cluster" }.map { |n| n["id"] }
      assert_equal ["c-pdiff"], pdiff_ids
    end
  end

  def test_sankey_interleaved_extract_dataset_no_topology_leak
    with_tmpdir("sankey-test-") do |workdir|
      ws1 = File.join(workdir, "topo_ws1")
      ws2 = File.join(workdir, "topo_ws2")

      setup_topo_workspace(
        ws1,
        topo_name: "topo-one",
        bucket_id: "ABRT/b1",
        cluster_id: "c1",
        seed_orig: "seed_0001",
        sync_alias: "alias_one",
        workers: [
          {
            "id" => "w_beta", "kind" => "afl", "fuzzer" => "fuzz", "sync_group" => "afl",
            "afl_role" => "main", "color" => "#445566",
            "peer_imports" => [{ "group" => "afl", "worker" => "w_alpha", "alias" => "alias_one" }]
          },
          {
            "id" => "w_alpha", "kind" => "afl", "fuzzer" => "fuzz", "sync_group" => "afl",
            "afl_role" => "secondary", "color" => "#112233"
          }
        ]
      )
      setup_topo_workspace(
        ws2,
        topo_name: "topo-two",
        bucket_id: "ABRT/b2",
        cluster_id: "c2",
        seed_orig: "sample.rb",
        sync_alias: "alias_two",
        workers: [
          {
            "id" => "w_alpha", "kind" => "afl", "fuzzer" => "fuzz", "sync_group" => "afl",
            "afl_role" => "main", "color" => "#abcdef"
          },
          {
            "id" => "w_beta", "kind" => "afl", "fuzzer" => "fuzz", "sync_group" => "afl",
            "afl_role" => "secondary", "color" => "#fedcba",
            "peer_imports" => [{ "group" => "afl", "worker" => "w_alpha", "alias" => "alias_two" }]
          }
        ]
      )

      ds1 = FuzzSankey.extract_dataset(triage_dir: File.join(ws1, "triage"), afl_dir: File.join(ws1, "afl"))
      ds2 = FuzzSankey.extract_dataset(triage_dir: File.join(ws2, "triage"), afl_dir: File.join(ws2, "afl"))

      refute FuzzSankey.instance_variable_defined?(:@active_topology), "FuzzSankey must not hold @active_topology state"
      assert_equal "topo-one", ds1[:topology]&.fetch("name", nil)
      assert_equal "topo-two", ds2[:topology]&.fetch("name", nil)

      # Verify origin tracer forwards topo so sync:alias_one -> w_alpha -> grammar
      beta_rec1 = ds1[:records].find { |r| r[:worker] == "w_beta" }
      refute_nil beta_rec1
      assert_equal "grammar", beta_rec1[:origin]

      beta_rec2 = ds2[:records].find { |r| r[:worker] == "w_beta" }
      refute_nil beta_rec2
      assert_equal "corpus", beta_rec2[:origin]

      # Render ds1 AFTER extracting ds2 (interleaved!) and ensure ds2 never leaks into ds1
      sec1 = FuzzSankey.render_sankey_sections(ds1)
      sec2 = FuzzSankey.render_sankey_sections(ds2)

      assert_includes sec1[:html], "#112233"
      assert_includes sec1[:html], "#445566"
      refute_includes sec1[:html], "#abcdef"
      refute_includes sec1[:html], "#fedcba"

      assert_includes sec2[:html], "#abcdef"
      assert_includes sec2[:html], "#fedcba"
      refute_includes sec2[:html], "#112233"
      refute_includes sec2[:html], "#445566"

      assert_equal %w[w_beta w_alpha], ds1[:active_workers]
      assert_equal %w[w_alpha w_beta], ds2[:active_workers]

      # Explicit vs nil default checks on color_for, worker_sort_rank, normalize_sync_source
      t1 = ds1[:topology]
      t2 = ds2[:topology]
      refute_includes ["#112233", "#abcdef"], FuzzSankey.color_for("w_alpha")
      assert_equal "#112233", FuzzSankey.color_for("w_alpha", topo: t1)
      assert_equal "#abcdef", FuzzSankey.color_for("w_alpha", topo: t2)

      assert_operator (FuzzSankey.worker_sort_rank("w_beta", topo: t1) <=> FuzzSankey.worker_sort_rank("w_alpha", topo: t1)), :<, 0
      assert_operator (FuzzSankey.worker_sort_rank("w_beta", topo: t2) <=> FuzzSankey.worker_sort_rank("w_alpha", topo: t2)), :>, 0
      assert_equal 3, FuzzSankey.worker_sort_rank("w_beta").first

      assert_equal "w_alpha", FuzzSankey.normalize_sync_source("alias_one", topo: t1)
      assert_equal "alias_one", FuzzSankey.normalize_sync_source("alias_one", topo: t2)
      assert_equal "alias_one", FuzzSankey.normalize_sync_source("alias_one")
    end
  end

  private

  def sankey_rb
    repo_path("report/sankey.rb")
  end

  def write_json(path, data)
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, JSON.pretty_generate(data))
  end

  def write_occurrences(triage_dir, bucket_id, entries)
    path = File.join(triage_dir, bucket_id, "occurrences.jsonl")
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, entries.map { |entry| "#{JSON.generate(entry)}\n" }.join)
  end

  def primary_triage_buckets
    [
      {
        "bucket_id" => "ABRT/b1",
        "reason" => "ABRT",
        "signature" => "b1",
        "reproducible" => true,
        "reproduced_by" => "fuzz.msan",
        "verify_profile" => "msan_slow",
        "occurrences" => { "count" => 12, "by_worker" => { "main" => 2, "msan" => 10 } },
        "symptom" => {
          "headline" => "INVARIANT[stream_diff]: kind=ast_mismatch",
          "invariant" => { "namespace" => "stream_diff", "fields" => { "kind" => "ast_mismatch" } }
        },
        "input" => { "loupe_url" => "https://example.invalid/?code=MQ==" }
      },
      {
        "bucket_id" => "ABRT/b2",
        "reason" => "ABRT",
        "signature" => "b2",
        "reproducible" => true,
        "reproduced_by" => "fuzz.diff",
        "verify_profile" => "diff_parse_y",
        "occurrences" => { "count" => 5, "by_worker" => { "diff" => 5 } },
        "symptom" => {
          "headline" => "INVARIANT[diff_parse_y]: kind=syntax_mismatch sub=prism_err_cruby_ok",
          "invariant" => { "namespace" => "diff_parse_y", "fields" => { "kind" => "syntax_mismatch", "sub" => "prism_err_cruby_ok" } }
        },
        "input" => {}
      },
      {
        "bucket_id" => "SEGV/b3",
        "reason" => "SEGV",
        "signature" => "b3",
        "reproducible" => true,
        "reproduced_by" => "fuzz",
        "verify_profile" => "asan_ubsan",
        "occurrences" => { "count" => 3, "by_worker" => { "main" => 3 } },
        "symptom" => { "headline" => "SUMMARY: AddressSanitizer: SEGV src/parser.c:10", "invariant" => nil },
        "input" => {}
      }
    ]
  end

  def primary_clusters(buckets)
    [
      {
        "cluster_id" => "cluster-01",
        "group" => "prism_flaw",
        "bucket_count" => 1,
        "occurrences" => 12,
        "representative" => { "bucket_id" => "ABRT/b1", "headline" => buckets[0]["symptom"]["headline"] },
        "buckets" => [{ "bucket_id" => "ABRT/b1" }]
      },
      {
        "cluster_id" => "cluster-02",
        "group" => "diff_parse_y",
        "bucket_count" => 1,
        "occurrences" => 5,
        "representative" => { "bucket_id" => "ABRT/b2", "headline" => buckets[1]["symptom"]["headline"] },
        "buckets" => [{ "bucket_id" => "ABRT/b2" }]
      },
      {
        "cluster_id" => "cluster-03",
        "group" => "prism_flaw",
        "bucket_count" => 1,
        "occurrences" => 3,
        "representative" => { "bucket_id" => "SEGV/b3", "headline" => buckets[2]["symptom"]["headline"] },
        "buckets" => [{ "bucket_id" => "SEGV/b3" }]
      }
    ]
  end

  def assert_conservation(graph_json)
    ins = Hash.new(0)
    outs = Hash.new(0)
    graph_json["links"].each do |link|
      outs[[link["from_layer"], link["from"]]] += link["value"]
      ins[[link["to_layer"], link["to"]]] += link["value"]
    end

    graph_json["nodes"].each do |node|
      key = [node["layer"], node["id"]]
      if node["layer"] != graph_json["layers"].first
        assert_equal node["value"], ins[key], "inflow mismatch for #{key.inspect}"
      end
      if node["layer"] != graph_json["layers"].last
        assert_equal node["value"], outs[key], "outflow mismatch for #{key.inspect}"
      end
    end
  end

  def setup_topo_workspace(ws, topo_name:, bucket_id:, cluster_id:, seed_orig:, sync_alias:, workers:)
    tdir = File.join(ws, "triage")
    afl_dir = File.join(ws, "afl")

    FileUtils.mkdir_p([
      File.join(afl_dir, "w_alpha", "queue"),
      File.join(afl_dir, "w_alpha", "crashes"),
      File.join(afl_dir, "w_beta", "queue"),
      File.join(afl_dir, "w_beta", "crashes"),
      File.join(tdir, bucket_id)
    ])

    FileUtils.touch([
      File.join(afl_dir, "w_alpha", "fuzzer_stats"),
      File.join(afl_dir, "w_beta", "fuzzer_stats")
    ])

    alpha_crash = File.join(afl_dir, "w_alpha", "crashes", "id:000000,sig:06,src:000000,time:10")
    beta_crash = File.join(afl_dir, "w_beta", "crashes", "id:000000,sig:06,src:000001,time:20")
    [
      File.join(afl_dir, "w_alpha", "queue", "id:000000,time:0,execs:0,orig:#{seed_orig}"),
      File.join(afl_dir, "w_beta", "queue", "id:000001,sync:#{sync_alias},src:000000"),
      alpha_crash,
      beta_crash
    ].each { |path| File.write(path, "") }

    write_occurrences(tdir, bucket_id, [
      { "worker" => "w_alpha", "path" => alpha_crash, "time_ms" => 10, "mtime" => "2026-11-20T00:00:10Z" },
      { "worker" => "w_beta", "path" => beta_crash, "time_ms" => 20, "mtime" => "2026-11-20T00:00:20Z" }
    ])

    topo = {
      "schema_version" => 2,
      "name" => topo_name,
      "workspace" => { "dir" => ws, "build_dir" => File.join(ws, "build") },
      "sources" => { "prism_a" => { "kind" => "prism", "repo" => "https://example.invalid/prism.git", "ref" => "main" } },
      "fuzzers" => { "fuzz" => { "shape" => "prism_parse", "source" => "prism_a" } },
      "sync_groups" => { "afl" => { "dir" => "afl", "primary" => true } },
      "workers" => workers
    }
    write_json(File.join(ws, "topology.json"), topo)

    write_json(File.join(tdir, "metadata.json"), {
      "buckets" => [{
        "bucket_id" => bucket_id,
        "reason" => "ABRT",
        "signature" => bucket_id.split("/").last,
        "reproducible" => true,
        "verify_profile" => "asan_ubsan",
        "occurrences" => { "count" => 4, "by_worker" => { "w_alpha" => 2, "w_beta" => 2 } },
        "symptom" => { "headline" => "SUMMARY: AddressSanitizer: ABRT src/prism.c:1", "invariant" => nil },
        "input" => {}
      }]
    })
    write_json(File.join(tdir, "clusters.json"), {
      "clusters" => [{
        "cluster_id" => cluster_id,
        "group" => "prism_flaw",
        "bucket_count" => 1,
        "occurrences" => 4,
        "representative" => { "bucket_id" => bucket_id, "headline" => "ABRT" },
        "buckets" => [{ "bucket_id" => bucket_id }]
      }]
    })
  end
end
