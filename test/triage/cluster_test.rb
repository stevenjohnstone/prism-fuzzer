# frozen_string_literal: true

require_relative "../lib/autorun"

require "digest"
require "fileutils"
require "json"
require "rbconfig"
require "rubygems/package"
require "zlib"

require_relative "../../triage/cluster"
require_relative "../../triage/inspect"
require_relative "../../triage/triage"

# Unit and integration tests for root-cause crash clustering (triage/cluster.rb),
# header round-trips & probe placement (FuzzClustering.place_probe),
# worker aggregation backfill (FuzzInspect.enrich_clusters), and cluster-aware
# verification workflows in triage/verify.rb.
class TriageClusterTest < Minitest::Test
  MOCK_FUZZ_TARGET_C = <<~'C'
    #include <stdint.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>

    static volatile uintptr_t leak_sink = 0;

    __attribute__((noinline)) static void do_leak(void) {
        void *p = malloc(128);
        if (!p) abort();
        leak_sink = ((uintptr_t)p) ^ (uintptr_t)0x5555;
    }

    __attribute__((noinline)) static void scrub_stack(void) {
        volatile char buf[512];
        for (size_t i = 0; i < sizeof(buf); i++) buf[i] = 0;
    }

    int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        if (size >= 5 && memcmp(data, "CRASH", 5) == 0) {
            fprintf(stderr, "INVARIANT[mock]: kind=crash\n");
            abort();
        }
        if (size >= 4 && memcmp(data, "HANG", 4) == 0) {
            for (;;) {}
        }
        if (size >= 4 && memcmp(data, "LEAK", 4) == 0) {
            do_leak();
        }
        scrub_stack();
        return 0;
    }
  C

  def test_multi_regime_clustering_and_permutation_invariance
    corpus, buckets, metadata = multi_regime_fixture

    report = FuzzClustering.cluster_metadata(metadata)
    groups = cluster_bucket_groups(report)
    expected = [
      ["ABRT/heredoc_full", "ABRT/heredoc_min"],
      ["ABRT/sym_array"],
      ["SEGV/lex_ijon", "heap-buffer-overflow/lex_shift", "use-of-uninitialized-value/lex_msan"],
      ["undefined-behavior/indent_for"],
      ["use-of-uninitialized-value/line_col"]
    ].sort

    assert_equal expected, groups
    assert_equal 1, report.dig("summary", "excluded_unreproducible")

    # Shuffling bucket order must produce identical deterministic output
    shuffled = { "schema_version" => 1, "corpus" => corpus, "buckets" => buckets.reverse }
    report_rev = FuzzClustering.cluster_metadata(shuffled)
    assert_equal report["clusters"], report_rev["clusters"], "cluster_metadata must be permutation-invariant"

    # Include unreproducible option preserves unreproducible bucket as its own cluster
    report_unrepro = FuzzClustering.cluster_metadata(metadata, include_unreproducible: true)
    assert_equal 6, report_unrepro.dig("summary", "cluster_count")
  end

  def test_single_bug_recovery_damping_setup_exclusion_and_subset_containment
    corpus, buckets, _metadata = multi_regime_fixture

    # Single-bug short-campaign mode (only the 2 heredoc buckets, 1 reason, zero external contrast)
    single_bug_meta = {
      "schema_version" => 1,
      "corpus" => corpus,
      "buckets" => buckets.select { |b| b["bucket_id"].start_with?("ABRT/heredoc") }
    }
    single_rep = FuzzClustering.cluster_metadata(single_bug_meta)
    assert_equal 1, single_rep.dig("summary", "cluster_count"),
                 "single-bug 2-bucket heredoc collapse failed: #{single_rep['clusters'].inspect}"

    # Recovery-only bug must still cluster (recovery weight = 0.10 > 0 rather than zeroed)
    rec_a = make_bucket(id: "ABRT/rec_a", reason: "ABRT", occ: 4, edges: { "1" => 1, "5" => 1, "6" => 1 })
    rec_b = make_bucket(id: "ABRT/rec_b", reason: "ABRT", occ: 2, edges: { "1" => 1, "5" => 1, "6" => 1 })
    rec_rep = FuzzClustering.cluster_metadata({ "schema_version" => 1, "corpus" => corpus, "buckets" => [rec_a, rec_b] })
    assert_equal 1, rec_rep.dig("summary", "cluster_count"),
                 "expected recovery-only bug buckets to merge via S_cov=1.0: #{rec_rep['clusters'].inspect}"

    # Setup/encoding-lookup functions (weight 0.0) must not alias unrelated syntax bugs sharing rare fuzz options
    setup_corpus = build_corpus(
      extra_functions: {
        "50" => "pm_parser_init",
        "51" => "pm_encoding_find",
        "52" => "parse_heredoc",
        "53" => "parse_global_variable"
      },
      extra_df: { "50" => 0, "51" => 0, "52" => 0, "53" => 0 }
    )
    setup_a = make_bucket(id: "ABRT/setup_a", reason: "ABRT", occ: 3, edges: { "1" => 1, "50" => 1, "51" => 1, "52" => 1 })
    setup_b = make_bucket(id: "ABRT/setup_b", reason: "ABRT", occ: 3, edges: { "1" => 1, "50" => 1, "51" => 1, "53" => 1 })
    setup_rep = FuzzClustering.cluster_metadata({ "schema_version" => 1, "corpus" => setup_corpus, "buckets" => [setup_a, setup_b] })
    assert_equal 2, setup_rep.dig("summary", "cluster_count"),
                 "expected SETUP_FUNCTIONS filtering to separate setup_a and setup_b: #{setup_rep['clusters'].inspect}"

    # Subset containment: short syntax bug whose rare edges also appear inside a much larger compound bug must not merge
    sub_ef = {}
    sub_df = {}
    %w[60 61].each { |k| sub_ef[k] = "parse_not"; sub_df[k] = 1 }
    %w[70 71 72 73 74 75 76 77 78 79 80 81 82 83].each { |k| sub_ef[k] = "parse_heredoc"; sub_df[k] = 0 }
    sub_corpus = build_corpus(extra_functions: sub_ef, extra_df: sub_df)
    sub_small = make_bucket(id: "ABRT/sub_small", reason: "ABRT", occ: 5, edges: { "60" => 1, "61" => 1 })
    sub_big_edges = { "60" => 1, "61" => 1 }.merge((70..83).each_with_object({}) { |k, h| h[k.to_s] = 1 })
    sub_big = make_bucket(id: "ABRT/sub_big", reason: "ABRT", occ: 5, edges: sub_big_edges)
    sub_rep = FuzzClustering.cluster_metadata({ "schema_version" => 1, "corpus" => sub_corpus, "buckets" => [sub_small, sub_big] })
    assert_equal 2, sub_rep.dig("summary", "cluster_count"),
                 "expected Weighted Jaccard to separate subset containment: #{sub_rep['clusters'].inspect}"
  end

  def test_empty_singleton_and_coverage_unavailable_fallbacks
    corpus, buckets, _metadata = multi_regime_fixture

    empty_rep = FuzzClustering.cluster_metadata({ "schema_version" => 1, "corpus" => corpus, "buckets" => [] })
    assert_equal 0, empty_rep.dig("summary", "cluster_count")

    one_rep = FuzzClustering.cluster_metadata({ "schema_version" => 1, "corpus" => corpus, "buckets" => [buckets.first] })
    assert_equal 1, one_rep.dig("summary", "cluster_count")

    no_cov_corpus = { "available" => false, "corpus_count" => 0 }
    no_cov_buckets = [
      make_bucket(id: "SEGV/s1", reason: "SEGV", occ: 5, frames: frames_segv, edges: {}).merge("coverage" => { "available" => false }),
      make_bucket(id: "use-of-uninitialized-value/s2", reason: "use-of-uninitialized-value", occ: 3, frames: frames_msan, edges: {}).merge("coverage" => { "available" => false }),
      make_bucket(id: "ABRT/u1", reason: "ABRT", occ: 2, edges: {}).merge("coverage" => { "available" => false }),
      make_bucket(id: "ABRT/u2", reason: "ABRT", occ: 1, edges: {}).merge("coverage" => { "available" => false })
    ]
    no_cov_rep = FuzzClustering.cluster_metadata({ "schema_version" => 1, "corpus" => no_cov_corpus, "buckets" => no_cov_buckets })
    no_cov_groups = cluster_bucket_groups(no_cov_rep)
    assert_equal [["ABRT/u1"], ["ABRT/u2"], ["SEGV/s1", "use-of-uninitialized-value/s2"]], no_cov_groups
  end

  def test_prefix_boilerplate_filtering_and_dispatcher_edge_cap
    # Regression 1: prefix boilerplate filtering (fuzz_*, check_*, pm_visit_*) applies in both IDF and frames
    pfx_corpus = build_corpus(
      extra_functions: {
        "80" => "fuzz_check_error_diag",
        "81" => "check_custom_location",
        "82" => "pm_visit_program_node",
        "83" => "parse_heredoc",
        "84" => "parse_case"
      },
      extra_df: { "80" => 0, "81" => 0, "82" => 0, "83" => 0, "84" => 0 }
    )
    pfx_a = make_bucket(
      id: "ABRT/pfx_a", reason: "ABRT", occ: 2,
      frames: [{ "scope" => "prism", "func" => "pm_visit_program_node", "file" => "node.c", "line" => 1 }],
      edges: { "1" => 1, "80" => 1, "81" => 1, "82" => 1, "83" => 1 }
    )
    pfx_b = make_bucket(
      id: "ABRT/pfx_b", reason: "ABRT", occ: 2,
      edges: { "1" => 1, "80" => 1, "81" => 1, "82" => 1, "84" => 1 }
    )
    pfx_rep = FuzzClustering.cluster_metadata({ "schema_version" => 1, "corpus" => pfx_corpus, "buckets" => [pfx_a, pfx_b] })
    assert_equal 2, pfx_rep.dig("summary", "cluster_count"), "prefix boilerplate filtering regression failed: #{pfx_rep.inspect}"
    assert pfx_rep["clusters"].all? { |c| c.dig("representative", "top_prism_frame").nil? },
           "expected boilerplate frames stripped from top_prism_frame: #{pfx_rep.inspect}"

    # Regression 3: dispatcher damping + function edge cap prevent monolithic dispatcher edges from merging distinct bugs
    disp_ef = {}
    disp_df = {}
    (200...400).each { |eid| disp_ef[eid.to_s] = "parser_lex"; disp_df[eid.to_s] = 0 }
    (401..402).each { |eid| disp_ef[eid.to_s] = "parse_array"; disp_df[eid.to_s] = 0 }
    (403..404).each { |eid| disp_ef[eid.to_s] = "parse_heredoc"; disp_df[eid.to_s] = 0 }
    disp_corpus = build_corpus(extra_functions: disp_ef, extra_df: disp_df)
    disp_a = make_bucket(id: "ABRT/disp_a", reason: "ABRT", occ: 2, edges: { "200" => 1, "401" => 1, "402" => 1 })
    disp_b = make_bucket(id: "ABRT/disp_b", reason: "ABRT", occ: 2, edges: { "200" => 1, "403" => 1, "404" => 1 })
    disp_rep = FuzzClustering.cluster_metadata({ "schema_version" => 1, "corpus" => disp_corpus, "buckets" => [disp_a, disp_b] })
    assert_equal 2, disp_rep.dig("summary", "cluster_count"),
                 "dispatcher + function_edge_cap regression failed: #{disp_rep.inspect}"
  end

  def test_oracle_family_separation_cruby_crash_and_option_metadata_projection
    corpus = build_corpus(
      extra_functions: { "83" => "parse_heredoc" },
      extra_df: { "83" => 0 }
    )

    # Regression 2: distinct oracle families never merge even with identical edges and threshold=0.0
    ora_cruby = make_bucket(
      id: "SEGV/ora_cruby_crash",
      reason: "SEGV",
      occ: 3,
      frames: [
        { "scope" => "external", "func" => "rb_print_backtrace", "file" => "/opt/ruby/vm_dump.c", "line" => 1108 },
        { "scope" => "harness", "func" => "diff_fatal_signal_handler", "file" => "harnesses/prism/diff.c", "line" => 1496 },
        { "scope" => "external", "func" => "parser_yylex", "file" => "parse.y", "line" => 7707 }
      ],
      edges: { "1" => 1, "83" => 1 }
    )
    ora_cruby["verify_profile"] = "diff_parse_y"
    ora_cruby["symptom"]["headline"] = "CRASH[diff_parse_y]: signal=SIGSEGV (11)"

    ora_buckets = [
      make_inv_bucket(id: "ABRT/ora_crash", profile: "ubsan", ns: "span"),
      make_inv_bucket(id: "ABRT/ora_diff", profile: "diff_parse_y", ns: "diff_parse_y", fields: { "kind" => "ast_mismatch", "node" => "CallNode" }),
      make_inv_bucket(id: "ABRT/ora_stream", profile: "msan_slow", ns: "stream_diff"),
      ora_cruby
    ]
    ora_rep = FuzzClustering.cluster_metadata({ "schema_version" => 1, "corpus" => corpus, "buckets" => ora_buckets }, threshold: 0.0)
    assert_equal [["ABRT/ora_crash"], ["ABRT/ora_diff"], ["ABRT/ora_stream"], ["SEGV/ora_cruby_crash"]],
                 cluster_bucket_groups(ora_rep)

    msan_prism = make_bucket(id: "use-of-uninitialized-value/msan_prism", reason: "use-of-uninitialized-value", occ: 2, frames: frames_segv)
    msan_prism["verify_profile"] = "msan_slow"
    assert_equal "crash_or_inv", FuzzClustering.oracle_family(msan_prism)

    # Regression 2b: cruby_crash uses external parse.y frames to cluster matching CRuby crashes and separate distinct ones
    cruby_st_frames = [
      { "scope" => "external", "func" => "rb_print_backtrace", "file" => "/opt/ruby/vm_dump.c", "line" => 1108 },
      { "scope" => "harness", "func" => "diff_fatal_signal_handler", "file" => "harnesses/prism/diff.c", "line" => 96 },
      { "scope" => "external", "func" => "rb_st_free_table", "file" => "/opt/ruby/st.c", "line" => 667 },
      { "scope" => "external", "func" => "ruby_yyparse", "file" => "parse.y", "line" => 4532 },
      { "scope" => "external", "func" => "rb_funcall", "file" => "/opt/ruby/vm_eval.c", "line" => 1137 }
    ]
    cruby_tok_frames_a = [
      { "scope" => "external", "func" => "rb_print_backtrace", "file" => "/opt/ruby/vm_dump.c", "line" => 1108 },
      { "scope" => "external", "func" => "parser_add_delayed_token", "file" => "parse.y", "line" => 7617 },
      { "scope" => "external", "func" => "parser_yylex", "file" => "parse.y", "line" => 7705 },
      { "scope" => "external", "func" => "rb_parser_enc_cr_str_buf_cat", "file" => "parse.y", "line" => 2400 },
      { "scope" => "external", "func" => "tokadd_utf8", "file" => "parse.y", "line" => 7981 }
    ]
    cruby_tok_frames_b = [
      { "scope" => "external", "func" => "rb_print_backtrace", "file" => "/opt/ruby/vm_dump.c", "line" => 1108 },
      { "scope" => "external", "func" => "parser_yylex", "file" => "parse.y", "line" => 7707 },
      { "scope" => "external", "func" => "rb_parser_enc_cr_str_buf_cat", "file" => "parse.y", "line" => 2400 },
      { "scope" => "external", "func" => "parser_yylex", "file" => "(null)", "line" => 0 },
      { "scope" => "external", "func" => "tokadd_utf8", "file" => "parse.y", "line" => 7962 }
    ]
    cruby_st = make_bucket(id: "SEGV/cruby_st", reason: "SEGV", occ: 2, frames: cruby_st_frames, edges: { "10" => 1, "11" => 1, "12" => 1 })
    cruby_tok_a = make_bucket(id: "SEGV/cruby_tok_a", reason: "SEGV", occ: 2, frames: cruby_tok_frames_a, edges: { "10" => 1, "11" => 1, "20" => 1 })
    cruby_tok_b = make_bucket(id: "SEGV/cruby_tok_b", reason: "SEGV", occ: 2, frames: cruby_tok_frames_b, edges: { "12" => 1, "40" => 1 })
    [cruby_st, cruby_tok_a, cruby_tok_b].each do |cb|
      cb["verify_profile"] = "diff_parse_y"
      cb["symptom"]["headline"] = "CRASH[diff_parse_y]: signal=SIGSEGV (11)"
    end
    cruby_rep = FuzzClustering.cluster_metadata({ "schema_version" => 1, "corpus" => corpus, "buckets" => [cruby_st, cruby_tok_a, cruby_tok_b] })
    assert_equal [["SEGV/cruby_st"], ["SEGV/cruby_tok_a", "SEGV/cruby_tok_b"]], cluster_bucket_groups(cruby_rep)
    assert cruby_rep["clusters"].all? { |c| c.dig("representative", "top_prism_frame").nil? }

    # Regression 2c: fuzz.diff assertions in Prism source files with empty frames stay in prism_flaw (not cruby_crash),
    # and non-default 4-byte options / input metadata project cleanly into clusters.json without altering UPGMA merges.
    prism_assert_diff = make_bucket(id: "ABRT/diff_prism_assert", reason: "ABRT", occ: 4, frames: [], edges: { "10" => 1, "11" => 1 }).merge(
      "verify_profile" => "diff_parse_y",
      "reproduced_by" => "fuzz.diff",
      "symptom" => {
        "headline" => "fuzz.diff: /prism/src/prism.c:13550: pm_node_t *parse_write(...): Assertion `foo' failed.",
        "assertion" => { "file" => "src/prism.c", "line" => 13550, "func" => "parse_write", "expr" => "foo" }
      },
      "input" => {
        "min_size_bytes" => 16,
        "header_hex" => "40080301",
        "has_shebang_prefix" => true,
        "payload_sha256" => "deadbeef",
        "source_preview" => "#!/usr/bin/ruby\\nself=,,",
        "loupe_url" => "https://example.invalid/?code=abc&stream=1"
      },
      "options" => {
        "ruby_version" => "4.1",
        "start_line" => 1,
        "encoding" => nil,
        "stream_mode" => true,
        "command_line_flags" => ["n"],
        "stack_budget" => "SIZE_MAX",
        "scopes_count" => 0
      }
    )
    assert_equal "crash_or_inv", FuzzClustering.oracle_family(prism_assert_diff)

    opt_rep = FuzzClustering.cluster_metadata({ "schema_version" => 1, "corpus" => corpus, "buckets" => [prism_assert_diff, cruby_st] })
    opt_prism_c = opt_rep["clusters"].find { |c| c.dig("representative", "bucket_id") == "ABRT/diff_prism_assert" }
    opt_cruby_c = opt_rep["clusters"].find { |c| c.dig("representative", "bucket_id") == "SEGV/cruby_st" }
    refute_nil opt_prism_c
    refute_nil opt_cruby_c
    assert_equal "prism_flaw", opt_prism_c["group"]
    assert_equal "cruby_crash", opt_cruby_c["group"]
    assert_equal ["stream_mode cmd=-n"], opt_prism_c["options_labels"]
    assert_equal ["diff_parse_y"], opt_prism_c["verify_profiles"]
    assert_equal "40080301", opt_prism_c.dig("representative", "header_hex")
    assert_equal({ "stream_mode" => true, "command_line_flags" => ["n"] }, opt_prism_c.dig("representative", "options"))
    assert_equal "stream_mode cmd=-n", opt_prism_c.dig("representative", "options_label")
    assert_equal true, opt_prism_c.dig("representative", "has_shebang_prefix")
    assert_equal "https://example.invalid/?code=abc&stream=1", opt_prism_c.dig("representative", "loupe_url")
    assert_equal "#!/usr/bin/ruby\\nself=,,", opt_prism_c.dig("representative", "source_preview")
    assert_equal "src/prism.c", opt_prism_c.dig("representative", "symptom", "assertion", "file")

    # Default options omit empty options/options_label/has_shebang_prefix keys
    assert_nil opt_cruby_c["options_labels"]
    assert_nil opt_cruby_c.dig("representative", "options")
    assert_nil opt_cruby_c.dig("representative", "options_label")
  end

  def test_conflict_aware_diff_parse_y_symptom_similarity
    # Regression 4: conflict-aware diff_parse_y symptom similarity + generic catch-all error exclusion
    diff_ef = {}
    diff_df = {}
    (500..520).each { |eid| diff_ef[eid.to_s] = "parse_for"; diff_df[eid.to_s] = 0 }
    diff_corpus = build_corpus(extra_functions: diff_ef, extra_df: diff_df)

    low_a = { "500" => 1, "501" => 1, "502" => 1, "503" => 1, "504" => 1 }
    low_b = { "500" => 1, "505" => 1, "506" => 1, "507" => 1, "508" => 1 }

    # Specific non-generic match boosts low coverage into merging
    d_spec = [
      make_inv_bucket(id: "ABRT/d_spec_a", profile: "diff_parse_y", ns: "diff_parse_y", edges: low_a,
                      fields: { "kind" => "ast_mismatch", "sub" => "node_kind", "node" => "YieldNode", "scope" => "program" }),
      make_inv_bucket(id: "ABRT/d_spec_b", profile: "diff_parse_y", ns: "diff_parse_y", edges: low_b,
                      fields: { "kind" => "ast_mismatch", "sub" => "node_kind", "node" => "YieldNode", "scope" => "program" })
    ]
    assert_equal 1, FuzzClustering.cluster_metadata({ "schema_version" => 1, "corpus" => diff_corpus, "buckets" => d_spec }).dig("summary", "cluster_count"),
                 "specific diff_parse_y match failed to merge"

    # Generic catch-all error alone does NOT boost low coverage into false merging
    d_gen = [
      make_inv_bucket(id: "ABRT/d_gen_a", profile: "diff_parse_y", ns: "diff_parse_y", edges: low_a,
                      fields: { "kind" => "syntax_mismatch", "sub" => "prism_err_cruby_ok", "prism" => "expect_eol_after_statement", "cruby" => "ok" }),
      make_inv_bucket(id: "ABRT/d_gen_b", profile: "diff_parse_y", ns: "diff_parse_y", edges: low_b,
                      fields: { "kind" => "syntax_mismatch", "sub" => "prism_err_cruby_ok", "prism" => "expect_eol_after_statement", "cruby" => "ok" })
    ]
    assert_equal 2, FuzzClustering.cluster_metadata({ "schema_version" => 1, "corpus" => diff_corpus, "buckets" => d_gen }).dig("summary", "cluster_count"),
                 "generic diff_parse_y error falsely boosted merge"

    # Conflicting scope/sub penalizes even moderate coverage similarity (scov=1/3 -> would merge without penalty)
    mod_a = { "500" => 1, "501" => 1 }
    mod_b = { "500" => 1, "502" => 1 }
    d_conf = [
      make_inv_bucket(id: "ABRT/d_conf_a", profile: "diff_parse_y", ns: "diff_parse_y", edges: mod_a,
                      fields: { "kind" => "ast_mismatch", "sub" => "node_kind", "node" => "YieldNode", "scope" => "program" }),
      make_inv_bucket(id: "ABRT/d_conf_b", profile: "diff_parse_y", ns: "diff_parse_y", edges: mod_b,
                      fields: { "kind" => "ast_mismatch", "sub" => "node_kind", "node" => "YieldNode", "scope" => "block" })
    ]
    assert_equal 2, FuzzClustering.cluster_metadata({ "schema_version" => 1, "corpus" => diff_corpus, "buckets" => d_conf }).dig("summary", "cluster_count"),
                 "conflicting diff_parse_y scope falsely merged"
  end

  def test_cluster_discovery_timestamps_and_summary_table
    # Regression 5: cluster-level discovery timestamps aggregate across members and fall back cleanly
    corpus = build_corpus
    ts_rep_b = make_bucket(id: "ABRT/ts_rep", reason: "ABRT", occ: 10, edges: { "10" => 1, "11" => 1 }).merge(
      "occurrences" => {
        "count" => 10,
        "first_seen" => "2026-11-15T14:00:00Z",
        "first_elapsed_ms" => 1_200_000,
        "last_seen" => "2026-11-15T16:00:00Z"
      }
    )
    ts_early_b = make_bucket(id: "ABRT/ts_early", reason: "ABRT", occ: 2, edges: { "10" => 1, "11" => 1 }).merge(
      "occurrences" => {
        "count" => 2,
        "first_seen" => "2026-11-15T13:45:00Z",
        "last_seen" => "2026-11-15T17:00:00Z",
        "sample_crashes" => [
          { "mtime" => "2026-11-15T13:45:00Z", "path" => "tmp/fuzz/afl/main/crashes/id:000001,sig:06,src:000001,time:300000,execs:100" }
        ]
      }
    )
    ts_sync_b = make_bucket(id: "ABRT/ts_sync", reason: "ABRT", occ: 1, edges: { "40" => 1 }).merge(
      "occurrences" => {
        "count" => 1,
        "first_seen" => "2026-11-15T13:48:10Z",
        "last_seen" => "2026-11-15T13:48:10Z",
        "sample_crashes" => [
          { "mtime" => "2026-11-15T13:48:10Z", "path" => "tmp/fuzz/afl/diff/crashes/id:000033,sig:06,sync:main,src:008749" }
        ]
      }
    )
    ts_notime_b = make_bucket(id: "ABRT/ts_notime", reason: "ABRT", occ: 1, edges: { "41" => 1 }).merge(
      "occurrences" => { "count" => 1, "sample_crashes" => [] }
    )

    ts_rep = FuzzClustering.cluster_metadata({ "schema_version" => 1, "corpus" => corpus, "buckets" => [ts_rep_b, ts_early_b, ts_sync_b, ts_notime_b] })
    ts_c1 = ts_rep["clusters"].find { |c| c.dig("representative", "bucket_id") == "ABRT/ts_rep" }
    ts_c2 = ts_rep["clusters"].find { |c| c.dig("representative", "bucket_id") == "ABRT/ts_sync" }
    ts_c3 = ts_rep["clusters"].find { |c| c.dig("representative", "bucket_id") == "ABRT/ts_notime" }

    refute_nil ts_c1
    assert_equal "2026-11-15T13:45:00Z", ts_c1["first_seen"]
    assert_equal 300_000, ts_c1["first_elapsed_ms"]
    assert_equal "ABRT/ts_early", ts_c1["first_seen_bucket"]
    assert_equal "2026-11-15T17:00:00Z", ts_c1["last_seen"]

    refute_nil ts_c2
    assert_equal "2026-11-15T13:48:10Z", ts_c2["first_seen"]
    assert_equal 190_000, ts_c2["first_elapsed_ms"]
    assert_equal 190_000, ts_c2.dig("representative", "first_elapsed_ms")
    assert_equal 190_000, ts_c2["buckets"].first["first_elapsed_ms"]

    refute_nil ts_c3
    assert_nil ts_c3["first_seen"]
    assert_nil ts_c3["first_elapsed_ms"]

    assert_equal "2026-11-15T13:45:00Z", ts_rep.dig("summary", "first_seen")
    assert_equal "2026-11-15T17:00:00Z", ts_rep.dig("summary", "last_seen")

    ts_table = FuzzClustering.format_summary_table(ts_rep)
    assert_includes ts_table, "First"
    assert_includes ts_table, "0h05m00s"
    assert_includes ts_table, "0h03m10s"
  end

  def test_algorithm2_dual_parser_diff_parse_y_clustering
    # Regression 6: Algorithm 2 (diff_parse_y dual-parser Prism + parse.y edges, boilerplate filtering,
    # two-population separation, and asymmetric Cosine+Jaccard merge)
    fx = diff_dual_fixture
    dual_rep = FuzzClustering.cluster_metadata({
      "schema_version" => 1,
      "corpus" => fx[:corpus],
      "diff_corpus" => fx[:diff_dual_corpus],
      "buckets" => fx[:dual_buckets]
    })

    assert_equal 4, dual_rep.dig("summary", "cluster_count")
    assert_equal 1, dual_rep.dig("summary", "by_group", "prism_flaws", "cluster_count")
    assert_equal 3, dual_rep.dig("summary", "by_group", "diff_parse_y", "cluster_count")
    assert_equal "dual_edge_prism_and_parse_y", dual_rep.dig("algorithm", "diff_parse_y", "mode")

    c_flaw = dual_rep["clusters"][0]
    c_begin = dual_rep["clusters"][1]
    assert_equal "prism_flaw", c_flaw["group"]
    assert_equal "prism_flaw", c_flaw["algorithm"]
    assert_equal "diff_parse_y", c_begin["group"]
    assert_equal "diff_parse_y_dual_edge", c_begin["algorithm"]
    assert_equal %w[ABRT/begin_big ABRT/begin_small], c_begin["buckets"].map { |b| b["bucket_id"] }.sort

    dual_table = FuzzClustering.format_summary_table(dual_rep)
    assert_includes dual_table, "Prism Flaws & Crashes"
    assert_includes dual_table, "Differential parse.y Divergences"

    # Same zero-overlap syntax_mismatch errors must NOT merge even when diagnostic codes match
    zero_diag_pair = [
      make_dual_diff_bucket(id: "ABRT/zero_d1", occ: 2, edges: fx[:boil_only_a],
                            fields: { "kind" => "syntax_mismatch", "sub" => "prism_ok_cruby_err", "prism" => "ok", "cruby" => "ArgumentError:unknown_encoding" }),
      make_dual_diff_bucket(id: "ABRT/zero_d2", occ: 2, edges: fx[:boil_only_b],
                            fields: { "kind" => "syntax_mismatch", "sub" => "prism_ok_cruby_err", "prism" => "ok", "cruby" => "ArgumentError:unknown_encoding" })
    ]
    zero_diag_rep = FuzzClustering.cluster_metadata({
      "schema_version" => 1,
      "corpus" => fx[:corpus],
      "diff_corpus" => fx[:diff_dual_corpus],
      "buckets" => zero_diag_pair
    })
    assert_equal 2, zero_diag_rep.dig("summary", "cluster_count"),
                 "expected zero edge-overlap diff_parse_y buckets not to merge on diagnostic match alone: #{zero_diag_rep.inspect}"

    # Even at threshold=0.0 & diff_threshold=0.0, Prism flaws never merge with diff_parse_y
    sep_rep = FuzzClustering.cluster_metadata({
      "schema_version" => 1,
      "corpus" => fx[:corpus],
      "diff_corpus" => fx[:diff_dual_corpus],
      "buckets" => [fx[:prism_flaw_b], fx[:dual_buckets][1], fx[:dual_buckets][3]]
    }, threshold: 0.0, diff_threshold: 0.0)
    assert_equal 2, sep_rep.dig("summary", "cluster_count")
    assert_equal %w[prism_flaw diff_parse_y], sep_rep["clusters"].map { |c| c["group"] }
  end

  def test_by_worker_aggregation_and_inspect_backfill
    # Regression (Bug #34): cluster.rb and FuzzInspect.enrich_clusters aggregate occurrences.by_worker onto cluster["by_worker"]
    bw_buckets = [
      {
        "bucket_id" => "ABRT/bw1", "reason" => "ABRT", "signature" => "bw1", "reproducible" => true,
        "occurrences" => { "count" => 3, "by_worker" => { "w_a" => 2, "w_b" => 1 } },
        "input" => { "min_size_bytes" => 5 },
        "symptom" => { "headline" => "Assertion `bw' failed" },
        "frames" => [{ "scope" => "prism", "func" => "pm_bw", "file" => "src/prism.c", "line" => 10 }]
      },
      {
        "bucket_id" => "ABRT/bw2", "reason" => "ABRT", "signature" => "bw2", "reproducible" => true,
        "occurrences" => { "count" => 4, "by_worker" => { "w_b" => 3, "w_c" => 1 } },
        "input" => { "min_size_bytes" => 5 },
        "symptom" => { "headline" => "Assertion `bw' failed" },
        "frames" => [{ "scope" => "prism", "func" => "pm_bw", "file" => "src/prism.c", "line" => 10 }]
      }
    ]
    bw_meta = { "schema_version" => 1, "buckets" => bw_buckets }
    bw_rep = FuzzClustering.cluster_metadata(bw_meta, threshold: 0.0)
    expected_workers = { "w_b" => 4, "w_a" => 2, "w_c" => 1 }
    assert_equal expected_workers, bw_rep.dig("clusters", 0, "by_worker")

    legacy_cl = {
      "schema_version" => 1,
      "clusters" => [
        {
          "cluster_id" => "cluster-01",
          "group" => "prism_flaw",
          "bucket_count" => 2,
          "occurrences" => 7,
          "representative" => { "bucket_id" => "ABRT/bw1" },
          "buckets" => [{ "bucket_id" => "ABRT/bw1" }, { "bucket_id" => "ABRT/bw2" }]
        }
      ]
    }
    enr_cl = FuzzInspect.enrich_clusters(legacy_cl, bw_meta, triage_dir: nil, read_files: false)
    assert_equal expected_workers, enr_cl.dig(0, "by_worker")
  end

  def test_cluster_cli_and_place_probe_with_fuzz_header_roundtrip
    with_tmpdir("triage-cluster-") do |workdir|
      _corpus, _buckets, metadata = multi_regime_fixture
      meta_path = File.join(workdir, "cluster_meta.json")
      out_path = File.join(workdir, "clusters_out.json")
      File.write(meta_path, JSON.generate(metadata))

      cli_out, = assert_ruby_cmd(
        repo_path("triage/cluster.rb"),
        "--metadata", meta_path,
        "--output", out_path,
        "--diff-threshold", "0.30"
      )
      assert_path_exists out_path
      assert_includes cli_out, "5 clusters"
      cli_json = JSON.parse(File.read(out_path))
      assert_in_delta 0.30, cli_json.dig("algorithm", "diff_threshold"), 1e-6

      stdout_raw, = assert_ruby_cmd(
        repo_path("triage/cluster.rb"),
        "--metadata", meta_path,
        "--output", "-",
        "--quiet"
      )
      stdout_json = JSON.parse(stdout_raw)
      assert_equal cli_json["clusters"], stdout_json["clusters"]

      # Exercise encode_fuzz_header round-trip
      default_hdr = FuzzTriage.encode_fuzz_header
      assert_equal "\x00\x00\x03\x01".b, default_hdr
      dec_def = FuzzTriage.decode_fuzz_header(default_hdr + "1+1")
      assert_equal "4.1", dec_def[:version]
      assert_equal 1, dec_def[:start_line]
      assert_nil dec_def[:encoding]

      custom_hdr = FuzzTriage.encode_fuzz_header(
        ruby_version: "3.4",
        encoding: "UTF-8",
        frozen_string_literal: true,
        partial_script: true,
        stream_mode: true,
        command_line: "xa",
        scopes_count: 2,
        forwarding: "pb"
      )
      dec_custom = FuzzTriage.decode_fuzz_header(custom_hdr + "x")
      assert_equal "3.4", dec_custom[:version]
      assert_equal "UTF-8", dec_custom[:encoding]
      assert_equal true, dec_custom[:has_frozen_string_literal]
      assert_equal true, dec_custom[:frozen_string_literal]
      assert_equal true, dec_custom[:partial_script]
      assert_equal true, dec_custom[:stream_mode]
      assert_equal %w[a x], dec_custom[:command_line_chars]
      assert_equal 2, dec_custom[:scopes_count]
      assert_equal %w[p b], dec_custom[:forwarding_chars]

      # Exercise FuzzClustering.place_probe on Prism and dual diff_parse_y fixtures
      probe_ctx = FuzzClustering.prepare_placement_context(metadata, report: cli_json, metadata_path: meta_path)
      target_prism_cluster = cli_json["clusters"].find { |c| c["group"] == "prism_flaw" && c["bucket_count"] >= 2 } || cli_json["clusters"].first
      target_prism_bid = target_prism_cluster.dig("representative", "bucket_id")
      target_prism_bucket = metadata["buckets"].find { |b| b["bucket_id"] == target_prism_bid }
      prism_probe = target_prism_bucket.merge("bucket_id" => "probe:prism")
      prism_place = FuzzClustering.place_probe(metadata, prism_probe, placement_ctx: probe_ctx)
      assert_equal "matched", prism_place["status"]
      assert_equal target_prism_cluster["cluster_id"], prism_place.dig("best_cluster", "cluster_id")

      fx = diff_dual_fixture
      dual_meta = {
        "schema_version" => 1,
        "corpus" => fx[:corpus],
        "diff_corpus" => fx[:diff_dual_corpus],
        "buckets" => [fx[:prism_flaw_b], fx[:dual_buckets][1], fx[:dual_buckets][3]]
      }
      dual_ctx = FuzzClustering.prepare_placement_context(dual_meta)
      dual_probe = fx[:dual_buckets][1].merge("bucket_id" => "probe:dual")
      dual_place = FuzzClustering.place_probe(dual_meta, dual_probe, placement_ctx: dual_ctx)
      expected_dual_cid = dual_ctx[:report]["clusters"].find do |c|
        c["buckets"].any? { |b| b["bucket_id"] == fx[:dual_buckets][1]["bucket_id"] }
      end&.dig("cluster_id")
      assert_equal "matched", dual_place["status"]
      assert_equal expected_dual_cid, dual_place.dig("best_cluster", "cluster_id")
      assert dual_place["candidates"].all? { |c| c["group"] == "diff_parse_y" }

      unmatched_diff_probe = fx[:dual_buckets][1].merge(
        "bucket_id" => "probe:novel_diff",
        "symptom" => {
          "headline" => "INVARIANT[diff_parse_y]: diagnostics_mismatch ...",
          "invariant" => { "namespace" => "diff_parse_y", "fields" => { "mismatch" => "diagnostics_mismatch" }, "detail" => {} }
        },
        "frames" => [],
        "coverage" => { "available" => false },
        "diff_coverage" => { "available" => true, "edges" => { "99999" => 1 } }
      )
      unmatched_place = FuzzClustering.place_probe(dual_meta, unmatched_diff_probe, placement_ctx: dual_ctx)
      assert_equal "unmatched", unmatched_place["status"]
      assert_empty unmatched_place["matched_clusters"]
      refute_empty unmatched_place["candidates"]
    end
  end

  def test_verify_cluster_workflows
    with_tmpdir("triage-cluster-") do |workdir|
      triage_dir = File.join(workdir, "cluster_verify_triage")
      c1_rep_dir = File.join(triage_dir, "ABRT", "c1_rep_pass")
      c1_sib_dir = File.join(triage_dir, "ABRT", "c1_sib_part")
      c2_dir = File.join(triage_dir, "ABRT", "c2_only_pass")
      FileUtils.mkdir_p([c1_rep_dir, c1_sib_dir, c2_dir])

      # cluster-01: representative (10 occ, PASS) + sibling (5 occ, PARTIAL -> cluster PARTIAL)
      # Representative vs sibling names intentionally pick alphabetical order != rep-first order
      # so tests verify representative runs first inside the cluster.
      File.binwrite(File.join(c1_rep_dir, "input.min"), "clean_rep")
      create_tar_gz(File.join(c1_rep_dir, "inputs.tar.gz"), ["clean_rep_sib".b])

      File.binwrite(File.join(c1_sib_dir, "input.min"), "clean_min")
      create_tar_gz(File.join(c1_sib_dir, "inputs.tar.gz"), ["clean_ok".b, "CRASH_cluster_sib".b])

      File.binwrite(File.join(c2_dir, "input.min"), "clean_c2")
      create_tar_gz(File.join(c2_dir, "inputs.tar.gz"), ["clean_c2_arch".b])

      metadata = {
        "schema_version" => 1,
        "corpus" => {
          "available" => true,
          "corpus_count" => 100,
          "edge_df" => { "10" => 0, "11" => 0, "20" => 0 },
          "edge_functions" => { "10" => "parse_heredoc", "11" => "parse_heredoc", "20" => "parse_for" }
        },
        "buckets" => [
          {
            "bucket_id" => "ABRT/c1_rep_pass",
            "reason" => "ABRT",
            "signature" => "c1_rep_pass",
            "reproducible" => true,
            "verify_profile" => "asan_ubsan",
            "occurrences" => { "count" => 10 },
            "input" => { "min_size_bytes" => 9 },
            "symptom" => { "headline" => "Assertion heredoc failed" },
            "frames" => [{ "function" => "parse_heredoc", "scope" => "prism" }],
            "coverage" => { "available" => true, "edges" => { "10" => 1, "11" => 1 } }
          },
          {
            "bucket_id" => "ABRT/c1_sib_part",
            "reason" => "ABRT",
            "signature" => "c1_sib_part",
            "reproducible" => true,
            "verify_profile" => "asan_ubsan",
            "occurrences" => { "count" => 5 },
            "input" => { "min_size_bytes" => 9 },
            "symptom" => { "headline" => "Assertion heredoc failed" },
            "frames" => [{ "function" => "parse_heredoc", "scope" => "prism" }],
            "coverage" => { "available" => true, "edges" => { "10" => 1, "11" => 1 } }
          },
          {
            "bucket_id" => "ABRT/c2_only_pass",
            "reason" => "ABRT",
            "signature" => "c2_only_pass",
            "reproducible" => true,
            "verify_profile" => "asan_ubsan",
            "occurrences" => { "count" => 3 },
            "input" => { "min_size_bytes" => 8 },
            "symptom" => { "headline" => "Assertion parse_for failed" },
            "frames" => [{ "function" => "parse_for", "scope" => "prism" }],
            "coverage" => { "available" => true, "edges" => { "20" => 1 } }
          }
        ]
      }
      meta_path = File.join(triage_dir, "metadata.json")
      File.write(meta_path, JSON.pretty_generate(metadata))

      stub_prism = create_stub_prism_root(workdir)
      verify_rb = repo_path("triage/verify.rb")
      base_env = {
        "PRISM_A_DIR" => stub_prism,
        "PRISM_DIR" => nil,
        "PRISM_ROOT" => nil
      }

      list_out, = assert_ruby_cmd(verify_rb, "--triage-dir", triage_dir, "--list-clusters", env: base_env)
      assert_includes list_out, "cluster-01"
      assert_includes list_out, "cluster-02"
      clusters_path = File.join(triage_dir, "clusters.json")
      assert_path_exists clusters_path

      # Verify stale clusters.json is automatically refreshed when older than metadata.json
      stale_time = File.mtime(meta_path) - 60
      File.write(clusters_path, JSON.generate({
        "schema_version" => 1,
        "clusters" => [{
          "cluster_id" => "cluster-99",
          "bucket_count" => 0,
          "occurrences" => 0,
          "reasons" => {},
          "representative" => {},
          "buckets" => []
        }]
      }))
      File.utime(stale_time, stale_time, clusters_path)

      refreshed_list, = assert_ruby_cmd(verify_rb, "--triage-dir", triage_dir, "--list-clusters", env: base_env)
      assert_includes refreshed_list, "cluster-01"
      refute_includes refreshed_list, "cluster-99"

      # Install mock_verify runner under VERIFY_BUILD_DIR and stamp its mtime safely ahead of repo sources
      mock_verify = build_mock_verify(workdir)
      mock_build_dir = File.join(workdir, "mock_verify_build")
      FileUtils.mkdir_p(mock_build_dir)
      runner_path = File.join(mock_build_dir, "verify_runner.asan_ubsan")
      FileUtils.cp(mock_verify, runner_path)
      future_mtime = newest_verify_input_mtime(stub_prism) + 5
      File.utime(future_mtime, future_mtime, runner_path)
      verify_env = base_env.merge("VERIFY_BUILD_DIR" => mock_build_dir)

      # Passing cluster (--cluster 2 numeric shorthand) exits 0 and runs only cluster-02
      c2_json_path = File.join(workdir, "verify_c2.json")
      assert_ruby_cmd(verify_rb, "--triage-dir", triage_dir, "--cluster", "2", "--json", c2_json_path, env: verify_env)
      c2 = JSON.parse(File.read(c2_json_path))
      assert_equal 1, c2.dig("summary", "clusters_checked")
      assert_equal 1, c2.dig("summary", "cluster_pass")
      assert_equal 1, c2.dig("summary", "buckets_checked")

      # Partial cluster (--cluster cluster-01, member-bucket expansion, --by-cluster sweep)
      c1_json_path = File.join(workdir, "verify_c1.json")
      _c1_out, _c1_err, c1_st = run_cmd(RbConfig.ruby, verify_rb, "--triage-dir", triage_dir, "--cluster", "cluster-01", "--json", c1_json_path, env: verify_env, chdir: root_dir)
      assert_equal 1, c1_st.exitstatus, "expected --cluster cluster-01 to exit 1 on PARTIAL sibling"
      c1 = JSON.parse(File.read(c1_json_path))
      assert_equal 1, c1.dig("summary", "clusters_checked")
      assert_equal 1, c1.dig("summary", "cluster_partial")
      assert_equal 2, c1.dig("summary", "buckets_checked")
      assert_equal %w[ABRT/c1_rep_pass ABRT/c1_sib_part], c1["buckets"].map { |b| b["bucket_id"] }
      assert_equal [true, false], c1["buckets"].map { |b| b["cluster_representative"] }
      assert_equal "PARTIAL", c1["clusters"].first["status"]

      mem_json_path = File.join(workdir, "verify_member.json")
      _mem_out, _mem_err, mem_st = run_cmd(RbConfig.ruby, verify_rb, "--triage-dir", triage_dir, "--cluster", "ABRT/c1_sib_part", "--json", mem_json_path, env: verify_env, chdir: root_dir)
      assert_equal 1, mem_st.exitstatus, "expected member-bucket --cluster lookup to exit 1"
      mem = JSON.parse(File.read(mem_json_path))
      assert_equal c1["buckets"].map { |b| b["bucket_id"] }, mem["buckets"].map { |b| b["bucket_id"] }

      all_json_path = File.join(workdir, "verify_all_clusters.json")
      all_out, _all_err, all_st = run_cmd(RbConfig.ruby, verify_rb, "--triage-dir", triage_dir, "--by-cluster", "--json", all_json_path, env: verify_env, chdir: root_dir)
      assert_equal 1, all_st.exitstatus, "expected --by-cluster sweep to exit 1"
      all_rep = JSON.parse(File.read(all_json_path))
      assert_equal 2, all_rep.dig("summary", "clusters_checked")
      assert_equal 1, all_rep.dig("summary", "cluster_partial")
      assert_equal 1, all_rep.dig("summary", "cluster_pass")
      assert_includes all_out, "== cluster-01"
      assert_includes all_out, "-> cluster-01: PARTIAL"
      assert_includes all_out, "Clusters:"
      assert_includes all_out, "2 clusters (1 PASS, 1 PARTIAL, 0 FAIL, 0 EMPTY)"

      _unk_out, _unk_err, unk_st = run_cmd(RbConfig.ruby, verify_rb, "--triage-dir", triage_dir, "--cluster", "cluster-99", env: verify_env, chdir: root_dir)
      refute unk_st.success?, "expected unknown --cluster filter to exit non-zero"
    end
  end

  private

  def build_corpus(extra_functions: {}, extra_df: {})
    edge_functions = {
      "1" => "pm_parse",
      "2" => "fuzz_invariant_fail",
      "3" => "check_node_location",
      "4" => "pm_visit_node",
      "5" => "pm_error_recovery_node_create",
      "6" => "context_recoverable",
      "10" => "pm_parser_err_heredoc_term",
      "11" => "parse_heredoc",
      "12" => "parse_string_part",
      "13" => "parse_statements",
      "20" => "parse_for",
      "21" => "parse_for",
      "22" => "parse_for",
      "30" => "parser_lex",
      "31" => "pm_string_ensure",
      "40" => "parse_interpolated_symbol_array"
    }.merge(extra_functions)
    edge_df = {
      "1" => 100,
      "2" => 0,
      "3" => 0,
      "4" => 100,
      "5" => 0,
      "6" => 0,
      "10" => 0,
      "11" => 5,
      "12" => 1,
      "13" => 1,
      "20" => 0,
      "21" => 0,
      "22" => 1,
      "30" => 0,
      "31" => 1,
      "40" => 0
    }.merge(extra_df)
    {
      "available" => true,
      "corpus_count" => 100,
      "edge_df" => edge_df,
      "edge_functions" => edge_functions
    }
  end

  def make_bucket(id:, reason:, occ:, size: 10, frames: [], edges: {}, unrepro: false)
    {
      "bucket_id" => id,
      "reason" => reason,
      "signature" => id.split("/", 2).last,
      "reproducible" => !unrepro,
      "occurrences" => { "count" => occ },
      "input" => { "min_size_bytes" => size },
      "symptom" => { "headline" => "synthetic #{id}" },
      "frames" => frames,
      "coverage" => { "available" => true, "edges" => edges }
    }
  end

  def make_inv_bucket(id:, profile:, ns:, fields: {}, edges: { "1" => 1, "83" => 1 })
    b = make_bucket(id: id, reason: "ABRT", occ: 3, edges: edges)
    b["verify_profile"] = profile
    b["symptom"]["invariant"] = { "namespace" => ns, "fields" => fields }
    b
  end

  def frames_segv
    [
      { "scope" => "prism", "func" => "parser_lex", "file" => "src/prism.c", "line" => 300 },
      { "scope" => "prism", "func" => "parse_expression", "file" => "src/prism.c", "line" => 2000 },
      { "scope" => "prism", "func" => "pm_parse", "file" => "src/prism.c", "line" => 3000 }
    ]
  end

  def frames_msan
    [
      { "scope" => "prism", "func" => "parser_lex", "file" => "src/prism.c", "line" => 305 },
      { "scope" => "prism", "func" => "parse_string_part", "file" => "src/prism.c", "line" => 900 },
      { "scope" => "prism", "func" => "pm_parse", "file" => "src/prism.c", "line" => 3000 }
    ]
  end

  def frames_shift
    [
      { "scope" => "prism", "func" => "pm_helper_read", "file" => "src/prism.c", "line" => 50 },
      { "scope" => "prism", "func" => "parser_lex", "file" => "src/prism.c", "line" => 300 },
      { "scope" => "prism", "func" => "parse_expression", "file" => "src/prism.c", "line" => 2000 },
      { "scope" => "prism", "func" => "pm_parse", "file" => "src/prism.c", "line" => 3000 }
    ]
  end

  def frames_other_leaf
    [
      { "scope" => "prism", "func" => "pm_line_offset_list_line_column", "file" => "src/line_offset_list.c", "line" => 96 },
      { "scope" => "prism", "func" => "parse_case", "file" => "src/prism.c", "line" => 1800 },
      { "scope" => "prism", "func" => "parse_expression", "file" => "src/prism.c", "line" => 2000 },
      { "scope" => "prism", "func" => "pm_parse", "file" => "src/prism.c", "line" => 3000 }
    ]
  end

  def frames_ub_for
    [
      { "scope" => "prism", "func" => "parser_warn_indentation_mismatch", "file" => "src/prism.c", "line" => 15213 },
      { "scope" => "prism", "func" => "parse_for", "file" => "src/prism.c", "line" => 19744 },
      { "scope" => "prism", "func" => "pm_parse", "file" => "src/prism.c", "line" => 3000 }
    ]
  end

  def multi_regime_fixture
    corpus = build_corpus
    buckets = [
      # Cross-reason leaf + 1-frame shift cluster (should merge across SEGV, msan, asan)
      make_bucket(id: "SEGV/lex_ijon", reason: "SEGV", occ: 40, frames: frames_segv, edges: { "1" => 1, "30" => 1, "31" => 1 }),
      make_bucket(id: "use-of-uninitialized-value/lex_msan", reason: "use-of-uninitialized-value", occ: 12, frames: frames_msan, edges: { "1" => 1, "30" => 1, "31" => 1 }),
      make_bucket(id: "heap-buffer-overflow/lex_shift", reason: "heap-buffer-overflow", occ: 5, frames: frames_shift, edges: { "1" => 1, "30" => 1, "31" => 1 }),
      # Separate stack bug sharing root frames
      make_bucket(id: "use-of-uninitialized-value/line_col", reason: "use-of-uninitialized-value", occ: 9, frames: frames_other_leaf, edges: { "1" => 1 }),
      # Stackless heredoc cluster (minimal + verbose + parse_for caller noise) + visitor wrapper stripped
      make_bucket(id: "ABRT/heredoc_min", reason: "ABRT", occ: 100, size: 9, frames: [{ "scope" => "prism", "func" => "pm_visit_node", "file" => "node.c", "line" => 1 }], edges: { "1" => 1, "2" => 1, "3" => 1, "4" => 1, "10" => 1, "11" => 1 }),
      make_bucket(id: "ABRT/heredoc_full", reason: "ABRT", occ: 25, size: 22, edges: { "1" => 1, "2" => 1, "3" => 1, "5" => 1, "6" => 1, "10" => 1, "11" => 1, "12" => 1, "13" => 1, "20" => 1, "21" => 1, "22" => 1 }),
      # Different stackless ABRT sharing recovery + boilerplate noise only (must NOT merge with heredoc_full)
      make_bucket(id: "ABRT/sym_array", reason: "ABRT", occ: 30, edges: { "1" => 1, "2" => 1, "3" => 1, "5" => 1, "6" => 1, "40" => 1 }),
      # Adversarial in-parse UB parse_for (must NOT merge with ABRT/heredoc_full despite shared parse_for edges)
      make_bucket(id: "undefined-behavior/indent_for", reason: "undefined-behavior", occ: 18, frames: frames_ub_for, edges: { "1" => 1, "5" => 1, "6" => 1, "20" => 1, "21" => 1, "22" => 1 }),
      # Unreproducible bucket (skipped by default; common parse edge only)
      make_bucket(id: "unreproducible/transient_01", reason: "unreproducible", occ: 2, unrepro: true, edges: { "1" => 1 })
    ]
    metadata = { "schema_version" => 1, "corpus" => corpus, "buckets" => buckets }
    [corpus, buckets, metadata]
  end

  def make_dual_diff_bucket(id:, occ:, fields:, edges:, prism_edges: { "10" => 1 })
    b = make_inv_bucket(id: id, profile: "diff_parse_y", ns: "diff_parse_y", edges: prism_edges, fields: fields)
    b["occurrences"] = { "count" => occ }
    b["diff_coverage"] = { "available" => true, "edge_count" => edges.size, "edges" => edges }
    b
  end

  def diff_dual_fixture
    corpus = build_corpus
    diff_dual_ef = {}
    diff_dual_dom = {}
    diff_dual_df = {}

    # Domain=harness (excluded 0.0), plus CRuby error-printer & Prism visitor boilerplate
    (1000..1030).each { |eid| diff_dual_ef[eid.to_s] = "diff_cruby_visit_node_ctx"; diff_dual_dom[eid.to_s] = "harness"; diff_dual_df[eid.to_s] = 0 }
    (1031..1050).each { |eid| diff_dual_ef[eid.to_s] = "ruby_show_error_line"; diff_dual_dom[eid.to_s] = "parse_y"; diff_dual_df[eid.to_s] = 0 }
    (1051..1070).each { |eid| diff_dual_ef[eid.to_s] = "pm_visit_child_nodes"; diff_dual_dom[eid.to_s] = "prism"; diff_dual_df[eid.to_s] = 0 }
    # Domain=prism parser edges (preexe bug + unrelated regex/def edges)
    (1100..1115).each { |eid| diff_dual_ef[eid.to_s] = "parse_preexe"; diff_dual_dom[eid.to_s] = "prism"; diff_dual_df[eid.to_s] = 0 }
    (1116..1135).each { |eid| diff_dual_ef[eid.to_s] = "parse_alias"; diff_dual_dom[eid.to_s] = "prism"; diff_dual_df[eid.to_s] = 0 }
    (1136..1150).each { |eid| diff_dual_ef[eid.to_s] = "parse_regexp"; diff_dual_dom[eid.to_s] = "prism"; diff_dual_df[eid.to_s] = 0 }
    # Domain=parse_y parser edges (kBEGIN rules + unrelated regex edges)
    (1200..1215).each { |eid| diff_dual_ef[eid.to_s] = "ruby_yyparse"; diff_dual_dom[eid.to_s] = "parse_y"; diff_dual_df[eid.to_s] = 0 }
    (1216..1235).each { |eid| diff_dual_ef[eid.to_s] = "rb_node_alias_new"; diff_dual_dom[eid.to_s] = "parse_y"; diff_dual_df[eid.to_s] = 0 }
    (1236..1250).each { |eid| diff_dual_ef[eid.to_s] = "reg_compile"; diff_dual_dom[eid.to_s] = "parse_y"; diff_dual_df[eid.to_s] = 0 }

    diff_dual_corpus = {
      "available" => true,
      "corpus_count" => 100,
      "edge_df" => diff_dual_df,
      "edge_functions" => diff_dual_ef,
      "edge_domains" => diff_dual_dom
    }

    preexe_small = ((1000..1015).to_a + (1051..1060).to_a + (1100..1110).to_a + (1200..1210).to_a).to_h { |e| [e.to_s, 1] }
    preexe_big   = ((1000..1015).to_a + (1051..1060).to_a + (1100..1110).to_a + (1116..1130).to_a + (1200..1210).to_a + (1216..1230).to_a).to_h { |e| [e.to_s, 1] }
    boil_only_a  = ((1000..1030).to_a + (1031..1050).to_a + (1136..1142).to_a + (1236..1240).to_a).to_h { |e| [e.to_s, 1] }
    boil_only_b  = ((1000..1030).to_a + (1031..1050).to_a + (1143..1150).to_a + (1241..1250).to_a).to_h { |e| [e.to_s, 1] }

    prism_flaw_b = make_bucket(
      id: "SEGV/prism_segv",
      reason: "SEGV",
      occ: 2,
      edges: { "10" => 1, "11" => 1 },
      frames: [{ "scope" => "prism", "func" => "parse_statements", "file" => "src/prism.c", "line" => 100 }]
    )
    dual_buckets = [
      prism_flaw_b,
      make_dual_diff_bucket(id: "ABRT/begin_small", occ: 100, edges: preexe_small, fields: { "kind" => "ast_tree_mismatch", "sub" => "tag", "prism" => "POSTEXE", "cruby" => "INT" }),
      make_dual_diff_bucket(id: "ABRT/begin_big", occ: 20, edges: preexe_big, fields: { "kind" => "ast_tree_mismatch", "sub" => "tag", "prism" => "ALIAS", "cruby" => "MASGN" }),
      make_dual_diff_bucket(id: "ABRT/syn_ok_a", occ: 5, edges: boil_only_a, fields: { "kind" => "syntax_mismatch", "sub" => "prism_ok_cruby_err", "prism" => "ok", "cruby" => "SyntaxError:foo" }),
      make_dual_diff_bucket(id: "ABRT/syn_ok_b", occ: 4, edges: boil_only_b, fields: { "kind" => "syntax_mismatch", "sub" => "prism_ok_cruby_err", "prism" => "ok", "cruby" => "ArgumentError:unknown_encoding" })
    ]

    {
      corpus: corpus,
      diff_dual_corpus: diff_dual_corpus,
      prism_flaw_b: prism_flaw_b,
      dual_buckets: dual_buckets,
      boil_only_a: boil_only_a,
      boil_only_b: boil_only_b
    }
  end

  def cluster_bucket_groups(report)
    report["clusters"].map { |c| c["buckets"].map { |b| b["bucket_id"] }.sort }.sort
  end

  def create_tar_gz(path, payloads)
    Zlib::GzipWriter.open(path) do |gz|
      Gem::Package::TarWriter.new(gz) do |tar|
        payloads.each do |data|
          sha = Digest::SHA256.hexdigest(data)
          tar.add_file_simple(sha, 0o644, data.bytesize) { |io| io.write(data) }
        end
      end
    end
  end

  def default_cc
    cc = ENV["CC"].to_s.strip
    cc.empty? ? "clang" : cc
  end

  def build_mock_verify(workdir)
    src_path = File.join(workdir, "mock_fuzz_target.c")
    bin_path = File.join(workdir, "mock_verify")
    File.write(src_path, MOCK_FUZZ_TARGET_C)
    assert_cmd(
      default_cc, "-O1", "-g", "-std=c99", "-fsanitize=address",
      repo_path("triage/verify_runner.c"), src_path, "-o", bin_path
    )
    bin_path
  end

  def create_stub_prism_root(workdir)
    stub = File.join(workdir, "stub_prism")
    FileUtils.mkdir_p([File.join(stub, "include"), File.join(stub, "src")])
    File.write(File.join(stub, "include", "prism.h"), <<~C)
      #ifndef PRISM_H
      #define PRISM_H
      void pm_parse(void);
      void pm_parser_new(void);
      #endif
    C
    stub
  end

  def newest_verify_input_mtime(target_root)
    paths = [
      repo_path("triage/verify_runner.c"),
      *Dir.glob(repo_path("harnesses/prism/**/*")).select { |p| File.file?(p) },
      *Dir.glob(File.join(target_root, "{src,include}/**/*")).select { |p| File.file?(p) }
    ]
    ([Time.now] + paths.map { |p| File.mtime(p) }).max
  end
end
