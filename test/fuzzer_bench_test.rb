# frozen_string_literal: true

require "json"
require "tmpdir"
require "minitest/autorun"
require_relative "../runtime/fuzzer_bench"

class FuzzerBenchTest < Minitest::Test
  def test_expand_matrix_shapes_and_features
    opts = FuzzerBench.parse_options(%w[
      --shapes prism_parse,prism_diff_ruby
      --ijon none,on
      --cmplog false,true
      --sand false,true
      --schedules fast
    ])
    cells = FuzzerBench.expand_matrix(opts)

    parse_cells = cells.select { |c| c["shape"] == "prism_parse" }
    diff_cells  = cells.select { |c| c["shape"] == "prism_diff_ruby" }

    # prism_parse: 2 ijon x 2 cmplog x 2 sand = 8
    assert_equal 8, parse_cells.length
    # prism_diff_ruby ignores cmplog/sand: 2 ijon = 2
    assert_equal 2, diff_cells.length
    assert diff_cells.none? { |c| c["cmplog"] || c["sand"] }

    on_cell = parse_cells.find { |c| c["ijon"] == "on" && !c["cmplog"] && !c["sand"] }
    assert_equal "bench_prism_parse_ijon_on", on_cell["binary"]
    assert_equal "bench_prism_parse_cfg", on_cell["cfg_binary"]
  end

  def test_build_topology_ir_valid_and_has_ijon_attrs
    opts = FuzzerBench.parse_options(%w[
      --shapes prism_parse,prism_diff_ruby
      --ijon none,on
      --cmplog true
      --sand true
    ])
    cells = FuzzerBench.expand_matrix(opts)
    topo = FuzzerBench.build_topology_ir(opts, cells)

    assert_equal 2, topo["schema_version"]
    assert topo["sources"].key?("prism_a")
    assert topo["sources"].key?("ruby")

    fuzzers = topo["fuzzers"]
    assert fuzzers.key?("bench_prism_parse_cfg")
    assert fuzzers.key?("bench_prism_diff_ruby_cfg")
    assert fuzzers.key?("bench_prism_parse_cmplog")
    assert fuzzers.key?("bench_prism_parse_sand")

    on_diff = fuzzers["bench_prism_diff_ruby_ijon_on"]
    assert_equal true, on_diff["ijon"]
    assert_nil on_diff["defines"]

    none_diff = fuzzers["bench_prism_diff_ruby_cfg"]
    refute none_diff["ijon"]
    assert_nil none_diff["defines"]
  end

  def test_parse_fuzzer_stats_and_aggregate
    Dir.mktmpdir("fbench-test-") do |dir|
      stats_path = File.join(dir, "fuzzer_stats")
      File.write(stats_path, <<~STATS)
        execs_done        : 120000
        execs_per_sec     : 2000.50
        corpus_count      : 450
        corpus_favored    : 42
        pending_favs      : 3
        bitmap_cvg        : 31.40%
      STATS

      parsed = FuzzerBench.parse_fuzzer_stats(stats_path)
      assert_equal "120000", parsed["execs_done"]
      assert_equal "2000.50", parsed["execs_per_sec"]
      assert_equal "450", parsed["corpus_count"]
    end

    cell = { "id" => "prism_parse__ijon_v2", "shape" => "prism_parse", "ijon" => "v2", "cmplog" => false, "sand" => false, "schedule" => "fast" }
    agg = FuzzerBench.aggregate_cell(cell, [
      { "trial" => 1, "execs_per_sec" => 1000.0, "execs_done" => 60_000, "corpus_count" => 300, "cfg_edges" => 2100, "ast_2paths" => 900, "valid_2paths" => 150, "valid_syntax_pct" => 40.0, "crashes" => { "total" => 2, "unique" => 1, "first_crash_ms" => 5000, "signatures" => ["INVARIANT[a]"] } },
      { "trial" => 2, "execs_per_sec" => 1200.0, "execs_done" => 72_000, "corpus_count" => 340, "cfg_edges" => 2300, "ast_2paths" => 1100, "valid_2paths" => 250, "valid_syntax_pct" => 50.0, "crashes" => { "total" => 1, "unique" => 1, "first_crash_ms" => 3000, "signatures" => ["INVARIANT[b]"] } }
    ])

    assert_equal 1100.0, agg["median_execs_per_sec"]
    assert_equal 2200, agg["median_cfg_edges"]
    assert_equal 1000, agg["median_ast_2paths"]
    assert_equal 200, agg["median_valid_2paths"]
    assert_equal 3, agg["total_crashes"]
    assert_equal 3000, agg["min_first_crash_ms"]
    assert_equal %w[INVARIANT[a] INVARIANT[b]], agg["all_signatures"]
  end

  def test_grammar_modes_expand_and_configure_env
    opts = FuzzerBench.parse_options(%w[
      --shapes prism_parse
      --ijon none
      --grammar none,mutator,mutator_mixed,lrama
    ])
    cells = FuzzerBench.expand_matrix(opts)
    assert_equal 4, cells.length

    mut = cells.find { |c| c["grammar"] == "mutator" }
    env, cmd = FuzzerBench.afl_command_for(mut, opts: opts, corpus_dir: "/in", out_dir: "/out", trial: 1, tree_dir: "/tmp/t")
    assert_equal "1", env["AFL_CUSTOM_MUTATOR_ONLY"]
    assert env["AFL_CUSTOM_MUTATOR_LIBRARY"].end_with?("libgrammarmutator-ruby.so")
    assert_equal "/tmp/t", env["GRAMMAR_MUTATOR_TREE_DIR"]
    assert_includes cmd, "afl-fuzz"

    mix = cells.find { |c| c["grammar"] == "mutator_mixed" }
    env_mix, _ = FuzzerBench.afl_command_for(mix, opts: opts, corpus_dir: "/in", out_dir: "/out", trial: 1, tree_dir: "/tmp/t")
    assert_nil env_mix["AFL_CUSTOM_MUTATOR_ONLY"]
    assert env_mix["AFL_CUSTOM_MUTATOR_LIBRARY"].end_with?("libgrammarmutator-ruby.so")

    lrama = cells.find { |c| c["grammar"] == "lrama" }
    _, cmd_lrama = FuzzerBench.afl_command_for(lrama, opts: opts, corpus_dir: "/in", out_dir: "/out", trial: 1, foreign_dir: "/tmp/f")
    assert_includes cmd_lrama, "-F"
    assert_includes cmd_lrama, "/tmp/f"
  end

  def test_dry_run_exits_zero
    out = nil
    status = nil
    Dir.mktmpdir("fbench-dry-") do |dir|
      out, status = Open3.capture2(
        "ruby", File.expand_path("../runtime/fuzzer_bench.rb", __dir__),
        "--dry-run", "--workspace", dir, "--shapes", "prism_parse", "--ijon", "none,on"
      )
    end
    assert status.success?, "dry-run failed: #{out}"
    assert_includes out, "prism_parse__ijon_none"
    assert_includes out, "prism_parse__ijon_on"
  end
end
