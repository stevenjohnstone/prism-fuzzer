#!/usr/bin/env ruby
# frozen_string_literal: true

require "base64"
require "cgi/escape"
require "digest"
require "fileutils"
require "json"
require "optparse"
require "pathname"
require "time"

require_relative "../runtime/common"
require_relative "../runtime/fuzz_header"

topology_lib = File.expand_path("../runtime/topology.rb", __dir__)
require topology_lib if File.file?(topology_lib)
sankey_lib = File.expand_path("sankey.rb", __dir__)
require sankey_lib if File.file?(sankey_lib)
inspect_lib = File.expand_path("../triage/inspect.rb", __dir__)
require inspect_lib if File.file?(inspect_lib)

require_relative "lib/helpers"
require_relative "lib/stats_ingest"
require_relative "lib/charts"
require_relative "lib/lineage"
require_relative "lib/topology_view"
require_relative "lib/triage_view"
require_relative "lib/coverage_view"
require_relative "lib/chunker"
require_relative "lib/page_renderer"

module PrismFuzzerReport
  Object.const_set(:RubyFuzzReport, self) unless Object.const_defined?(:RubyFuzzReport, false)

  module_function

  def resolve_paths(afl_dir: nil, out_path: nil, cov_json_path: nil, triage_dir: nil, topo: nil)
    root_dir = File.expand_path("..", __dir__)
    ws_defaults = if defined?(PrismFuzzer::Topology)
                    discovered = topo || PrismFuzzer::Topology.discover(afl_dir: afl_dir, triage_dir: triage_dir, start_dir: root_dir)
                    PrismFuzzer::Topology.workspace_paths(discovered)
                  end

    resolved_afl = afl_dir || (ws_defaults ? ws_defaults[:afl_dir] : "./tmp/fuzz/afl")
    resolved_out = out_path || (ws_defaults ? File.join(ws_defaults[:report_dir], "index.html") : "./tmp/fuzz/report/index.html")
    resolved_cov = cov_json_path || (ws_defaults ? File.join(ws_defaults[:coverage_dir], "coverage.json") : File.join(File.dirname(resolved_out), "coverage", "coverage.json"))
    resolved_triage = triage_dir || ENV["TRIAGE_DIR"]
    resolved_triage = nil if resolved_triage && resolved_triage.strip.empty?
    resolved_triage ||= ws_defaults ? ws_defaults[:triage_dir] : "./tmp/fuzz/report/triage"

    {
      afl_dir: resolved_afl,
      out_path: resolved_out,
      cov_json_path: resolved_cov,
      triage_dir: resolved_triage
    }
  end

  def generate(
    afl_dir: nil,
    out_path: nil,
    cov_json_path: nil,
    triage_dir: nil,
    sankey_top: nil,
    title: nil,
    topo: nil,
    coverage_pending: false,
    write_output: true,
    single_file: false,
    max_chunk_bytes: Chunker::DEFAULT_MAX_CHUNK_BYTES
  )
    paths = resolve_paths(
      afl_dir: afl_dir,
      out_path: out_path,
      cov_json_path: cov_json_path,
      triage_dir: triage_dir,
      topo: topo
    )

    resolved_afl = paths[:afl_dir]
    resolved_out = paths[:out_path]
    resolved_cov = paths[:cov_json_path]
    resolved_triage = paths[:triage_dir]

    if topo.nil? && defined?(PrismFuzzer::Topology)
      topo = PrismFuzzer::Topology.discover(
        afl_dir: resolved_afl,
        triage_dir: resolved_triage,
        start_dir: File.expand_path("..", __dir__)
      )
    end
    topo_ctx = Helpers.topology_context(topo)

    fleet = StatsIngest.ingest_fuzzers(resolved_afl, topo_ctx: topo_ctx)
    fleet_lineage = Lineage.analyze_fleet_lineage(resolved_afl, triage_dir: resolved_triage, topo_ctx: topo_ctx)
    out_dir_abs = Pathname.new(File.expand_path(File.dirname(resolved_out)))
    cov_info = CoverageView.ingest_coverage(
      cov_json_path: resolved_cov,
      out_dir_abs: out_dir_abs,
      fuzzers: fleet[:fuzzers],
      topo_ctx: topo_ctx,
      coverage_pending: coverage_pending
    )
    triage_view = TriageView.load_triage_view_data(
      triage_dir: resolved_triage,
      afl_dir: resolved_afl,
      out_dir_abs: out_dir_abs,
      sankey_top: sankey_top,
      topo: topo
    )

    use_chunks = write_output && !single_file
    chunker = use_chunks ? Chunker.new(max_chunk_bytes: max_chunk_bytes) : nil

    html = PageRenderer.render_page(
      afl_dir: resolved_afl,
      title: title,
      triage_dir: resolved_triage,
      fleet: fleet,
      fleet_lineage: fleet_lineage,
      triage_view: triage_view,
      cov_info: cov_info,
      topo_ctx: topo_ctx,
      chunker: chunker
    )

    chunk_files = []
    out_dir_str = File.dirname(resolved_out)
    if write_output
      FileUtils.mkdir_p(out_dir_str)
      chunk_files = chunker.write_chunks!(out_dir_str) if chunker
      tmp_out = "#{resolved_out}.tmp.#{Process.pid}"
      File.write(tmp_out, html)
      File.rename(tmp_out, resolved_out)
      chunker&.prune_stale_chunks!(out_dir_str)
    end

    {
      html: html,
      out_path: resolved_out,
      chunks_dir: chunker ? File.join(out_dir_str, "chunks") : nil,
      chunk_files: chunk_files,
      fuzzer_count: fleet[:fuzzers].size
    }
  end

  def split_existing_html!(html_path, max_chunk_bytes: Chunker::DEFAULT_MAX_CHUNK_BYTES)
    raise InputError, "HTML report not found: #{html_path}" unless html_path && File.file?(html_path)

    raw_html = File.binread(html_path).force_encoding("UTF-8")
    sankey_js = defined?(FuzzSankey::SANKEY_JS) ? FuzzSankey::SANKEY_JS : ""
    res = Chunker.split_monolithic_html(
      raw_html,
      max_chunk_bytes: max_chunk_bytes,
      report_js: PageRenderer::REPORT_JS,
      sankey_js: sankey_js
    )
    return { out_path: html_path, chunk_files: [], already_chunked: true } unless res

    new_html, chunker = res
    out_dir = File.dirname(html_path)
    chunk_files = chunker.write_chunks!(out_dir)
    tmp_out = "#{html_path}.tmp.#{Process.pid}"
    File.binwrite(tmp_out, new_html)
    File.rename(tmp_out, html_path)
    chunker.prune_stale_chunks!(out_dir)
    {
      out_path: html_path,
      chunks_dir: File.join(out_dir, "chunks"),
      chunk_files: chunk_files,
      already_chunked: false
    }
  end

  def run_cli(argv = ARGV)
    cli_opts = {
      triage_dir: nil,
      sankey_top: nil,
      title: nil,
      out: nil,
      coverage_pending: false,
      single_file: false,
      max_chunk_bytes: Chunker::DEFAULT_MAX_CHUNK_BYTES,
      split_existing: nil
    }
    cli_args = argv.dup
    OptionParser.new do |op|
      op.banner = "Usage: report.rb [afl_dir] [out_html] [cov_json] [options]"
      op.on("--triage-dir DIR", "Triage directory for clusters & Sankey tab") { |v| cli_opts[:triage_dir] = v }
      op.on("--sankey-top N", Integer, "Max cluster bars shown in embedded Sankey") { |v| cli_opts[:sankey_top] = v }
      op.on("--title TEXT", "Custom HTML report title") { |v| cli_opts[:title] = v }
      op.on("--coverage-pending", "Render live pending/updating state while coverage.sh runs") { cli_opts[:coverage_pending] = true }
      op.on("--single-file", "Inline all tabs and drawers into a single monolithic HTML file") { cli_opts[:single_file] = true }
      op.on("--max-chunk-mb FLOAT", Float, "Maximum size per generated chunk file in MiB (default: 8)") do |v|
        cli_opts[:max_chunk_bytes] = (v * 1024 * 1024).to_i
      end
      op.on("--split-existing PATH", "Split an existing monolithic index.html in-place into chunks/") { |v| cli_opts[:split_existing] = v }
      op.on("-o", "--out PATH", "Output HTML report path") { |v| cli_opts[:out] = v }
      op.on("-h", "--help", "Show help") { puts op; exit 0 }
    end.parse!(cli_args)

    if cli_opts[:split_existing]
      split_res = split_existing_html!(cli_opts[:split_existing], max_chunk_bytes: cli_opts[:max_chunk_bytes])
      puts "Split report #{split_res[:out_path]} into #{split_res[:chunk_files].size} chunk file(s)"
      return
    end

    result = generate(
      afl_dir: cli_args[0],
      out_path: cli_opts[:out] || cli_args[1],
      cov_json_path: cli_args[2],
      triage_dir: cli_opts[:triage_dir],
      sankey_top: cli_opts[:sankey_top],
      title: cli_opts[:title],
      coverage_pending: cli_opts[:coverage_pending],
      single_file: cli_opts[:single_file],
      max_chunk_bytes: cli_opts[:max_chunk_bytes]
    )
    chunk_note = result[:chunk_files].empty? ? "" : " + #{result[:chunk_files].size} chunk(s)"
    puts "Wrote campaign report (#{result[:fuzzer_count]} fuzzers#{chunk_note}) to #{result[:out_path]}"
  rescue InputError => e
    warn e.message
    exit 1
  end
end

PrismFuzzerReport.run_cli(ARGV) if __FILE__ == $PROGRAM_NAME
