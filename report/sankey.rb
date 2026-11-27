#!/usr/bin/env ruby
# frozen_string_literal: true

require "cgi/escape"
require "fileutils"
require "json"
require "optparse"
require "set"
require "time"

topology_lib = File.expand_path("../runtime/topology.rb", __dir__)
require topology_lib if File.file?(topology_lib)

# Generates interactive HTML, standalone SVG, and JSON Sankey flow diagrams
# tracing fuzzing finds from seed origin / discovering fuzzer worker through
# bug category into deduplicated root-cause clusters.
module FuzzSankey
  DEFAULT_TRIAGE_DIR = "tmp/fuzz/report/triage"
  DEFAULT_OUTPUT_PATH = "tmp/fuzz/report/sankey.html"
  DEFAULT_MAX_CLUSTERS = 20

  WORKER_COLORS = {
    "corpus" => "#fbbf24",
    "main" => "#60a5fa",
    "main-2" => "#38bdf8",
    "ijon" => "#4ade80",
    "msan" => "#a78bfa",
    "slow" => "#f472b6",
    "diff" => "#f97316",
    "diff-2" => "#fb923c",
    "diff-3" => "#fdba74",
    "diff-4" => "#f59e0b",
    "arm32" => "#2dd4bf",
    "ppc" => "#e879f9"
  }.freeze

  FALLBACK_PALETTE = [
    "#60a5fa", "#34d399", "#f472b6", "#fbbf24", "#a78bfa", "#38bdf8",
    "#fb7185", "#4ade80", "#f97316", "#2dd4bf", "#e879f9", "#facc15"
  ].freeze

  OTHER_COLOR = "#64748b"

  module_function

  def run_cli(argv = ARGV)
    ws_defaults = if defined?(PrismFuzzer::Topology)
                    t = PrismFuzzer::Topology.discover(triage_dir: ENV["TRIAGE_DIR"], start_dir: File.expand_path("..", __dir__))
                    PrismFuzzer::Topology.workspace_paths(t) if t
                  end
    default_triage = ws_defaults ? PrismFuzzer::Topology.path_relative_or_abs(ws_defaults[:triage_dir], Dir.pwd) : DEFAULT_TRIAGE_DIR
    default_output = ws_defaults ? PrismFuzzer::Topology.path_relative_or_abs(File.join(ws_defaults[:report_dir], "sankey.html"), Dir.pwd) : DEFAULT_OUTPUT_PATH
    options = {
      triage_dir: ENV.fetch("TRIAGE_DIR", default_triage),
      metadata: nil,
      clusters: nil,
      afl_dir: nil,
      output: default_output,
      format: nil,
      metric: "occurrences",
      layers: "auto",
      group: "all",
      max_clusters: DEFAULT_MAX_CLUSTERS,
      title: "Prism Fuzzing Flow: Fuzzer → Cluster Sankey",
      trace_origins: true
    }

    OptionParser.new do |opts|
      opts.banner = "Usage: sankey.rb [OPTIONS]"
      opts.on("--triage-dir DIR", "Triage directory (default: #{DEFAULT_TRIAGE_DIR})") { |v| options[:triage_dir] = v }
      opts.on("--metadata PATH", "Path to metadata.json") { |v| options[:metadata] = v }
      opts.on("--clusters PATH", "Path to clusters.json") { |v| options[:clusters] = v }
      opts.on("--afl-dir DIR", "AFL++ directory for corpus lineage") { |v| options[:afl_dir] = v }
      opts.on("-o", "--output PATH", "Output path (.html, .svg, .json, or '-' for stdout)") { |v| options[:output] = v }
      opts.on("--format FMT", "Output format: html | svg | json") { |v| options[:format] = v.downcase }
      opts.on("--metric METRIC", "occurrences | buckets (default: occurrences)") { |v| options[:metric] = v }
      opts.on("--layers MODE", "auto | 2 | 3 | 3o | 4") { |v| options[:layers] = v }
      opts.on("--group GROUP", "all | prism_flaw | cruby_crash | diff_parse_y | diff_prism") { |v| options[:group] = v }
      opts.on("--max-clusters N", Integer, "Max cluster bars before collapsing tail (0 = all, default: #{DEFAULT_MAX_CLUSTERS})") { |v| options[:max_clusters] = v }
      opts.on("--title TEXT", "Custom diagram title") { |v| options[:title] = v }
      opts.on("--no-origins", "Skip AFL++ queue lineage walk for corpus seed origins") { options[:trace_origins] = false }
    end.parse!(argv)

    fmt = options[:format]
    if fmt.nil?
      ext = File.extname(options[:output].to_s).downcase
      fmt = case ext
            when ".svg" then "svg"
            when ".json" then "json"
            else "html"
            end
    end

    dataset = extract_dataset(
      triage_dir: options[:triage_dir],
      metadata_path: options[:metadata],
      clusters_path: options[:clusters],
      afl_dir: options[:afl_dir],
      trace_origins: options[:trace_origins]
    )

    rendered = case fmt
               when "svg"
                 graph = build_sankey_graph(
                   dataset,
                   metric: options[:metric],
                   group: options[:group],
                   layers_mode: options[:layers],
                   max_clusters: options[:max_clusters]
                 )
                 layout = compute_sankey_layout(graph)
                 render_svg(layout, title: options[:title], metric_label: options[:metric], interactive: false)
               when "json"
                 JSON.pretty_generate(
                   generate_json_report(
                     dataset,
                     metric: options[:metric],
                     group: options[:group],
                     layers_mode: options[:layers],
                     max_clusters: options[:max_clusters]
                   )
                 ) + "\n"
               when "html"
                 generate_html_report(
                   dataset,
                   title: options[:title],
                   default_metric: options[:metric],
                   default_group: options[:group],
                   default_layers: options[:layers],
                   default_max_clusters: options[:max_clusters]
                 )
               else
                 abort "Unknown format '#{fmt}' (expected html, svg, or json)"
               end

    if options[:output] == "-"
      $stdout.write(rendered)
    else
      FileUtils.mkdir_p(File.dirname(options[:output]))
      File.write(options[:output], rendered)
      puts "Wrote Sankey #{fmt} (#{dataset[:clusters].size} clusters, #{format_int(dataset[:records].sum { |r| r[:occurrences] })} occurrences) to #{options[:output]}"
    end
  end
end

require_relative "lib/sankey/extract"
require_relative "lib/sankey/graph"
require_relative "lib/sankey/render"

FuzzSankey.run_cli(ARGV) if __FILE__ == $PROGRAM_NAME
