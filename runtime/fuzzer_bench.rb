#!/usr/bin/env ruby
# frozen_string_literal: true

require "etc"
require "fileutils"
require "json"
require "open3"
require "optparse"
require "set"
require "shellwords"
require "tmpdir"

# Feature-matrix fuzzer benchmark harness for comparing fuzzer shapes and
# instrumentation/runtime features (IJON none / v1 / v2 / v1+v2, CmpLog, SAND,
# AFL++ power schedules) under identical corpus, target ref, and time budget.
module FuzzerBench
  VALID_SHAPES = %w[prism_parse prism_diff_ruby cruby_compile cruby_pipeline_diff].freeze
  VALID_IJON_MODES = %w[none on].freeze
  VALID_GRAMMAR_MODES = %w[none mutator mutator_mixed lrama prism prism_mixed].freeze
  VALID_SCHEDULES = %w[fast explore rare coe lin quad mmopt seek].freeze

  DEFAULT_PRISM_REF = "a5e01d818fa45f2cea9232754251a6855f82ab98"
  FUZZ_HEADER_DEFAULT = "\x00\x00\x03\x01".b.freeze

  BUILTIN_SEEDS = [
    "1 + 2\n",
    "def foo(a, *b, c: 1, **d, &e); yield(a, b, c, d); end\n",
    "class C < B; module M; X = [1, 2, 3]; end; end\n",
    "a = <<~EOF\n  hello \#{1 + 2}\nEOF\n",
    "case x; in { a: [1, *rest] } if rest.any?; p rest; end\n",
    "/^(?<name>[a-z]+)\\s+\\u{1f600}/imx =~ s\n",
    "begin; a[0] ||= b rescue nil; ensure; c; end\n",
    "->(x = 1) { x * 2 }.call(3)\n",
    "%w[a b c] + %i[x y z] + %r{foo/bar}i\n",
    "# coding: UTF-8\nfor i in 1..3; next if i == 2; break; end\n"
  ].freeze

  module_function

  def default_ruby_ref(fuzz_root)
    df = File.join(fuzz_root, "docker", "Dockerfile")
    if File.file?(df)
      ref = File.read(df)[/^ARG RUBY_GIT_REF=([0-9a-f]+)/, 1]
      return ref if ref && !ref.empty?
    end
    "17eecca74a586156acebb8b06417f4df17cdedfc"
  end

  def parse_bool_list(raw)
    raw.split(",").map(&:strip).reject(&:empty?).map do |v|
      case v.downcase
      when "true", "1", "yes", "on" then true
      when "false", "0", "no", "off" then false
      else raise OptionParser::InvalidArgument, "invalid boolean: #{v}"
      end
    end.uniq
  end

  def parse_options(argv, fuzz_root: File.expand_path("..", __dir__))
    opts = {
      shapes: %w[prism_parse prism_diff_ruby],
      ijon_modes: %w[none on],
      grammar_modes: %w[none],
      cmplog: [false],
      sand: [false],
      schedules: %w[fast],
      duration: 60,
      trials: 1,
      parallel: 1,
      seed: 1337,
      max_input_size: 256,
      prism_ref: DEFAULT_PRISM_REF,
      prism_dir: nil,
      ruby_ref: default_ruby_ref(fuzz_root),
      ruby_dir: nil,
      corpus_dir: nil,
      workspace: File.join(fuzz_root, "tmp", "fuzzer-bench"),
      json_path: nil,
      compare_path: nil,
      valid_sample_limit: 0,
      dry_run: false,
      skip_build: false,
      quiet: false
    }

    OptionParser.new do |p|
      p.banner = "Usage: ruby #{File.basename($PROGRAM_NAME)} [options]"
      p.on("--shapes LIST", "Comma-separated shapes: #{VALID_SHAPES.join(',')} (default: #{opts[:shapes].join(',')})") do |v|
        opts[:shapes] = v.split(",").map(&:strip).reject(&:empty?).uniq
      end
      p.on("--ijon LIST", "Comma-separated IJON modes: #{VALID_IJON_MODES.join(',')} (default: #{opts[:ijon_modes].join(',')})") do |v|
        opts[:ijon_modes] = v.split(",").map(&:strip).reject(&:empty?).uniq
      end
      p.on("--grammar LIST", "Comma-separated grammar modes: #{VALID_GRAMMAR_MODES.join(',')} (default: none)") do |v|
        opts[:grammar_modes] = v.split(",").map(&:strip).reject(&:empty?).uniq
      end
      p.on("--cmplog LIST", "Comma-separated booleans for CmpLog (-c) on prism_parse (default: false)") do |v|
        opts[:cmplog] = parse_bool_list(v)
      end
      p.on("--sand LIST", "Comma-separated booleans for SAND (-w) on prism_parse (default: false)") do |v|
        opts[:sand] = parse_bool_list(v)
      end
      p.on("--schedules LIST", "Comma-separated AFL++ power schedules (-p) (default: fast)") do |v|
        opts[:schedules] = v.split(",").map(&:strip).reject(&:empty?).uniq
      end
      p.on("--duration SECONDS", Integer, "Wall-clock seconds per cell/trial (default: #{opts[:duration]})") { |v| opts[:duration] = v }
      p.on("--trials N", Integer, "Number of independent trials per cell (default: #{opts[:trials]})") { |v| opts[:trials] = v }
      p.on("--parallel K", Integer, "Max concurrent afl-fuzz processes (default: #{opts[:parallel]})") { |v| opts[:parallel] = v }
      p.on("--seed N", Integer, "Base deterministic AFL++ RNG seed (-s) (default: #{opts[:seed]})") { |v| opts[:seed] = v }
      p.on("--max-input-size N", Integer, "Max Ruby payload bytes (-G N+4) (default: #{opts[:max_input_size]})") { |v| opts[:max_input_size] = v }
      p.on("--prism-ref REF", String, "Prism git ref (default: #{opts[:prism_ref]})") { |v| opts[:prism_ref] = v }
      p.on("--prism-dir DIR", String, "Local Prism checkout directory (overrides --prism-ref)") { |v| opts[:prism_dir] = File.expand_path(v) }
      p.on("--ruby-ref REF", String, "CRuby git ref (default: #{opts[:ruby_ref]})") { |v| opts[:ruby_ref] = v }
      p.on("--ruby-dir DIR", String, "Local CRuby checkout directory (overrides --ruby-ref)") { |v| opts[:ruby_dir] = File.expand_path(v) }
      p.on("--corpus-dir DIR", String, "Explicit seed corpus directory (default: generated bench corpus)") { |v| opts[:corpus_dir] = File.expand_path(v) }
      p.on("--workspace DIR", String, "Benchmark workspace dir (default: #{opts[:workspace]})") { |v| opts[:workspace] = File.expand_path(v) }
      p.on("--json PATH", String, "Write structured JSON benchmark report") { |v| opts[:json_path] = File.expand_path(v) }
      p.on("--compare PATH", String, "Compare against a baseline JSON benchmark report") { |v| opts[:compare_path] = File.expand_path(v) }
      p.on("--valid-sample N", Integer, "Max queued seeds to sample for valid-syntax % (default: #{opts[:valid_sample_limit]})") { |v| opts[:valid_sample_limit] = v }
      p.on("--skip-build", "Skip target sync/build (reuse existing binaries in workspace)") { opts[:skip_build] = true }
      p.on("--dry-run", "Print matrix, topology binaries, and afl-fuzz commands without executing") { opts[:dry_run] = true }
      p.on("--quiet", "Suppress human-readable tables") { opts[:quiet] = true }
    end.parse!(argv)

    validate_options!(opts)
    opts
  end

  def validate_options!(opts)
    bad_shapes = opts[:shapes] - VALID_SHAPES
    raise ArgumentError, "Unknown shapes: #{bad_shapes.join(', ')}" unless bad_shapes.empty?
    bad_ijon = opts[:ijon_modes] - VALID_IJON_MODES
    raise ArgumentError, "Unknown IJON modes: #{bad_ijon.join(', ')}" unless bad_ijon.empty?
    bad_grammar = opts[:grammar_modes] - VALID_GRAMMAR_MODES
    raise ArgumentError, "Unknown grammar modes: #{bad_grammar.join(', ')}" unless bad_grammar.empty?
    bad_sched = opts[:schedules] - VALID_SCHEDULES
    raise ArgumentError, "Unknown schedules: #{bad_sched.join(', ')}" unless bad_sched.empty?
    raise ArgumentError, "--duration must be >= 1" unless opts[:duration] >= 1
    raise ArgumentError, "--trials must be >= 1" unless opts[:trials] >= 1
    raise ArgumentError, "--parallel must be >= 1" unless opts[:parallel] >= 1
  end

  def ijon_mode_slug(mode)
    mode.tr("+", "_")
  end

  def ijon_fuzzer_attrs(mode)
    case mode
    when "none"
      { "ijon" => false, "defines" => {} }
    when "on"
      { "ijon" => true, "defines" => {} }
    else
      raise ArgumentError, "Unsupported IJON mode: #{mode}"
    end
  end

  def expand_matrix(opts)
    cells = []
    opts[:shapes].each do |shape|
      cmplog_vals = shape == "prism_parse" ? opts[:cmplog] : [false]
      sand_vals   = shape == "prism_parse" ? opts[:sand] : [false]

      opts[:ijon_modes].each do |ijon_mode|
        opts[:grammar_modes].each do |grammar_mode|
          cmplog_vals.each do |cmplog|
            sand_vals.each do |sand|
              opts[:schedules].each do |schedule|
                slug_parts = [shape, "ijon_#{ijon_mode_slug(ijon_mode)}"]
                slug_parts << "gram_#{grammar_mode}" if opts[:grammar_modes].length > 1 || grammar_mode != "none"
                slug_parts << "cmplog" if cmplog
                slug_parts << "sand" if sand
                slug_parts << "sched_#{schedule}" if opts[:schedules].length > 1 || schedule != "fast"

                bin_name =
                  if ijon_mode == "none" && !sand
                    "bench_#{shape}_cfg"
                  else
                    name = "bench_#{shape}_ijon_#{ijon_mode_slug(ijon_mode)}"
                    sand ? "#{name}_fast" : name
                  end

                cells << {
                  "id" => slug_parts.join("__"),
                  "shape" => shape,
                  "ijon" => ijon_mode,
                  "grammar" => grammar_mode,
                  "cmplog" => cmplog,
                  "sand" => sand,
                  "schedule" => schedule,
                  "binary" => bin_name,
                  "cfg_binary" => "bench_#{shape}_cfg",
                  "cmplog_binary" => cmplog ? "bench_prism_parse_cmplog" : nil,
                  "sand_binary" => sand ? "bench_prism_parse_sand" : nil
                }
              end
            end
          end
        end
      end
    end
    cells
  end

  def build_topology_ir(opts, cells)
    build_dir = File.join(opts[:workspace], "build")
    fuzzers = {}

    # Always build shared CFG oracle binaries for apples-to-apples afl-showmap comparison.
    opts[:shapes].each do |shape|
      cfg_bin = "bench_#{shape}_cfg"
      fuzzers[cfg_bin] = base_fuzzer_spec(shape, ijon: "none", sanitizers_override: shape == "prism_parse" ? %w[asan ubsan] : [])
    end

    if cells.any? { |c| c["cmplog"] }
      fuzzers["bench_prism_parse_cmplog"] = {
        "shape" => "prism_parse",
        "source" => "prism_a",
        "sanitizers" => [],
        "mode" => "fast",
        "afl" => "cmplog"
      }
    end

    if cells.any? { |c| c["sand"] }
      fuzzers["bench_prism_parse_sand"] = {
        "shape" => "prism_parse",
        "source" => "prism_a",
        "sanitizers" => %w[asan ubsan],
        "mode" => "fast",
        "afl" => "sand"
      }
    end

    cells.each do |cell|
      next if fuzzers.key?(cell["binary"])
      sans =
        if cell["shape"] == "prism_parse"
          cell["sand"] ? [] : %w[asan ubsan]
        else
          []
        end
      fuzzers[cell["binary"]] = base_fuzzer_spec(cell["shape"], ijon: cell["ijon"], sanitizers_override: sans)
    end

    prism_spec =
      if opts[:prism_dir]
        {
          "kind" => "prism",
          "dir" => opts[:prism_dir],
          "patches" => "none",
          "templates" => "auto"
        }
      else
        {
          "kind" => "prism",
          "repo" => "https://github.com/ruby/prism.git",
          "ref" => opts[:prism_ref],
          "patches" => "auto",
          "templates" => "auto"
        }
      end

    sources = { "prism_a" => prism_spec }

    needs_ruby = opts[:shapes].any? { |s| %w[prism_diff_ruby cruby_compile cruby_pipeline_diff].include?(s) }
    if needs_ruby
      sources["ruby"] =
        if opts[:ruby_dir]
          { "kind" => "ruby", "dir" => opts[:ruby_dir] }
        else
          { "kind" => "ruby", "repo" => "https://github.com/ruby/ruby.git", "ref" => opts[:ruby_ref] }
        end
    end

    {
      "schema_version" => 2,
      "name" => "fuzzer-bench",
      "workspace" => {
        "dir" => opts[:workspace],
        "build_dir" => build_dir
      },
      "defaults" => {
        "max_input_size" => opts[:max_input_size],
        "max_allocated_mb" => 128
      },
      "sources" => sources,
      "fuzzers" => fuzzers,
      "sync_groups" => {
        "bench" => { "dir" => "afl", "primary" => true }
      },
      "workers" => []
    }
  end

  def base_fuzzer_spec(shape, ijon:, sanitizers_override: [])
    ijon_attrs = ijon_fuzzer_attrs(ijon)
    spec =
      case shape
      when "prism_parse"
        {
          "shape" => "prism_parse",
          "source" => "prism_a",
          "sanitizers" => sanitizers_override,
          "mode" => "fast",
          "afl" => "lto"
        }
      when "prism_diff_ruby"
        {
          "shape" => "prism_diff_ruby",
          "prism" => "prism_a",
          "ruby" => "ruby",
          "sanitizers" => [],
          "afl" => "pcguard"
        }
      when "cruby_compile"
        {
          "shape" => "cruby_compile",
          "ruby" => "ruby",
          "prism" => "prism_a",
          "sanitizers" => [],
          "afl" => "pcguard"
        }
      when "cruby_pipeline_diff"
        {
          "shape" => "cruby_pipeline_diff",
          "ruby" => "ruby",
          "prism" => "prism_a",
          "sanitizers" => [],
          "afl" => "pcguard"
        }
      else
        raise ArgumentError, "Unsupported shape: #{shape}"
      end

    spec["ijon"] = ijon_attrs["ijon"] if ijon_attrs["ijon"]
    spec["defines"] = ijon_attrs["defines"] unless ijon_attrs["defines"].empty?
    spec
  end

  def prepare_corpus!(opts, shape: nil)
    return opts[:corpus_dir] if opts[:corpus_dir] && Dir.exist?(opts[:corpus_dir])

    one_byte = %w[cruby_compile cruby_pipeline_diff].include?(shape)
    corpus_dir = File.join(opts[:workspace], one_byte ? "corpus-compile" : "corpus")
    header = one_byte ? "\x00".b : FUZZ_HEADER_DEFAULT
    FileUtils.mkdir_p(corpus_dir)
    if Dir.children(corpus_dir).empty?
      BUILTIN_SEEDS.each_with_index do |src, idx|
        File.binwrite(File.join(corpus_dir, format("seed_%03d.bin", idx)), header + src.b)
      end
    end
    corpus_dir
  end

  def build_grammar_mutator!(opts, fuzz_root:)
    build_dir = File.join(opts[:workspace], "build")
    so_out = File.join(build_dir, "libgrammarmutator-ruby.so")
    gen_out = File.join(build_dir, "grammar_generator-ruby")
    return [so_out, gen_out] if File.file?(so_out) && File.executable?(gen_out)

    gm_src = "/AFLplusplus/Grammar-Mutator"
    abort "fuzzer_bench: #{gm_src} not found (rebuild Docker image)" unless Dir.exist?(gm_src)

    grammar_json = File.join(fuzz_root, "grammar", "ruby.json")
    patch_file   = File.join(fuzz_root, "patches", "grammar-mutator", "grammar-mutator.patch")
    abort "fuzzer_bench: missing #{grammar_json}" unless File.file?(grammar_json)
    abort "fuzzer_bench: missing #{patch_file}" unless File.file?(patch_file)

    gm_work = File.join(opts[:workspace], "build", "grammar-mutator-src")
    FileUtils.rm_rf(gm_work)
    FileUtils.mkdir_p(File.dirname(gm_work))
    FileUtils.cp_r(gm_src, gm_work)

    ok = system("git", "-C", gm_work, "apply", patch_file) &&
         system("python3", File.join(gm_work, "grammars", "f1_c_gen.py"), grammar_json, gm_work) &&
         system("make", "-C", File.join(gm_work, "third_party", "rxi_map")) &&
         system("make", "-C", File.join(gm_work, "third_party", "Cyan4973_xxHash")) &&
         system("make", "-C", File.join(gm_work, "src"), "GRAMMAR_FILENAME=ruby", "NO_ANTLR=1")
    abort "fuzzer_bench: failed to build Grammar-Mutator" unless ok

    FileUtils.cp(File.join(gm_work, "src", "libgrammarmutator-ruby.so"), so_out)
    FileUtils.cp(File.join(gm_work, "src", "grammar_generator-ruby"), gen_out)
    FileUtils.chmod(0o755, gen_out)
    [so_out, gen_out]
  end

  def build_prism_mutator!(opts, fuzz_root:)
    build_dir = File.join(opts[:workspace], "build")
    so_out = File.join(build_dir, "libprismmutator.so")
    mut_src = File.join(fuzz_root, "harnesses", "prism", "prism_mutator.c")
    abort "fuzzer_bench: missing #{mut_src}" unless File.file?(mut_src)
    return so_out if File.file?(so_out) && File.mtime(so_out) >= File.mtime(mut_src)

    prism_dir = opts[:prism_dir] || File.join(build_dir, "targets", "prism_a")
    abort "fuzzer_bench: missing prism checkout at #{prism_dir}" unless Dir.exist?(prism_dir)

    pm_work = File.join(build_dir, "prism-mutator-src")
    FileUtils.rm_rf(pm_work)
    FileUtils.mkdir_p(File.dirname(pm_work))
    FileUtils.cp_r(prism_dir, pm_work)

    nproc = begin
      Etc.nprocessors
    rescue StandardError
      4
    end
    ok = system("ruby", "-I#{File.join(pm_work, 'lib')}", File.join(pm_work, "templates", "template.rb"), chdir: pm_work) &&
         system("make", "-C", pm_work, "-j#{nproc}", "build/libprism.a", "CC=clang",
                "CFLAGS=-O2 -fPIC -std=c99 -Iinclude -DPRISM_EXPORT_SYMBOLS") &&
         system("clang", "-O2", "-fPIC", "-shared", "-Wall", "-Wextra", "-Werror",
                "-I#{File.join(pm_work, 'include')}",
                mut_src, File.join(pm_work, "build", "libprism.a"),
                "-o", so_out)
    abort "fuzzer_bench: failed to build libprismmutator.so" unless ok
    so_out
  end

  def afl_command_for(cell, opts:, corpus_dir:, out_dir:, trial:, foreign_dir: nil, tree_dir: nil)
    build_dir = File.join(opts[:workspace], "build")
    target_bin = File.join(build_dir, cell["binary"])
    max_len = opts[:max_input_size] + 4

    env = {
      "AFL_NO_UI" => "1",
      "AFL_SKIP_CPUFREQ" => "1",
      "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES" => "1",
      "AFL_AUTORESUME" => "0",
      "AFL_EXIT_ON_TIME" => opts[:duration].to_s,
      "AFL_NO_AFFINITY" => "1"
    }

    if %w[mutator mutator_mixed].include?(cell["grammar"])
      env["AFL_CUSTOM_MUTATOR_LIBRARY"] = File.join(build_dir, "libgrammarmutator-ruby.so")
      env["AFL_CUSTOM_MUTATOR_ONLY"] = "1" if cell["grammar"] == "mutator"
      env["GRAMMAR_MUTATOR_TREE_DIR"] = tree_dir if tree_dir
    elsif %w[prism prism_mixed].include?(cell["grammar"])
      env["AFL_CUSTOM_MUTATOR_LIBRARY"] = File.join(build_dir, "libprismmutator.so")
      env["AFL_CUSTOM_MUTATOR_ONLY"] = "1" if cell["grammar"] == "prism"
      env["PRISM_MUTATOR_HEADER_BYTES"] = %w[cruby_compile cruby_pipeline_diff].include?(cell["shape"]) ? "1" : "4"
    end

    cmd = [
      "afl-fuzz",
      "-i", corpus_dir,
      "-o", out_dir,
      "-V", opts[:duration].to_s,
      "-p", cell["schedule"],
      "-G", max_len.to_s,
      "-s", (opts[:seed] + trial).to_s,
      "-t", "1000+"
    ]
    cmd.push("-M", "default", "-F", foreign_dir) if foreign_dir
    cmd.push("-c", File.join(build_dir, cell["cmplog_binary"])) if cell["cmplog_binary"]
    cmd.push("-w", File.join(build_dir, cell["sand_binary"])) if cell["sand_binary"]
    cmd.push("--", target_bin, "@@")
    [env, cmd]
  end

  def parse_fuzzer_stats(stats_path)
    return {} unless File.file?(stats_path)

    stats = {}
    File.readlines(stats_path, chomp: true).each do |line|
      key, val = line.split(":", 2)
      next unless key && val
      stats[key.strip] = val.strip
    end
    stats
  end

  def measure_cfg_edges(cfg_bin, queue_dir, tmp_dir)
    return nil unless File.executable?(cfg_bin) && Dir.exist?(queue_dir)
    return 0 if Dir.glob(File.join(queue_dir, "id:*")).empty?

    out_map = File.join(tmp_dir, "showmap.out")
    _, _, st = Open3.capture3(
      { "AFL_QUIET" => "1" },
      "afl-showmap", "-q", "-C", "-i", queue_dir, "-o", out_map, "-t", "1000", "--", cfg_bin, "@@"
    )
    return nil unless st.success? && File.file?(out_map)

    File.readlines(out_map).length
  end

  def classify_crashes(oracle_bin, crashes_dir)
    return { "total" => 0, "unique" => 0, "first_crash_ms" => nil, "signatures" => [] } unless Dir.exist?(crashes_dir)

    files = Dir.glob(File.join(crashes_dir, "id:*")).sort
    return { "total" => 0, "unique" => 0, "first_crash_ms" => nil, "signatures" => [] } if files.empty?

    first_ms = files.filter_map { |f| File.basename(f)[/time:(\d+)/, 1]&.to_i }.min
    sigs = {}

    files.each do |f|
      sig = "unknown"
      if File.executable?(oracle_bin)
        out, err, st = Open3.capture3(oracle_bin, f)
        combined = (out + err).b
        if (m = combined.match(/INVARIANT\[[^\]]+\]:[^\n\[]+/))
          sig = m[0].strip
        elsif (m = combined.match(/Assertion `[^']+' failed/))
          sig = m[0]
        elsif (m = combined.match(/ERROR: AddressSanitizer: ([^\n]+)/))
          sig = "ASan: #{m[1].strip}"
        elsif st.signaled?
          sig = "SIG#{st.termsig}"
        elsif st.exitstatus != 0
          sig = "EXIT#{st.exitstatus}"
        else
          sig = "no_repro"
        end
      end
      sigs[sig] = (sigs[sig] || 0) + 1
    end

    {
      "total" => files.length,
      "unique" => sigs.keys.reject { |s| s == "no_repro" }.length,
      "first_crash_ms" => first_ms,
      "signatures" => sigs.keys.sort
    }
  end

  def measure_queue_ast_stats(queue_dir, limit: nil)
    empty = { "valid_syntax_pct" => nil, "ast_2paths" => nil, "valid_2paths" => nil }
    return empty unless Dir.exist?(queue_dir) && defined?(Ruby::Prism)

    files = Dir.glob(File.join(queue_dir, "id:*")).sort
    return empty if files.empty?

    step = (limit && limit > 0 && files.length > limit) ? (files.length.to_f / limit) : 1.0
    sampled = 0
    valid = 0
    edges = Set.new
    valid_edges = Set.new

    idx = 0.0
    while idx < files.length && (limit.nil? || limit <= 0 || sampled < limit)
      raw = File.binread(files[idx.to_i])
      body = raw.bytesize > 4 ? raw.byteslice(4..-1) : "".b
      res = Ruby::Prism.parse(body)
      ok = res.success?
      valid += 1 if ok
      sampled += 1

      stack = [[nil, res.value]]
      visited = 0
      while (pair = stack.pop) && visited < 512
        parent, node = pair
        next unless node
        visited += 1
        edge = [parent, node.type]
        edges << edge
        valid_edges << edge if ok
        node.compact_child_nodes.each { |child| stack << [node.type, child] }
      end

      idx += step
    end

    {
      "valid_syntax_pct" => sampled > 0 ? ((valid * 100.0) / sampled).round(1) : nil,
      "ast_2paths" => edges.size,
      "valid_2paths" => valid_edges.size
    }
  end

  def median(values)
    nums = values.compact.sort
    return nil if nums.empty?

    mid = nums.length / 2
    nums.length.odd? ? nums[mid] : ((nums[mid - 1] + nums[mid]) / 2.0)
  end

  def aggregate_cell(cell, trial_results)
    {
      "id" => cell["id"],
      "shape" => cell["shape"],
      "ijon" => cell["ijon"],
      "grammar" => cell["grammar"] || "none",
      "cmplog" => cell["cmplog"],
      "sand" => cell["sand"],
      "schedule" => cell["schedule"],
      "trials" => trial_results.length,
      "median_execs_per_sec" => median(trial_results.map { |t| t["execs_per_sec"] })&.round(1),
      "median_execs_done" => median(trial_results.map { |t| t["execs_done"] })&.round(0)&.to_i,
      "median_corpus_count" => median(trial_results.map { |t| t["corpus_count"] })&.round(0)&.to_i,
      "median_cfg_edges" => median(trial_results.map { |t| t["cfg_edges"] })&.round(0)&.to_i,
      "median_ast_2paths" => median(trial_results.map { |t| t["ast_2paths"] })&.round(0)&.to_i,
      "median_valid_2paths" => median(trial_results.map { |t| t["valid_2paths"] })&.round(0)&.to_i,
      "median_valid_syntax_pct" => median(trial_results.map { |t| t["valid_syntax_pct"] })&.round(1),
      "total_crashes" => trial_results.sum { |t| t.dig("crashes", "total").to_i },
      "median_unique_crashes" => median(trial_results.map { |t| t.dig("crashes", "unique") })&.round(1),
      "min_first_crash_ms" => trial_results.filter_map { |t| t.dig("crashes", "first_crash_ms") }.min,
      "all_signatures" => trial_results.flat_map { |t| t.dig("crashes", "signatures") || [] }.uniq.sort,
      "per_trial" => trial_results
    }
  end

  def run_trial(cell, opts:, corpus_dir:, trial:, fuzz_root:)
    out_dir = File.join(opts[:workspace], "runs", cell["id"], "trial_#{trial}")
    FileUtils.rm_rf(out_dir)
    FileUtils.mkdir_p(out_dir)

    build_dir = File.join(opts[:workspace], "build")
    eff_corpus = corpus_dir
    foreign_dir = nil
    tree_dir = nil
    lrama_pid = nil

    if %w[mutator mutator_mixed].include?(cell["grammar"])
      eff_corpus = File.join("/tmp/fbench-gm", "#{cell['id']}_t#{trial}", "seeds")
      tree_dir   = File.join("/tmp/fbench-gm", "#{cell['id']}_t#{trial}", "trees")
      FileUtils.rm_rf(File.dirname(eff_corpus))
      FileUtils.mkdir_p(eff_corpus)
      FileUtils.mkdir_p(tree_dir)
      gen_bin = File.join(build_dir, "grammar_generator-ruby")
      ok = system(gen_bin, "200", opts[:max_input_size].to_s, eff_corpus, tree_dir, out: File::NULL, err: File::NULL)
      abort "fuzzer_bench: grammar_generator-ruby failed" unless ok
    elsif cell["grammar"] == "lrama"
      foreign_dir = File.join("/tmp/fbench-lrama", "#{cell['id']}_t#{trial}", "seeds")
      FileUtils.rm_rf(File.dirname(foreign_dir))
      FileUtils.mkdir_p(foreign_dir)
      lrama_script = File.join(fuzz_root, "runtime", "grammar.rb")
      lrama_env = {
        "FUZZ_MAX_INPUT_SIZE" => opts[:max_input_size].to_s,
        "AFL_SYNC_TIME" => "1"
      }
      lrama_pid = Process.spawn(lrama_env, "ruby", lrama_script, out_dir, foreign_dir, out: File::NULL, err: File::NULL)
      # Wait briefly for initial lrama seeds so -F has inputs early.
      sleep 1
    end

    env, cmd = afl_command_for(
      cell,
      opts: opts,
      corpus_dir: eff_corpus,
      out_dir: out_dir,
      trial: trial,
      foreign_dir: foreign_dir,
      tree_dir: tree_dir
    )
    log_path = File.join(out_dir, "afl.log")

    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    begin
      # Hard safety timeout = duration + 30s in case afl-fuzz takes a moment to flush.
      _, _, _st = Open3.capture3(env, "timeout", "--signal=INT", (opts[:duration] + 30).to_s, *cmd, stdin_data: "")
    ensure
      if lrama_pid
        begin
          Process.kill("TERM", lrama_pid)
        rescue SystemCallError
          nil
        end
        begin
          Process.wait(lrama_pid)
        rescue SystemCallError
          nil
        end
      end
    end
    elapsed = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).round(2)

    default_dir = File.join(out_dir, "default")
    stats = parse_fuzzer_stats(File.join(default_dir, "fuzzer_stats"))
    cfg_bin = File.join(build_dir, cell["cfg_binary"])

    cfg_edges = Dir.mktmpdir("fbench-map-") do |tmp_dir|
      measure_cfg_edges(cfg_bin, File.join(default_dir, "queue"), tmp_dir)
    end
    crashes = classify_crashes(cfg_bin, File.join(default_dir, "crashes"))
    ast_stats = measure_queue_ast_stats(File.join(default_dir, "queue"), limit: opts[:valid_sample_limit])

    {
      "trial" => trial,
      "elapsed_sec" => elapsed,
      "execs_done" => stats["execs_done"]&.to_i,
      "execs_per_sec" => stats["execs_per_sec"]&.to_f,
      "corpus_count" => stats["corpus_count"]&.to_i,
      "corpus_favored" => stats["corpus_favored"]&.to_i,
      "pending_favs" => stats["pending_favs"]&.to_i,
      "bitmap_cvg" => stats["bitmap_cvg"],
      "cfg_edges" => cfg_edges,
      "ast_2paths" => ast_stats["ast_2paths"],
      "valid_2paths" => ast_stats["valid_2paths"],
      "valid_syntax_pct" => ast_stats["valid_syntax_pct"],
      "crashes" => crashes,
      "log" => log_path
    }
  end

  def print_summary_table(results, compare: nil)
    baseline_by_id = {}
    if compare && compare["cells"].is_a?(Array)
      compare["cells"].each { |c| baseline_by_id[c["id"]] = c }
    end

    puts ""
    puts format(
      "%-36s | %-5s | %-13s | %-4s | %8s | %6s | %9s | %6s | %6s | %6s | %7s | %4s | %8s",
      "Cell", "IJON", "Grammar", "SAND", "Exec/s", "Queue", "CFG Edges", "2Paths", "Val2P", "Valid%", "Crashes", "Uniq", "1st(s)"
    )
    puts "-" * 149
    results.each do |r|
      first_s = r["min_first_crash_ms"] ? format("%.1f", r["min_first_crash_ms"] / 1000.0) : "-"
      edges_s = r["median_cfg_edges"] ? r["median_cfg_edges"].to_s : "-"
      if (base = baseline_by_id[r["id"]]) && base["median_cfg_edges"] && r["median_cfg_edges"]
        delta = r["median_cfg_edges"] - base["median_cfg_edges"]
        edges_s = "#{edges_s} (#{delta >= 0 ? "+#{delta}" : delta})"
      end
      puts format(
        "%-36s | %-5s | %-13s | %-4s | %8s | %6s | %9s | %6s | %6s | %6s | %7d | %4s | %8s",
        r["id"][0, 36],
        r["ijon"],
        r["grammar"] || "none",
        r["sand"] ? "yes" : "no",
        r["median_execs_per_sec"] ? format("%.1f", r["median_execs_per_sec"]) : "-",
        r["median_corpus_count"] || "-",
        edges_s,
        r["median_ast_2paths"] || "-",
        r["median_valid_2paths"] || "-",
        r["median_valid_syntax_pct"] ? format("%.1f%%", r["median_valid_syntax_pct"]) : "-",
        r["total_crashes"],
        r["median_unique_crashes"] || "-",
        first_s
      )
    end
    puts ""
  end

  def run(argv = ARGV, fuzz_root: File.expand_path("..", __dir__))
    opts = parse_options(argv, fuzz_root: fuzz_root)
    cells = expand_matrix(opts)
    topo = build_topology_ir(opts, cells)

    if opts[:dry_run]
      puts "Fuzzer feature matrix (#{cells.length} cells x #{opts[:trials]} trial(s), #{opts[:duration]}s each):"
      cells.each do |cell|
        env, cmd = afl_command_for(
          cell,
          opts: opts,
          corpus_dir: opts[:corpus_dir] || File.join(opts[:workspace], "corpus"),
          out_dir: File.join(opts[:workspace], "runs", cell["id"], "trial_1"),
          trial: 1
        )
        puts "  #{cell['id']}: #{cmd.map { |t| Shellwords.escape(t) }.join(' ')} (AFL_EXIT_ON_TIME=#{env['AFL_EXIT_ON_TIME']})"
      end
      puts "Binaries to build (#{topo['fuzzers'].length}): #{topo['fuzzers'].keys.sort.join(', ')}"
      return 0
    end

    FileUtils.mkdir_p(opts[:workspace])
    topo_path = File.join(opts[:workspace], "bench-topology.json")
    File.write(topo_path, JSON.pretty_generate(topo) + "\n")

    unless opts[:skip_build]
      campaign_bin = File.join(fuzz_root, "bin", "campaign.rb")
      ok_afl = system("ruby", campaign_bin, "ensure-afl-passes")
      abort "fuzzer_bench: ensure-afl-passes failed" unless ok_afl

      topo_bin = File.join(fuzz_root, "bin", "topology.rb")
      %w[sync build].each do |sub|
        ok = system("ruby", topo_bin, sub, "--topology", topo_path)
        abort "fuzzer_bench: topology #{sub} failed" unless ok
      end

      if cells.any? { |c| %w[mutator mutator_mixed].include?(c["grammar"]) }
        build_grammar_mutator!(opts, fuzz_root: fuzz_root)
      end

      if cells.any? { |c| %w[prism prism_mixed].include?(c["grammar"]) }
        build_prism_mutator!(opts, fuzz_root: fuzz_root)
      end
    end

    corpus_by_shape = opts[:shapes].each_with_object({}) { |s, h| h[s] = prepare_corpus!(opts, shape: s) }

    jobs = []
    cells.each do |cell|
      (1..opts[:trials]).each { |t| jobs << [cell, t] }
    end

    per_cell = Hash.new { |h, k| h[k] = [] }
    mutex = Mutex.new
    queue = Queue.new
    jobs.each { |j| queue << j }

    workers = [opts[:parallel], jobs.length].min.times.map do
      Thread.new do
        loop do
          job = begin
            queue.pop(true)
          rescue ThreadError
            break
          end
          cell, trial = job
          warn "[fuzzer-bench] starting #{cell['id']} trial #{trial}/#{opts[:trials]} (#{opts[:duration]}s)..." unless opts[:quiet]
          res = run_trial(cell, opts: opts, corpus_dir: corpus_by_shape.fetch(cell["shape"]), trial: trial, fuzz_root: fuzz_root)
          mutex.synchronize { per_cell[cell["id"]] << res }
          warn "[fuzzer-bench] finished #{cell['id']} trial #{trial}: exec/s=#{res['execs_per_sec']} edges=#{res['cfg_edges']} crashes=#{res.dig('crashes', 'total')}" unless opts[:quiet]
        end
      end
    end
    workers.each(&:join)

    aggregated = cells.map { |cell| aggregate_cell(cell, per_cell[cell["id"]].sort_by { |r| r["trial"] }) }
    report = {
      "schema_version" => 1,
      "generated_at" => Time.now.utc.iso8601,
      "config" => {
        "shapes" => opts[:shapes],
        "ijon_modes" => opts[:ijon_modes],
        "grammar_modes" => opts[:grammar_modes],
        "cmplog" => opts[:cmplog],
        "sand" => opts[:sand],
        "schedules" => opts[:schedules],
        "duration" => opts[:duration],
        "trials" => opts[:trials],
        "max_input_size" => opts[:max_input_size],
        "prism_ref" => opts[:prism_ref],
        "ruby_ref" => opts[:ruby_ref]
      },
      "cells" => aggregated
    }

    if opts[:json_path]
      FileUtils.mkdir_p(File.dirname(opts[:json_path]))
      File.write(opts[:json_path], JSON.pretty_generate(report) + "\n")
    end

    compare = opts[:compare_path] && File.file?(opts[:compare_path]) ? JSON.parse(File.read(opts[:compare_path])) : nil
    print_summary_table(aggregated, compare: compare) unless opts[:quiet]
    0
  end
end

if __FILE__ == $PROGRAM_NAME
  require "time"
  exit(FuzzerBench.run(ARGV))
end
