#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "json"
require "open3"
require "optparse"
require "rbconfig"
require "tmpdir"
require "yaml"

module PrismFuzzer
  module Lint
    REPO_ROOT = File.expand_path("..", __dir__)

    CONFIG_YAML_FILES = [
      ".rubocop.yml",
      ".clang-format",
      ".github/workflows/ci.yml"
    ].freeze

    CONFIG_JSON_FILES = [
      "topology.schema.json"
    ].freeze

    RUBOCOP_COPS = [
      "Security/YAMLLoad",
      "Security/Eval",
      "Style/TopLevelMethodDefinition",
      "Lint/RescueException",
      "Style/RescueModifier",
      "Layout/TrailingEmptyLines",
      "Layout/EndOfLine",
      "Style/GlobalVars"
    ].freeze

    TOP_LEVEL_DEF_EXCLUDES = [
      "campaigns/",
      "examples/",
      "patches/",
      "test/"
    ].freeze

    RUBOCOP_EXCLUDES = [
      "tmp/",
      "build/",
      "reports/",
      "patches/"
    ].freeze

    CFLAGS_GUARD_PREFIXES = [
      "runtime/",
      "harnesses/",
      "oss-fuzz/",
      "Makefile"
    ].freeze

    CFLAGS_GUARD_ALLOWLIST = [
      "harnesses/prism/gen_api_compat.rb"
    ].freeze

    CLEAN_REQUIRE_LIBS = %w[
      lib/prism_fuzzer
      lib/ruby_fuzz
      runtime/common
      runtime/fuzz_header
      runtime/provenance
      runtime/corpus
      runtime/status
      triage/triage
      triage/bisect
      triage/cluster
      triage/explain
      triage/inspect
      triage/match
      triage/retriage
      triage/verify
      harnesses/prism/gen_diff_ids
      harnesses/prism/gen_node_locations
      harnesses/prism/gen_api_compat
      harnesses/prism/gen_serialize_walk
      report/report
      report/sankey
      bin/lint
      bin/publish
    ].freeze

    FORBIDDEN_TOP_CONSTS = %w[
      PRISM_LOUPE_BASE_URL
      STATUS_TOPOLOGY
      DEFAULT_HEADER
      PrismComposer
    ].freeze

    ALLOWED_GLOBAL_VARS = %i[
      $PROGRAM_NAME $0 $: $LOAD_PATH $" $LOADED_FEATURES
      $! $@ $? $$ $~ $& $` $' $+
      $1 $2 $3 $4 $5 $6 $7 $8 $9
      $stdin $stdout $stderr $/ $\\ $, $; $. $_ $*
      $VERBOSE $DEBUG $SAFE
      $-0 $-F $-I $-K $-W $-a $-d $-i $-l $-p $-v $-w
    ].each_with_object({}) { |sym, acc| acc[sym] = true }.freeze

    UNSAFE_YAML_RE = /\bYAML\.(?:load|load_file)\b/
    SUPPRESSED_CFLAG_RE = /-Wno-(?:implicit-function-declaration|shorten-64-to-32)/

    module_function

    def run_cli(argv)
      augment_path!
      options = parse_options(argv)

      files = options[:staged] ? staged_files : tracked_files
      if files.empty?
        puts "lint: no files to check" unless options[:quiet]
        return 0
      end

      errors = []
      with_materialized_blobs(files, staged: options[:staged]) do |disk_map|
        check_eof_and_line_endings(files, disk_map, errors)
        check_ruby_syntax_and_configs(files, disk_map, options, errors)
        check_shellcheck(files, disk_map, options, errors)
        check_coding_standards(files, disk_map, errors)
        check_rubocop_or_ast(files, disk_map, options, errors)
        check_topologies_and_requires(files, disk_map, options, errors)
      end

      if errors.empty?
        scope = options[:staged] ? "#{files.size} staged file(s)" : "#{files.size} tracked file(s)"
        puts "lint: ok (#{scope})" unless options[:quiet]
        0
      else
        warn "lint: FAILED (#{errors.size} check group(s)):"
        errors.each do |err|
          warn ""
          warn err
        end
        1
      end
    end

    def augment_path!
      extra_dirs = ["/opt/homebrew/bin", "/usr/local/bin", RbConfig::CONFIG["bindir"]].compact
      current = ENV.fetch("PATH", "").split(File::PATH_SEPARATOR)
      prepend = extra_dirs.select { |dir| File.directory?(dir) && !current.include?(dir) }
      ENV["PATH"] = (prepend + current).join(File::PATH_SEPARATOR) unless prepend.empty?
    end

    def parse_options(argv)
      options = {
        staged: false,
        require_shellcheck: false,
        require_rubocop: false,
        quiet: false
      }

      parser = OptionParser.new do |opts|
        opts.banner = "Usage: bin/lint.rb [--staged] [--require-shellcheck] [--require-rubocop] [--quiet]"
        opts.on("--staged", "Lint only staged Git index files (for pre-commit hooks)") { options[:staged] = true }
        opts.on("--all", "Lint all git-tracked files (default)") { options[:staged] = false }
        opts.on("--require-shellcheck", "Require shellcheck even if no shell scripts are in scope") do
          options[:require_shellcheck] = true
        end
        opts.on("--require-rubocop", "Require the rubocop gem binary (used in CI)") do
          options[:require_rubocop] = true
        end
        opts.on("-q", "--quiet", "Suppress success output") { options[:quiet] = true }
      end
      parser.parse!(argv)
      options
    end

    def tracked_files
      out, err, status = Open3.capture3("git", "-C", REPO_ROOT, "ls-files", "-z")
      raise "git ls-files failed: #{err}" unless status.success?

      out.split("\0").reject(&:empty?)
    end

    def staged_files
      out, err, status = Open3.capture3(
        "git", "-C", REPO_ROOT, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"
      )
      raise "git diff --cached failed: #{err}" unless status.success?

      out.split("\0").reject(&:empty?)
    end

    def partially_staged_files(files)
      return [] if files.empty?

      out, _err, status = Open3.capture3("git", "-C", REPO_ROOT, "diff", "--name-only", "-z", "--", *files)
      return files unless status.success?

      out.split("\0").reject(&:empty?)
    end

    # Maps each repo-relative path to an absolute filesystem path holding the exact
    # content under test. In --staged mode, any file that also has unstaged working-tree
    # edits is materialized from the Git index (`:path`) into a temporary directory so
    # linters inspect what will actually be committed rather than unstaged hunks.
    def with_materialized_blobs(files, staged:)
      dirty = staged ? partially_staged_files(files) : []
      if dirty.empty?
        disk_map = files.each_with_object({}) do |rel, acc|
          abs = File.join(REPO_ROOT, rel)
          acc[rel] = abs if File.file?(abs) && !File.symlink?(abs)
        end
        return yield(disk_map)
      end

      dirty_set = dirty.each_with_object({}) { |rel, acc| acc[rel] = true }
      Dir.mktmpdir("prism-fuzzer-lint-") do |tmpdir|
        disk_map = {}
        files.each do |rel|
          if dirty_set[rel]
            blob, _err, status = Open3.capture3("git", "-C", REPO_ROOT, "show", ":#{rel}", binmode: true)
            next unless status.success?

            dest = File.join(tmpdir, rel)
            FileUtils.mkdir_p(File.dirname(dest))
            File.binwrite(dest, blob)
            disk_map[rel] = dest
          else
            abs = File.join(REPO_ROOT, rel)
            disk_map[rel] = abs if File.file?(abs) && !File.symlink?(abs)
          end
        end
        yield(disk_map)
      end
    end

    def normalize_output_paths(text, disk_map)
      out = text.dup
      disk_map.each do |rel, abs|
        repo_abs = File.join(REPO_ROOT, rel)
        out.gsub!(abs, rel) if abs != repo_abs
        out.gsub!(repo_abs, rel)
      end
      out
    end

    def check_eof_and_line_endings(files, disk_map, errors)
      offenses = []
      files.each do |rel|
        abs = disk_map[rel]
        next unless abs && File.file?(abs)

        data = File.binread(abs)
        next if data.empty? || data.include?("\x00")

        offenses << "#{rel}: missing trailing newline" unless data.end_with?("\n")
        offenses << "#{rel}: contains CRLF" if data.include?("\r\n") && !rel.end_with?(".patch")
      end
      errors << "[EOF / line endings]\n#{offenses.join("\n")}" unless offenses.empty?
    end

    def check_ruby_syntax_and_configs(files, disk_map, options, errors)
      rb_files = files.select { |rel| rel.end_with?(".rb") && disk_map.key?(rel) }
      offenses = []

      rb_files.each do |rel|
        _out, err, status = Open3.capture3(RbConfig.ruby, "-c", disk_map[rel])
        offenses << normalize_output_paths(err.strip, disk_map) unless status.success?
      end

      json_targets = options[:staged] ? (files & CONFIG_JSON_FILES) : CONFIG_JSON_FILES
      json_targets.each do |rel|
        abs = disk_map[rel] || File.join(REPO_ROOT, rel)
        next unless File.file?(abs)

        begin
          JSON.parse(File.read(abs, encoding: "UTF-8"))
        rescue StandardError => e
          offenses << "#{rel}: invalid JSON (#{e.message})"
        end
      end

      yaml_targets = options[:staged] ? (files & CONFIG_YAML_FILES) : CONFIG_YAML_FILES
      yaml_targets.each do |rel|
        abs = disk_map[rel] || File.join(REPO_ROOT, rel)
        next unless File.file?(abs)

        begin
          YAML.safe_load_file(abs)
        rescue StandardError => e
          offenses << "#{rel}: invalid YAML (#{e.message})"
        end
      end

      errors << "[Ruby syntax & JSON/YAML config validity]\n#{offenses.join("\n")}" unless offenses.empty?
    end

    def shell_script?(rel)
      rel.end_with?(".sh") || rel.start_with?(".githooks/")
    end

    def find_executable(name)
      ENV.fetch("PATH", "").split(File::PATH_SEPARATOR).each do |dir|
        next if dir.empty?

        candidate = File.join(dir, name)
        return candidate if File.file?(candidate) && File.executable?(candidate)
      end
      nil
    end

    def check_shellcheck(files, disk_map, options, errors)
      sh_files = files.select { |rel| shell_script?(rel) && disk_map.key?(rel) }
      return if sh_files.empty? && !options[:require_shellcheck]

      shellcheck_bin = find_executable("shellcheck")
      unless shellcheck_bin
        errors << "[ShellCheck]\nshellcheck executable not found in PATH " \
                  "(install via `brew install shellcheck` or `apt-get install shellcheck`)"
        return
      end
      return if sh_files.empty?

      args = ["-S", "warning", *sh_files.map { |rel| disk_map[rel] }]
      out, err, status = Open3.capture3(shellcheck_bin, *args, chdir: REPO_ROOT)
      return if status.success?

      combined = [out, err].map(&:strip).reject(&:empty?).join("\n")
      errors << "[ShellCheck]\n#{normalize_output_paths(combined, disk_map)}"
    end

    def check_coding_standards(files, disk_map, errors)
      leaks = []
      yaml_unsafe = []
      cflags_bad = []

      files.each do |rel|
        abs = disk_map[rel]
        next unless abs && File.file?(abs)

        if rel.end_with?(".rb")
          lines = File.readlines(abs, encoding: "UTF-8", invalid: :replace, undef: :replace)

          unless TOP_LEVEL_DEF_EXCLUDES.any? { |prefix| rel.start_with?(prefix) }
            defs = lines.each_with_index.select { |line, _| line.match?(/^def\s+/) }.map { |_, idx| idx + 1 }
            consts = lines.each_with_index.select { |line, _| line.match?(/^[A-Z][A-Z0-9_]*\s*=/) }.map { |_, idx| idx + 1 }
            leaks << "#{rel}: top-level defs=#{defs.inspect} consts=#{consts.inspect}" unless defs.empty? && consts.empty?
          end

          lines.each_with_index do |line, idx|
            yaml_unsafe << "#{rel}:#{idx + 1}:#{line.rstrip}" if line.match?(UNSAFE_YAML_RE)
          end
        end

        if cflags_guarded_path?(rel)
          data = File.binread(abs)
          next if data.include?("\x00")

          data.force_encoding("UTF-8").scrub.lines.each_with_index do |line, idx|
            cflags_bad << "#{rel}:#{idx + 1}:#{line.rstrip}" if line.match?(SUPPRESSED_CFLAG_RE)
          end
        end
      end

      errors << "[Object namespace leaks]\n#{leaks.join("\n")}" unless leaks.empty?
      errors << "[Unsafe YAML loader]\n#{yaml_unsafe.join("\n")}" unless yaml_unsafe.empty?
      errors << "[Unexpected global C warning suppression]\n#{cflags_bad.join("\n")}" unless cflags_bad.empty?
    end

    def cflags_guarded_path?(rel)
      return false if CFLAGS_GUARD_ALLOWLIST.include?(rel)

      CFLAGS_GUARD_PREFIXES.any? { |prefix| rel == prefix || rel.start_with?(prefix) }
    end

    def working_rubocop_bin
      ENV.fetch("PATH", "").split(File::PATH_SEPARATOR).uniq.each do |dir|
        next if dir.empty?

        candidate = File.join(dir, "rubocop")
        next unless File.file?(candidate) && File.executable?(candidate)

        _out, _err, status = Open3.capture3(candidate, "--version")
        return candidate if status.success?
      end
      nil
    end

    def check_rubocop_or_ast(files, disk_map, options, errors)
      rb_files = files.select do |rel|
        rel.end_with?(".rb") &&
          disk_map.key?(rel) &&
          RUBOCOP_EXCLUDES.none? { |prefix| rel.start_with?(prefix) }
      end

      rubocop_bin = working_rubocop_bin
      if options[:require_rubocop] && !rubocop_bin
        errors << "[RuboCop]\nworking `rubocop` gem executable not found in PATH (`gem install rubocop`)"
        return
      end
      return if rb_files.empty?

      if rubocop_bin
        config_path = File.join(REPO_ROOT, ".rubocop.yml")
        args = [
          "--config", config_path,
          "--format", "simple",
          "--only", RUBOCOP_COPS.join(","),
          *rb_files.map { |rel| disk_map[rel] }
        ]
        out, err, status = Open3.capture3(rubocop_bin, *args, chdir: REPO_ROOT)
        return if status.success?

        combined = [out, err].map(&:strip).reject(&:empty?).join("\n")
        errors << "[RuboCop]\n#{normalize_output_paths(combined, disk_map)}"
      else
        offenses = run_prism_ast_cops(rb_files, disk_map)
        errors << "[Ruby AST lint rules]\n#{offenses.join("\n")}" unless offenses.empty?
      end
    end

    def run_prism_ast_cops(rb_files, disk_map)
      require "prism"
      offenses = []

      rb_files.each do |rel|
        abs = disk_map[rel]
        raw = File.binread(abs)
        offenses << "#{rel}:1: Layout/EndOfLine: Carriage return character detected." if raw.include?("\r\n")
        if !raw.empty? && !raw.end_with?("\n")
          offenses << "#{rel}:1: Layout/TrailingEmptyLines: Final newline missing."
        elsif raw.end_with?("\n\n")
          line_no = raw.count("\n")
          offenses << "#{rel}:#{line_no}: Layout/TrailingEmptyLines: Trailing blank lines detected."
        end

        result = Prism.parse_file(abs)
        check_top_defs = TOP_LEVEL_DEF_EXCLUDES.none? { |prefix| rel.start_with?(prefix) }
        inspect_prism_node(result.value, rel, offenses, scope_depth: 0, check_top_defs: check_top_defs)
      end

      offenses
    end

    def inspect_prism_node(node, rel, offenses, scope_depth:, check_top_defs:)
      case node
      when Prism::ModuleNode, Prism::ClassNode, Prism::SingletonClassNode
        node.compact_child_nodes.each do |child|
          inspect_prism_node(child, rel, offenses, scope_depth: scope_depth + 1, check_top_defs: check_top_defs)
        end
        return
      when Prism::DefNode
        if check_top_defs && scope_depth.zero?
          line = node.location.start_line
          offenses << "#{rel}:#{line}: Style/TopLevelMethodDefinition: Do not define methods at the top level."
        end
      when Prism::RescueModifierNode
        line = node.location.start_line
        offenses << "#{rel}:#{line}: Style/RescueModifier: Avoid using `rescue` in its modifier form."
      when Prism::RescueNode
        node.exceptions.each do |exc|
          if exception_root_const?(exc)
            line = exc.location.start_line
            offenses << "#{rel}:#{line}: Lint/RescueException: Avoid rescuing the `Exception` class."
          end
        end
      when Prism::CallNode
        check_call_security_cops(node, rel, offenses)
        if block_creates_namespace?(node)
          node.compact_child_nodes.each do |child|
            inspect_prism_node(child, rel, offenses, scope_depth: scope_depth + 1, check_top_defs: check_top_defs)
          end
          return
        end
      when Prism::GlobalVariableReadNode,
           Prism::GlobalVariableWriteNode,
           Prism::GlobalVariableAndWriteNode,
           Prism::GlobalVariableOrWriteNode,
           Prism::GlobalVariableOperatorWriteNode,
           Prism::GlobalVariableTargetNode
        unless ALLOWED_GLOBAL_VARS.key?(node.name) || node.name.to_s.match?(/\A\$[1-9]\d*\z/)
          line = node.location.start_line
          offenses << "#{rel}:#{line}: Style/GlobalVars: Do not introduce global variables (`#{node.name}`)."
        end
      end

      node.compact_child_nodes.each do |child|
        inspect_prism_node(child, rel, offenses, scope_depth: scope_depth, check_top_defs: check_top_defs)
      end
    end

    def exception_root_const?(node)
      case node
      when Prism::ConstantReadNode
        node.name == :Exception
      when Prism::ConstantPathNode
        node.parent.nil? && node.name == :Exception
      else
        false
      end
    end

    def const_named?(node, target)
      case node
      when Prism::ConstantReadNode
        node.name == target
      when Prism::ConstantPathNode
        node.parent.nil? && node.name == target
      else
        false
      end
    end

    def block_creates_namespace?(call_node)
      return false unless call_node.block && call_node.name == :new

      const_named?(call_node.receiver, :Class) || const_named?(call_node.receiver, :Module)
    end

    def check_call_security_cops(call_node, rel, offenses)
      if const_named?(call_node.receiver, :YAML) && %i[load load_file].include?(call_node.name)
        line = call_node.location.start_line
        offenses << "#{rel}:#{line}: Security/YAMLLoad: Prefer `YAML.safe_load` over `YAML.#{call_node.name}`."
      elsif call_node.name == :eval && eval_receiver?(call_node.receiver)
        first_arg = call_node.arguments&.arguments&.first
        if first_arg && !first_arg.is_a?(Prism::StringNode)
          line = call_node.location.start_line
          offenses << "#{rel}:#{line}: Security/Eval: The use of `eval` is a serious security risk."
        end
      end
    end

    def eval_receiver?(receiver)
      return true if receiver.nil? || const_named?(receiver, :Kernel)

      receiver.is_a?(Prism::CallNode) && receiver.receiver.nil? && receiver.name == :binding
    end

    def check_topologies_and_requires(files, disk_map, options, errors)
      core_schema_touched = !options[:staged] || files.any? do |rel|
        rel == "topology.schema.json" || rel.start_with?("lib/", "runtime/")
      end

      campaigns_to_check = if core_schema_touched
                             Dir.glob("campaigns/*.rb", base: REPO_ROOT).sort
                           else
                             files.select { |rel| rel.start_with?("campaigns/") && rel.end_with?(".rb") }
                           end

      examples_to_check = if core_schema_touched
                            Dir.glob("examples/*.rb", base: REPO_ROOT).sort
                          else
                            files.select { |rel| rel.start_with?("examples/") && rel.end_with?(".rb") }
                          end

      topo_offenses = []
      campaign_cli = File.join(REPO_ROOT, "bin", "campaign.rb")
      lib_flag = "-I#{File.join(REPO_ROOT, "lib")}"

      campaigns_to_check.each do |rel|
        target = disk_map[rel] || File.join(REPO_ROOT, rel)
        next unless File.file?(target)

        _out, err, status = Open3.capture3(
          RbConfig.ruby, lib_flag, campaign_cli, "validate", "-c", target, chdir: REPO_ROOT
        )
        topo_offenses << "#{rel} (validate): #{err.strip}" unless status.success?

        _out2, err2, status2 = Open3.capture3(
          RbConfig.ruby, lib_flag, campaign_cli, "plan-launch", "--no-stage", "-c", target, chdir: REPO_ROOT
        )
        topo_offenses << "#{rel} (plan-launch): #{err2.strip}" unless status2.success?
      end

      examples_to_check.each do |rel|
        target = disk_map[rel] || File.join(REPO_ROOT, rel)
        next unless File.file?(target)

        _out, err, status = Open3.capture3(
          RbConfig.ruby, lib_flag, campaign_cli, "validate", "-c", target, chdir: REPO_ROOT
        )
        topo_offenses << "#{rel} (validate): #{err.strip}" unless status.success?
      end

      errors << "[Campaign & example topology validation]\n#{topo_offenses.join("\n")}" unless topo_offenses.empty?

      lib_rb_touched = !options[:staged] || files.any? do |rel|
        rel.end_with?(".rb") && !rel.start_with?("test/", "campaigns/", "examples/")
      end
      return unless lib_rb_touched

      check_clean_library_requires(errors)
    end

    def check_clean_library_requires(errors)
      probe = <<~RUBY
        before_priv = Object.private_instance_methods(false)
        before_pub = Object.public_instance_methods(false)
        ARGV.each { |lib| require File.expand_path(lib) }
        new_priv = Object.private_instance_methods(false) - before_priv
        new_pub = Object.public_instance_methods(false) - before_pub
        abort "unexpected private Object methods: \#{new_priv.inspect}" unless new_priv.empty?
        abort "unexpected public Object methods: \#{new_pub.inspect}" unless new_pub.empty?
        #{FORBIDDEN_TOP_CONSTS.inspect}.each do |const_name|
          abort "unexpected top-level constant \#{const_name}" if Object.const_defined?(const_name.to_sym, false)
        end
      RUBY

      _out, err, status = Open3.capture3(
        RbConfig.ruby, "-Ilib", "-ryaml", "-rdigest", "-rtempfile", "-rjson",
        "-e", probe, *CLEAN_REQUIRE_LIBS,
        chdir: REPO_ROOT
      )
      errors << "[Clean library require hygiene]\n#{err.strip}" unless status.success?
    end
  end
end

exit(PrismFuzzer::Lint.run_cli(ARGV)) if __FILE__ == $PROGRAM_NAME
