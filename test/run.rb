#!/usr/bin/env ruby
# frozen_string_literal: true

require "minitest"
require "optparse"
require_relative "lib/test_helpers"

module PrismFuzzerTest
  RUNNER_ACTIVE = true

  module Runner
    TEST_ROOT = File.expand_path(__dir__)

    module_function

    def top_level_test_files
      %w[sankey grammar prism_diff oss_fuzz]
        .map { |name| File.join(TEST_ROOT, "#{name}_test.rb") }
        .select { |path| File.file?(path) }
    end

    def suite_files(name)
      case name
      when "sankey", "grammar", "prism_diff", "oss_fuzz"
        path = File.join(TEST_ROOT, "#{name}_test.rb")
        File.file?(path) ? [path] : []
      when "targets"
        Dir.glob(File.join(TEST_ROOT, "targets", "*_test.rb")).sort
      when "triage"
        Dir.glob(File.join(TEST_ROOT, "triage", "*_test.rb")).sort
      when "all"
        all_test_files
      end
    end

    def all_test_files
      (
        top_level_test_files +
        Dir.glob(File.join(TEST_ROOT, "targets", "*_test.rb")).sort +
        Dir.glob(File.join(TEST_ROOT, "triage", "*_test.rb")).sort
      ).uniq
    end

    def resolve_stage_or_file(arg)
      return File.expand_path(arg) if File.file?(arg)

      rel_cand = File.join(TEST_ROOT, arg)
      return rel_cand if File.file?(rel_cand)

      %w[triage targets].each do |sub|
        cand = File.join(TEST_ROOT, sub, "#{arg}_test.rb")
        return cand if File.file?(cand)

        cand2 = File.join(TEST_ROOT, sub, "#{arg}.rb")
        return cand2 if File.file?(cand2)
      end

      top_cand = File.join(TEST_ROOT, "#{arg}_test.rb")
      return top_cand if File.file?(top_cand)

      matches = all_test_files.select { |p| File.basename(p).include?(arg) }
      return matches if matches.size == 1

      raise ArgumentError, "Unknown test suite/stage/file: '#{arg}'"
    end

    def main(argv = ARGV)
      suites = []
      stages = []
      list_only = false
      docker_only = false
      minitest_args = []

      args = argv.dup
      if (dash = args.index("--"))
        minitest_args.concat(args[(dash + 1)..])
        args = args[0...dash]
      end

      OptionParser.new do |op|
        op.banner = "Usage: ruby test/run.rb [options] [test_files_or_stages...] [-- minitest_args...]"
        op.on("--suite NAME", "Suite to run: all, sankey, grammar, prism_diff, oss_fuzz, targets, triage") { |v| suites << v }
        op.on("--stage NAME", "Individual stage or sub-suite name") { |v| stages << v }
        op.on("--docker-only", "Enable TEST_OSS_FUZZ_DOCKER=1 host Docker test mode") { docker_only = true }
        op.on("--list", "List matched test files and exit") { list_only = true }
        op.on("-n", "--name PATTERN", "Filter Minitest test names") { |v| minitest_args.push("-n", v) }
        op.on("-v", "--verbose", "Verbose Minitest output") { minitest_args << "-v" }
        op.on("--seed N", Integer, "Deterministic Minitest seed") { |v| minitest_args.push("--seed", v.to_s) }
        op.on("-h", "--help", "Show help") { puts op; return 0 }
      end.parse!(args)

      files = []
      suites.each do |s|
        matched = suite_files(s)
        raise OptionParser::InvalidArgument, "Unknown or empty suite '#{s}'" if matched.nil?

        files.concat(matched)
      end
      (stages + args).each { |target| files.concat(Array(resolve_stage_or_file(target))) }
      files = all_test_files if files.empty?
      files = files.map { |f| File.expand_path(f) }.uniq

      raise ArgumentError, "No test files matched." if files.empty?

      if list_only
        files.each { |f| puts f }
        return 0
      end

      PrismFuzzerTest.sanitize_env!
      if docker_only
        ENV["TEST_OSS_FUZZ_DOCKER"] = "1"
        ENV["TEST_OSS_FUZZ_DOCKER_ONLY"] = "1"
      end

      Minitest::Test.include(PrismFuzzerTest::Helpers) unless Minitest::Test < PrismFuzzerTest::Helpers

      files.each_with_index do |path, idx|
        rel = path.delete_prefix("#{PrismFuzzerTest::ROOT_DIR}/")
        puts "[#{idx + 1}/#{files.size}] Loading #{rel}..."
        require path
      end

      Minitest.run(minitest_args) ? 0 : 1
    end
  end
end

if __FILE__ == $PROGRAM_NAME
  exit(PrismFuzzerTest::Runner.main(ARGV))
end
