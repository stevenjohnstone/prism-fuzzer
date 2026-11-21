# frozen_string_literal: true

require "fileutils"
require "json"
require "minitest"
require "open3"
require "rbconfig"
require "shellwords"
require "tmpdir"

module PrismFuzzerTest
  ROOT_DIR = File.expand_path("../..", __dir__)

  SANITIZE_ENV_KEYS = %w[
    CAMPAIGN
    TOPOLOGY
    TOPOLOGY_FILE
    TOPOLOGY_RESOLVED
    FUZZ_WORKERS
    PRISM_REF
    PRISM_REPO
    PRISM_DIR
    PRISM_PATCHES
    PRISM_TEMPLATES
    PRISM_B_REF
    PRISM_B_REPO
    PRISM_B_DIR
    PRISM_B_PATCHES
    PRISM_B_TEMPLATES
    RUBY_REF
    RUBY_REPO
    RUBY_DIR
    TARGETS_OFFLINE
  ].freeze

  module_function

  # Clears inherited Makefile/campaign environment overrides that would divert
  # isolated test fixtures while preserving explicit PRISM_A_DIR / PRISM_A_GEN_DIR
  # test target paths passed by test/tests.mk.
  def sanitize_env!
    SANITIZE_ENV_KEYS.each { |k| ENV.delete(k) }
    # Ignore host ~/.gitconfig (signing keys, hooks, URL rewrites) in synthetic git repos.
    ENV["GIT_CONFIG_GLOBAL"] = "/dev/null"
  end

  module Helpers
    def root_dir
      PrismFuzzerTest::ROOT_DIR
    end

    def repo_path(*parts)
      File.join(root_dir, *parts)
    end

    def linux?
      RbConfig::CONFIG["host_os"].to_s.include?("linux")
    end

    def find_executable(cmd)
      ENV.fetch("PATH", "").split(File::PATH_SEPARATOR).each do |dir|
        next if dir.empty?

        cand = File.join(dir, cmd)
        return cand if File.file?(cand) && File.executable?(cand)
      end
      nil
    end

    def prism_a_dir
      cand = [ENV["PRISM_A_DIR"], ENV["PRISM_DIR"], repo_path("tmp/fuzz/build/targets/prism_a")].find do |d|
        d && !d.strip.empty? && File.file?(File.join(d, "include/prism.h"))
      end
      cand && File.expand_path(cand)
    end

    def prism_a_gen_dir
      cand = [ENV["PRISM_A_GEN_DIR"], repo_path("tmp/fuzz/build/targets/gen/prism_a")].find do |d|
        d && !d.strip.empty? && File.directory?(d)
      end
      cand && File.expand_path(cand)
    end

    def afl_build_dir
      cand = [ENV["FUZZ_AFL_DIR"], repo_path("build/afl")].find { |d| d && !d.empty? && File.directory?(d) }
      cand && File.expand_path(cand)
    end

    def afl_pcguard_ready?
      linux? && !find_executable("afl-clang-fast").nil? &&
        !(d = afl_build_dir).nil? && File.file?(File.join(d, "SanitizerCoveragePCGUARD.so"))
    end

    def afl_lto_ready?
      linux? && !find_executable("afl-clang-lto").nil? && !find_executable("afl-showmap").nil? &&
        !(d = afl_build_dir).nil? && File.file?(File.join(d, "SanitizerCoverageLTO.so"))
    end

    def with_tmpdir(prefix = "prism-fuzzer-test-")
      Dir.mktmpdir(prefix) { |dir| yield dir }
    end

    def run_cmd(*cmd, env: {}, chdir: nil, input: nil)
      string_env = {}
      env.each { |k, v| string_env[k.to_s] = v.nil? ? nil : v.to_s }
      opts = {}
      opts[:chdir] = chdir if chdir
      opts[:stdin_data] = input unless input.nil?
      Open3.capture3(string_env, *cmd.map(&:to_s), **opts)
    end

    def assert_cmd(*cmd, env: {}, chdir: nil, input: nil, msg: nil)
      out, err, st = run_cmd(*cmd, env: env, chdir: chdir, input: input)
      assert st.success?, lambda {
        label = msg ? "#{msg}\n" : ""
        "#{label}Command failed (status=#{st.exitstatus || st.termsig}): #{cmd.inspect}\n" \
          "--- stdout ---\n#{out}\n--- stderr ---\n#{err}"
      }
      [out, err]
    end

    def assert_ruby_cmd(*args, env: {}, chdir: root_dir, input: nil, msg: nil)
      assert_cmd(RbConfig.ruby, *args, env: env, chdir: chdir, input: input, msg: msg)
    end

    def with_env(overrides)
      saved = {}
      overrides.each do |k, v|
        key = k.to_s
        saved[key] = ENV.key?(key) ? ENV[key] : :__absent__
        if v.nil?
          ENV.delete(key)
        else
          ENV[key] = v.to_s
        end
      end
      yield
    ensure
      saved.each do |key, prev|
        if prev == :__absent__
          ENV.delete(key)
        else
          ENV[key] = prev
        end
      end
    end

    def stub_singleton_method(target, method_name, impl = nil, &body)
      raise ArgumentError, "stub_singleton_method requires a stub Proc and a block" unless impl && body

      sc = target.singleton_class
      had_orig = sc.method_defined?(method_name) || sc.private_method_defined?(method_name)
      orig = target.method(method_name) if had_orig
      sc.define_method(method_name, impl)
      body.call
    ensure
      if had_orig
        sc.define_method(method_name, orig)
      elsif sc.method_defined?(method_name) || sc.private_method_defined?(method_name)
        sc.remove_method(method_name)
      end
    end

    def write_executable(path, content)
      FileUtils.mkdir_p(File.dirname(path))
      File.write(path, content)
      File.chmod(0o755, path)
      path
    end

    def seed_bytes(body = "1 + 2\n", header: "\x00\x00\x03\x01".b)
      header.b + body.b
    end
  end
end
