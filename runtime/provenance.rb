#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "open3"
require "rbconfig"
require "time"

require_relative "common"
topology_lib = File.join(__dir__, "topology.rb")
require topology_lib if File.file?(topology_lib)

module FuzzProvenance
  BINARIES = %w[
    fuzz
    fuzz.cmplog
    fuzz.msan
    fuzz.lsan
    fuzz.ijon
    fuzz.native
    fuzz.slow
    fuzz.sand
    fuzz.diff
    fuzz.compile
    fuzz.pipeline
    fuzz.prism_diff
    fuzz.arm32
    fuzz.arm32.repro
    fuzz.ppc
    fuzz.ppc.repro
  ].freeze

  AUX_FILES = %w[fuzz.ids fuzz.diff.ids fuzz.compile.ids fuzz.pipeline.ids fuzz.prism_diff.ids mutator_oracle64.so libprismmutator.so fuzz.explain fuzz.explain.b].freeze
  REPRO_DIR_ENTRIES = %w[fuzz-ruby-ext prism_lib].freeze
  SNAPSHOT_PATHS = %w[
    bin
    campaigns
    dict
    harnesses
    lib
    runtime
    triage
    topology.schema.json
  ].freeze
  GIT_DIRTY_PATHS = %w[harnesses runtime triage patches].freeze
  PRISM_DIRTY_PATHS = %w[src include templates].freeze
  MARKER_REGEX = /@\(#\)PRISM_FUZZ_PROVENANCE\t([^\n\0]+)/

  CACHE_MUTEX = Mutex.new
  EMBEDDED_CACHE = {}
  DIFF_VERSION_CACHE = {}
  GIT_STATE_CACHE = {}
  SHA256_CACHE = {}
  MANIFEST_CACHE = {}
  CONTAINER_CACHE = {}

  module_function

  def locate_fuzz_root(start_dir = nil)
    PrismFuzzer::Common.locate_fuzz_root(start_dir)
  end

  def locate_prism_root(start_dir = nil, fuzz_root: locate_fuzz_root(start_dir), topo: nil)
    PrismFuzzer::Common.locate_prism_root(start_dir, fuzz_root: fuzz_root, topo: topo)
  end

  def locate_repo_root(start_dir = nil)
    PrismFuzzer::Common.locate_repo_root(start_dir)
  end

  def resolve_fuzz_snapshot_root(repo_root = nil)
    fuzz = locate_fuzz_root || locate_repo_root
    return fuzz unless repo_root && !repo_root.to_s.empty?

    expanded = File.expand_path(repo_root)
    # Guard against synced target Prism checkouts being passed where prism-fuzzer root is required.
    prism_checkout = File.file?(File.join(expanded, "include/prism/version.h")) &&
                     !File.file?(File.join(expanded, "harnesses/prism/parse.c"))
    prism_checkout ? fuzz : expanded
  end

  def read_target_state(dir)
    return nil unless dir && File.directory?(dir)

    p = File.join(dir, ".fuzz-target-state.json")
    return nil unless File.file?(p)

    read_manifest(p)
  end

  def normalize_path(path, repo_root = locate_repo_root)
    return nil if path.nil? || path.to_s.empty?

    str = path.to_s
    return str unless repo_root

    expanded = File.expand_path(str)
    prefix = "#{File.expand_path(repo_root)}/"
    expanded.start_with?(prefix) ? expanded.delete_prefix(prefix) : str
  rescue ArgumentError, EncodingError
    path.to_s
  end

  def utf8_safe(text)
    text.to_s.encode("UTF-8", invalid: :replace, undef: :replace, replace: "\uFFFD")
  end

  def stat_cache_key(path)
    st = File.stat(path)
    [File.expand_path(path), st.size, st.mtime.to_i, st.mtime.nsec]
  end

  def binary_sha256(path)
    return nil if path.nil? || path.empty? || !File.file?(path)

    key = stat_cache_key(path)
    cached = CACHE_MUTEX.synchronize { SHA256_CACHE[key] }
    return cached if cached

    digest = Digest::SHA256.file(path).hexdigest
    CACHE_MUTEX.synchronize { SHA256_CACHE[key] = digest }
  rescue Errno::ENOENT, Errno::ESTALE
    nil
  rescue SystemCallError, IOError => e
    warn "FuzzProvenance: failed to hash #{path}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
    nil
  end

  def native_executable_magic?(path)
    File.open(path, "rb") do |f|
      magic = f.read(4)
      return false unless magic && magic.bytesize == 4

      bytes = magic.bytes
      magic == "\x7fELF".b ||
        bytes == [0xfe, 0xed, 0xfa, 0xce] ||
        bytes == [0xce, 0xfa, 0xed, 0xfe] ||
        bytes == [0xfe, 0xed, 0xfa, 0xcf] ||
        bytes == [0xcf, 0xfa, 0xed, 0xfe] ||
        bytes == [0xca, 0xfe, 0xba, 0xbe]
    end
  rescue Errno::ENOENT, Errno::EISDIR, Errno::ENOTDIR
    false
  rescue SystemCallError, IOError => e
    warn "FuzzProvenance: failed to inspect executable magic for #{path}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
    false
  end

  def read_prism_header_version(repo_root = locate_repo_root)
    return nil unless repo_root

    header = File.join(repo_root, "include/prism/version.h")
    return nil unless File.file?(header)

    File.read(header, encoding: "BINARY")[/^\s*#\s*define\s+PRISM_VERSION\s+"([^"]+)"/, 1]
  rescue Errno::ENOENT, Errno::ENOTDIR
    nil
  rescue SystemCallError, IOError => e
    warn "FuzzProvenance: failed to read #{header}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
    nil
  end

  def detect_git_state(repo_root = locate_repo_root, paths: GIT_DIRTY_PATHS)
    return nil unless repo_root

    cache_key = [File.expand_path(repo_root), paths]
    CACHE_MUTEX.synchronize do
      return GIT_STATE_CACHE[cache_key] if GIT_STATE_CACHE.key?(cache_key)

      commit_out, commit_st = Open3.capture2e("git", "-C", repo_root, "rev-parse", "HEAD")
      commit_str = utf8_safe(commit_out).strip
      unless commit_st.success? && commit_str =~ /\A[0-9a-f]{40}\z/i
        GIT_STATE_CACHE[cache_key] = nil
        return nil
      end

      commit = commit_str
      status_cmd = ["git", "--no-optional-locks", "-C", repo_root, "status", "--porcelain", "--", *paths]
      status_out, status_st = Open3.capture2e(*status_cmd)
      dirty = status_st.success? ? !utf8_safe(status_out).strip.empty? : nil

      GIT_STATE_CACHE[cache_key] = {
        "git_commit" => commit,
        "git_short" => commit[0, 9],
        "git_dirty" => dirty
      }.compact
    end
  rescue Errno::ENOENT, Errno::ENOTDIR
    nil
  rescue SystemCallError, IOError => e
    warn "FuzzProvenance: git state check failed for #{repo_root}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
    nil
  end

  def parse_bool_token(val)
    case val
    when "1", "true" then true
    when "0", "false" then false
    end
  end

  def read_embedded_binary_provenance(bin_path)
    return nil if bin_path.nil? || bin_path.empty? || !File.file?(bin_path)

    key = stat_cache_key(bin_path)
    cached = CACHE_MUTEX.synchronize { EMBEDDED_CACHE.fetch(key, :miss) }
    return cached unless cached == :miss

    raw = File.binread(bin_path)
    matches = raw.scan(MARKER_REGEX)
    parsed = nil
    unless matches.empty?
      kv = {}
      matches.last.first.split("\t").each do |entry|
        k, v = entry.split("=", 2)
        next unless k && v && !v.empty? && v != "unknown"

        kv[k] = v
      end

      commit = kv["git_commit"]
      dirty = parse_bool_token(kv["git_dirty"])
      prism_info = {
        "version" => kv["prism"],
        "git_commit" => commit,
        "git_short" => commit && !commit.empty? ? commit[0, 9] : nil,
        "git_dirty" => dirty,
        "source" => "embedded"
      }.compact
      prism_info.delete("source") if prism_info.size == 1

      ruby_info = {
        "version" => kv["ruby_version"],
        "revision" => kv["ruby_revision"],
        "release_date" => kv["ruby_release_date"]
      }.compact

      result = {}
      result["prism"] = prism_info unless prism_info.empty?
      result["ruby_parse_y"] = ruby_info unless ruby_info.empty?
      parsed = result unless result.empty?
    end

    CACHE_MUTEX.synchronize { EMBEDDED_CACHE[key] = parsed }
  rescue Errno::ENOENT, Errno::EISDIR, Errno::ESTALE
    nil
  rescue SystemCallError, IOError => e
    warn "FuzzProvenance: failed to read embedded provenance from #{bin_path}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
    nil
  end

  def probe_diff_binary_versions(bin_path)
    return nil if bin_path.nil? || bin_path.empty?
    return nil unless File.file?(bin_path) && File.executable?(bin_path) && native_executable_magic?(bin_path)

    key = stat_cache_key(bin_path)
    cached = CACHE_MUTEX.synchronize { DIFF_VERSION_CACHE.fetch(key, :miss) }
    return cached unless cached == :miss

    out, status = Open3.capture2e(bin_path, "--version")
    parsed = nil
    if status.success?
      kv = {}
      utf8_safe(out).each_line do |line|
        k, v = line.strip.split("=", 2)
        kv[k] = v if k && v && !v.empty? && v != "unknown"
      end
      parsed = kv if kv["prism"] && kv["ruby_version"]
    end
    CACHE_MUTEX.synchronize { DIFF_VERSION_CACHE[key] = parsed }
  rescue Errno::ENOENT, Errno::EACCES, Errno::ENOEXEC
    nil
  rescue SystemCallError, IOError => e
    warn "FuzzProvenance: failed to probe #{bin_path} --version: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
    nil
  end

  def detect_oracle_dir_versions(oracle_dir = ENV["RUBY_ORACLE_DIR"], ws_build: nil)
    fuzz_root = locate_fuzz_root
    if (oracle_dir.nil? || oracle_dir.strip.empty?) && (ws_build || fuzz_root)
      bdir = ws_build || File.join(fuzz_root, "tmp/fuzz/build")
      rjson = read_manifest(File.join(bdir, "targets/ruby.json"))
      oracle_dir = rjson["oracle_dir"] if rjson && rjson["oracle_dir"]
    end
    dir = (oracle_dir && !oracle_dir.strip.empty?) ? oracle_dir.strip : "/opt/ruby"
    return nil unless File.directory?(dir)

    inc_ver_path = File.join(dir, "include/ruby/version.h")
    top_ver_path = File.join(dir, "version.h")
    rev_path = File.join(dir, "revision.h")

    version = nil
    release_date = nil
    revision = nil

    if File.file?(inc_ver_path) && File.file?(top_ver_path)
      inc_ver = File.read(inc_ver_path, encoding: "BINARY")
      top_ver = File.read(top_ver_path, encoding: "BINARY")
      maj = inc_ver[/^\s*#\s*define\s+RUBY_API_VERSION_MAJOR\s+(\d+)/, 1]
      min = inc_ver[/^\s*#\s*define\s+RUBY_API_VERSION_MINOR\s+(\d+)/, 1]
      teeny = top_ver[/^\s*#\s*define\s+RUBY_VERSION_TEENY\s+(\d+)/, 1] ||
              inc_ver[/^\s*#\s*define\s+RUBY_API_VERSION_TEENY\s+(\d+)/, 1]
      version = "#{maj}.#{min}.#{teeny}" if maj && min && teeny
    end

    if File.file?(rev_path)
      rev_src = File.read(rev_path, encoding: "BINARY")
      revision = rev_src[/^\s*#\s*define\s+RUBY_FULL_REVISION\s+"([^"]+)"/, 1] ||
                 rev_src[/^\s*#\s*define\s+RUBY_REVISION\s+"([^"]+)"/, 1]
      y = rev_src[/^\s*#\s*define\s+RUBY_RELEASE_YEAR\s+(\d+)/, 1]
      m = rev_src[/^\s*#\s*define\s+RUBY_RELEASE_MONTH\s+(\d+)/, 1]
      d = rev_src[/^\s*#\s*define\s+RUBY_RELEASE_DAY\s+(\d+)/, 1]
      release_date = format("%04d-%02d-%02d", y.to_i, m.to_i, d.to_i) if y && m && d
    end

    {
      "oracle_dir" => dir,
      "version" => version,
      "revision" => revision,
      "release_date" => release_date
    }.compact
  rescue Errno::ENOENT, Errno::ENOTDIR
    nil
  rescue SystemCallError, IOError => e
    warn "FuzzProvenance: failed to read Ruby oracle headers in #{dir}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
    nil
  end

  def find_in_path(cmd)
    ENV.fetch("PATH", "").split(File::PATH_SEPARATOR).each do |dir|
      next if dir.empty?

      cand = File.join(dir, cmd)
      return cand if File.file?(cand) && File.executable?(cand)
    end
    nil
  end

  def capture_cmd_output(*cmd)
    Open3.capture2e(*cmd)
  rescue Errno::ENOENT, Errno::EACCES, Errno::ENOEXEC
    [nil, nil]
  rescue SystemCallError, IOError => e
    warn "FuzzProvenance: failed to run #{cmd.first}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
    [nil, nil]
  end

  def collect_container_provenance(repo_root: locate_repo_root)
    image_id = ENV["FUZZ_IMAGE_ID"].to_s.strip
    cache_key = [repo_root ? File.expand_path(repo_root) : nil, image_id, ENV["LLVM_VERSION"].to_s]

    cached = CACHE_MUTEX.synchronize { CONTAINER_CACHE.fetch(cache_key, :miss) }
    return cached unless cached == :miss

    os_name = nil
    if File.file?("/etc/os-release")
      os_rel = utf8_safe(File.read("/etc/os-release"))
      os_name = os_rel[/^PRETTY_NAME="([^"]+)"/, 1] ||
                os_rel[/^PRETTY_NAME=([^\s#]+)/, 1]
    end
    os_name ||= RbConfig::CONFIG["host_os"]

    clang_ver = nil
    if find_in_path("clang")
      out, st = capture_cmd_output("clang", "--version")
      clang_ver = utf8_safe(out).gsub(/\e\[[0-9;]*m/, "").lines.first&.strip if st&.success?
    end

    afl_ver = nil
    if find_in_path("afl-fuzz")
      out, = capture_cmd_output("afl-fuzz", "-h")
      first = utf8_safe(out).gsub(/\e\[[0-9;]*m/, "").lines.find { |l| !l.strip.empty? }&.strip if out
      afl_ver = first if first && !first.empty?
    end

    afl_patch_sha256 = nil
    if (fuzz_root = locate_fuzz_root(repo_root))
      patch_path = File.join(fuzz_root, "patches/afl/aflplusplus.patch")
      afl_patch_sha256 = binary_sha256(patch_path) if File.file?(patch_path)
    end

    lrama_ver = if defined?(Gem::Specification)
                  begin
                    Gem::Specification.find_by_name("lrama-fuzz").version.to_s
                  rescue Gem::LoadError
                    nil
                  end
                end

    qemu_vers = %w[qemu-arm qemu-ppc].each_with_object({}) do |cmd, acc|
      next unless find_in_path(cmd)

      out, st = capture_cmd_output(cmd, "--version")
      ver = utf8_safe(out).gsub(/\e\[[0-9;]*m/, "").lines.first&.strip if st&.success?
      acc[cmd.tr("-", "_")] = ver if ver
    end

    llvm_ver = ENV["LLVM_VERSION"].to_s.strip
    info = {
      "image_id" => image_id.empty? ? nil : image_id,
      "os" => os_name,
      "arch" => RbConfig::CONFIG["host_cpu"],
      "clang" => clang_ver,
      "llvm_version" => llvm_ver.empty? ? nil : llvm_ver,
      "aflplusplus" => afl_ver,
      "afl_patch_sha256" => afl_patch_sha256,
      "qemu_arm" => qemu_vers["qemu_arm"],
      "qemu_ppc" => qemu_vers["qemu_ppc"],
      "ruby" => defined?(RUBY_DESCRIPTION) ? RUBY_DESCRIPTION : nil,
      "lrama_fuzz" => lrama_ver
    }.compact

    result = info.empty? ? nil : info
    CACHE_MUTEX.synchronize { CONTAINER_CACHE[cache_key] = result }
  rescue SystemCallError, IOError => e
    warn "FuzzProvenance: failed to collect container provenance: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
    nil
  end

  def read_manifest(manifest_path)
    return nil if manifest_path.nil? || manifest_path.empty? || !File.file?(manifest_path)

    key = stat_cache_key(manifest_path)
    cached = CACHE_MUTEX.synchronize { MANIFEST_CACHE.fetch(key, :miss) }
    return cached unless cached == :miss

    data = PrismFuzzer::Common.read_json(manifest_path, context: "FuzzProvenance")
    return nil if data.nil?

    unless data.is_a?(Hash)
      warn "FuzzProvenance: expected JSON object in #{manifest_path}, got #{data.class}" unless ENV["FUZZ_QUIET"] == "1"
      return nil
    end
    CACHE_MUTEX.synchronize { MANIFEST_CACHE[key] = data }
  rescue Errno::ENOENT, Errno::ENOTDIR, Errno::ESTALE
    nil
  rescue SystemCallError, IOError => e
    warn "FuzzProvenance: failed to read manifest #{manifest_path}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
    nil
  end

  def find_manifest_for_bin_dir(bin_dir)
    return nil if bin_dir.nil? || bin_dir.empty? || !File.directory?(bin_dir)

    [
      File.join(bin_dir, "versions.json"),
      File.join(bin_dir, "fuzz.versions.json")
    ].each do |cand|
      m = read_manifest(cand)
      return m if m
    end
    nil
  end

  def write_json_atomic(path, data)
    PrismFuzzer::Common.write_json_atomic(path, data)
  end

  def topology_for_dir(dir)
    return nil if dir.nil? || dir.empty? || !File.directory?(dir)

    [
      File.join(dir, "topology.json"),
      File.join(dir, "topology.resolved.json")
    ].each do |cand|
      m = read_manifest(cand)
      return m if m
    end
    nil
  end

  def topology_artifact_lists(dir)
    topo = topology_for_dir(dir)
    if topo && topo["snapshot"].is_a?(Hash)
      bins = Array(topo.dig("snapshot", "binaries")).map { |b| File.basename(b.to_s) }.reject(&:empty?)
      aux = Array(topo.dig("snapshot", "aux_files")).map { |b| File.basename(b.to_s) }.reject(&:empty?)
      [bins.empty? ? BINARIES : bins.uniq, (AUX_FILES + aux).uniq]
    elsif topo && topo["fuzzers"].is_a?(Hash)
      bins = topo["fuzzers"].values.filter_map { |f| File.basename(f["binary"].to_s) if f.is_a?(Hash) && f["binary"] }
      aux = topo["fuzzers"].values.filter_map { |f| File.basename(f["ids_file"].to_s) if f.is_a?(Hash) && f["ids_file"] }
      [(BINARIES + bins).uniq, (AUX_FILES + aux).uniq]
    else
      [BINARIES, AUX_FILES]
    end
  end

  def summarize_dir_binaries(bin_dir)
    bins_list, aux_list = topology_artifact_lists(bin_dir)
    out = {}
    (bins_list + aux_list).uniq.each do |name|
      p = File.join(bin_dir, name)
      next unless File.file?(p)

      entry = {
        "sha256" => binary_sha256(p),
        "size_bytes" => File.size(p)
      }
      if bins_list.include?(name)
        emb = read_embedded_binary_provenance(p)
        entry["embedded"] = emb if emb
      end
      out[name] = entry
    end
    out
  end

  def resolve_dir_provenance(bin_dir, repo_root: locate_fuzz_root || locate_repo_root, fallback_live_git: true, fallback_live_container: true, use_manifest: true)
    manifest = use_manifest ? find_manifest_for_bin_dir(bin_dir) : nil
    bins = summarize_dir_binaries(bin_dir)
    fuzz_root = locate_fuzz_root(repo_root)
    sibling_build = if bin_dir && !bin_dir.to_s.empty?
                      exp_bin = File.expand_path(bin_dir)
                      File.basename(exp_bin) == "bin" ? File.join(File.dirname(exp_bin), "build") : exp_bin
                    end
    topo = topology_for_dir(bin_dir) || (sibling_build && topology_for_dir(sibling_build))
    ws_build = if topo && fuzz_root && defined?(PrismFuzzer::Topology)
                 PrismFuzzer::Topology.workspace_paths(topo, fuzz_root: fuzz_root)[:build_dir]
               else
                 sibling_build || (fuzz_root && File.join(fuzz_root, "tmp/fuzz/build"))
               end
    diff_fuzzer_id = topo&.dig("coverage", "diff_fuzzer") || "fuzz.diff"
    diff_bin = File.join(bin_dir, File.basename(topo&.dig("fuzzers", diff_fuzzer_id, "binary") || diff_fuzzer_id))

    manifest_matches = manifest && !bins.empty? && bins.all? do |name, info|
      m_sha = manifest.dig("binaries", name, "sha256")
      m_sha && m_sha == info["sha256"]
    end

    embedded_prism = nil
    embedded_ruby = nil
    bins.each_value do |info|
      emb = info["embedded"]
      next unless emb.is_a?(Hash)

      embedded_prism ||= emb["prism"] if emb["prism"].is_a?(Hash)
      embedded_ruby ||= emb["ruby_parse_y"] if emb["ruby_parse_y"].is_a?(Hash)
    end

    prism_root = locate_prism_root(nil, fuzz_root: fuzz_root || repo_root, topo: topo)
    t_state = read_target_state(prism_root)

    prism_info = if embedded_prism
                   embedded_prism.dup
                 elsif manifest_matches && manifest["prism"].is_a?(Hash)
                   manifest["prism"].merge("source" => "manifest")
                 else
                   ver = read_prism_header_version(prism_root)
                   git_info = fallback_live_git ? detect_git_state(prism_root, paths: PRISM_DIRTY_PATHS) : nil
                   p_hash = {
                     "version" => ver,
                     "git_commit" => git_info&.dig("git_commit") || t_state&.dig("commit"),
                     "git_short" => (git_info&.dig("git_commit") || t_state&.dig("commit"))&.[](0, 9),
                     "git_dirty" => git_info&.dig("git_dirty"),
                     "source" => "live_git"
                   }.compact
                   p_hash.delete("source") if p_hash.size == 1
                   p_hash
                 end
    if t_state
      prism_info["requested_ref"] ||= t_state["requested_ref"] if t_state["requested_ref"]
      prism_info["applied_patches"] ||= t_state["applied_patches"] if t_state["applied_patches"] && !t_state["applied_patches"].empty?
      prism_info["skipped_patches"] ||= t_state["skipped_patches"] if t_state["skipped_patches"] && !t_state["skipped_patches"].empty?
    end

    probe = File.file?(diff_bin) ? probe_diff_binary_versions(diff_bin) : nil
    oracle_info = nil
    if probe || embedded_ruby || (manifest_matches && manifest["ruby_parse_y"].is_a?(Hash))
      oracle_info = detect_oracle_dir_versions(ws_build: ws_build)
    end

    if probe && prism_info["git_commit"].nil? && probe["git_commit"]
      prism_info["git_commit"] = probe["git_commit"]
      prism_info["git_short"] = probe["git_commit"][0, 9]
      dirty = parse_bool_token(probe["git_dirty"])
      prism_info["git_dirty"] = dirty unless dirty.nil?
      prism_info["version"] ||= probe["prism"]
      prism_info["source"] = "binary_version"
    end

    manifest_ruby = (manifest_matches && manifest["ruby_parse_y"].is_a?(Hash)) ? manifest["ruby_parse_y"] : {}
    ruby_info = {
      "version" => probe&.dig("ruby_version") || embedded_ruby&.dig("version") || manifest_ruby["version"] || oracle_info&.dig("version"),
      "revision" => probe&.dig("ruby_description")&.[](/\brevision ([0-9a-f]+)\b/, 1) ||
                    embedded_ruby&.dig("revision") || manifest_ruby["revision"] || oracle_info&.dig("revision"),
      "release_date" => probe&.dig("ruby_release_date") || embedded_ruby&.dig("release_date") || manifest_ruby["release_date"] || oracle_info&.dig("release_date"),
      "description" => probe&.dig("ruby_description") || manifest_ruby["description"],
      "oracle_dir" => manifest_ruby["oracle_dir"] || oracle_info&.dig("oracle_dir")
    }.compact

    container_info = if manifest_matches && manifest["container"].is_a?(Hash) && !manifest["container"].empty?
                       manifest["container"]
                     elsif fallback_live_container
                       collect_container_provenance(repo_root: repo_root)
                     end

    fuzz_repo_info = (fallback_live_git && fuzz_root) ? detect_git_state(fuzz_root, paths: GIT_DIRTY_PATHS) : nil
    prism_b_dir = if ENV["PRISM_B_DIR"] && !ENV["PRISM_B_DIR"].empty?
                    ENV["PRISM_B_DIR"]
                  elsif topo&.dig("sources", "prism_b", "path")
                    topo.dig("sources", "prism_b", "path")
                  elsif topo.nil? && ws_build && File.file?(File.join(ws_build, "targets/prism_b.json"))
                    File.join(ws_build, "targets/prism_b")
                  elsif ws_build && !topo && File.directory?(File.join(ws_build, "targets/prism_b"))
                    File.join(ws_build, "targets/prism_b")
                  end
    b_state = read_target_state(prism_b_dir)
    prism_b_info = b_state ? {
      "version" => read_prism_header_version(b_state["path"]),
      "git_commit" => b_state["commit"],
      "git_short" => b_state["commit"]&.[](0, 9),
      "requested_ref" => b_state["requested_ref"],
      "applied_patches" => b_state["applied_patches"]
    }.compact : nil

    topo_summary = if topo
                     {
                       "name" => topo["name"],
                       "workspace" => topo["workspace"],
                       "sources" => topo["sources"]&.transform_values { |s| s.is_a?(Hash) ? s.slice("kind", "commit", "requested_ref", "mode", "applied_patches", "skipped_patches").compact : s }
                     }.compact
                   end

    payload = {
      "schema_version" => 1,
      "topology" => topo_summary,
      "fuzz_repo" => fuzz_repo_info,
      "prism" => prism_info.empty? ? nil : prism_info,
      "prism_b" => (prism_b_info && !prism_b_info.empty?) ? prism_b_info : nil,
      "ruby_parse_y" => ruby_info.empty? ? nil : ruby_info,
      "container" => container_info,
      "binaries" => bins.empty? ? nil : bins
    }.compact
    payload
  end

  def write_build_manifest(build_dir, repo_root: locate_fuzz_root || locate_repo_root)
    payload = resolve_dir_provenance(build_dir, repo_root: repo_root, use_manifest: false)
    payload["built_at"] = Time.now.utc.iso8601
    if payload["ruby_parse_y"].nil?
      oracle = detect_oracle_dir_versions
      payload["ruby_parse_y"] = oracle if oracle && !oracle.empty?
    end
    out_path = File.join(build_dir, "fuzz.versions.json")
    write_json_atomic(out_path, payload)
    out_path
  end

  def snapshot_scripts_to_dir(repo_root, dst_snapshot_dir)
    repo_root = resolve_fuzz_snapshot_root(repo_root)
    return nil unless repo_root && dst_snapshot_dir && !dst_snapshot_dir.empty?

    FileUtils.mkdir_p(File.dirname(dst_snapshot_dir))
    staging_dir = File.join(File.dirname(dst_snapshot_dir), ".snapshot.staging.#{Process.pid}")
    old_dir = File.join(File.dirname(dst_snapshot_dir), ".snapshot.old.#{Process.pid}")
    FileUtils.rm_rf(staging_dir)
    FileUtils.rm_rf(old_dir)
    FileUtils.mkdir_p(staging_dir)

    copied = []
    SNAPSHOT_PATHS.each do |rel|
      src = File.join(repo_root, rel)
      next unless File.exist?(src)

      dst = File.join(staging_dir, rel)
      FileUtils.mkdir_p(File.dirname(dst))
      FileUtils.cp_r(src, dst)
      copied << rel
    end

    # Also snapshot an explicit custom CAMPAIGN / TOPOLOGY file outside campaigns/ if configured.
    custom_topo = ENV["CAMPAIGN"].to_s.strip
    custom_topo = ENV["TOPOLOGY_FILE"].to_s.strip if custom_topo.empty?
    custom_topo = ENV["TOPOLOGY"].to_s.strip if custom_topo.empty?
    if !custom_topo.empty? && File.file?(File.expand_path(custom_topo, repo_root))
      src = File.expand_path(custom_topo, repo_root)
      campaigns_dir = File.expand_path("campaigns", repo_root)
      unless src.start_with?("#{campaigns_dir}/") && copied.include?("campaigns")
        dest_rel = File.extname(src) == ".rb" ? "campaign.rb" : "topology.json"
        FileUtils.cp(src, File.join(staging_dir, dest_rel))
        copied << dest_rel unless copied.include?(dest_rel)
      end
    end

    File.rename(dst_snapshot_dir, old_dir) if File.exist?(dst_snapshot_dir)
    File.rename(staging_dir, dst_snapshot_dir)
    FileUtils.rm_rf(old_dir) if File.exist?(old_dir)
    copied
  ensure
    FileUtils.rm_rf(staging_dir) if staging_dir && File.exist?(staging_dir)
    FileUtils.rm_rf(old_dir) if old_dir && File.exist?(old_dir) && !File.exist?(dst_snapshot_dir)
  end

  def snapshot_build_to_bin(src_build_dir, dst_bin_dir, dst_snapshot_dir: nil, repo_root: locate_fuzz_root || locate_repo_root)
    repo_root = resolve_fuzz_snapshot_root(repo_root)
    FileUtils.mkdir_p(File.dirname(dst_bin_dir))
    staging_dir = File.join(File.dirname(dst_bin_dir), ".bin.staging.#{Process.pid}")
    old_dir = File.join(File.dirname(dst_bin_dir), ".bin.old.#{Process.pid}")
    FileUtils.rm_rf(staging_dir)
    FileUtils.rm_rf(old_dir)
    FileUtils.mkdir_p(staging_dir)

    topo = topology_for_dir(src_build_dir)
    bins_list, aux_list = topology_artifact_lists(src_build_dir)

    copied = []
    (bins_list + aux_list).uniq.each do |name|
      src = File.join(src_build_dir, name)
      next unless File.file?(src)

      FileUtils.cp(src, File.join(staging_dir, name), preserve: true)
      copied << name
    end

    if topo
      write_json_atomic(File.join(staging_dir, "topology.json"), topo)
    end

    ext_sources = Array(topo&.dig("snapshot", "grammar_ext_sources"))
    if ext_sources.empty?
      REPRO_DIR_ENTRIES.each do |dir_name|
        src_sub = if dir_name == "prism_lib"
                    p_root = if File.directory?(File.join(src_build_dir, "targets/prism_a/lib"))
                               File.join(src_build_dir, "targets/prism_a")
                             else
                               locate_prism_root(nil, fuzz_root: repo_root, topo: topo)
                             end
                    p_root ? File.join(p_root, "lib") : nil
                  else
                    File.join(src_build_dir, dir_name)
                  end
        next unless src_sub && File.directory?(src_sub)

        FileUtils.cp_r(src_sub, File.join(staging_dir, dir_name), preserve: true)
      end
    else
      ext_sources.each_with_index do |src_id, idx|
        src_path = topo.dig("sources", src_id, "path")
        if src_path && File.directory?(File.join(src_path, "lib"))
          FileUtils.cp_r(File.join(src_path, "lib"), File.join(staging_dir, "prism_lib"), preserve: true) if idx == 0
          FileUtils.cp_r(File.join(src_path, "lib"), File.join(staging_dir, "prism_lib_#{src_id}"), preserve: true)
        end
        ext_src = idx == 0 ? File.join(src_build_dir, "fuzz-ruby-ext") : File.join(src_build_dir, "fuzz-ruby-ext-sources", src_id)
        if File.directory?(ext_src)
          FileUtils.cp_r(ext_src, File.join(staging_dir, "fuzz-ruby-ext"), preserve: true) if idx == 0
          FileUtils.cp_r(ext_src, File.join(staging_dir, "fuzz-ruby-ext-#{src_id}"), preserve: true)
        end
      end
    end

    src_manifest = File.join(src_build_dir, "fuzz.versions.json")
    src_m_data = read_manifest(src_manifest)
    bins = summarize_dir_binaries(staging_dir)

    manifest_matches = src_m_data && !bins.empty? && bins.all? do |name, info|
      m_sha = src_m_data.dig("binaries", name, "sha256")
      m_sha && m_sha == info["sha256"]
    end

    provenance = if manifest_matches
                   src_m_data.dup
                 else
                   resolve_dir_provenance(staging_dir, repo_root: repo_root, use_manifest: false)
                 end

    copied_scripts = snapshot_scripts_to_dir(repo_root, dst_snapshot_dir) if dst_snapshot_dir

    provenance["started_at"] = Time.now.utc.iso8601
    provenance["source_build_dir"] = normalize_path(src_build_dir, repo_root)
    provenance["snapshot_bin_dir"] = normalize_path(dst_bin_dir, repo_root)
    if copied_scripts && !copied_scripts.empty?
      provenance["snapshot_dir"] = normalize_path(dst_snapshot_dir, repo_root)
      provenance["snapshot_paths"] = copied_scripts
    end
    provenance["max_input_size"] = ENV["FUZZ_MAX_INPUT_SIZE"] if ENV["FUZZ_MAX_INPUT_SIZE"] && !ENV["FUZZ_MAX_INPUT_SIZE"].empty?

    write_json_atomic(File.join(staging_dir, "versions.json"), provenance)

    File.rename(dst_bin_dir, old_dir) if File.exist?(dst_bin_dir)
    File.rename(staging_dir, dst_bin_dir)
    FileUtils.rm_rf(old_dir) if File.exist?(old_dir)

    File.join(dst_bin_dir, "versions.json")
  ensure
    FileUtils.rm_rf(staging_dir) if staging_dir && File.exist?(staging_dir)
    FileUtils.rm_rf(old_dir) if old_dir && File.exist?(old_dir) && !File.exist?(dst_bin_dir)
  end

  def resolve_binary_provenance(bin_path, is_diff: false, target_ruby_version: nil, include_ruby_oracle: is_diff, repo_root: locate_fuzz_root || locate_repo_root)
    exe_str = bin_path.to_s
    exe_exists = !exe_str.empty? && File.file?(exe_str)
    bin_dir = exe_exists ? File.dirname(exe_str) : nil
    bin_name = exe_exists ? File.basename(exe_str) : nil
    manifest = find_manifest_for_bin_dir(bin_dir)
    build_id = exe_exists ? binary_sha256(exe_str) : nil
    manifest_matches = manifest && build_id && manifest.dig("binaries", bin_name, "sha256") == build_id

    embedded = exe_exists ? read_embedded_binary_provenance(exe_str) : nil

    fuzz_root = locate_fuzz_root(repo_root)
    topo = bin_dir ? topology_for_dir(bin_dir) : nil
    ws_build = if bin_dir
                 exp_bin = File.expand_path(bin_dir)
                 File.basename(exp_bin) == "bin" ? File.join(File.dirname(exp_bin), "build") : exp_bin
               elsif fuzz_root && defined?(PrismFuzzer::Topology) && (dt = PrismFuzzer::Topology.discover(start_dir: fuzz_root))
                 PrismFuzzer::Topology.workspace_paths(dt, fuzz_root: fuzz_root)[:build_dir]
               elsif fuzz_root
                 File.join(fuzz_root, "tmp/fuzz/build")
               end
    diff_probe_bin = if (is_diff || exe_str.end_with?("diff") || bin_name == "fuzz.diff") && exe_exists
                       exe_str
                     elsif include_ruby_oracle && bin_dir && File.file?(File.join(bin_dir, "fuzz.diff"))
                       File.join(bin_dir, "fuzz.diff")
                     elsif include_ruby_oracle && ws_build && File.file?(File.join(ws_build, "fuzz.diff"))
                       File.join(ws_build, "fuzz.diff")
                     elsif include_ruby_oracle && bin_dir.nil? && File.file?("./tmp/fuzz/bin/fuzz.diff")
                       "./tmp/fuzz/bin/fuzz.diff"
                     elsif include_ruby_oracle && bin_dir.nil? && File.file?("./tmp/fuzz/build/fuzz.diff")
                       "./tmp/fuzz/build/fuzz.diff"
                     end
    probe = diff_probe_bin ? probe_diff_binary_versions(diff_probe_bin) : nil
    diff_embedded = diff_probe_bin ? read_embedded_binary_provenance(diff_probe_bin) : nil

    prism_info = nil
    if embedded && embedded["prism"]
      prism_info = embedded["prism"].dup
      if manifest_matches && manifest.dig("prism", "git_commit") && prism_info["git_commit"].nil?
        prism_info["git_commit"] = manifest.dig("prism", "git_commit")
        prism_info["git_short"] = manifest.dig("prism", "git_short")
        prism_info["git_dirty"] = manifest.dig("prism", "git_dirty") unless manifest.dig("prism", "git_dirty").nil?
      end
    elsif manifest_matches && manifest["prism"].is_a?(Hash)
      prism_info = manifest["prism"].dup
      prism_info["source"] = "manifest"
    elsif probe && probe["git_commit"]
      dirty = parse_bool_token(probe["git_dirty"])
      prism_info = {
        "version" => probe["prism"] || read_prism_header_version(locate_prism_root(nil, fuzz_root: repo_root, topo: topo)),
        "git_commit" => probe["git_commit"],
        "git_short" => probe["git_commit"][0, 9],
        "git_dirty" => dirty,
        "source" => "binary_version"
      }.compact
    else
      p_root = locate_prism_root(nil, fuzz_root: locate_fuzz_root(repo_root) || repo_root, topo: topo)
      git_info = detect_git_state(p_root, paths: PRISM_DIRTY_PATHS)
      t_state = read_target_state(p_root)
      commit = git_info&.dig("git_commit") || t_state&.dig("commit")
      prism_info = {
        "version" => probe&.dig("prism") || read_prism_header_version(p_root),
        "git_commit" => commit,
        "git_short" => commit&.[](0, 9),
        "git_dirty" => git_info&.dig("git_dirty"),
        "requested_ref" => t_state&.dig("requested_ref"),
        "applied_patches" => (t_state&.dig("applied_patches")&.empty? == false ? t_state&.dig("applied_patches") : nil),
        "source" => git_info ? "live_git" : nil
      }.compact
    end
    prism_info["target_ruby_version"] = target_ruby_version if target_ruby_version && !target_ruby_version.to_s.empty?
    prism_info = nil if prism_info.empty?

    ruby_info = nil
    if include_ruby_oracle || is_diff
      manifest_ruby = (manifest_matches && manifest["ruby_parse_y"].is_a?(Hash)) ? manifest["ruby_parse_y"] : {}
      emb_ruby = embedded&.dig("ruby_parse_y") || diff_embedded&.dig("ruby_parse_y") || {}
      oracle_info = detect_oracle_dir_versions(ws_build: ws_build)
      desc = probe&.dig("ruby_description") || manifest_ruby["description"]
      rev = desc&.[](/\brevision ([0-9a-f]+)\b/, 1) || emb_ruby["revision"] || manifest_ruby["revision"] || oracle_info&.dig("revision")

      ruby_info = {
        "version" => probe&.dig("ruby_version") || emb_ruby["version"] || manifest_ruby["version"] || oracle_info&.dig("version"),
        "revision" => rev,
        "release_date" => probe&.dig("ruby_release_date") || emb_ruby["release_date"] || manifest_ruby["release_date"] || oracle_info&.dig("release_date"),
        "description" => desc,
        "oracle_dir" => manifest_ruby["oracle_dir"] || oracle_info&.dig("oracle_dir")
      }.compact
      ruby_info = nil if ruby_info.empty?
    end

    container_info = if manifest_matches && manifest["container"].is_a?(Hash) && !manifest["container"].empty?
                       manifest["container"]
                     else
                       collect_container_provenance(repo_root: repo_root)
                     end

    out = {
      "binary" => exe_str.empty? ? nil : normalize_path(exe_str, repo_root),
      "build_id" => build_id,
      "prism" => prism_info,
      "ruby_parse_y" => ruby_info,
      "container" => container_info
    }.compact
    out.empty? ? nil : out
  end
end

if __FILE__ == $PROGRAM_NAME
  cmd = ARGV.shift
  case cmd
  when "write-build"
    build_dir = ARGV[0] || "./tmp/fuzz/build"
    puts FuzzProvenance.write_build_manifest(build_dir)
  when "snapshot"
    src_dir = ARGV[0] || "./tmp/fuzz/build"
    dst_dir = ARGV[1] || "./tmp/fuzz/bin"
    snap_dir = ARGV[2]
    puts FuzzProvenance.snapshot_build_to_bin(src_dir, dst_dir, dst_snapshot_dir: snap_dir)
  when "show-container"
    puts JSON.pretty_generate(FuzzProvenance.collect_container_provenance || {})
  else
    warn "Usage: #{$PROGRAM_NAME} {write-build [DIR]|snapshot [SRC DST [SNAPSHOT_DIR]]|show-container}"
    exit 2
  end
end
