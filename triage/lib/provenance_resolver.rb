# frozen_string_literal: true

module FuzzTriage
  # Resolves Prism, ruby parse.y, fuzz binary, and triage binary version
  # provenance for bucket metadata and metadata.json indexes.
  module ProvenanceResolver
    include Config
    extend self

    def locate_version_repo_root
      FuzzProvenance.locate_repo_root
    end

    def native_executable_magic?(path)
      FuzzProvenance.native_executable_magic?(path)
    end

    def probe_diff_binary_versions(bin_path)
      FuzzProvenance.probe_diff_binary_versions(bin_path)
    end

    def read_prism_header_version(repo_root)
      FuzzProvenance.read_prism_header_version(repo_root)
    end

    def detect_git_revision(repo_root)
      git_info = FuzzProvenance.detect_git_state(repo_root)
      return nil unless git_info

      {
        commit: git_info["git_commit"],
        short: git_info["git_short"],
        dirty: git_info["git_dirty"]
      }.compact
    end

    def detect_oracle_dir_versions(oracle_dir = ENV["RUBY_ORACLE_DIR"])
      info = FuzzProvenance.detect_oracle_dir_versions(oracle_dir)
      return nil unless info

      info.transform_keys(&:to_sym)
    end

    def compact_provenance_entry(entry, top_container:, include_workspace_git: false, workspace_git: nil, coverage_bin: nil)
      return nil unless entry.is_a?(Hash) && !entry.empty?

      out = {}
      out["binary"] = entry["binary"] if entry["binary"] && !entry["binary"].empty?
      out["build_id"] = entry["build_id"] if entry["build_id"] && !entry["build_id"].empty?
      out["snapshot_dir"] = entry["snapshot_dir"] if entry["snapshot_dir"] && !entry["snapshot_dir"].empty?
      out["built_at"] = entry["built_at"] if entry["built_at"] && !entry["built_at"].empty?
      out["started_at"] = entry["started_at"] if entry["started_at"] && !entry["started_at"].empty?
      out["coverage_binary"] = normalize_repo_path(coverage_bin) if coverage_bin && !coverage_bin.to_s.empty?
      out["prism"] = entry["prism"] if entry["prism"].is_a?(Hash) && !entry["prism"].empty?
      out["prism_a"] = entry["prism_a"] if entry["prism_a"].is_a?(Hash) && !entry["prism_a"].empty?
      out["prism_b"] = entry["prism_b"] if entry["prism_b"].is_a?(Hash) && !entry["prism_b"].empty?
      out["fuzz_repo"] = entry["fuzz_repo"] if entry["fuzz_repo"].is_a?(Hash) && !entry["fuzz_repo"].empty?
      out["ruby_parse_y"] = entry["ruby_parse_y"] if entry["ruby_parse_y"].is_a?(Hash) && !entry["ruby_parse_y"].empty?
      if include_workspace_git && workspace_git.is_a?(Hash) && !workspace_git.empty?
        out["workspace_git"] = workspace_git
      end
      if entry["container"].is_a?(Hash) && !entry["container"].empty? && entry["container"] != top_container
        out["container"] = entry["container"]
      end
      out.empty? ? nil : out
    end

    def resolve_versions_metadata(executable: "", worker_executable: nil, is_diff: false, target_ruby_version: nil, include_ruby_oracle: is_diff, include_diff_binary: false, triage_dir: nil, coverage_bin: nil, fuzz_versions_override: nil, fuzz_buckets: nil)
      repo_root = locate_version_repo_root
      exe_str = executable.to_s
      worker_str = (worker_executable && !worker_executable.to_s.empty?) ? worker_executable.to_s : exe_str

      triage_roots = triage_ws_roots(triage_dir)
      triage_ws_build = if triage_dir && defined?(PrismFuzzer::Topology) && (tt = resolve_topology(triage_dir: triage_dir))
                          PrismFuzzer::Topology.workspace_paths(tt)[:build_dir]
                        elsif !triage_roots.empty?
                          triage_roots.map { |r| File.join(r, "build") }.find { |d| File.directory?(d) } || File.join(triage_roots.first, "build")
                        end
      triage_snap_diff = triage_roots.map { |r| File.join(r, "bin", "fuzz.diff") }.find { |p| File.file?(p) }
      diff_bin = if is_diff && !exe_str.empty? && (exe_str.end_with?("diff") || File.basename(exe_str) == "fuzz.diff") && File.file?(exe_str)
                   exe_str
                 elsif !worker_str.empty? && File.file?(File.join(File.dirname(worker_str), "fuzz.diff"))
                   File.join(File.dirname(worker_str), "fuzz.diff")
                 elsif triage_snap_diff
                   triage_snap_diff
                 elsif triage_ws_build && File.file?(File.join(triage_ws_build, "fuzz.diff"))
                   File.join(triage_ws_build, "fuzz.diff")
                 elsif triage_dir.nil? && File.file?("./tmp/fuzz/bin/fuzz.diff")
                   "./tmp/fuzz/bin/fuzz.diff"
                 elsif triage_dir.nil? && File.file?("./tmp/fuzz/build/fuzz.diff")
                   "./tmp/fuzz/build/fuzz.diff"
                 elsif repo_root
                   File.join(repo_root, "tmp/fuzz/build/fuzz.diff")
                 else
                   "./tmp/fuzz/build/fuzz.diff"
                 end

      snap_bin_dir = triage_roots.map { |r| File.join(r, "bin") }.find { |d| File.directory?(d) } || (triage_roots.first && File.join(triage_roots.first, "bin"))
      fuzz_prov = if fuzz_versions_override.is_a?(Hash) && !fuzz_versions_override.empty?
                    fuzz_versions_override.dup
                  elsif !worker_str.empty?
                    FuzzProvenance.resolve_binary_provenance(
                      worker_str,
                      is_diff: is_diff,
                      target_ruby_version: target_ruby_version,
                      include_ruby_oracle: is_diff || include_ruby_oracle,
                      repo_root: repo_root
                    )
                  elsif snap_bin_dir && File.directory?(snap_bin_dir) && (File.file?(File.join(snap_bin_dir, "versions.json")) || FuzzProvenance::BINARIES.any? { |b| File.file?(File.join(snap_bin_dir, b)) })
                    dir_prov = FuzzProvenance.resolve_dir_provenance(snap_bin_dir, repo_root: repo_root)
                    snap_manifest = FuzzProvenance.find_manifest_for_bin_dir(snap_bin_dir)
                    {
                      "snapshot_dir" => normalize_repo_path(snap_bin_dir),
                      "built_at" => snap_manifest&.dig("built_at"),
                      "started_at" => snap_manifest&.dig("started_at"),
                      "prism" => dir_prov["prism"],
                      "ruby_parse_y" => dir_prov["ruby_parse_y"],
                      "container" => dir_prov["container"]
                    }.compact
                  elsif Array(fuzz_buckets).any? { |b| b.dig("versions", "fuzz").is_a?(Hash) }
                    first_f = Array(fuzz_buckets).lazy.filter_map { |b| b.dig("versions", "fuzz") }.first
                    first_c = Array(fuzz_buckets).lazy.filter_map { |b| b.dig("versions", "container") }.first
                    fc = first_f.dup
                    fc["container"] ||= first_c if first_c
                    fc
                  end

      triage_target = if !exe_str.empty?
                        exe_str
                      elsif coverage_bin && !coverage_bin.to_s.empty? && File.file?(coverage_bin.to_s)
                        coverage_bin.to_s
                      elsif File.file?(diff_bin)
                        diff_bin
                      else
                        ""
                      end

      triage_prov = FuzzProvenance.resolve_binary_provenance(
        triage_target,
        is_diff: is_diff,
        target_ruby_version: nil,
        include_ruby_oracle: is_diff || include_ruby_oracle,
        repo_root: repo_root
      )
      workspace_git = FuzzProvenance.detect_git_state(repo_root)

      top_container = fuzz_prov&.dig("container") || triage_prov&.dig("container")
      top_prism = (fuzz_prov&.dig("prism") || triage_prov&.dig("prism"))&.dup
      if top_prism && target_ruby_version && !target_ruby_version.to_s.empty?
        top_prism["target_ruby_version"] = target_ruby_version
      end

      top_ruby = nil
      if include_ruby_oracle || is_diff
        top_ruby = (fuzz_prov&.dig("ruby_parse_y") || triage_prov&.dig("ruby_parse_y"))&.dup
        if include_diff_binary && File.file?(diff_bin)
          top_ruby ||= {}
          top_ruby["binary"] ||= normalize_repo_path(diff_bin) if File.executable?(diff_bin)
          top_ruby["build_id"] ||= binary_build_id(diff_bin)
        end
        top_ruby = nil if top_ruby && top_ruby.empty?
      end

      fuzz_out = compact_provenance_entry(fuzz_prov, top_container: top_container)
      triage_out = compact_provenance_entry(
        triage_prov,
        top_container: top_container,
        include_workspace_git: true,
        workspace_git: workspace_git,
        coverage_bin: coverage_bin
      )

      top_prism_b = (fuzz_prov&.dig("prism_b") || triage_prov&.dig("prism_b"))&.dup
      fuzz_repo_info = (triage_prov&.dig("fuzz_repo") || fuzz_prov&.dig("fuzz_repo"))&.dup

      versions = {}
      versions["prism"] = top_prism if top_prism && !top_prism.empty?
      versions["prism_b"] = top_prism_b if top_prism_b && !top_prism_b.empty?
      versions["fuzz_repo"] = fuzz_repo_info if fuzz_repo_info && !fuzz_repo_info.empty?
      versions["ruby_parse_y"] = top_ruby if top_ruby && !top_ruby.empty?
      versions["container"] = top_container if top_container && !top_container.empty?
      versions["fuzz"] = fuzz_out if fuzz_out && !fuzz_out.empty?
      versions["triage"] = triage_out if triage_out && !triage_out.empty?
      versions.empty? ? nil : versions
    end
  end
end
