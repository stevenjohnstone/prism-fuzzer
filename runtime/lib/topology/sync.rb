# frozen_string_literal: true

require_relative "../../../harnesses/prism/gen_api_compat"

module PrismFuzzer
  module Topology
    module_function

    def mirror_path_for(cache_dir, kind, repo_url)
      slug = Digest::SHA256.hexdigest(repo_url.to_s)[0, 12]
      File.join(cache_dir, "#{kind}-#{slug}.git")
    end

    def ensure_mirror(cache_dir, kind, repo_url, offline: ENV["TARGETS_OFFLINE"] == "1")
      mirror = mirror_path_for(cache_dir, kind, repo_url)
      FileUtils.mkdir_p(File.dirname(mirror))
      if File.directory?(mirror)
        unless offline
          _, _, st = run_cmd("git", "-C", mirror, "remote", "set-url", "origin", repo_url, allow_fail: true)
          run_cmd("git", "-C", mirror, "fetch", "--prune", "--tags", "origin", allow_fail: true) if st.success?
        end
        return mirror
      end

      raise TopologyError, "Mirror missing at #{mirror} while TARGETS_OFFLINE=1" if offline

      run_cmd("git", "clone", "--mirror", repo_url, mirror)
      mirror
    end

    def resolve_git_ref!(mirror, repo_url, ref, offline: ENV["TARGETS_OFFLINE"] == "1")
      out, _, st = run_cmd("git", "-C", mirror, "rev-parse", "--verify", "#{ref}^{commit}", allow_fail: true)
      return out.strip if st.success?

      raise TopologyError, "Unknown ref '#{ref}' in cached mirror while TARGETS_OFFLINE=1" if offline

      run_cmd("git", "-C", mirror, "fetch", "origin", ref, allow_fail: true)
      out, _, st = run_cmd("git", "-C", mirror, "rev-parse", "--verify", "#{ref}^{commit}", allow_fail: true)
      return out.strip if st.success?

      run_cmd("git", "-C", mirror, "fetch", "--tags", "origin", allow_fail: true)
      out, err, st = run_cmd("git", "-C", mirror, "rev-parse", "--verify", "#{ref}^{commit}", allow_fail: true)
      raise TopologyError, "Could not resolve ref '#{ref}' from #{repo_url}: #{err.strip}" unless st.success?

      out.strip
    end

    def checkout_detached_worktree!(mirror, sha, worktree_dir, role: "target")
      FileUtils.mkdir_p(File.dirname(worktree_dir))
      mirror_url = "file://#{File.expand_path(mirror)}"
      ref_name = "refs/fuzz/#{role}"
      run_cmd("git", "-C", mirror, "update-ref", ref_name, sha)

      if File.directory?(File.join(worktree_dir, ".git"))
        _, _, valid = run_cmd("git", "-C", worktree_dir, "rev-parse", "--is-inside-work-tree", allow_fail: true)
        if valid.success?
          _, _, has_obj = run_cmd("git", "-C", worktree_dir, "cat-file", "-e", "#{sha}^{commit}", allow_fail: true)
          run_cmd("git", "-C", worktree_dir, "fetch", "--depth=1", mirror_url, ref_name) unless has_obj.success?
          run_cmd("git", "-C", worktree_dir, "reset", "--hard", sha)
          run_cmd("git", "-C", worktree_dir, "clean", "-fdx")
          run_cmd("git", "-C", worktree_dir, "checkout", "--detach", "--force", sha)
          return
        end
      end

      FileUtils.rm_rf(worktree_dir)
      FileUtils.mkdir_p(worktree_dir)
      run_cmd("git", "-C", worktree_dir, "init", "-q")
      run_cmd("git", "-C", worktree_dir, "fetch", "--depth=1", mirror_url, ref_name)
      run_cmd("git", "-C", worktree_dir, "checkout", "--detach", "--force", "FETCH_HEAD")
    end

    def select_patch_files(patch_spec, fuzz_root: locate_fuzz_root)
      return [] if patch_spec == false || patch_spec.to_s.strip.downcase == "none"

      patches_dir = File.join(fuzz_root, "patches", "prism")
      return [] unless Dir.exist?(patches_dir)

      all_patches = Dir.glob(File.join(patches_dir, "*.patch")).sort
      return all_patches if patch_spec == true || patch_spec.nil? || patch_spec.to_s.strip.downcase == "auto"

      names = patch_spec.is_a?(Array) ? patch_spec.map(&:to_s) : patch_spec.to_s.split(",").map(&:strip).reject(&:empty?)
      names.map do |n|
        cand = File.exist?(n) ? File.expand_path(n) : File.join(patches_dir, File.basename(n))
        cand = "#{cand}.patch" unless File.file?(cand)
        raise TopologyError, "Missing patch file '#{n}' under #{patches_dir}" unless File.file?(cand)

        cand
      end
    end

    def mirror_objects_dir(mirror)
      return nil unless mirror

      base = File.expand_path(mirror)
      [File.join(base, "objects"), File.join(base, ".git", "objects")].find { |d| File.directory?(d) }
    end

    def apply_prism_patches!(worktree_dir, patch_files, mirror: nil)
      applied = []
      skipped = []
      alt_objects = mirror_objects_dir(mirror)
      three_way_env = if alt_objects
                        prev_alt = ENV["GIT_ALTERNATE_OBJECT_DIRECTORIES"].to_s.strip
                        val = prev_alt.empty? ? alt_objects : "#{prev_alt}#{File::PATH_SEPARATOR}#{alt_objects}"
                        { "GIT_ALTERNATE_OBJECT_DIRECTORIES" => val }
                      end

      patch_files.each do |patch|
        name = File.basename(patch)
        _, _, can_apply = run_cmd("git", "-C", worktree_dir, "apply", "--check", "--index", patch, allow_fail: true)
        if can_apply.success?
          run_cmd("git", "-C", worktree_dir, "apply", "--index", patch)
          applied << name
          next
        end

        _, _, already_in = run_cmd("git", "-C", worktree_dir, "apply", "--reverse", "--check", patch, allow_fail: true)
        if already_in.success?
          skipped << { "patch" => name, "reason" => "already_upstream" }
          next
        end

        _, _, can_c1 = run_cmd("git", "-C", worktree_dir, "apply", "-C1", "--check", "--index", patch, allow_fail: true)
        if can_c1.success?
          run_cmd("git", "-C", worktree_dir, "apply", "-C1", "--index", patch)
          applied << name
          next
        end

        _, err_3way, st_3way = run_cmd("git", "-C", worktree_dir, "apply", "--3way", patch, env: three_way_env, allow_fail: true)
        if st_3way.success?
          applied << name
        else
          raise TopologyError, "Patch '#{name}' failed to apply cleanly to #{worktree_dir}:\n#{err_3way}"
        end
      end
      [applied, skipped]
    end

    def templates_stale?(prism_dir)
      sentinel = File.join(prism_dir, "src", "node.c")
      ast_h = File.join(prism_dir, "include", "prism", "ast.h")
      return true unless File.file?(sentinel) && File.file?(ast_h)

      cfg = File.join(prism_dir, "config.yml")
      return false unless File.file?(cfg)

      newest_input = ([cfg] + Dir.glob(File.join(prism_dir, "templates", "**", "*")).select { |f| File.file?(f) }).map { |f| File.mtime(f) }.max
      newest_input && (File.mtime(sentinel) < newest_input || File.mtime(ast_h) < newest_input)
    end

    def ensure_prism_templates!(prism_dir, mode)
      return false if mode == false || mode.to_s.strip.downcase == "never"

      force = mode == true || mode.to_s.strip.downcase == "always"
      return false unless force || templates_stale?(prism_dir)

      tpl_script = File.join(prism_dir, "templates", "template.rb")
      raise TopologyError, "Missing templates/template.rb in #{prism_dir}" unless File.file?(tpl_script)

      run_cmd("ruby", "templates/template.rb", chdir: prism_dir)
      true
    end

    def ensure_harness_generated_inc!(prism_dir, gen_dir, fuzz_root: locate_fuzz_root)
      FileUtils.mkdir_p(gen_dir)
      cfg = File.join(prism_dir, "config.yml")
      locs = File.join(gen_dir, "node_locations.inc")
      if File.file?(cfg)
        walk = File.join(gen_dir, "node_serialize_walk.inc")
        gen_loc_rb = File.join(fuzz_root, "harnesses", "prism", "gen_node_locations.rb")
        gen_walk_rb = File.join(fuzz_root, "harnesses", "prism", "gen_serialize_walk.rb")

        cfg_mtime = File.mtime(cfg)
        run_cmd("ruby", gen_loc_rb, cfg, locs) if !File.file?(locs) || File.mtime(locs) < cfg_mtime || File.mtime(gen_loc_rb) > File.mtime(locs)
        run_cmd("ruby", gen_walk_rb, cfg, walk) if !File.file?(walk) || File.mtime(walk) < cfg_mtime || File.mtime(gen_walk_rb) > File.mtime(walk)
      end

      inc_dir = File.join(prism_dir, "include")
      if Dir.exist?(inc_dir)
        PrismFuzzCompat.generate!(
          include_dir: inc_dir,
          subloc_inc: File.file?(locs) ? locs : nil,
          out_path: File.join(gen_dir, "prism_fuzz_compat.h")
        )
      end
      gen_dir
    end

    def validate_prism_root!(dir)
      return if File.file?(File.join(dir, "include", "prism.h")) && File.directory?(File.join(dir, "src"))

      raise TopologyError, "Invalid Prism source directory '#{dir}' (expected include/prism.h and src/)"
    end

    def compute_patch_digest(patch_files)
      d = Digest::SHA256.new
      patch_files.each do |p|
        d.update("#{File.basename(p)}\0")
        d.update(File.binread(p))
        d.update("\0")
      end
      d.hexdigest
    end

    def sync_prism_source(spec, fuzz_root:, build_dir:, cache_dir:)
      role = spec.fetch("id")
      gen_dir = File.join(build_dir, "targets", "gen", role)
      state_path = File.join(build_dir, "targets", "#{role}.json")

      if spec["dir"]
        prism_dir = spec["dir"]
        validate_prism_root!(prism_dir) unless templates_stale?(prism_dir)
        ensure_prism_templates!(prism_dir, spec["templates"])
        validate_prism_root!(prism_dir)
        ensure_harness_generated_inc!(prism_dir, gen_dir, fuzz_root: fuzz_root)
        commit_out, _, commit_st = run_cmd("git", "-C", prism_dir, "rev-parse", "HEAD", allow_fail: true)
        commit = commit_st.success? ? commit_out.strip : nil
        state = {
          "schema_version" => 1,
          "role" => role,
          "mode" => "local_dir",
          "path" => prism_dir,
          "gen_dir" => gen_dir,
          "commit" => commit,
          "applied_patches" => [],
          "skipped_patches" => []
        }.compact
        write_json_atomic(state_path, state)
        return state
      end

      raise TopologyError, "No ref or dir configured for #{role}" if blank?(spec["ref"])

      mirror = ensure_mirror(cache_dir, "prism", spec.fetch("repo"))
      sha = resolve_git_ref!(mirror, spec.fetch("repo"), spec["ref"])
      worktree_dir = File.join(build_dir, "targets", role)
      patch_files = select_patch_files(spec["patches"], fuzz_root: fuzz_root)
      patch_digest = compute_patch_digest(patch_files)
      wt_state_path = File.join(worktree_dir, ".fuzz-target-state.json")

      prev = read_json(wt_state_path)
      can_reuse = prev &&
                  prev["commit"] == sha &&
                  prev["patch_digest"] == patch_digest &&
                  File.file?(File.join(worktree_dir, "include", "prism.h")) &&
                  File.directory?(File.join(worktree_dir, "src")) &&
                  !templates_stale?(worktree_dir)

      if can_reuse
        ensure_harness_generated_inc!(worktree_dir, gen_dir, fuzz_root: fuzz_root)
        reused = prev.merge("path" => worktree_dir, "gen_dir" => gen_dir)
        write_json_atomic(state_path, reused)
        return reused
      end

      checkout_detached_worktree!(mirror, sha, worktree_dir, role: role)
      applied, skipped = apply_prism_patches!(worktree_dir, patch_files, mirror: mirror)
      tpl_ran = ensure_prism_templates!(worktree_dir, spec["templates"])
      validate_prism_root!(worktree_dir)
      ensure_harness_generated_inc!(worktree_dir, gen_dir, fuzz_root: fuzz_root)

      state = {
        "schema_version" => 1,
        "role" => role,
        "mode" => "managed_worktree",
        "repo" => spec["repo"],
        "requested_ref" => spec["ref"],
        "commit" => sha,
        "path" => worktree_dir,
        "gen_dir" => gen_dir,
        "patch_digest" => patch_digest,
        "applied_patches" => applied,
        "skipped_patches" => skipped,
        "templates_generated" => tpl_ran
      }
      write_json_atomic(wt_state_path, state)
      write_json_atomic(state_path, state)
      state
    end

    def container_ruby_matches?(oracle_dir, ref)
      return false unless File.directory?(oracle_dir) && File.file?(File.join(oracle_dir, "libruby-static.a"))
      return true if blank?(ref)

      head_out, _, st = run_cmd("git", "-C", oracle_dir, "rev-parse", "HEAD", allow_fail: true)
      return false unless st.success?

      head = head_out.strip
      head.start_with?(ref) || ref.start_with?(head[0, 10])
    end

    def sync_ruby_source(spec, build_dir:, cache_dir:, allow_build: false)
      role = spec.fetch("id")
      state_path = File.join(build_dir, "targets", "#{role}.json")
      default_oracle = ENV.fetch("RUBY_ORACLE_DIR", "/opt/ruby")
      default_bin = ENV.fetch("COMPARE_RUBY", RbConfig.ruby)

      if spec["dir"]
        d = spec["dir"]
        unless File.file?(File.join(d, "parse.c")) && File.file?(File.join(d, "libruby-static.a"))
          raise TopologyError, "Invalid RUBY_DIR '#{d}' (missing parse.c or libruby-static.a)"
        end

        cand_bin = File.join(d, "ruby")
        rbin = File.executable?(cand_bin) ? cand_bin : default_bin
        return write_json_atomic(state_path, {
          "role" => role,
          "mode" => "local_dir",
          "oracle_dir" => d,
          "ruby_bin" => rbin,
          "requested_ref" => spec["ref"]
        }.compact)
      end

      if container_ruby_matches?(default_oracle, spec["ref"])
        head_out, _, st = run_cmd("git", "-C", default_oracle, "rev-parse", "HEAD", allow_fail: true)
        return write_json_atomic(state_path, {
          "role" => role,
          "mode" => "container_default",
          "oracle_dir" => default_oracle,
          "ruby_bin" => File.executable?("/usr/local/bin/ruby") ? "/usr/local/bin/ruby" : default_bin,
          "requested_ref" => spec["ref"],
          "commit" => st.success? ? head_out.strip : nil
        }.compact)
      end

      mirror = ensure_mirror(cache_dir, "ruby", spec.fetch("repo"))
      sha = resolve_git_ref!(mirror, spec.fetch("repo"), spec["ref"])
      ruby_base = File.join(build_dir, "targets", "ruby", sha[0, 12])
      src_dir = File.join(ruby_base, "src")
      inst_dir = File.join(ruby_base, "install")
      built_lib = File.join(src_dir, "libruby-static.a")
      built_ruby = File.join(inst_dir, "bin", "ruby")

      if !File.file?(built_lib) || !File.executable?(built_ruby)
        unless allow_build
          raise TopologyError, "RUBY_REF '#{spec['ref']}' (#{sha[0, 12]}) differs from '#{default_oracle}' and is not yet built; run 'make ruby-sync' or 'make docker-build RUBY_GIT_REF=#{sha}'"
        end

        checkout_detached_worktree!(mirror, sha, src_dir, role: role)
        FileUtils.mkdir_p(inst_dir)
        run_cmd("./autogen.sh", chdir: src_dir) if File.file?(File.join(src_dir, "autogen.sh"))
        run_cmd("./configure", "--disable-install-doc", "--prefix=#{inst_dir}", chdir: src_dir)
        jobs = ENV.fetch("JOBS", "8")
        run_cmd("make", "-j#{jobs}", chdir: src_dir)
        run_cmd("make", "install", chdir: src_dir)
      end

      write_json_atomic(state_path, {
        "role" => role,
        "mode" => "managed_build",
        "repo" => spec["repo"],
        "requested_ref" => spec["ref"],
        "commit" => sha,
        "oracle_dir" => src_dir,
        "ruby_bin" => built_ruby
      })
    end

    def sync_plan!(plan, fuzz_root: locate_fuzz_root, build_dir: nil, cache_dir: default_cache_dir(fuzz_root), allow_ruby_build: false)
      build_dir ||= workspace_paths(plan, fuzz_root: fuzz_root)[:build_dir]
      resolved = deep_dup(plan)
      targets_dir = File.join(build_dir, "targets")
      FileUtils.mkdir_p(targets_dir)

      # Remove stale state files for optional sources no longer active (e.g. prism_b cleared).
      Dir.glob(File.join(targets_dir, "*.json")).each do |st_file|
        base = File.basename(st_file, ".json")
        FileUtils.rm_f(st_file) unless resolved["sources"].key?(base)
      end

      resolved["sources"].each do |id, spec|
        PrismFuzzer::Progress.current_stage&.note("syncing source #{id} (#{spec['kind']})") if defined?(PrismFuzzer::Progress)
        state = if spec["kind"] == "prism"
                  sync_prism_source(spec, fuzz_root: fuzz_root, build_dir: build_dir, cache_dir: cache_dir)
                else
                  if File.directory?(ENV.fetch("RUBY_ORACLE_DIR", "/opt/ruby")) || spec["dir"] || allow_ruby_build
                    sync_ruby_source(spec, build_dir: build_dir, cache_dir: cache_dir, allow_build: allow_ruby_build)
                  else
                    nil
                  end
                end
        next unless state

        spec["resolved"] = state
        spec["path"] = state["path"] || state["oracle_dir"]
        spec["gen_dir"] = state["gen_dir"] if state["gen_dir"]
        spec["commit"] = state["commit"] if state["commit"]
        spec["oracle_dir"] = state["oracle_dir"] if state["oracle_dir"]
        spec["ruby_bin"] = state["ruby_bin"] if state["ruby_bin"]
      end

      write_json_atomic(File.join(build_dir, "topology.resolved.json"), resolved)
      resolved
    end
  end
end
