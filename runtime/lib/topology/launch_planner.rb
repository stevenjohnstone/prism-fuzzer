# frozen_string_literal: true

module PrismFuzzer
  module Topology
    module_function

    def select_shard_files(files, shard_index, shard_total)
      return [] if files.empty?

      total = [shard_total.to_i, 1].max
      idx = shard_index.to_i
      selected = []
      j = idx
      while j < files.size
        selected << files[j]
        j += total
      end
      selected << files[idx % files.size] if selected.empty?
      selected
    end

    def format_generator_worker_cmd(gen_spec, tmpdir:)
      env_vars = gen_spec.fetch("env_tokens")
      ulimit = gen_spec["ulimit_v_kb"].to_i
      prefix = ulimit > 0 ? "ulimit -v #{ulimit} && " : ""
      cmd = "#{prefix}#{env_vars.join(' ')} ruby #{Shellwords.escape(gen_spec.fetch('grammar_rb'))} #{Shellwords.escape(gen_spec.fetch('sync_dir'))} #{Shellwords.escape(gen_spec.fetch('seeds_dir'))}"
      "/bin/bash -c #{Shellwords.escape("AFL_TMPDIR=#{tmpdir} #{cmd}")}"
    end

    def format_afl_worker_cmd(launch_spec, tmpdir:, map_size: nil)
      env_prefix = launch_spec.fetch("env_prefix").dup
      if map_size && !map_size.to_s.empty?
        skip_idx = env_prefix.index("AFL_SKIP_BIN_CHECK=1")
        map_tok = "AFL_MAP_SIZE=#{Shellwords.escape(map_size.to_s)}"
        if skip_idx
          env_prefix.insert(skip_idx + 1, map_tok)
        else
          env_prefix << map_tok
        end
      end

      afl_args = launch_spec.fetch("afl_args_pre_input") +
                 ["-i", launch_spec.fetch("input_dir")] +
                 launch_spec.fetch("afl_args_post_input")
      target_cmd = launch_spec.fetch("target_cmd")

      ulimit = launch_spec["ulimit_v_kb"].to_i
      ulimit_prefix = ulimit > 0 ? "ulimit -v #{ulimit} && " : ""
      afl_line = +"#{ulimit_prefix}#{env_prefix.join(' ')}#{env_prefix.empty? ? '' : ' '}afl-fuzz #{afl_args.map { |a| Shellwords.escape(a.to_s) }.join(' ')} -- #{target_cmd.map { |a| Shellwords.escape(a.to_s) }.join(' ')}"
      afl_line << " || read -r -n 1" if launch_spec["keep_open_on_exit"]
      "/bin/bash -c #{Shellwords.escape("AFL_TMPDIR=#{tmpdir} #{afl_line}")}"
    end

    # Purely computes the tmux worker launch plan, shard/filter specs, sync layout,
    # and staging descriptors without creating directories, mutating /tmp/afl-tmpdir,
    # invoking corpus.rb, or executing target binaries.
    def plan_launch(plan, fuzz_root: locate_fuzz_root, fuzz_dir: nil, corpus_dir: nil, bin_dir: nil)
      default_ws = workspace_paths(plan, fuzz_root: fuzz_root, fuzz_dir: fuzz_dir, bin_dir: bin_dir)
      ws = workspace_paths(plan, fuzz_root: fuzz_root, fuzz_dir: fuzz_dir, corpus_dir: corpus_dir, bin_dir: bin_dir)
      fuzz_dir = ws[:fuzz_dir]
      corpus_dir = ws[:corpus_dir]
      bin_dir = ws[:bin_dir]
      corpus_overridden = !corpus_dir.nil? && corpus_dir != default_ws[:corpus_dir]
      repo_root = outer_repo_root(fuzz_root, fuzz_dir: fuzz_dir)
      ws_raw_dir = plan.dig("workspace", "dir")
      max_input_size = Integer(plan.dig("defaults", "max_input_size") || 1024)
      max_alloc_mb = Integer(plan.dig("defaults", "max_allocated_mb") || 128)
      hard_rss = max_alloc_mb * 16
      asan_opts = "abort_on_error=1:handle_abort=1:handle_segv=2:use_sigaltstack=1:detect_leaks=0:quarantine_size_mb=16:malloc_context_size=0:max_allocation_size_mb=#{max_alloc_mb}:hard_rss_limit_mb=#{hard_rss}:symbolize=0"
      ubsan_opts = "abort_on_error=1:symbolize=0"
      msan_opts = "exit_code=86:abort_on_error=1:max_allocation_size_mb=#{max_alloc_mb}:hard_rss_limit_mb=#{hard_rss}:symbolize=0"
      lsan_opts = "abort_on_error=1:handle_abort=1:max_allocation_size_mb=#{max_alloc_mb}:hard_rss_limit_mb=#{hard_rss}:symbolize=0"
      diff_bt = ENV.fetch("FUZZ_DIFF_BACKTRACE", "0")

      dict_cand = File.join(fuzz_dir, "snapshot", "dict", "prism.dict")
      dict_file = File.file?(dict_cand) ? dict_cand : File.join(fuzz_root, "dict", "prism.dict")
      grammar_rb_cand = File.join(fuzz_dir, "snapshot", "runtime", "grammar.rb")
      grammar_rb = File.file?(grammar_rb_cand) ? grammar_rb_cand : File.join(fuzz_root, "runtime", "grammar.rb")

      sync_groups = plan.fetch("sync_groups")
      grammar_gen = plan.fetch("generators", {}).values.find { |g| g["kind"] == "grammar" }
      primary_group_id = sync_groups.find { |_, g| g["primary"] }&.first || grammar_gen&.dig("sync_group") || sync_groups.keys.first
      primary_afl_dir = primary_group_id ? File.join(fuzz_dir, sync_groups.fetch(primary_group_id).fetch("dir")) : nil
      sync_dirs = sync_groups.values.map { |sg| File.join(fuzz_dir, sg.fetch("dir")) }

      corpus_gens = plan.fetch("generators", {}).select { |_, g| g["kind"] == "corpus" }
      corpus_populations = corpus_gens.map do |cg_id, corpus_gen|
        c_src = plan.fetch("sources").fetch(corpus_gen.fetch("source"))
        fixtures_dir = c_src["path"] ? File.join(c_src["path"], "test", "prism", "fixtures") : nil
        c_bin_rel = nil
        c_bin_candidates = []
        if corpus_gen["fuzzer"]
          c_fspec = plan.fetch("fuzzers").fetch(corpus_gen["fuzzer"])
          c_bin_rel = c_fspec.fetch("binary")
          c_bin_candidates << File.join(bin_dir, File.basename(c_bin_rel))
          c_bin_candidates << File.expand_path(c_bin_rel, repo_root)
          c_bin_candidates << File.expand_path(c_bin_rel, fuzz_root)
          c_bin_candidates.uniq!
        end
        out_cdir = resolve_corpus_generator_dir(
          corpus_gen["dir"],
          fuzz_dir: fuzz_dir,
          fuzz_root: fuzz_root,
          ws_raw_dir: ws_raw_dir,
          default_corpus_dir: corpus_dir
        )
        {
          "id" => cg_id.to_s,
          "output_dir" => out_cdir,
          "default_dir" => blank?(corpus_gen["dir"]),
          "corpus_rb" => File.join(fuzz_root, "runtime", "corpus.rb"),
          "fixtures_dir" => fixtures_dir,
          "fuzzer_binary_rel" => c_bin_rel,
          "fuzzer_bin_candidates" => c_bin_candidates,
          "max_input_size" => Integer(corpus_gen["max_input_size"] || max_input_size)
        }.compact
      end
      corpus_population = corpus_populations.first

      existing_corpus_files = Dir.exist?(corpus_dir) ? Dir.glob(File.join(corpus_dir, "*")).select { |p| File.file?(p) }.sort : []
      generator_seeds_dirs = grammar_seeds_dirs(plan)
      seeds_backup_dir = File.join(fuzz_dir, "seeds")

      group_worker_ids = Hash.new { |h, k| h[k] = [] }
      plan.fetch("workers").each do |w|
        next if w["kind"] == "generator" || w["sync_group"].nil?

        gdir = File.join(fuzz_dir, sync_groups.fetch(w.fetch("sync_group")).fetch("dir"))
        wid_s = w.fetch("id").to_s
        group_worker_ids[gdir] << wid_s unless group_worker_ids[gdir].include?(wid_s)
      end

      legacy_diff_migration = if primary_afl_dir
                                {
                                  "from" => File.join(fuzz_dir, "#{File.basename(primary_afl_dir)}-diff", "diff"),
                                  "to" => File.join(primary_afl_dir, "diff")
                                }
                              end

      peer_import_links = []
      plan.fetch("workers").each do |w|
        Array(w["peer_imports"]).each do |pi|
          dst_group_dir = File.join(fuzz_dir, sync_groups.fetch(w.fetch("sync_group")).fetch("dir"))
          src_group_dir = File.join(fuzz_dir, sync_groups.fetch(pi.fetch("group")).fetch("dir"))
          alias_name = pi.fetch("alias")
          src_worker = pi.fetch("worker")
          legacy_worker = File.join(dst_group_dir, src_worker)
          target_worker = File.join(src_group_dir, src_worker)
          target_queue = File.expand_path(File.join(target_worker, "queue"))
          peer_dir = File.join(dst_group_dir, alias_name)
          rel_target = Pathname.new(target_queue).relative_path_from(Pathname.new(File.expand_path(peer_dir))).to_s
          peer_import_links << {
            "dst_group_dir" => dst_group_dir,
            "src_group_dir" => src_group_dir,
            "alias" => alias_name,
            "src_worker" => src_worker,
            "legacy_worker" => legacy_worker,
            "target_worker" => target_worker,
            "target_queue" => target_queue,
            "peer_dir" => peer_dir,
            "rel_target" => rel_target
          }
        end
      end

      worker_entries = []
      plan.fetch("workers").each do |w|
        wid = w.fetch("id")
        tmpdir = "/tmp/afl-tmpdir/#{wid}"

        if w["kind"] == "generator"
          gspec = plan.fetch("generators").fetch(w.fetch("generator"))
          gid = gspec.fetch("id")
          sdir = generator_seeds_dirs.fetch(gid)
          src_id = gspec.fetch("source")
          src_spec = plan.fetch("sources").fetch(src_id)
          lib_dir = File.join(bin_dir, "prism_lib")
          lib_dir = File.join(bin_dir, "prism_lib_#{src_id}") if File.directory?(File.join(bin_dir, "prism_lib_#{src_id}"))
          lib_dir = File.join(src_spec.fetch("path"), "lib") unless File.directory?(lib_dir) || src_spec["path"].nil?

          ext_dir = File.join(bin_dir, "fuzz-ruby-ext")
          ext_cand = File.join(bin_dir, "fuzz-ruby-ext-#{src_id}")
          ext_dir = ext_cand if File.directory?(ext_cand)

          target_sync_dir = if gspec["sync_group"]
                              File.join(fuzz_dir, sync_groups.fetch(gspec["sync_group"]).fetch("dir"))
                            else
                              primary_afl_dir
                            end
          consumer_w = plan.fetch("workers").find do |cw|
            cw["kind"] != "generator" && Array(cw["foreign_sync"]).map(&:to_s).include?(gid)
          end
          intake_stats_path = if consumer_w
                                c_out_dir = File.join(fuzz_dir, sync_groups.fetch(consumer_w.fetch("sync_group")).fetch("dir"))
                                File.join(c_out_dir, consumer_w.fetch("id"), "fuzzer_stats")
                              else
                                ""
                              end

          gen_max_input = Integer(w["max_input_size"] || gspec["max_input_size"] || max_input_size)
          env_map = {
            "FUZZ_BIN_DIR" => bin_dir,
            "FUZZ_RUBY_EXT_DIR" => ext_dir,
            "FUZZ_RUBY_LIB_DIR" => lib_dir,
            "FUZZ_GRAMMAR_WORKER_ID" => wid,
            "FUZZ_INTAKE_STATS_PATH" => intake_stats_path,
            "FUZZ_MAX_INPUT_SIZE" => gen_max_input.to_s
          }
          env_vars = env_map.map { |k, v| "#{k}=#{Shellwords.escape(v)}" }
          if gspec["fuzzer"] && (g_fspec = plan.dig("fuzzers", gspec["fuzzer"].to_s))
            gbin = File.basename(g_fspec.fetch("binary"))
            env_map["FUZZ_GRAMMAR_BIN"] = gbin
            env_vars << "FUZZ_GRAMMAR_BIN=#{Shellwords.escape(gbin)}"
          end
          if w["env"].is_a?(Hash)
            w["env"].each do |k, v|
              env_map[k.to_s] = v.to_s
              env_vars << "#{k}=#{Shellwords.escape(v.to_s)}"
            end
          end

          ulimit = (w["ulimit_v_kb"] || gspec["ulimit_v_kb"]).to_i
          gen_launch = {
            "grammar_rb" => grammar_rb,
            "sync_dir" => target_sync_dir,
            "seeds_dir" => sdir,
            "source_id" => src_id,
            "source_path" => src_spec["path"],
            "fuzzer_bin" => env_map["FUZZ_GRAMMAR_BIN"],
            "intake_stats_path" => intake_stats_path,
            "max_input_size" => gen_max_input,
            "ulimit_v_kb" => ulimit,
            "extra_env" => w["env"].is_a?(Hash) ? w["env"].transform_keys(&:to_s).transform_values(&:to_s) : {},
            "env_tokens" => env_vars
          }.compact

          worker_entries << {
            "id" => wid,
            "kind" => "generator",
            "tmpdir" => tmpdir,
            "generator" => gid,
            "seeds_dir" => sdir,
            "sync_dir" => target_sync_dir,
            "env" => env_map,
            "generator_launch" => gen_launch,
            "cmd" => format_generator_worker_cmd(gen_launch, tmpdir: tmpdir),
            "staged" => false
          }
          next
        end

        fspec = plan.fetch("fuzzers").fetch(w.fetch("fuzzer"))
        bin_rel = fspec.fetch("binary")
        bin_path = File.join(bin_dir, File.basename(bin_rel))
        seed_cfg = w["seeds"].is_a?(Hash) ? w["seeds"] : {}
        seed_from_dir = nil
        if seed_cfg["from"]
          src_gen = plan.dig("generators", seed_cfg["from"].to_s)
          if src_gen && !blank?(src_gen["dir"])
            seed_from_dir = resolve_corpus_generator_dir(
              src_gen["dir"],
              fuzz_dir: fuzz_dir,
              fuzz_root: fuzz_root,
              ws_raw_dir: ws_raw_dir,
              default_corpus_dir: corpus_dir
            )
          end
        end
        eff_seed_from_dir = corpus_overridden ? nil : seed_from_dir

        base_seed_files = existing_corpus_files
        if eff_seed_from_dir && Dir.exist?(eff_seed_from_dir) && !Dir.children(eff_seed_from_dir).reject { |f| f.start_with?(".") }.empty?
          base_seed_files = Dir.glob(File.join(eff_seed_from_dir, "*")).select { |p| File.file?(p) }.sort
        end

        seed_filter = seed_cfg["filter"]&.to_s
        cache_key = (seed_cfg["cache_key"] || fspec["id"]).to_s
        has_shard = seed_cfg.key?("shard_index") && seed_cfg.key?("shard_total")
        shard_index = has_shard ? seed_cfg["shard_index"].to_i : nil
        shard_total = has_shard ? [seed_cfg["shard_total"].to_i, 1].max : nil
        seed_dir = "/tmp/afl-tmpdir/#{wid}/seeds"

        if seed_filter == "self_pass"
          input_dir = seed_dir
          selected_preview = nil
        elsif has_shard
          if !base_seed_files.empty?
            input_dir = seed_dir
            selected_preview = select_shard_files(base_seed_files, shard_index, shard_total)
          elsif corpus_populations.any?
            input_dir = seed_dir
            selected_preview = nil
          else
            input_dir = eff_seed_from_dir || corpus_dir
            selected_preview = []
          end
        else
          input_dir = eff_seed_from_dir || corpus_dir
          selected_preview = base_seed_files
        end

        out_dir = File.join(fuzz_dir, sync_groups.fetch(w.fetch("sync_group")).fetch("dir"))
        fspec_sans = Array(fspec["sanitizers"]).map(&:to_s)
        aux_fspec = if w["aux_fuzzer"] && !w["aux_fuzzer"].to_s.empty?
                      plan.dig("fuzzers", w["aux_fuzzer"].to_s)
                    end
        sans = aux_fspec ? (fspec_sans | Array(aux_fspec["sanitizers"]).map(&:to_s)) : fspec_sans

        env_prefix = []
        env_prefix << "FUZZ_DIFF_BACKTRACE=#{diff_bt}" if %w[prism_diff_ruby cruby_compile cruby_pipeline_diff].include?(fspec["shape"])
        env_prefix << "AFL_FUZZER_LOOPCOUNT=#{w['loopcount']}" if w["loopcount"]
        env_prefix << "AFL_DISABLE_TRIM=1" if w["no_trim"]
        w["env"].each { |k, v| env_prefix << "#{k}=#{Shellwords.escape(v.to_s)}" } if w["env"].is_a?(Hash)

        cross_oracle = nil
        cmplog_bin = nil
        aux_bin = nil
        mutator_name = nil

        worker_max_input = Integer(w["max_input_size"] || max_input_size)
        afl_max_raw = worker_max_input + 4

        if fspec["shape"] == "prism_cross_oracle"
          arch_cfg = CROSS_ARCH_CONFIGS.fetch(fspec.fetch("arch"))
          qemu_bin = arch_cfg[:qemu]
          sysroot = arch_cfg[:sysroot]
          mutator_name = File.basename(fspec["mutator"] || "mutator_oracle64.so")
          mutator_path = File.join(bin_dir, mutator_name)
          env_prefix << "AFL_CUSTOM_MUTATOR_LIBRARY=#{Shellwords.escape(mutator_path)}"
          env_prefix << "AFL_POST_PROCESS_KEEP_ORIGINAL=1"
          env_prefix << "__AFL_DEFER_FORKSRV=1"
          env_prefix << "__AFL_PERSISTENT=1"
          env_prefix << "AFL_SKIP_BIN_CHECK=1"
          env_prefix << "ASAN_OPTIONS=#{asan_opts}" if sans.include?("asan")
          env_prefix << "UBSAN_OPTIONS=#{ubsan_opts}" if sans.include?("ubsan")

          max_env = [afl_max_raw < 1028 ? 262_144 : afl_max_raw * 256, 1_048_576].min
          mem_limit = (w["mem_limit"] || "none").to_s
          afl_args_pre = ["-t", "250+", "-m", mem_limit, "-x", dict_file, "-G", max_env.to_s]
          afl_args_post = ["-o", out_dir, w["afl_role"] == "main" ? "-M" : "-S", wid]
          afl_args_post.push("-p", w["schedule"]) if w["schedule"]
          afl_args_post.concat(Array(w["afl_flags"]).map(&:to_s))
          target_cmd = [qemu_bin, "-L", sysroot, bin_path]
          cross_oracle = {
            "arch" => fspec.fetch("arch"),
            "qemu_bin" => qemu_bin,
            "sysroot" => sysroot,
            "bin_path" => bin_path,
            "mutator_name" => mutator_name,
            "asan_opts" => sans.include?("asan") ? asan_opts : nil,
            "map_size" => nil
          }
        else
          env_prefix << "MSAN_OPTIONS=#{msan_opts}" if sans.include?("msan")
          cruby_shapes = %w[prism_diff_ruby cruby_compile cruby_pipeline_diff]
          is_cruby_vm = cruby_shapes.include?(fspec["shape"]) || cruby_shapes.include?(aux_fspec&.dig("shape"))
          gc_disabled = w["env"].is_a?(Hash) && !w["env"]["FUZZ_DISABLE_GC"].to_s.empty? && w["env"]["FUZZ_DISABLE_GC"].to_s != "0"
          uar_opt = is_cruby_vm ? ":detect_stack_use_after_return=#{gc_disabled ? 1 : 0}" : ""
          asan_eff = "#{asan_opts}#{uar_opt}"
          env_prefix << "LSAN_OPTIONS=#{lsan_opts}" if sans.include?("lsan")
          env_prefix << "ASAN_OPTIONS=#{asan_eff}" if sans.include?("asan")
          env_prefix << "UBSAN_OPTIONS=#{ubsan_opts}" if sans.include?("ubsan")

          mem_limit = w["mem_limit"]&.to_s
          afl_args_pre = ["-t", "250+"]
          afl_args_pre.push("-m", mem_limit) if mem_limit
          afl_args_pre.push("-x", dict_file, "-G", afl_max_raw.to_s)
          if w["cmplog"] && !w["cmplog"].to_s.empty?
            cmplog_fspec = plan.dig("fuzzers", w["cmplog"].to_s)
            cmplog_bin = File.join(bin_dir, File.basename(cmplog_fspec ? cmplog_fspec["binary"] : w["cmplog"].to_s))
            afl_args_pre.push("-c", cmplog_bin)
          end
          if w["aux_fuzzer"] && !w["aux_fuzzer"].to_s.empty?
            aux_bin = File.join(bin_dir, File.basename(aux_fspec ? aux_fspec["binary"] : w["aux_fuzzer"].to_s))
            afl_args_pre.push("-w", aux_bin)
          end
          if (raw_mut = w["mutator"] || fspec["mutator"]) && !raw_mut.to_s.empty?
            mutator_name = File.basename(raw_mut.to_s)
            mutator_path = File.join(bin_dir, mutator_name)
            env_prefix << "AFL_CUSTOM_MUTATOR_LIBRARY=#{Shellwords.escape(mutator_path)}"
            if mutator_name == "libprismmutator.so"
              env_prefix << "PRISM_MUTATOR_HEADER_BYTES=4"
            end
          end
          afl_args_post = ["-o", out_dir, w["afl_role"] == "main" ? "-M" : "-S", wid]
          Array(w["foreign_sync"]).each do |gid|
            sdir = generator_seeds_dirs[gid.to_s]
            afl_args_post.push("-F", sdir) if sdir
          end
          afl_args_post.push("-p", w["schedule"]) if w["schedule"]
          afl_args_post.concat(Array(w["afl_flags"]).map(&:to_s))
          target_cmd = [bin_path]
        end

        self_pass_env = nil
        if seed_filter == "self_pass"
          # Reuse fuzz-time sanitizer options (especially ASan detect_leaks=0 / symbolize=0)
          # so embedded runtimes like CRuby do not fail LSan or stall on exit during seed screening.
          self_pass_env = { "FUZZ_DIFF_BACKTRACE" => "0" }
          gc_disabled = w["env"].is_a?(Hash) && !w["env"]["FUZZ_DISABLE_GC"].to_s.empty? && w["env"]["FUZZ_DISABLE_GC"].to_s != "0"
          uar_opt = %w[prism_diff_ruby cruby_compile cruby_pipeline_diff].include?(fspec["shape"]) ? ":detect_stack_use_after_return=#{gc_disabled ? 1 : 0}" : ""
          asan_eff = "#{asan_opts}#{uar_opt}"
          self_pass_env["MSAN_OPTIONS"] = msan_opts if fspec_sans.include?("msan")
          self_pass_env["LSAN_OPTIONS"] = lsan_opts if fspec_sans.include?("lsan")
          self_pass_env["ASAN_OPTIONS"] = asan_eff if fspec_sans.include?("asan")
          self_pass_env["UBSAN_OPTIONS"] = ubsan_opts if fspec_sans.include?("ubsan")
          w["env"].each { |k, v| self_pass_env[k.to_s] = v.to_s } if w["env"].is_a?(Hash)
        end

        ulimit = w["ulimit_v_kb"].to_i
        afl_launch = {
          "env_prefix" => env_prefix,
          "afl_args_pre_input" => afl_args_pre,
          "input_dir" => input_dir,
          "afl_args_post_input" => afl_args_post,
          "target_cmd" => target_cmd,
          "ulimit_v_kb" => ulimit,
          "keep_open_on_exit" => !!w["keep_open_on_exit"],
          "bin_name" => File.basename(bin_rel),
          "cmplog_name" => cmplog_bin ? File.basename(cmplog_bin) : nil,
          "aux_name" => aux_bin ? File.basename(aux_bin) : nil,
          "mutator_name" => mutator_name
        }.compact

        seeds_meta = {
          "from" => seed_cfg["from"]&.to_s,
          "from_dir" => seed_from_dir,
          "filter" => seed_filter,
          "cache_key" => cache_key,
          "bin_path" => bin_path,
          "bin_rel" => bin_rel,
          "seed_dir" => seed_dir,
          "shard_index" => shard_index,
          "shard_total" => shard_total,
          "selected_files" => selected_preview,
          "self_pass_env" => self_pass_env,
          "staged" => false
        }.compact

        worker_entries << {
          "id" => wid,
          "kind" => "afl",
          "fuzzer" => fspec.fetch("id"),
          "shape" => fspec.fetch("shape"),
          "tmpdir" => tmpdir,
          "input_dir" => input_dir,
          "output_dir" => out_dir,
          "seeds" => seeds_meta,
          "cross_oracle" => cross_oracle,
          "afl_launch" => afl_launch,
          "cmd" => format_afl_worker_cmd(afl_launch, tmpdir: tmpdir),
          "staged" => false
        }.compact
      end

      {
        "schema_version" => TOPOLOGY_SCHEMA_VERSION,
        "fuzz_dir" => fuzz_dir,
        "corpus_dir" => corpus_dir,
        "default_corpus_dir" => default_ws[:corpus_dir],
        "corpus_overridden" => corpus_overridden ? true : nil,
        "bin_dir" => bin_dir,
        "primary_afl_dir" => primary_afl_dir,
        "sync_dirs" => sync_dirs,
        "generator_seeds_dirs" => generator_seeds_dirs.values,
        "generator_seeds_map" => generator_seeds_dirs,
        "corpus_population" => corpus_population,
        "corpus_populations" => corpus_populations.empty? ? nil : corpus_populations,
        "staging" => {
          "seeds_backup_dir" => seeds_backup_dir,
          "group_worker_ids" => group_worker_ids,
          "legacy_diff_migration" => legacy_diff_migration,
          "peer_import_links" => peer_import_links
        }.compact,
        "worker_names" => worker_entries.map { |e| e["id"] },
        "workers" => worker_entries,
        "staged" => false
      }.compact
    end
  end
end
