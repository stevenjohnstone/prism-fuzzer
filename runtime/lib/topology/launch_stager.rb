# frozen_string_literal: true

module PrismFuzzer
  module Topology
    module_function

    def self_pass_env_for(seeds_meta, afl_launch)
      env = { "FUZZ_DIFF_BACKTRACE" => "0" }
      if seeds_meta["self_pass_env"].is_a?(Hash)
        seeds_meta["self_pass_env"].each { |k, v| env[k.to_s] = v.to_s }
      else
        # Support launch plans serialized without self_pass_env by reusing sanitizer flags.
        Array(afl_launch["env_prefix"]).each do |tok|
          k, v = tok.to_s.split("=", 2)
          next unless v && %w[ASAN_OPTIONS UBSAN_OPTIONS MSAN_OPTIONS LSAN_OPTIONS].include?(k)

          env[k] = v
        end
      end
      env
    end

    # Executes filesystem and subprocess side effects for a pre-computed launch plan:
    # directory creation, corpus generation, seed backup restore & cleanup, stale peer
    # cleanup, legacy migrations, peer_imports symlinks, self_pass validation & staging,
    # seed sharding copies into /tmp/afl-tmpdir/<wid>/seeds, and AFL_DUMP_MAP_SIZE probes.
    def stage_launch!(launch_plan, fuzz_root: locate_fuzz_root, corpus_dir: nil, bin_dir: nil)
      staged = deep_dup(launch_plan)
      fuzz_dir = staged.fetch("fuzz_dir")
      effective_corpus_dir = corpus_dir ? File.expand_path(corpus_dir, fuzz_root) : staged.fetch("corpus_dir")
      effective_bin_dir = bin_dir ? File.expand_path(bin_dir, fuzz_root) : staged.fetch("bin_dir")
      bin_overridden = effective_bin_dir != staged["bin_dir"]
      staged["corpus_dir"] = effective_corpus_dir
      staged["bin_dir"] = effective_bin_dir

      primary_afl_dir = staged["primary_afl_dir"]
      FileUtils.mkdir_p(primary_afl_dir) if primary_afl_dir

      if (cpop = staged["corpus_population"]).is_a?(Hash)
        if !Dir.exist?(effective_corpus_dir) || Dir.children(effective_corpus_dir).reject { |f| f.start_with?(".") }.empty?
          c_env = {}
          fixtures_dir = cpop["fixtures_dir"]
          c_env["CORPUS_FIXTURES_DIR"] = fixtures_dir if fixtures_dir && Dir.exist?(fixtures_dir)
          cands = []
          if (frel = cpop["fuzzer_binary_rel"])
            cands << File.join(effective_bin_dir, File.basename(frel))
            cands.concat(Array(cpop["fuzzer_bin_candidates"]))
            cands << File.expand_path(frel, fuzz_root)
          end
          c_bin = cands.compact.uniq.find { |p| File.executable?(p) }
          c_env["CORPUS_FUZZ_BIN"] = c_bin if c_bin
          if cpop["max_input_size"] && ENV["FUZZ_MAX_INPUT_SIZE"].to_s.strip.empty?
            c_env["FUZZ_MAX_INPUT_SIZE"] = cpop["max_input_size"].to_s
          end
          run_cmd(RbConfig.ruby, cpop.fetch("corpus_rb"), effective_corpus_dir, env: c_env)
        end
      end

      corpus_files = Dir.exist?(effective_corpus_dir) ? Dir.glob(File.join(effective_corpus_dir, "*")).select { |p| File.file?(p) }.sort : []

      generator_seeds_dirs = staged.fetch("generator_seeds_map", {})
      generator_seeds_dirs.each_value { |sdir| FileUtils.mkdir_p(sdir) }

      staging_meta = staged["staging"].is_a?(Hash) ? staged["staging"] : {}
      seeds_backup_dir = staging_meta["seeds_backup_dir"] || File.join(fuzz_dir, "seeds")
      if Dir.exist?(seeds_backup_dir) && !generator_seeds_dirs.empty?
        first_sdir = generator_seeds_dirs.values.first
        Dir.children(seeds_backup_dir).each do |fn|
          next if fn.start_with?(".")

          src = File.join(seeds_backup_dir, fn)
          if File.directory?(src)
            target_sdir = generator_seeds_dirs[fn]
            next unless target_sdir

            Dir.children(src).each do |sub_fn|
              next if sub_fn.start_with?(".")

              sub_src = File.join(src, sub_fn)
              FileUtils.cp(sub_src, File.join(target_sdir, sub_fn)) if File.file?(sub_src)
            end
          elsif File.file?(src)
            FileUtils.cp(src, File.join(first_sdir, fn))
          end
        end
        FileUtils.rm_rf(seeds_backup_dir)
      end

      group_worker_ids = {}
      staging_meta.fetch("group_worker_ids", {}).each do |gdir, wids|
        group_worker_ids[gdir] = Array(wids).to_set
      end
      staged.fetch("sync_dirs", []).each do |gdir|
        FileUtils.mkdir_p(gdir)
        active_wids = group_worker_ids[gdir] || Set.new
        Dir.children(gdir).each do |entry|
          next if entry.start_with?(".") || active_wids.include?(entry)

          p = File.join(gdir, entry)
          next unless File.directory?(p) && File.symlink?(File.join(p, "queue"))

          FileUtils.rm_rf(p)
        end
      end

      if (legacy_diff = staging_meta["legacy_diff_migration"]).is_a?(Hash)
        legacy_diff_dir = legacy_diff.fetch("from")
        target_diff_dir = legacy_diff.fetch("to")
        if File.directory?(legacy_diff_dir) && !File.exist?(target_diff_dir)
          FileUtils.mv(legacy_diff_dir, target_diff_dir)
          FileUtils.rm_f(File.join(target_diff_dir, "is_main_node"))
        end
      end

      Array(staging_meta["peer_import_links"]).each do |pi|
        src_group_dir = pi.fetch("src_group_dir")
        legacy_worker = pi.fetch("legacy_worker")
        target_worker = pi.fetch("target_worker")
        target_queue = pi.fetch("target_queue")
        peer_dir = pi.fetch("peer_dir")
        rel_target = pi.fetch("rel_target")

        if File.file?(File.join(legacy_worker, "fuzzer_stats")) && !File.exist?(target_worker)
          FileUtils.mkdir_p(src_group_dir)
          FileUtils.mv(legacy_worker, target_worker)
        end
        FileUtils.rm_rf(File.join(src_group_dir, ".foreign"))
        FileUtils.mkdir_p(target_queue)
        FileUtils.mkdir_p(peer_dir)
        FileUtils.ln_s(rel_target, File.join(peer_dir, "queue"), force: true)
        FileUtils.rm_f(File.join(peer_dir, "is_main_node"))
      end

      filtered_seed_cache = {}
      staged.fetch("workers", []).each do |w|
        wid = w.fetch("id")
        tmpdir = w["tmpdir"] || "/tmp/afl-tmpdir/#{wid}"
        FileUtils.mkdir_p(tmpdir)

        if w["kind"] == "generator"
          if bin_overridden && (gl = w["generator_launch"]).is_a?(Hash)
            src_id = gl["source_id"]
            lib_dir = File.join(effective_bin_dir, "prism_lib")
            lib_dir = File.join(effective_bin_dir, "prism_lib_#{src_id}") if src_id && File.directory?(File.join(effective_bin_dir, "prism_lib_#{src_id}"))
            lib_dir = File.join(gl["source_path"], "lib") if !File.directory?(lib_dir) && gl["source_path"]

            ext_dir = File.join(effective_bin_dir, "fuzz-ruby-ext")
            ext_cand = src_id ? File.join(effective_bin_dir, "fuzz-ruby-ext-#{src_id}") : nil
            ext_dir = ext_cand if ext_cand && File.directory?(ext_cand)

            env_map = {
              "FUZZ_BIN_DIR" => effective_bin_dir,
              "FUZZ_RUBY_EXT_DIR" => ext_dir,
              "FUZZ_RUBY_LIB_DIR" => lib_dir,
              "FUZZ_GRAMMAR_WORKER_ID" => wid,
              "FUZZ_INTAKE_STATS_PATH" => gl["intake_stats_path"].to_s
            }
            env_tokens = env_map.map { |k, v| "#{k}=#{Shellwords.escape(v)}" }
            if gl["fuzzer_bin"]
              env_map["FUZZ_GRAMMAR_BIN"] = gl["fuzzer_bin"]
              env_tokens << "FUZZ_GRAMMAR_BIN=#{Shellwords.escape(gl['fuzzer_bin'])}"
            end
            if gl["extra_env"].is_a?(Hash)
              gl["extra_env"].each do |k, v|
                env_map[k] = v
                env_tokens << "#{k}=#{Shellwords.escape(v)}"
              end
            end
            gl["env_tokens"] = env_tokens
            w["env"] = env_map
            w["cmd"] = format_generator_worker_cmd(gl, tmpdir: tmpdir)
          end
          w["staged"] = true
          next
        end

        seeds_meta = w["seeds"].is_a?(Hash) ? w["seeds"] : {}
        afl_launch = w.fetch("afl_launch")
        bin_name = afl_launch["bin_name"] || File.basename(seeds_meta.fetch("bin_path"))
        bin_path = bin_overridden ? File.join(effective_bin_dir, bin_name) : (seeds_meta["bin_path"] || File.join(effective_bin_dir, bin_name))

        base_seed_files = corpus_files
        if (from_dir = seeds_meta["from_dir"]) && Dir.exist?(from_dir) && !Dir.children(from_dir).reject { |f| f.start_with?(".") }.empty?
          base_seed_files = Dir.glob(File.join(from_dir, "*")).select { |p| File.file?(p) }.sort
        end

        selected_files = base_seed_files
        need_seed_copy = false
        if seeds_meta["filter"] == "self_pass"
          ckey = seeds_meta["cache_key"] || w["fuzzer"] || wid
          passing = filtered_seed_cache[ckey]
          unless passing
            pass_env = self_pass_env_for(seeds_meta, afl_launch)
            co = w["cross_oracle"].is_a?(Hash) ? w["cross_oracle"] : nil
            exec_cmd = co ? [co.fetch("qemu_bin"), "-L", co.fetch("sysroot"), bin_path] : [bin_path]
            passing = []
            q = Queue.new
            base_seed_files.each { |f| q << f }
            mu = Mutex.new
            [Etc.nprocessors, 1].max.times.map do
              Thread.new do
                loop do
                  begin
                    f = q.pop(true)
                  rescue ThreadError
                    f = nil
                  end
                  break unless f
                  next unless system(pass_env, *exec_cmd, f, [:out, :err] => File::NULL)

                  mu.synchronize { passing << f }
                end
              end
            end.each(&:join)
            passing.sort!
            filtered_seed_cache[ckey] = passing
          end
          if passing.empty?
            raise TopologyError, "Seed filter 'self_pass' for worker '#{wid}' (#{w['fuzzer'] || ckey}) matched 0 of #{base_seed_files.size} seeds; verify differential baseline/candidate compatibility."
          end

          selected_files = passing
          need_seed_copy = true
        end

        if seeds_meta.key?("shard_index") && seeds_meta.key?("shard_total") && !selected_files.empty?
          selected_files = select_shard_files(selected_files, seeds_meta["shard_index"], seeds_meta["shard_total"])
          need_seed_copy = true
        end

        input_dir = effective_corpus_dir
        if need_seed_copy
          seed_dir = seeds_meta["seed_dir"] || "/tmp/afl-tmpdir/#{wid}/seeds"
          FileUtils.rm_rf(seed_dir)
          FileUtils.mkdir_p(seed_dir)
          selected_files.each { |f| FileUtils.cp(f, File.join(seed_dir, File.basename(f))) }
          input_dir = seed_dir
        end

        seeds_meta["bin_path"] = bin_path if seeds_meta.key?("bin_path")
        seeds_meta["selected_files"] = selected_files
        seeds_meta["staged"] = true
        w["input_dir"] = input_dir
        afl_launch["input_dir"] = input_dir

        if bin_overridden
          rebind_afl_bin_paths!(afl_launch, effective_bin_dir, bin_path)
        end

        map_size = nil
        if (co = w["cross_oracle"]).is_a?(Hash)
          co_bin = bin_overridden ? bin_path : (co["bin_path"] || bin_path)
          co["bin_path"] = co_bin
          dump_env = { "AFL_DUMP_MAP_SIZE" => "1" }
          dump_env["ASAN_OPTIONS"] = co["asan_opts"] if co["asan_opts"]
          map_out, _ = Open3.capture2(dump_env, co.fetch("qemu_bin"), "-L", co.fetch("sysroot"), co_bin)
          map_size = map_out.strip
          co["map_size"] = map_size unless map_size.empty?
        end

        w["cmd"] = format_afl_worker_cmd(afl_launch, tmpdir: tmpdir, map_size: map_size)
        w["staged"] = true
      end

      staged["staged"] = true
      staged
    end

    def rebind_afl_bin_paths!(afl_launch, bin_dir, bin_path)
      tcmd = afl_launch["target_cmd"]
      tcmd[-1] = bin_path if tcmd.is_a?(Array) && !tcmd.empty?

      if (mname = afl_launch["mutator_name"])
        mpath = File.join(bin_dir, mname)
        afl_launch["env_prefix"].map! do |tok|
          tok.start_with?("AFL_CUSTOM_MUTATOR_LIBRARY=") ? "AFL_CUSTOM_MUTATOR_LIBRARY=#{Shellwords.escape(mpath)}" : tok
        end
      end

      pre = afl_launch["afl_args_pre_input"]
      { "-c" => afl_launch["cmplog_name"], "-w" => afl_launch["aux_name"] }.each do |flag, name|
        next unless name
        next unless (idx = pre.index(flag)) && idx + 1 < pre.size

        pre[idx + 1] = File.join(bin_dir, name)
      end
    end

    # Prepares seed shards, self-pass filtered diff seeds, foreign sync / shadow
    # peer directories, and emits the concrete tmux worker launch plan.
    def plan_launch!(plan, fuzz_root: locate_fuzz_root, fuzz_dir: nil, corpus_dir: nil, bin_dir: nil)
      launch = plan_launch(plan, fuzz_root: fuzz_root, fuzz_dir: fuzz_dir, corpus_dir: corpus_dir, bin_dir: bin_dir)
      stage_launch!(launch, fuzz_root: fuzz_root, corpus_dir: corpus_dir, bin_dir: bin_dir)
    end
  end
end
