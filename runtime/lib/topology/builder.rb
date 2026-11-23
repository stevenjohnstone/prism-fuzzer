# frozen_string_literal: true

module PrismFuzzer
  module Topology
    module_function

    def read_prism_version(prism_dir)
      header = File.join(prism_dir, "include", "prism", "version.h")
      return nil unless File.file?(header)

      File.read(header, encoding: "BINARY")[/^\s*#\s*define\s+PRISM_VERSION\s+"([^"]+)"/, 1]
    rescue Errno::ENOENT, Errno::ENOTDIR
      nil
    rescue SystemCallError, IOError => e
      warn "PrismFuzzer::Topology: failed to read #{header}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
      nil
    end

    def prism_c_sources(prism_dir)
      (Dir.glob(File.join(prism_dir, "src", "*.c")) + Dir.glob(File.join(prism_dir, "src", "*", "*.c"))).sort
    end

    def prism_headers(prism_dir)
      (
        Dir.glob(File.join(prism_dir, "include", "*.h")) +
        Dir.glob(File.join(prism_dir, "include", "prism", "*.h")) +
        Dir.glob(File.join(prism_dir, "include", "prism", "*", "*.h"))
      ).sort
    end

    def parse_user_flags(raw_flags = ENV["FUZZ_FLAGS"].to_s)
      Shellwords.split(raw_flags.to_s)
    end

    def normalized_flag_names(tokens)
      names = Set.new
      i = 0
      while i < tokens.size
        tok = tokens[i]
        if tok == "-D" && i + 1 < tokens.size
          names << tokens[i + 1].split("=", 2).first
          i += 2
          next
        elsif tok.start_with?("-D")
          names << tok.delete_prefix("-D").split("=", 2).first
        end
        i += 1
      end
      names
    end

    def common_define_flags(plan, user_flags: parse_user_flags, extra_flags: [])
      defined = normalized_flag_names(user_flags + Array(extra_flags))
      max_in = plan.dig("defaults", "max_input_size") || 1024
      max_alloc = plan.dig("defaults", "max_allocated_mb") || 128
      defaults = {
        "PM_INTEGER_DIVIDE_THRESHOLD" => 8,
        "PRISM_DEPTH_MAXIMUM" => 128,
        "FUZZ_MAX_INPUT_SIZE" => max_in,
        "FUZZ_MAX_ALLOCATED" => max_alloc,
        "FUZZ_HARD_RSS_LIMIT" => max_alloc * 16
      }
      out = []
      defaults.each do |macro, val|
        out << "-D#{macro}=#{val}" unless defined.include?(macro)
      end
      cleaned_user = user_flags.reject { |t| DEFAULT_WARNING_FLAGS.include?(t) }
      out + cleaned_user + DEFAULT_WARNING_FLAGS
    end

    def source_provenance_flags(src_spec)
      commit = src_spec["commit"]
      if blank?(commit) && src_spec["path"]
        out, st = Open3.capture2e("git", "-C", src_spec["path"], "rev-parse", "HEAD")
        commit = out.strip if st.success? && out.strip =~ /\A[0-9a-f]{40}\z/i
      end
      commit = "unknown" if blank?(commit)

      dirty = "unknown"
      if src_spec["path"] && File.directory?(src_spec["path"])
        out, st = Open3.capture2e("git", "--no-optional-locks", "-C", src_spec["path"], "status", "--porcelain", "--", "src", "include", "templates")
        dirty = st.success? ? (out.strip.empty? ? "0" : "1") : "0"
      end
      ["-DFUZZ_GIT_COMMIT=#{commit}", "-DFUZZ_GIT_DIRTY=#{dirty}"]
    end

    def newest_mtime(paths)
      paths.filter_map { |p| File.exist?(p) ? File.mtime(p) : nil }.max
    end

    def stamp_up_to_date?(stamp_path, binary_path, expected_key, input_files)
      return false unless File.file?(binary_path) && File.file?(stamp_path)

      prev = read_json(stamp_path)
      return false unless prev && prev["key"] == expected_key

      bin_mtime = File.mtime(binary_path)
      max_in = newest_mtime(input_files)
      return true unless max_in

      max_in <= bin_mtime
    end

    def record_stamp(stamp_path, key, binary_path)
      write_json_atomic(stamp_path, { "key" => key, "binary" => binary_path, "built_at" => Time.now.utc.to_i })
    end

    def split_extra_flags(var_name)
      Shellwords.split(ENV.fetch(var_name, ""))
    end

    def build_key_digest(payload)
      Digest::SHA256.hexdigest(JSON.generate(payload))[0, 16]
    end

    def fuzzer_override_flags(fspec)
      fuzzer_cflags = fspec["cflags"].is_a?(Array) ? fspec["cflags"].map(&:to_s) : []
      fuzzer_defines = if fspec["defines"].is_a?(Hash)
                         fspec["defines"].map { |k, v| v == true ? "-D#{k}" : "-D#{k}=#{v}" }
                       else
                         []
                       end
      override_flags = fuzzer_cflags + fuzzer_defines
      user_flags = parse_user_flags
      override_macros = normalized_flag_names(user_flags + override_flags)
      [override_flags, user_flags, override_macros, fuzzer_defines]
    end

    def format_dry_run_tokens(tokens)
      fmt = ->(s) { s.match?(/\A[A-Za-z0-9_.\/:=,-]+\z/) ? s : Shellwords.escape(s) }
      tokens.map { |t| fmt.call(t.to_s) }.join(" ")
    end

    def sanitizer_afl_env(sans)
      env = {}
      env["AFL_USE_MSAN"] = "1" if sans.include?("msan")
      env["AFL_USE_LSAN"] = "1" if sans.include?("lsan")
      if sans.include?("ubsan")
        env["AFL_USE_UBSAN"] = "1"
        env["AFL_UBSAN_VERBOSE"] = "1"
      end
      env
    end

    def explain_sources_and_deps(src_dir, gen_dir, fuzz_root:)
      c_files = prism_c_sources(src_dir)
      h_files = prism_headers(src_dir)
      explain_srcs = [
        File.join(fuzz_root, "harnesses", "prism", "explain.c"),
        File.join(fuzz_root, "harnesses", "prism", "explain", "analysis.c"),
        File.join(fuzz_root, "harnesses", "prism", "explain", "prettyprint.c"),
        File.join(fuzz_root, "harnesses", "prism", "explain", "json_digest.c")
      ]
      deps = c_files + h_files + explain_srcs + [
        File.join(fuzz_root, "harnesses", "prism", "explain", "explain.h"),
        File.join(fuzz_root, "harnesses", "prism", "include", "fuzz_invariants.h"),
        File.join(fuzz_root, "harnesses", "prism", "include", "fuzz_options.h"),
        File.join(fuzz_root, "harnesses", "prism", "include", "fuzz_json.h"),
        File.join(gen_dir, "node_locations.inc")
      ]
      inc_flags = [
        "-I#{File.join(src_dir, 'include')}",
        "-I#{gen_dir}",
        "-I#{File.join(fuzz_root, 'harnesses', 'prism')}",
        "-I#{File.join(fuzz_root, 'harnesses', 'prism', 'include')}"
      ]
      [c_files, explain_srcs, deps, inc_flags]
    end

    def build_prism_parse!(id, fspec, plan:, fuzz_root:, build_dir:, afl_path:, afl_stamp:, dry_run: false)
      src = plan.fetch("sources").fetch(fspec.fetch("source"))
      src_dir = src.fetch("path")
      gen_dir = src.fetch("gen_dir")
      out_path = File.expand_path(fspec.fetch("binary"), fuzz_root)
      stamps_dir = File.join(build_dir, ".stamps")
      FileUtils.mkdir_p(File.dirname(out_path))

      c_files = prism_c_sources(src_dir)
      h_files = prism_headers(src_dir)
      inc_dirs = [
        File.join(src_dir, "include"),
        gen_dir,
        File.join(fuzz_root, "harnesses", "prism"),
        File.join(fuzz_root, "harnesses", "prism", "include")
      ]
      harness_srcs = [
        File.join(fuzz_root, "harnesses", "prism", "parse.c"),
        File.join(fuzz_root, "harnesses", "prism", "fuzz.c")
      ]
      harness_hdrs = [
        File.join(fuzz_root, "harnesses", "prism", "include", "fuzz_invariants.h"),
        File.join(fuzz_root, "harnesses", "prism", "include", "fuzz_options.h"),
        File.join(fuzz_root, "harnesses", "prism", "include", "prism_ijon.h"),
        File.join(fuzz_root, "harnesses", "prism", "include", "prism_xallocator.h"),
        File.join(gen_dir, "node_locations.inc")
      ]

      afl_mode = fspec["afl"].to_s.empty? ? "lto" : fspec["afl"].to_s
      ijon_enabled = !!fspec["ijon"]
      sans = Array(fspec["sanitizers"]).map(&:to_s)
      mode = fspec["mode"].to_s

      if afl_mode == "cmplog"
        c_files = c_files.reject { |p| File.basename(p) == "strncasecmp.c" }
      end

      override_flags, user_flags, override_macros, = fuzzer_override_flags(fspec)

      flags = []
      flags.concat(split_extra_flags("DEBUG_FLAGS"))
      flags.concat(split_extra_flags("CPPFLAGS"))
      flags.concat(split_extra_flags("CFLAGS"))
      if (!sans.empty? || fspec["xallocator"]) && !override_macros.include?("PM_ARENA_INITIAL_SIZE")
        flags << "-DPM_ARENA_INITIAL_SIZE=0"
      end
      if mode == "slow"
        flags << "-DSLOW"
      else
        flags.concat(%w[-DPRISM_EXCLUDE_SERIALIZATION -DPRISM_EXCLUDE_JSON -DPRISM_EXCLUDE_PRETTYPRINT])
      end
      flags.concat(common_define_flags(plan, user_flags: user_flags, extra_flags: override_flags))
      flags.concat(source_provenance_flags(src))
      inc_dirs.each { |d| flags << "-I#{d}" }
      flags << "-DPRISM_FUZZ_IJON" if ijon_enabled
      if afl_mode != "cmplog" && !override_macros.include?("PRISM_FUZZ_INLINE_ASSERTS") && !override_macros.include?("PRISM_NO_INLINE_ASSERTS")
        flags << "-DPRISM_FUZZ_INLINE_ASSERTS"
      end
      flags << "-DPRISM_XALLOCATOR" if fspec["xallocator"]
      flags << "-Dpm_strncasecmp=strncasecmp" if afl_mode == "cmplog"
      flags.concat(override_flags)
      san_arg = sans.include?("asan") ? "-fsanitize=address,fuzzer" : "-fsanitize=fuzzer"
      flags.concat([san_arg, "-ggdb3", "-std=c99"])

      cc_bin = afl_mode == "pcguard" ? "afl-clang-fast" : "afl-clang-lto"
      env = { "AFL_PATH" => afl_path }
      env["AFL_LLVM_INSTRUMENT"] = "PCGUARD" if afl_mode == "pcguard"
      env.merge!(sanitizer_afl_env(sans))
      env["AFL_LLVM_IJON"] = "1" if ijon_enabled
      env["AFL_LLVM_ONLY_FSRV"] = "1" if afl_mode == "sand"
      env["AFL_LLVM_CMPLOG"] = "1" if afl_mode == "cmplog"
      if fspec["document_ids"]
        ids_path = File.expand_path(fspec.fetch("ids_file"), fuzz_root)
        env["AFL_LLVM_DOCUMENT_IDS"] = ids_path
      end

      bkey = build_key_digest({ shape: "prism_parse", id: id, afl: afl_mode, ijon: ijon_enabled, env: env, flags: flags, src: src["commit"], patch: src.dig("resolved", "patch_digest") })
      stamp_file = File.join(stamps_dir, "#{id}.json")
      deps = c_files + h_files + harness_srcs + harness_hdrs + [afl_stamp]
      if dry_run
        fmt = ->(s) { s.match?(/\A[A-Za-z0-9_.\/:=,-]+\z/) ? s : Shellwords.escape(s) }
        env_str = env.map { |k, v| "#{k}=#{fmt.call(v.to_s)}" }.join(" ")
        puts "#{env_str} #{cc_bin} #{flags.map { |f| fmt.call(f) }.join(' ')} -o #{fmt.call(out_path)} #{(c_files + harness_srcs).map { |p| fmt.call(p) }.join(' ')}"
        return
      end
      return if stamp_up_to_date?(stamp_file, out_path, bkey, deps) && (!fspec["document_ids"] || File.file?(env["AFL_LLVM_DOCUMENT_IDS"]))

      log_progress "building #{id} (#{mode}, sanitizers=#{sans.empty? ? 'none' : sans.join('+')}, afl=#{afl_mode}#{ijon_enabled ? '+ijon' : ''})"
      FileUtils.rm_f(env["AFL_LLVM_DOCUMENT_IDS"]) if env["AFL_LLVM_DOCUMENT_IDS"]
      tmp_out = "#{out_path}.tmp.#{Process.pid}"
      run_cmd(cc_bin, *flags, "-o", tmp_out, *c_files, *harness_srcs, env: env)
      File.rename(tmp_out, out_path)
      record_stamp(stamp_file, bkey, out_path)
    ensure
      FileUtils.rm_f(tmp_out) if tmp_out && File.exist?(tmp_out)
    end

    def build_prism_diff_ruby!(id, fspec, plan:, fuzz_root:, build_dir:, afl_path:, afl_stamp:, dry_run: false)
      prism_src = plan.fetch("sources").fetch(fspec.fetch("prism"))
      ruby_src = plan.fetch("sources").fetch(fspec.fetch("ruby"))
      out_path = File.expand_path(fspec.fetch("binary"), fuzz_root)
      stamps_dir = File.join(build_dir, ".stamps")
      stamp_file = File.join(stamps_dir, "#{id}.json")
      afl_mode = fspec["afl"].to_s.empty? ? "pcguard" : fspec["afl"].to_s
      ijon_enabled = !!fspec["ijon"]
      sans = Array(fspec["sanitizers"]).map(&:to_s)
      override_flags, user_flags, override_macros, = fuzzer_override_flags(fspec)

      extra_cflags = []
      extra_cflags << "-DPRISM_FUZZ_IJON" if ijon_enabled
      if !sans.empty? && !override_macros.include?("PM_ARENA_INITIAL_SIZE")
        extra_cflags << "-DPM_ARENA_INITIAL_SIZE=0"
      end
      extra_cflags.concat(user_flags)
      extra_cflags.concat(override_flags)

      env = {
        "FUZZ_GIT_COMMIT" => "",
        "FUZZ_GIT_DIRTY" => ""
      }
      env["AFL_USE_ASAN"] = "1" if sans.include?("asan")
      env.merge!(sanitizer_afl_env(sans))
      env["AFL_LLVM_IJON"] = "1" if ijon_enabled

      if dry_run
        san_env = env.reject { |k, _| k.start_with?("FUZZ_GIT_") }
        env_tokens = san_env.map { |k, v| "#{k}=#{v}" }
        env_str = env_tokens.empty? ? "" : "#{format_dry_run_tokens(env_tokens)} "
        cflag_tokens = extra_cflags.flat_map { |f| ["--cflag", f] }
        cflag_str = cflag_tokens.empty? ? "" : " #{format_dry_run_tokens(cflag_tokens)}"
        puts "#{env_str}build_diff.sh --mode fuzz --oracle-dir #{Shellwords.escape(File.join(build_dir, 'diff-oracle'))}#{cflag_str} --output #{Shellwords.escape(fspec.fetch('binary'))}"
        return
      end

      build_diff_sh = File.join(fuzz_root, "harnesses", "prism", "build_diff.sh")
      deps = prism_c_sources(prism_src.fetch("path")) +
             prism_headers(prism_src.fetch("path")) +
             [
               File.join(fuzz_root, "harnesses", "prism", "diff.c"),
               File.join(fuzz_root, "harnesses", "prism", "diff", "summary.h"),
               File.join(fuzz_root, "harnesses", "prism", "diff", "summary.c"),
               File.join(fuzz_root, "harnesses", "prism", "diff", "cruby_vm.h"),
               File.join(fuzz_root, "harnesses", "prism", "diff", "cruby_vm.c"),
               File.join(fuzz_root, "harnesses", "prism", "diff", "prism_walker.h"),
               File.join(fuzz_root, "harnesses", "prism", "diff", "prism_walker.c"),
               File.join(fuzz_root, "harnesses", "prism", "diff", "cruby_walker.c"),
               File.join(fuzz_root, "harnesses", "prism", "include", "prism_ijon.h"),
               build_diff_sh,
               File.join(fuzz_root, "harnesses", "prism", "gen_diff_ids.rb"),
               File.join(fuzz_root, "runtime", "provenance.rb"),
               afl_stamp
             ]
      max_in = (plan.dig("defaults", "max_input_size") || 1024).to_s
      prov_flags = source_provenance_flags(prism_src)
      env["FUZZ_GIT_COMMIT"] = prov_flags[0].split("=", 2).last
      env["FUZZ_GIT_DIRTY"] = prov_flags[1].split("=", 2).last
      bkey = build_key_digest({
        shape: "prism_diff_ruby",
        id: id,
        afl: afl_mode,
        ijon: ijon_enabled,
        sans: sans,
        env: env,
        flags: extra_cflags,
        prism: prism_src["commit"],
        patch: prism_src.dig("resolved", "patch_digest"),
        ruby: ruby_src["oracle_dir"] || ruby_src["commit"],
        max_in: max_in,
        prov: prov_flags
      })
      return if stamp_up_to_date?(stamp_file, out_path, bkey, deps) && (!fspec["document_ids"] || File.file?("#{out_path}.ids"))

      log_progress "building differential fuzz binary #{id} (#{fspec['prism']} vs #{fspec['ruby']}#{sans.empty? ? '' : ", #{sans.join('+')}"}#{ijon_enabled ? ', ijon' : ''})"
      FileUtils.rm_f("#{out_path}.ids")
      cmd = [
        build_diff_sh,
        "--mode", "fuzz",
        "--prism-root", prism_src.fetch("path"),
        "--fuzz-root", fuzz_root,
        "--oracle-dir", File.join(build_dir, "diff-oracle"),
        "--afl-path", afl_path,
        "--max-input-size", max_in,
        "--output", out_path
      ]
      if ruby_src["oracle_dir"] && !ruby_src["oracle_dir"].empty?
        cmd.push("--ruby-dir", ruby_src["oracle_dir"])
      end
      extra_cflags.each { |flag| cmd.push("--cflag", flag) }
      run_cmd(*cmd, env: env)
      record_stamp(stamp_file, bkey, out_path)
    end

    def build_prism_diff_prism!(id, fspec, plan:, fuzz_root:, build_dir:, afl_path:, afl_stamp:, dry_run: false)
      a_src = plan.fetch("sources").fetch(fspec.fetch("prism_a"))
      b_src = plan.fetch("sources").fetch(fspec.fetch("prism_b"))
      out_path = File.expand_path(fspec.fetch("binary"), fuzz_root)
      stamps_dir = File.join(build_dir, ".stamps")
      stamp_file = File.join(stamps_dir, "#{id}.json")
      afl_mode = fspec["afl"].to_s.empty? ? "pcguard" : fspec["afl"].to_s
      ijon_enabled = !!fspec["ijon"]
      sans = Array(fspec["sanitizers"]).map(&:to_s)
      override_flags, user_flags, override_macros, = fuzzer_override_flags(fspec)

      extra_cflags = []
      extra_cflags << "-DPRISM_FUZZ_IJON" if ijon_enabled
      san_tokens = []
      san_tokens << "address" if sans.include?("asan")
      san_tokens << "undefined" if sans.include?("ubsan")
      extra_cflags << "-fsanitize=#{san_tokens.join(',')}" unless san_tokens.empty?
      extra_cflags << "-fno-sanitize-recover=all" if sans.include?("ubsan")
      if !sans.empty? && !override_macros.include?("PM_ARENA_INITIAL_SIZE")
        extra_cflags << "-DPM_ARENA_INITIAL_SIZE=0"
      end
      extra_cflags.concat(user_flags)
      extra_cflags.concat(override_flags)

      env = {}
      env["AFL_USE_MSAN"] = "1" if sans.include?("msan")
      env["AFL_USE_LSAN"] = "1" if sans.include?("lsan")
      env["AFL_UBSAN_VERBOSE"] = "1" if sans.include?("ubsan")
      env["AFL_LLVM_IJON"] = "1" if ijon_enabled

      if dry_run
        env_tokens = env.map { |k, v| "#{k}=#{v}" }
        env_str = env_tokens.empty? ? "" : "#{format_dry_run_tokens(env_tokens)} "
        cflag_tokens = extra_cflags.flat_map { |f| ["--cflag", f] }
        cflag_str = cflag_tokens.empty? ? "" : " #{format_dry_run_tokens(cflag_tokens)}"
        puts "#{env_str}build_prism_diff.sh --mode fuzz#{cflag_str} --output #{Shellwords.escape(fspec.fetch('binary'))}"
        return
      end

      script = File.join(fuzz_root, "harnesses", "prism", "build_prism_diff.sh")
      deps = prism_c_sources(a_src.fetch("path")) +
             prism_headers(a_src.fetch("path")) +
             prism_c_sources(b_src.fetch("path")) +
             prism_headers(b_src.fetch("path")) +
             [
               File.join(fuzz_root, "harnesses", "prism", "prism_diff.c"),
               File.join(fuzz_root, "harnesses", "prism", "prism_diff_side.c"),
               File.join(fuzz_root, "harnesses", "prism", "prism_diff_side.h"),
               File.join(fuzz_root, "harnesses", "prism", "include", "fuzz_serialize_scan.h"),
               File.join(fuzz_root, "harnesses", "prism", "include", "prism_ijon.h"),
               File.join(fuzz_root, "harnesses", "prism", "gen_serialize_walk.rb"),
               File.join(fuzz_root, "harnesses", "prism", "gen_diff_ids.rb"),
               script,
               afl_stamp
             ]
      max_in = effective_compiled_max_input_size(plan).to_s
      bkey = build_key_digest({
        shape: "prism_diff_prism",
        id: id,
        afl: afl_mode,
        ijon: ijon_enabled,
        sans: sans,
        env: env,
        flags: extra_cflags,
        prism_a: a_src["commit"] || a_src["path"],
        prism_b: b_src["commit"] || b_src["path"],
        a_patch: a_src.dig("resolved", "patch_digest"),
        b_patch: b_src.dig("resolved", "patch_digest"),
        max_in: max_in
      })
      return if stamp_up_to_date?(stamp_file, out_path, bkey, deps) && (!fspec["document_ids"] || File.file?("#{out_path}.ids"))

      log_progress "building Prism-vs-Prism differential fuzzer #{id} (#{fspec['prism_a']} vs #{fspec['prism_b']}#{sans.empty? ? '' : ", #{sans.join('+')}"}#{ijon_enabled ? ', ijon' : ''})"
      FileUtils.rm_f("#{out_path}.ids")
      cmd = [
        script,
        "--mode", "fuzz",
        "--prism-a", a_src.fetch("path"),
        "--prism-b", b_src.fetch("path"),
        "--fuzz-root", fuzz_root,
        "--work-dir", File.join(build_dir, "prism-diff-#{id.gsub(/[^a-zA-Z0-9._-]/, '_')}"),
        "--afl-path", afl_path,
        "--max-input-size", max_in,
        "--output", out_path
      ]
      extra_cflags.each { |flag| cmd.push("--cflag", flag) }
      run_cmd(*cmd, env: env.empty? ? nil : env)
      record_stamp(stamp_file, bkey, out_path)
    end

    def build_oracle64_helpers!(source_spec, fspec, plan:, fuzz_root:, build_dir:)
      src_dir = source_spec.fetch("path")
      gen_dir = source_spec.fetch("gen_dir")
      c_files = prism_c_sources(src_dir)
      h_files = prism_headers(src_dir)
      _, user_flags, _, fuzzer_defines = fuzzer_override_flags(fspec)
      common_defs = common_define_flags(plan, user_flags: user_flags, extra_flags: fuzzer_defines)
      inc_flags = [
        "-I#{File.join(src_dir, 'include')}",
        "-I#{gen_dir}",
        "-I#{File.join(fuzz_root, 'harnesses', 'prism')}",
        "-I#{File.join(fuzz_root, 'harnesses', 'prism', 'include')}"
      ]
      mutator_src = File.join(fuzz_root, "harnesses", "prism", "mutator_oracle64.c")
      deps = c_files + h_files + [mutator_src, File.join(fuzz_root, "harnesses", "prism", "include", "fuzz_options.h")]
      base_flags = %w[-O2] + split_extra_flags("CPPFLAGS") + split_extra_flags("CFLAGS") +
                   %w[-U_FORTIFY_SOURCE -UNDEBUG -DNDEBUG=1 -fno-sanitize=all -Wno-unused-function] +
                   inc_flags + common_defs + %w[-DPRISM_EXCLUDE_JSON -DPRISM_EXCLUDE_PRETTYPRINT] + fuzzer_defines

      mutator_name = fspec["mutator"] || "mutator_oracle64.so"
      mutator_path = File.join(build_dir, mutator_name)
      m_key = build_key_digest({ kind: "mutator64", src: source_spec["commit"], flags: base_flags })
      m_stamp = File.join(build_dir, ".stamps", "#{File.basename(mutator_name)}.json")
      unless stamp_up_to_date?(m_stamp, mutator_path, m_key, deps)
        log_progress "building 64-bit AST oracle mutator (#{mutator_name})"
        tmp = "#{mutator_path}.tmp.#{Process.pid}"
        run_cmd("clang", "-fPIC", "-shared", "-fvisibility=hidden", "-Wl,-Bsymbolic", *base_flags, *c_files, mutator_src, "-o", tmp)
        File.rename(tmp, mutator_path)
        record_stamp(m_stamp, m_key, mutator_path)
      end

      arch = fspec.fetch("arch")
      cfg = CROSS_ARCH_CONFIGS.fetch(arch)
      target_bin_name = File.basename(fspec.fetch("binary"))
      target_bin_cstr = target_bin_name.gsub(/["\\]/) { |m| "\\#{m}" }
      repro_name = fspec["repro"] || "#{target_bin_name}.repro"
      repro_path = File.join(build_dir, repro_name)
      repro_flags = base_flags + ["-DORACLE64_REPLAY_MAIN"] + cfg[:repro_cflags] +
                    [%(-DORACLE_REPLAY_TARGET_NAME="#{target_bin_cstr}")]
      r_key = build_key_digest({ kind: "oracle_repro", arch: arch, target_name: target_bin_name, src: source_spec["commit"], flags: repro_flags })
      r_stamp = File.join(build_dir, ".stamps", "#{File.basename(repro_name)}.json")
      unless stamp_up_to_date?(r_stamp, repro_path, r_key, deps)
        log_progress "building 64-bit oracle replay wrapper for #{arch} (#{repro_name})"
        tmp = "#{repro_path}.tmp.#{Process.pid}"
        run_cmd("clang", *repro_flags, *c_files, mutator_src, "-o", tmp)
        File.rename(tmp, repro_path)
        record_stamp(r_stamp, r_key, repro_path)
      end
    end

    def build_prism_cross_oracle!(id, fspec, plan:, fuzz_root:, build_dir:, afl_path:, afl_stamp:, dry_run: false)
      src = plan.fetch("sources").fetch(fspec.fetch("source"))
      arch = fspec.fetch("arch")
      cfg = CROSS_ARCH_CONFIGS.fetch(arch)
      triple = cfg[:triple]
      src_dir = src.fetch("path")
      gen_dir = src.fetch("gen_dir")
      out_path = File.expand_path(fspec.fetch("binary"), fuzz_root)
      stamps_dir = File.join(build_dir, ".stamps")
      stamp_file = File.join(stamps_dir, "#{id}.json")

      afl_mode = fspec["afl"].to_s.empty? ? "pcguard" : fspec["afl"].to_s
      ijon_enabled = !!fspec["ijon"]
      sans = Array(fspec["sanitizers"]).map(&:to_s)
      unsupported = sans - %w[asan ubsan]
      unless unsupported.empty?
        raise TopologyError, "Fuzzer '#{id}' (prism_cross_oracle) supports only asan/ubsan sanitizers (got #{unsupported.join(', ')})"
      end

      override_flags, user_flags, override_macros, = fuzzer_override_flags(fspec)
      san_tokens = []
      san_tokens << "address" if sans.include?("asan")
      san_tokens << "undefined" if sans.include?("ubsan")
      san_cflags = san_tokens.empty? ? [] : ["-fsanitize=#{san_tokens.join(',')}"]
      san_cflags << "-fno-sanitize-recover=all" if sans.include?("ubsan")
      san_ldflags = san_tokens.empty? ? [] : ["-fsanitize=#{san_tokens.join(',')}"]
      arena_flags = if !sans.empty? && !override_macros.include?("PM_ARENA_INITIAL_SIZE")
                      ["-DPM_ARENA_INITIAL_SIZE=0"]
                    else
                      []
                    end

      if dry_run
        ijon_prefix = ijon_enabled ? "AFL_LLVM_IJON=1 " : ""
        summary_flags = []
        summary_flags << "-DPRISM_FUZZ_IJON" if ijon_enabled
        summary_flags.concat(arena_flags)
        summary_flags.concat(san_cflags)
        summary_flags.concat(user_flags)
        summary_flags.concat(override_flags)
        flag_str = summary_flags.empty? ? "" : " #{format_dry_run_tokens(summary_flags)}"
        puts "#{ijon_prefix}cross_oracle #{Shellwords.escape(arch)}#{flag_str} --output #{Shellwords.escape(fspec.fetch('binary'))}"
        return
      end

      build_oracle64_helpers!(src, fspec, plan: plan, fuzz_root: fuzz_root, build_dir: build_dir)

      c_files = prism_c_sources(src_dir)
      h_files = prism_headers(src_dir)
      harness_srcs = [
        File.join(fuzz_root, "harnesses", "prism", "parse32.c"),
        File.join(fuzz_root, "harnesses", "prism", "fuzz.c")
      ]
      deps = c_files + h_files + harness_srcs + [
        File.join(fuzz_root, "harnesses", "prism", "include", "fuzz_options.h"),
        File.join(fuzz_root, "harnesses", "prism", "include", "fuzz_serialize_scan.h"),
        File.join(fuzz_root, "harnesses", "prism", "include", "prism_ijon.h"),
        File.join(gen_dir, "node_serialize_walk.inc"),
        afl_stamp
      ]
      pcguard_so = File.join(afl_path, "SanitizerCoveragePCGUARD.so")
      cflags = [
        "--target=#{triple}", "-isystem", "/usr/#{triple}/include",
        *cfg[:extra_cflags],
        "-O1", "-g", "-fno-omit-frame-pointer", "-std=c99",
        "-Wall", "-Werror", "-Wextra", "-Wpedantic", "-Wundef", "-Wconversion",
        "-Wno-missing-braces", "-fvisibility=hidden", "-Wimplicit-fallthrough",
        "-I#{File.join(src_dir, 'include')}",
        "-I#{gen_dir}",
        "-I#{File.join(fuzz_root, 'harnesses', 'prism')}",
        "-I#{File.join(fuzz_root, 'harnesses', 'prism', 'include')}",
        "-DPRISM_OSS_FUZZ", *arena_flags,
        "-DPRISM_EXCLUDE_JSON", "-DPRISM_EXCLUDE_PRETTYPRINT",
        *common_define_flags(plan, user_flags: user_flags, extra_flags: override_flags),
        *source_provenance_flags(src),
        *san_cflags,
        "-fpass-plugin=#{pcguard_so}"
      ]
      cflags << "-DPRISM_FUZZ_IJON" if ijon_enabled
      cflags.concat(override_flags)

      bkey = build_key_digest({ shape: "prism_cross_oracle", id: id, arch: arch, afl: afl_mode, ijon: ijon_enabled, sans: sans, src: src["commit"], patch: src.dig("resolved", "patch_digest"), cflags: cflags })
      return if stamp_up_to_date?(stamp_file, out_path, bkey, deps)

      mode_desc = (sans.map(&:upcase) + ["PCGUARD"] + (ijon_enabled ? ["IJON"] : [])).join("+")
      log_progress "building 32-bit #{arch.upcase} fuzz target #{id} (qemu-#{arch} #{mode_desc})"
      obj_dir = File.join(build_dir, "cross-#{id.gsub(/[^a-zA-Z0-9._-]/, '_')}")
      FileUtils.rm_rf(obj_dir)
      FileUtils.mkdir_p(obj_dir)
      FileUtils.mkdir_p(File.dirname(out_path))
      clang_env = ijon_enabled ? { "AFL_LLVM_IJON" => "1" } : nil
      objs = (c_files + harness_srcs).map do |src_file|
        obj = File.join(obj_dir, "#{src_file.gsub(/[^a-zA-Z0-9_-]/, '_')}.o")
        run_cmd("clang", *cflags, "-c", src_file, "-o", obj, env: clang_env)
        obj
      end
      tmp_out = "#{out_path}.tmp.#{Process.pid}"
      run_cmd(
        "#{triple}-gcc", "-no-pie", *san_ldflags, *objs,
        File.join(afl_path, "aflpp_driver-#{cfg[:rt_suffix]}.o"),
        File.join(afl_path, "afl-compiler-rt-#{cfg[:rt_suffix]}.o"),
        *cfg[:extra_ldflags], "-ldl", "-lpthread", "-o", tmp_out
      )
      File.rename(tmp_out, out_path)
      FileUtils.rm_rf(obj_dir)
      record_stamp(stamp_file, bkey, out_path)
    ensure
      FileUtils.rm_rf(obj_dir) if obj_dir && File.exist?(obj_dir)
      FileUtils.rm_f(tmp_out) if tmp_out && File.exist?(tmp_out)
    end

    def build_explain_for_source!(src_id, out_rel, plan:, fuzz_root:, build_dir:)
      src = plan.fetch("sources").fetch(src_id)
      src_dir = src.fetch("path")
      gen_dir = src.fetch("gen_dir")
      out_path = File.expand_path(out_rel, fuzz_root)
      stamps_dir = File.join(build_dir, ".stamps")
      stamp_file = File.join(stamps_dir, "explain.#{src_id}.json")

      cc = ENV.fetch("CC", "clang")
      c_files, explain_srcs, deps, inc_flags = explain_sources_and_deps(src_dir, gen_dir, fuzz_root: fuzz_root)
      flags = split_extra_flags("CPPFLAGS") + split_extra_flags("CFLAGS") +
              inc_flags + common_define_flags(plan)
      bkey = build_key_digest({ kind: "explain", cc: cc, src: src["commit"] || src_dir, out: out_path, flags: flags })
      return out_path if stamp_up_to_date?(stamp_file, out_path, bkey, deps)

      log_progress "building fuzz diagnostic explain helper (#{src_id} -> #{out_rel})"
      FileUtils.mkdir_p(File.dirname(out_path))
      tmp_out = "#{out_path}.tmp.#{Process.pid}"
      run_cmd(cc, *flags, *c_files, *explain_srcs, "-lm", "-o", tmp_out)
      File.rename(tmp_out, out_path)
      record_stamp(stamp_file, bkey, out_path)
      out_path
    ensure
      FileUtils.rm_f(tmp_out) if tmp_out && File.exist?(tmp_out)
    end

    def build_cross_explain!(arch, plan:, fuzz_root: locate_fuzz_root, build_dir: nil, out_path: nil, src_id: nil)
      cfg = CROSS_ARCH_CONFIGS.fetch(arch.to_s) do
        raise TopologyError, "Unsupported cross-arch explain target '#{arch}'"
      end
      ws = workspace_paths(plan, fuzz_root: fuzz_root, build_dir: build_dir)
      build_dir = ws[:build_dir]
      src = if src_id
              plan.dig("sources", src_id.to_s)
            else
              plan.dig("sources", "prism_a") || plan.fetch("sources").values.find { |s| s["kind"] == "prism" }
            end
      raise TopologyError, "No prism source found in topology to build fuzz.explain.#{arch}" unless src

      src_dir = src.fetch("path")
      gen_dir = src.fetch("gen_dir")
      out_path = out_path ? File.expand_path(out_path, fuzz_root) : File.join(build_dir, "fuzz.explain.#{arch}")
      stamps_dir = File.join(build_dir, ".stamps")
      stamp_file = File.join(stamps_dir, "explain.#{arch}.json")

      c_files, explain_srcs, deps, inc_flags = explain_sources_and_deps(src_dir, gen_dir, fuzz_root: fuzz_root)
      triple = cfg[:triple]
      cflags = [
        "--target=#{triple}", "-isystem", "/usr/#{triple}/include",
        *cfg[:extra_cflags],
        "-O1", "-std=c99", "-Wall", "-Werror", "-Wextra", "-Wpedantic", "-Wundef", "-Wconversion",
        "-Wno-missing-braces", "-fvisibility=hidden", "-Wimplicit-fallthrough",
        *inc_flags,
        *common_define_flags(plan)
      ]
      bkey = build_key_digest({ kind: "cross_explain", arch: arch.to_s, src: src["commit"] || src_dir, out: out_path, flags: cflags })
      return out_path if stamp_up_to_date?(stamp_file, out_path, bkey, deps)

      log_progress "building #{arch} diagnostic explain helper -> #{path_relative_or_abs(out_path, fuzz_root)}"
      obj_dir = File.join(build_dir, "cross-explain-#{arch}")
      FileUtils.rm_rf(obj_dir)
      FileUtils.mkdir_p(obj_dir)
      FileUtils.mkdir_p(File.dirname(out_path))
      objs = (c_files + explain_srcs).map do |src_file|
        obj = File.join(obj_dir, "#{src_file.gsub(/[^a-zA-Z0-9_-]/, '_')}.o")
        run_cmd("clang", *cflags, "-c", src_file, "-o", obj)
        obj
      end
      tmp_out = "#{out_path}.tmp.#{Process.pid}"
      run_cmd("#{triple}-gcc", "-no-pie", *objs, "-lm", *cfg[:extra_ldflags], "-o", tmp_out)
      File.rename(tmp_out, out_path)
      FileUtils.rm_rf(obj_dir)
      record_stamp(stamp_file, bkey, out_path)
      out_path
    ensure
      FileUtils.rm_rf(obj_dir) if obj_dir && File.exist?(obj_dir)
      FileUtils.rm_f(tmp_out) if tmp_out && File.exist?(tmp_out)
    end

    def build_ruby_ext_for_source!(src_id, src_spec, build_dir:, primary: false)
      src_dir = src_spec.fetch("path")
      extconf = File.join(src_dir, "ext", "prism", "extconf.rb")
      return nil unless File.file?(extconf)

      ext_dir = primary ? File.join(build_dir, "fuzz-ruby-ext", "prism") : File.join(build_dir, "fuzz-ruby-ext-sources", src_id, "prism")
      so_path = File.join(ext_dir, "prism.so")
      stamp_file = File.join(build_dir, ".stamps", "ruby-ext.#{src_id}#{primary ? '.primary' : ''}.json")
      bkey = build_key_digest({ kind: "ruby_ext", src: src_spec["commit"] || src_dir, path: src_dir })
      deps = prism_c_sources(src_dir) + prism_headers(src_dir) + [extconf]
      return ext_dir if stamp_up_to_date?(stamp_file, so_path, bkey, deps)

      log_progress "building Ruby C extension for grammar generator (#{src_id})"
      FileUtils.mkdir_p(ext_dir)
      run_cmd(RbConfig.ruby, extconf, chdir: ext_dir)
      run_cmd(ENV.fetch("MAKE", "make"), chdir: ext_dir)
      record_stamp(stamp_file, bkey, so_path)
      ext_dir
    end

    def build_plan!(plan, fuzz_root: locate_fuzz_root, build_dir: nil, dry_run: false)
      ws = workspace_paths(plan, fuzz_root: fuzz_root, build_dir: build_dir)
      build_dir = ws[:build_dir]
      shared_build = default_build_dir(fuzz_root)
      afl_stamp = [File.join(build_dir, ".fuzz.afl.stamp"), File.join(shared_build, ".fuzz.afl.stamp")].find { |p| File.file?(p) } ||
                  File.join(shared_build, ".fuzz.afl.stamp")
      afl_path = File.directory?(File.join(build_dir, "afl")) ? File.join(build_dir, "afl") : File.join(shared_build, "afl")
      raise TopologyError, "Missing AFL++ instrumentation stamp (#{afl_stamp}); build inside Docker via 'make build'" unless dry_run || File.file?(afl_stamp)

      plan.fetch("fuzzers").each do |id, fspec|
        case fspec.fetch("shape")
        when "prism_parse"
          build_prism_parse!(id, fspec, plan: plan, fuzz_root: fuzz_root, build_dir: build_dir, afl_path: afl_path, afl_stamp: afl_stamp, dry_run: dry_run)
        when "prism_diff_ruby"
          build_prism_diff_ruby!(id, fspec, plan: plan, fuzz_root: fuzz_root, build_dir: build_dir, afl_path: afl_path, afl_stamp: afl_stamp, dry_run: dry_run)
        when "prism_diff_prism"
          build_prism_diff_prism!(id, fspec, plan: plan, fuzz_root: fuzz_root, build_dir: build_dir, afl_path: afl_path, afl_stamp: afl_stamp, dry_run: dry_run)
        when "prism_cross_oracle"
          build_prism_cross_oracle!(id, fspec, plan: plan, fuzz_root: fuzz_root, build_dir: build_dir, afl_path: afl_path, afl_stamp: afl_stamp, dry_run: dry_run)
        else
          raise TopologyError, "No builder registered for shape '#{fspec['shape']}'"
        end
      end

      return plan if dry_run

      plan.fetch("explain_binaries", {}).each do |src_id, out_rel|
        build_explain_for_source!(src_id, out_rel, plan: plan, fuzz_root: fuzz_root, build_dir: build_dir)
      end

      ext_sources = Array(plan["grammar_ext_sources"])
      ext_sources.each_with_index do |src_id, idx|
        src_spec = plan.dig("sources", src_id)
        next unless src_spec

        build_ruby_ext_for_source!(src_id, src_spec, build_dir: build_dir, primary: idx == 0)
      end

      write_json_atomic(File.join(build_dir, "topology.resolved.json"), plan)
      plan
    end
  end
end
