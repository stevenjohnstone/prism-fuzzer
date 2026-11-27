# frozen_string_literal: true

module PrismFuzzer
  module Campaign
    module_function

    def in_docker?
      File.exist?("/.dockerenv") || File.exist?("/run/.containerenv")
    end

    def default_image
      env = ENV["FUZZ_DOCKER_IMAGE"].to_s.strip
      env.empty? ? DEFAULT_DOCKER_IMAGE : env
    end

    def default_tmpfs_flags
      Shellwords.split(ENV.fetch("FUZZ_TMPFS_FLAGS", "--tmpfs /tmp:rw,exec,mode=1777"))
    end

    def container_name_for(plan, ws: nil, override: nil, fuzz_root: Topology.locate_fuzz_root)
      explicit = override || ENV["FUZZ_CONTAINER_NAME"]
      return explicit.strip if explicit && !explicit.strip.empty?

      slug = plan.fetch("name", "default").to_s.downcase.gsub(/[^a-z0-9]+/, "-").gsub(/\A-+|-+\z/, "")
      slug = "default" if slug.empty?
      base = "prism-fuzzer-#{slug[0, 36]}"

      resolved_dir = ws ? ws[:fuzz_dir].to_s : nil
      raw_dir = resolved_dir && !resolved_dir.empty? ? resolved_dir : plan.dig("workspace", "dir").to_s
      return base if raw_dir.empty?

      abs_dir = File.expand_path(raw_dir, fuzz_root)
      default_dir = File.expand_path("tmp/fuzz", fuzz_root)
      return base if abs_dir == default_dir

      digest = Digest::SHA256.hexdigest(abs_dir)[0, 6]
      "#{base}-#{digest}"
    end

    def guest_path_for(host_path, ctx, ws_key: nil)
      fuzz_root = File.expand_path(ctx[:fuzz_root])
      abs = File.expand_path(host_path)
      return File.join("/prism-fuzzer", abs.delete_prefix("#{fuzz_root}/")) if abs.start_with?("#{fuzz_root}/")
      return "/prism-fuzzer" if abs == fuzz_root

      if ctx[:campaign_path] && abs == File.expand_path(ctx[:campaign_path])
        ext = File.extname(abs) == ".rb" ? ".rb" : ".json"
        return ext == ".rb" ? "/external/campaign.rb" : "/external/topology#{ext}"
      end

      ws = ctx[:ws] || {}
      ws_mounts = [
        ["build_dir", ws[:build_dir]],
        ["triage_dir", ws[:triage_dir]],
        ["corpus_dir", ws[:corpus_dir]],
        ["coverage_dir", ws[:coverage_dir]],
        ["report_dir", ws[:report_dir]],
        ["logs_dir", ws[:logs_dir]],
        ["dir", ws[:fuzz_dir]]
      ].filter_map do |k, raw|
        next if raw.nil? || raw.to_s.empty?

        base = File.expand_path(raw)
        next if base == fuzz_root || base.start_with?("#{fuzz_root}/")

        [k, base]
      end.sort_by { |(_k, base)| -base.length }

      ws_mounts.each do |k, base|
        guest_base = "/external/ws_#{k}"
        return guest_base if abs == base
        return File.join(guest_base, abs.delete_prefix("#{base}/")) if abs.start_with?("#{base}/")
      end

      return "/external/ws_#{ws_key}" if ws_key

      abs
    end

    def container_ir(ctx)
      ir = Topology.deep_dup(ctx[:ir])
      fuzz_root = ctx[:fuzz_root]
      ws = ctx[:ws]
      if ctx[:ws_overridden] || !ir["workspace"].is_a?(Hash)
        base_ws = ir["workspace"].is_a?(Hash) ? ir["workspace"].dup : {}
        base_ws["dir"] = Topology.path_relative_or_abs(ws[:fuzz_dir], fuzz_root)
        base_ws["build_dir"] = Topology.path_relative_or_abs(ws[:build_dir], fuzz_root)
        if ctx[:ws_overridden] || base_ws.key?("corpus_dir")
          base_ws["corpus_dir"] = Topology.path_relative_or_abs(ws[:corpus_dir], fuzz_root)
        end
        if ctx[:ws_overridden]
          base_ws["triage_dir"] = Topology.path_relative_or_abs(ws[:triage_dir], fuzz_root) if !Topology.blank?(ENV["TRIAGE_DIR"]) || ctx[:ws_custom_dir]
          base_ws["coverage_dir"] = Topology.path_relative_or_abs(ws[:coverage_dir], fuzz_root) if ctx[:ws_custom_dir]
          base_ws["report_dir"] = Topology.path_relative_or_abs(ws[:report_dir], fuzz_root) if ctx[:ws_custom_dir]
          base_ws["logs_dir"] = Topology.path_relative_or_abs(ws[:logs_dir], fuzz_root) if !Topology.blank?(ENV["FUZZ_LOGS_DIR"]) || ctx[:ws_custom_dir]
          base_ws["reports_dir"] = Topology.path_relative_or_abs(ws[:reports_dir], fuzz_root) unless Topology.blank?(ENV["REPORTS_DIR"])
        end
        ir["workspace"] = base_ws
      end

      if ir["sources"].is_a?(Hash)
        ir["sources"].each do |id, s|
          next unless s.is_a?(Hash)

          plan_dir = ctx.dig(:plan, "sources", id, "dir")
          s["dir"] = plan_dir if s["dir"] && !Topology.blank?(plan_dir)
        end
      end
      ir["lifecycle"] = Topology.deep_dup(ctx[:lifecycle]) if ctx[:lifecycle].is_a?(Hash) && !ctx[:lifecycle].empty?
      ir
    end

    def container_plan(ctx)
      plan = Topology.deep_dup(ctx[:plan])
      ir_ws = container_ir(ctx)["workspace"]
      plan["workspace"] = ir_ws if ir_ws.is_a?(Hash)
      plan
    end

    def ir_snapshot_host_path(ctx)
      File.join(ctx[:ws][:build_dir], "topology.ir.json")
    end

    def container_ir_guest_path(ctx)
      guest_path_for(ir_snapshot_host_path(ctx), ctx, ws_key: "build_dir")
    end

    def write_container_ir!(ctx, dry_run: false)
      host_path = ir_snapshot_host_path(ctx)
      unless dry_run
        ir_data = container_ir(ctx)
        serialized = "#{JSON.pretty_generate(ir_data)}\n"
        existing = begin
          File.read(host_path, encoding: "UTF-8")
        rescue SystemCallError, IOError
          nil
        end
        Topology.write_json_atomic(host_path, ir_data) unless existing == serialized
      end
      host_path
    end

    def host_forwarded_env(ctx, extra = {})
      env = {}
      DOCKER_FORWARD_ENV_KEYS.each do |k|
        env[k] = ENV[k] if ENV.key?(k) && !ENV[k].to_s.empty?
      end
      guest_ir = container_ir_guest_path(ctx)
      env["CAMPAIGN"] = guest_ir
      env["TOPOLOGY"] = guest_ir
      env.delete("TOPOLOGY_FILE")
      env["FUZZ_IMAGE_ID"] = docker_image_id(default_image) unless in_docker? || docker_image_id(default_image).nil?
      env["FUZZ_DIR"] = guest_path_for(ctx[:ws][:fuzz_dir], ctx, ws_key: "dir") if ctx[:ws_custom_dir]
      env["FUZZ_BUILD_DIR"] = guest_path_for(ctx[:ws][:build_dir], ctx, ws_key: "build_dir") if ctx[:ws_custom_build] || ctx[:ws_custom_dir]
      env["TRIAGE_CORPUS_DIR"] = guest_path_for(ctx[:ws][:corpus_dir], ctx, ws_key: "corpus_dir") if ctx[:ws_custom_corpus]
      env.merge!(extra.transform_keys(&:to_s).transform_values(&:to_s))
      env
    end

    def docker_image_id(image = default_image)
      out, _err, st = Open3.capture3("docker", "image", "inspect", "-f", "{{.Id}}", image)
      st.success? ? out.strip : nil
    rescue Errno::ENOENT
      nil
    end

    def invalidate_docker_dependent_caches!(fuzz_root: Topology.locate_fuzz_root, build_dir: nil)
      FileUtils.rm_f(File.join(fuzz_root, "build", ".fuzz.afl.stamp"))
      oracle_dirs = [
        File.join(fuzz_root, "build", "diff-oracle"),
        File.join(Topology.default_build_dir(fuzz_root), "diff-oracle"),
        *Dir.glob(File.join(fuzz_root, "tmp", "*", "build", "diff-oracle")),
        *Dir.glob(File.join(fuzz_root, "tmp", "examples", "*", "build", "diff-oracle")),
        *Dir.glob(File.join(fuzz_root, "tmp", "*", ".coverage-cache")),
        *Dir.glob(File.join(fuzz_root, "tmp", "examples", "*", ".coverage-cache"))
      ]
      if build_dir && !build_dir.to_s.empty?
        eff_build = File.expand_path(build_dir.to_s, fuzz_root)
        FileUtils.rm_f(File.join(eff_build, ".fuzz.afl.stamp"))
        oracle_dirs << File.join(eff_build, "diff-oracle")
      end
      oracle_dirs.map { |d| File.expand_path(d) }.uniq.each do |d|
        FileUtils.rm_rf(d) if File.directory?(d)
      end
    end

    def ensure_docker_image!(fuzz_root: Topology.locate_fuzz_root, build_dir: nil, image: default_image, ruby_git_ref: ENV["RUBY_GIT_REF"], prism_git_ref: ENV["PRISM_GIT_REF"], force: false, dry_run: false, logs_dir: nil, emit_cached: false)
      return true if in_docker?

      dockerfile = File.join(fuzz_root, "docker", "Dockerfile")
      raise CampaignError, "Dockerfile not found at #{dockerfile}" unless File.file?(dockerfile)

      stamp = File.join(fuzz_root, "build", ".fuzz.docker.stamp")
      ref_val = ruby_git_ref.to_s.strip
      prism_ref_val = prism_git_ref.to_s.strip
      sync_script = File.join(fuzz_root, "docker", "sync_prism_into_ruby.rb")
      sync_src = File.file?(sync_script) ? File.read(sync_script) : ""
      digest = Digest::SHA256.hexdigest(File.read(dockerfile) + "\n" + sync_src + "\nRUBY_GIT_REF=#{ref_val}\nPRISM_GIT_REF=#{prism_ref_val}\n")
      existing_id = docker_image_id(image)
      stamp_lines = File.file?(stamp) ? File.read(stamp).lines.map(&:strip) : []
      prev_digest = stamp_lines[0]
      prev_id = stamp_lines[1]

      up_to_date = !force && !existing_id.nil? && !existing_id.empty? && File.file?(stamp) && (prev_digest.to_s.empty? || prev_digest == digest)
      if up_to_date
        Progress.cached("Docker image '#{image}' up to date") if emit_cached && !dry_run
        return true
      end

      cmd = ["docker", "build"]
      cmd.push("--build-arg", "RUBY_GIT_REF=#{ref_val}") unless ref_val.empty?
      cmd.push("--build-arg", "PRISM_GIT_REF=#{prism_ref_val}") unless prism_ref_val.empty?
      cmd.push("-t", image, "-f", dockerfile, fuzz_root)

      if dry_run
        puts "[dry-run] #{cmd.map { |t| Shellwords.escape(t) }.join(' ')}"
        return true
      end

      log_abs = logs_dir ? File.join(logs_dir, "docker-build.log") : File.join(Topology.default_build_dir(fuzz_root), "docker-build.log")
      rel = Topology.path_relative_or_abs(log_abs, fuzz_root)
      display_log = rel.start_with?("/") ? rel : "./#{rel}"
      Progress.stage("Build Docker image #{image}", log_path: log_abs, display_log: display_log, done_message: "Docker image '#{image}' ready") do |stage|
        stage.exec_stream(*cmd, env: { "BUILDKIT_PROGRESS" => "plain" }, fail_message: "docker build failed for image '#{image}'")
      end

      new_id = docker_image_id(image)
      prior_id = (existing_id && !existing_id.empty?) ? existing_id : prev_id
      if new_id && !new_id.empty? && prior_id && !prior_id.empty? && new_id != prior_id
        invalidate_docker_dependent_caches!(fuzz_root: fuzz_root, build_dir: build_dir)
      end
      FileUtils.mkdir_p(File.dirname(stamp))
      File.write(stamp, [digest, new_id].compact.reject(&:empty?).join("\n") + "\n")
      true
    end

    def docker_cmd_for(ctx, cmd_args, interactive: false, detach: false, name: nil, extra_env: {})
      fuzz_root = ctx[:fuzz_root]
      plan = container_plan(ctx)
      mount_args = Topology.docker_mount_args(plan, topology_path: nil, fuzz_root: fuzz_root)

      cmd = ["docker", "run", "--init", "--rm"]
      if detach
        cmd << "-d"
      elsif interactive && $stdin.tty? && $stdout.tty?
        cmd << "-it"
      elsif interactive
        cmd << "-i"
      end
      if name
        cmd.push("--name", name)
        cmd.push("--label", "prism_fuzzer.campaign=#{plan['name']}") if plan["name"]
        cmd.push("--label", "prism_fuzzer.campaign_file=#{ctx[:campaign_path]}") if ctx[:campaign_path]
        cmd.push("--label", "prism_fuzzer.workspace=#{ctx.dig(:ws, :fuzz_dir)}") if ctx.dig(:ws, :fuzz_dir)
      end
      cmd.concat(default_tmpfs_flags)
      if ENV["FUZZ_CCACHE"].to_s.strip != "0" && ENV["CCACHE_DIR"].to_s.strip.empty?
        ccache_vol = ENV.fetch("FUZZ_CCACHE_VOLUME", DEFAULT_CCACHE_VOLUME).to_s.strip
        cmd.push("-v", "#{ccache_vol}:/ccache") unless ccache_vol.empty?
      end

      host_forwarded_env(ctx, extra_env).each do |k, v|
        cmd.push("-e", "#{k}=#{v}")
      end

      cmd.concat(mount_args)
      cmd.push("-v", "#{fuzz_root}:/prism-fuzzer", "-w", "/prism-fuzzer", default_image)
      cmd.concat(cmd_args)
      cmd
    end

    def run_in_container!(ctx, cmd_args, interactive: false, extra_env: {}, dry_run: false, capture: false, stage: nil)
      ir_host = write_container_ir!(ctx, dry_run: dry_run)
      if in_docker?
        if dry_run
          puts "[dry-run] #{cmd_args.map { |t| Shellwords.escape(t) }.join(' ')}"
          return capture ? "" : true
        end
        child_env = { "CAMPAIGN" => ir_host, "TOPOLOGY" => ir_host }.merge(extra_env.transform_keys(&:to_s).transform_values(&:to_s))
        if capture
          out, err, st = Open3.capture3(child_env, *cmd_args, chdir: ctx[:fuzz_root])
          raise CampaignError, "Command failed (#{cmd_args.join(' ')}): #{err}" unless st.success?

          return out
        end
        if stage
          stage.exec_stream(*cmd_args, env: child_env.merge("FUZZ_PROGRESS" => "inner"), chdir: ctx[:fuzz_root], fail_message: "Command failed (#{cmd_args.join(' ')})")
          return true
        end
        ok = system(child_env, *cmd_args, chdir: ctx[:fuzz_root])
        raise CampaignError, "Command failed (#{cmd_args.join(' ')})" unless ok

        return true
      end

      docker_cmd = docker_cmd_for(ctx, cmd_args, interactive: interactive, extra_env: stage ? extra_env.merge("FUZZ_PROGRESS" => "inner") : extra_env)
      if dry_run
        puts "[dry-run] #{docker_cmd.map { |t| Shellwords.escape(t) }.join(' ')}"
        return capture ? "" : true
      end

      if capture
        out, err, st = Open3.capture3(*docker_cmd)
        raise CampaignError, "Container command failed (#{cmd_args.join(' ')}): #{err}" unless st.success?

        return out
      end

      if stage
        stage.exec_stream(*docker_cmd, fail_message: "Container command failed (#{cmd_args.join(' ')})")
        return true
      end

      ok = system(*docker_cmd)
      raise CampaignError, "Container command failed (#{cmd_args.join(' ')})" unless ok

      true
    end

    def container_running?(name)
      out, _err, st = Open3.capture3("docker", "ps", "-q", "-f", "name=^/#{name}$")
      st.success? && !out.strip.empty?
    rescue Errno::ENOENT
      false
    end

    def stop_container!(name, timeout: 30, quiet: false)
      return false unless container_running?(name)

      puts "Stopping container '#{name}' cleanly (saving unread seeds & shutting down tmux)..." unless quiet
      system("docker", "stop", "-t", timeout.to_s, name, out: File::NULL, err: File::NULL)
      # Wait briefly for --rm container cleanup
      20.times do
        break unless container_running?(name)

        sleep 0.25
      end
      true
    end

    def list_containers
      fmt = "{{.Names}}\t{{.Status}}\t{{.RunningFor}}\t{{.Label \"prism_fuzzer.campaign\"}}\t{{.Label \"prism_fuzzer.campaign_file\"}}\t{{.Label \"prism_fuzzer.workspace\"}}\t{{.Label \"ruby_fuzz.campaign\"}}\t{{.Label \"ruby_fuzz.campaign_file\"}}\t{{.Label \"ruby_fuzz.workspace\"}}"
      out, _err, st = Open3.capture3("docker", "ps", "--filter", "name=^/prism-fuzzer", "--filter", "name=^/ruby-fuzz", "--format", fmt)
      return [] unless st.success?

      out.lines(chomp: true).map do |ln|
        name, status, running_for, camp, camp_file, ws_dir, leg_camp, leg_file, leg_ws = ln.split("\t", 9)
        entry = { "name" => name, "status" => status, "running_for" => running_for }
        eff_camp = (camp && !camp.empty?) ? camp : leg_camp
        eff_file = (camp_file && !camp_file.empty?) ? camp_file : leg_file
        eff_ws = (ws_dir && !ws_dir.empty?) ? ws_dir : leg_ws
        entry["campaign"] = eff_camp if eff_camp && !eff_camp.empty?
        entry["campaign_file"] = eff_file if eff_file && !eff_file.empty?
        entry["workspace"] = eff_ws if eff_ws && !eff_ws.empty?
        entry
      end
    rescue Errno::ENOENT
      []
    end

    def start_detached_container!(ctx)
      write_container_ir!(ctx, dry_run: false)
      cname = ctx[:container_name]
      stop_container!(cname) if container_running?(cname)
      run_token = write_run_state!(ctx, lifecycle: ctx[:lifecycle], post_handled: false)
      cmd = docker_cmd_for(ctx, ["/bin/bash", "-c", "exec ./runtime/run.sh"], detach: true, name: cname, extra_env: { "FUZZ_DAEMON" => "1" })
      out, err, st = Open3.capture3(*cmd)
      raise CampaignError, "Failed to start container '#{cname}': #{err}" unless st.success?

      [out.strip[0, 12], run_token]
    end

    DEFAULT_START_TIMEOUT = 180

    def start_timeout_seconds
      raw = ENV["FUZZ_START_TIMEOUT"].to_s.strip
      val = raw.empty? ? DEFAULT_START_TIMEOUT : raw.to_i
      val > 0 ? val : DEFAULT_START_TIMEOUT
    end

    def wait_for_tmux_session!(name, timeout: start_timeout_seconds, abort_if: nil)
      deadline = Time.now + timeout
      loop do
        return false if abort_if&.call
        return false unless container_running?(name)

        _, _, st = Open3.capture3("docker", "exec", name, "sh", "-c", "test -f /tmp/.fuzzer.tmux.ready && tmux has-session -t fuzzer")
        return true if st.success?
        return false if abort_if&.call || Time.now >= deadline

        sleep 0.25
      end
    rescue Errno::ENOENT
      false
    end

    def tmux_session_alive?(name)
      return false unless container_running?(name)

      _, _, st = Open3.capture3("docker", "exec", name, "tmux", "has-session", "-t", "fuzzer")
      st.success?
    rescue Errno::ENOENT
      false
    end

    def wait_for_container_exit(name, timeout: 30)
      steps = (timeout / 0.25).to_i
      steps.times do
        break unless container_running?(name)

        sleep 0.25
      end
    end
  end
end
