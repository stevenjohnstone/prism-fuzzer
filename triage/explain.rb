#!/usr/bin/env ruby
# frozen_string_literal: true

require "base64"
require "json"
require "open3"
require "optparse"
require "rbconfig"
require "set"
require "shellwords"
require "tempfile"

require_relative "cluster"
require_relative "inspect"
require_relative "../runtime/common"
require_relative "../runtime/fuzz_header"
topology_lib = File.expand_path("../runtime/topology.rb", __dir__)
require topology_lib if File.file?(topology_lib)

module FuzzExplain
  DEFAULT_TIMEOUT_SECONDS = 10.0
  REPO_ROOT = File.expand_path("..", __dir__)
  DEFAULT_DOCKER_IMAGE = "prism-fuzzer"
  CROSS_ARCH_SPECS = {
    "arm32" => {
      label: "arm32 (qemu-arm)",
      bin: File.join(REPO_ROOT, "tmp", "fuzz", "build", "fuzz.explain.arm32"),
      env_bin: "EXPLAIN_ARM32_BIN",
      qemu: "/usr/bin/qemu-arm",
      sysroot: "/usr/arm-linux-gnueabihf"
    },
    "ppc" => {
      label: "ppc (qemu-ppc)",
      bin: File.join(REPO_ROOT, "tmp", "fuzz", "build", "fuzz.explain.ppc"),
      env_bin: "EXPLAIN_PPC_BIN",
      qemu: "/usr/bin/qemu-ppc",
      sysroot: "/usr/powerpc-linux-gnu"
    }
  }.freeze

  class ConfigError < StandardError; end

  module_function

  def run_with_timeout(cmd, timeout_sec:, chdir: nil, stdin_data: nil)
    spawn_opts = { pgroup: true }
    spawn_opts[:chdir] = chdir if chdir

    stdout_r, stdout_w = IO.pipe
    stderr_r, stderr_w = IO.pipe
    in_r = in_w = nil
    if stdin_data
      in_r, in_w = IO.pipe
      in_r.binmode
      in_w.binmode
    end

    out_buf = +""
    err_buf = +""
    timed_out = false

    pid = Process.spawn(*cmd, in: (in_r || File::NULL), out: stdout_w, err: stderr_w, **spawn_opts)
    stdout_w.close
    stderr_w.close
    if in_r
      in_r.close
      begin
        in_w.write(stdin_data)
      rescue Errno::EPIPE
        nil
      ensure
        in_w.close
      end
    end

    readers = [stdout_r, stderr_r]
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout_sec

    until readers.empty?
      remain = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
      if remain <= 0
        timed_out = true
        begin
          Process.kill("KILL", -pid)
        rescue Errno::ESRCH, Errno::EPERM
          begin
            Process.kill("KILL", pid)
          rescue Errno::ESRCH
            nil
          end
        end
        break
      end

      ready = IO.select(readers, nil, nil, [remain, 0.25].min)
      next unless ready

      ready[0].each do |io|
        chunk = io.read_nonblock(65_536)
        (io == stdout_r ? out_buf : err_buf) << chunk
      rescue IO::WaitReadable
        nil
      rescue EOFError
        io.close
        readers.delete(io)
      end
    end

    stdout_r.close unless stdout_r.closed?
    stderr_r.close unless stderr_r.closed?
    _, status = Process.wait2(pid)

    {
      stdout: out_buf.encode("UTF-8", invalid: :replace, undef: :replace, replace: "\uFFFD"),
      stderr: err_buf.encode("UTF-8", invalid: :replace, undef: :replace, replace: "\uFFFD"),
      exitstatus: timed_out ? nil : status.exitstatus,
      signaled: timed_out ? true : status.signaled?,
      termsig: status.termsig,
      timed_out: timed_out
    }
  end

  def ruby_supports_parse_y?(ruby_bin, timeout_sec:)
    res = run_with_timeout([ruby_bin, "--parser=parse.y", "-e", ""], timeout_sec: timeout_sec)
    res[:exitstatus] == 0
  end

  def check_ruby_parser_support(ruby_bin, timeout_sec:)
    res = run_with_timeout([ruby_bin, "--parser=parse.y", "-e", ""], timeout_sec: timeout_sec)
    if res[:exitstatus] != 0
      detail = [res[:stderr], res[:stdout]].reject(&:empty?).join("\n").strip
      raise ConfigError, "'#{ruby_bin}' does not support '--parser=parse.y' (#{detail.empty? ? 'exit != 0' : detail}); omit '--ruby' to run in Docker or pass '--no-compare'"
    end

    ver_res = run_with_timeout([ruby_bin, "-v"], timeout_sec: timeout_sec)
    ver_res[:stdout].strip
  end

  def normalize_disasm(text, ignore_locations: false)
    s = text.to_s
    s = s.gsub(/^(== disasm: #<ISeq:[^>]+?)\s+\(\d+,\d+\)-\(\d+,\d+\)>/) { "#{Regexp.last_match(1)}>" } if ignore_locations
    s
  end

  def simple_line_diff(a_text, b_text, label_a: "parse.y", label_b: "prism")
    a_lines = a_text.to_s.lines(chomp: true)
    b_lines = b_text.to_s.lines(chomp: true)
    return "" if a_lines == b_lines

    out = ["--- #{label_a}", "+++ #{label_b}"]
    # Guard against O(N*M) blowup on massive disassemblies by falling back to first-divergence window.
    if a_lines.size * b_lines.size > 400_000
      idx = 0
      idx += 1 while idx < a_lines.size && idx < b_lines.size && a_lines[idx] == b_lines[idx]
      start = [idx - 3, 0].max
      out << "@@ line #{start + 1} @@"
      a_lines[start, 20].to_a.each { |l| out << "-#{l}" }
      b_lines[start, 20].to_a.each { |l| out << "+#{l}" }
      return out.join("\n")
    end

    m = a_lines.size
    n = b_lines.size
    dp = Array.new(m + 1) { Array.new(n + 1, 0) }
    (m - 1).downto(0) do |i|
      (n - 1).downto(0) do |j|
        dp[i][j] = a_lines[i] == b_lines[j] ? dp[i + 1][j + 1] + 1 : [dp[i + 1][j], dp[i][j + 1]].max
      end
    end

    ops = []
    i = 0
    j = 0
    while i < m && j < n
      if a_lines[i] == b_lines[j]
        ops << [" ", a_lines[i]]
        i += 1
        j += 1
      elsif dp[i + 1][j] >= dp[i][j + 1]
        ops << ["-", a_lines[i]]
        i += 1
      else
        ops << ["+", b_lines[j]]
        j += 1
      end
    end
    while i < m
      ops << ["-", a_lines[i]]
      i += 1
    end
    while j < n
      ops << ["+", b_lines[j]]
      j += 1
    end

    changed_indices = ops.each_index.select { |k| ops[k][0] != " " }
    return "" if changed_indices.empty?

    lo = [changed_indices.first - 2, 0].max
    hi = [changed_indices.last + 2, ops.size - 1].min
    out << "@@ ops #{lo + 1}..#{hi + 1} @@"
    (lo..hi).each do |k|
      prefix, line = ops[k]
      out << "#{prefix}#{line}"
    end
    out.join("\n")
  end

  ISEQ_PROBE_SCRIPT = <<~'RUBY'.freeze
    require "json"
    code = File.binread(ARGV.fetch(0))
    include_prism = ARGV[1] == "1"
    out = {}

    if include_prism
      begin
        require "prism"
        pr = Prism.parse(code)
        out["prism_parse"] = {
          "errors" => pr.errors.map { |e| { "type" => e.type.to_s, "message" => e.message } },
          "warnings" => pr.warnings.map { |w| { "type" => w.type.to_s, "message" => w.message } }
        }
      rescue LoadError => e
        out["prism_parse_error"] = e.message
      end
    end

    begin
      iseq = RubyVM::InstructionSequence.compile(code, "(compare)", "(compare)", 1)
      out["compile"] = { "ok" => true, "disasm" => iseq.disasm }
    rescue ScriptError, StandardError => e
      out["compile"] = { "ok" => false, "error_class" => e.class.name, "error_message" => e.message }
    end

    puts JSON.generate(out)
  RUBY

  def run_syntax_check(ruby_bin, parser:, src_path:, cmd_flags:, timeout_sec:)
    cmd = [ruby_bin, "--parser=#{parser}", "-c"]
    cmd_flags.each { |f| cmd << "-#{f}" if %w[a l n p x].include?(f) }
    cmd << src_path
    res = run_with_timeout(cmd, timeout_sec: timeout_sec)
    {
      "ok" => !res[:timed_out] && res[:exitstatus] == 0,
      "timed_out" => res[:timed_out],
      "exitstatus" => res[:exitstatus],
      "stdout" => res[:stdout].strip,
      "stderr" => res[:stderr].strip
    }
  end

  def run_iseq_probe(ruby_bin, parser:, src_path:, include_prism:, timeout_sec:)
    Tempfile.create(["fuzz-cmp-probe", ".rb"]) do |tf|
      tf.write(ISEQ_PROBE_SCRIPT)
      tf.flush
      res = run_with_timeout(
        [ruby_bin, "--parser=#{parser}", tf.path, src_path, include_prism ? "1" : "0"],
        timeout_sec: timeout_sec
      )
      if res[:timed_out]
        return { "compile" => { "ok" => false, "timed_out" => true, "error_class" => "Timeout", "error_message" => "timed out after #{timeout_sec}s" } }
      end

      begin
        parsed = JSON.parse(res[:stdout])
        return parsed if parsed.is_a?(Hash) && parsed["compile"].is_a?(Hash)
      rescue JSON::ParserError
        nil
      end

      {
        "compile" => {
          "ok" => false,
          "error_class" => "ProcessCrash",
          "error_message" => "exit=#{res[:exitstatus]} termsig=#{res[:termsig]} #{res[:stderr].strip}".strip
        }
      }
    end
  end

  def run_eval_check(ruby_bin, parser:, src_path:, cmd_flags:, timeout_sec:)
    cmd = [ruby_bin, "--parser=#{parser}"]
    cmd_flags.each { |f| cmd << "-#{f}" if %w[a l n p x].include?(f) }
    cmd << src_path
    res = run_with_timeout(cmd, timeout_sec: timeout_sec)
    {
      "ok" => !res[:timed_out] && res[:exitstatus] == 0,
      "timed_out" => res[:timed_out],
      "exitstatus" => res[:exitstatus],
      "termsig" => res[:termsig],
      "stdout" => res[:stdout],
      "stderr" => res[:stderr]
    }
  end

  def compare_entry(entry, options)
    body = entry[:body]
    cmd_flags = options[:apply_cmd_flags] ? Array(entry[:cmd_flags]) : []

    out = {}
    Tempfile.create(["fuzz-cmp-src", ".rb"], binmode: true) do |tf|
      tf.write(body)
      tf.flush

      syn_y = run_syntax_check(options[:ruby], parser: "parse.y", src_path: tf.path, cmd_flags: cmd_flags, timeout_sec: options[:timeout])
      syn_p = run_syntax_check(options[:ruby], parser: "prism", src_path: tf.path, cmd_flags: cmd_flags, timeout_sec: options[:timeout])

      syntax_status =
        if syn_y["timed_out"] || syn_p["timed_out"]
          "timeout"
        elsif syn_y["ok"] && syn_p["ok"]
          "both_ok"
        elsif !syn_y["ok"] && !syn_p["ok"]
          "both_error"
        elsif syn_y["ok"] && !syn_p["ok"]
          "parse_y_ok_prism_err"
        else
          "prism_ok_parse_y_err"
        end

      out["syntax"] = {
        "status" => syntax_status,
        "parse_y" => syn_y,
        "prism" => syn_p
      }

      iseq_y = run_iseq_probe(options[:ruby], parser: "parse.y", src_path: tf.path, include_prism: false, timeout_sec: options[:timeout])
      iseq_p = run_iseq_probe(options[:ruby], parser: "prism", src_path: tf.path, include_prism: true, timeout_sec: options[:timeout])

      cy = iseq_y["compile"]
      cp = iseq_p["compile"]
      out["prism_parse"] = iseq_p["prism_parse"] if iseq_p["prism_parse"]

      iseq_status =
        if cy["timed_out"] || cp["timed_out"]
          "timeout"
        elsif cy["ok"] && cp["ok"]
          dy = normalize_disasm(cy["disasm"], ignore_locations: options[:ignore_locations])
          dp = normalize_disasm(cp["disasm"], ignore_locations: options[:ignore_locations])
          dy == dp ? "match" : "disasm_diff"
        elsif !cy["ok"] && !cp["ok"]
          cy["error_class"] == cp["error_class"] ? "both_compile_error" : "compile_error_class_mismatch"
        elsif cy["ok"] && !cp["ok"]
          "parse_y_ok_prism_compile_err"
        else
          "prism_ok_parse_y_compile_err"
        end

      iseq_hash = {
        "status" => iseq_status,
        "parse_y" => cy.slice("ok", "timed_out", "error_class", "error_message").compact,
        "prism" => cp.slice("ok", "timed_out", "error_class", "error_message").compact
      }
      if iseq_status == "disasm_diff"
        iseq_hash["disasm_diff"] = simple_line_diff(
          normalize_disasm(cy["disasm"], ignore_locations: options[:ignore_locations]),
          normalize_disasm(cp["disasm"], ignore_locations: options[:ignore_locations])
        )
      elsif options[:disasm]
        if cy["ok"] && cp["ok"]
          iseq_hash["disasm"] = cy["disasm"]
        elsif cy["ok"]
          iseq_hash["disasm_parser"] = "parse.y"
          iseq_hash["disasm"] = cy["disasm"]
        elsif cp["ok"]
          iseq_hash["disasm_parser"] = "prism"
          iseq_hash["disasm"] = cp["disasm"]
        end
      end
      out["iseq"] = iseq_hash

      eval_mismatch = false
      if options[:eval]
        ev_y = run_eval_check(options[:ruby], parser: "parse.y", src_path: tf.path, cmd_flags: cmd_flags, timeout_sec: options[:timeout])
        ev_p = run_eval_check(options[:ruby], parser: "prism", src_path: tf.path, cmd_flags: cmd_flags, timeout_sec: options[:timeout])
        ev_status =
          if ev_y["timed_out"] || ev_p["timed_out"]
            "timeout"
          elsif ev_y["exitstatus"] == ev_p["exitstatus"] && ev_y["stdout"] == ev_p["stdout"] &&
                ((ev_y["exitstatus"] == 0) || (ev_y["stderr"] == ev_p["stderr"]))
            "match"
          elsif ev_y["exitstatus"] != ev_p["exitstatus"]
            "exit_mismatch"
          elsif ev_y["stdout"] != ev_p["stdout"]
            "stdout_mismatch"
          else
            "stderr_mismatch"
          end
        eval_mismatch = ev_status != "match"
        out["eval"] = {
          "status" => ev_status,
          "parse_y" => ev_y,
          "prism" => ev_p
        }
      end

      syntax_mismatch = !%w[both_ok both_error].include?(syntax_status)
      iseq_mismatch = !%w[match both_compile_error].include?(iseq_status)
      out["parity"] = (syntax_mismatch || iseq_mismatch || eval_mismatch) ? "mismatch" : "match"
    end

    out
  end

  def running_in_container?
    File.exist?("/.dockerenv") || File.exist?("/run/.containerenv")
  end

  def use_local_ruby_for_compare?(options)
    return true if options[:ruby_explicit]
    return true if ENV["COMPARE_RUBY"] && !ENV["COMPARE_RUBY"].empty?
    return true if ENV["EXPLAIN_HOST_RUBY"] == "1"
    return true if running_in_container?

    false
  end

  def ensure_docker_image!(image, timeout_sec:, purpose:)
    inspect_res = run_with_timeout(["docker", "image", "inspect", image], timeout_sec: timeout_sec)
    if inspect_res[:exitstatus] != 0
      raise ConfigError, "Docker image '#{image}' not found (needed for #{purpose}); run 'make docker-build'"
    end
  end

  def run_cruby_comparisons(entries, options)
    if use_local_ruby_for_compare?(options)
      ruby_banner = check_ruby_parser_support(options[:ruby], timeout_sec: options[:timeout])
      results = entries.map { |entry| compare_entry(entry, options) }
      return { "ruby" => ruby_banner, "source" => "local", "results" => results }
    end

    if ENV["EXPLAIN_NO_DOCKER"] == "1" && ruby_supports_parse_y?(options[:ruby], timeout_sec: options[:timeout])
      ruby_banner = check_ruby_parser_support(options[:ruby], timeout_sec: options[:timeout])
      results = entries.map { |entry| compare_entry(entry, options) }
      return { "ruby" => ruby_banner, "source" => "local", "results" => results }
    end

    if ENV["EXPLAIN_NO_DOCKER"] == "1"
      raise ConfigError, "'#{options[:ruby]}' does not support '--parser=parse.y' and EXPLAIN_NO_DOCKER=1 is set; pass '--ruby PATH' or '--no-compare'"
    end

    image = ENV.fetch("FUZZ_DOCKER_IMAGE", DEFAULT_DOCKER_IMAGE)
    ensure_docker_image!(image, timeout_sec: options[:timeout], purpose: "CRuby --parser=parse.y comparison")

    tmpfs_flags = Shellwords.split(ENV.fetch("FUZZ_TMPFS_FLAGS", "--tmpfs /tmp:rw,exec,mode=1777"))
    cmd = [
      "docker", "run", "--rm", "-i", "--init",
      *tmpfs_flags,
      "-v", "#{REPO_ROOT}:/prism-fuzzer",
      "-w", "/prism-fuzzer",
      image,
      "ruby", "./triage/explain.rb", "--cruby-worker",
      "--timeout", options[:timeout].to_s
    ]
    cmd << "--disasm" if options[:disasm]
    cmd << "--ignore-locations" if options[:ignore_locations]
    cmd << "--eval" if options[:eval]
    cmd << "--apply-cmd-flags" if options[:apply_cmd_flags]

    req = {
      "entries" => entries.map do |e|
        {
          "label" => e[:label],
          "body_b64" => Base64.strict_encode64(e[:body].to_s.b),
          "cmd_flags" => Array(e[:cmd_flags])
        }
      end
    }
    worker_timeout = [options[:timeout] * entries.size * 5.0 + 15.0, 30.0].max
    res = run_with_timeout(cmd, timeout_sec: worker_timeout, chdir: REPO_ROOT, stdin_data: JSON.generate(req))
    if res[:timed_out] || res[:exitstatus] != 0
      detail = [res[:stderr], res[:stdout]].reject(&:empty?).join("\n").strip
      raise ConfigError, "Docker CRuby comparison failed (#{detail.empty? ? "exit=#{res[:exitstatus]}" : detail})"
    end

    parsed = JSON.parse(res[:stdout])
    parsed["source"] = "docker"
    parsed
  rescue JSON::ParserError => e
    raise ConfigError, "Invalid JSON from Docker CRuby worker: #{e.message}"
  end

  def strip_fuzz_header(raw_bytes)
    PrismFuzzer::FuzzHeader.strip_header(raw_bytes)
  end

  def raw_input_file?(path, options)
    return false if options[:raw] == false
    return true if options[:raw] == true

    base = File.basename(path)
    base == "input.min" || base.start_with?("id:")
  end

  def ordered_cluster_buckets(cluster)
    rep_bid = cluster.dig("representative", "bucket_id").to_s
    buckets = Array(cluster["buckets"])
    return buckets if rep_bid.empty?

    rep = buckets.select { |b| b["bucket_id"].to_s == rep_bid }
    others = buckets.reject { |b| b["bucket_id"].to_s == rep_bid }
    rep + others
  end

  def parse_member_specs(specs, total, cluster_id)
    selected = []
    seen = Set.new
    specs.each do |raw|
      raw.split(",").map(&:strip).reject(&:empty?).each do |tok|
        if tok =~ /\A(\d+)(?:\.\.|-)(\d+)\z/
          a = Regexp.last_match(1).to_i
          b = Regexp.last_match(2).to_i
          raise ConfigError, "Invalid member range '#{tok}' for #{cluster_id}" if a <= 0 || b < a || b > total
          (a..b).each do |idx|
            next if seen.include?(idx)
            seen << idx
            selected << idx
          end
        elsif tok =~ /\A\d+\z/
          idx = tok.to_i
          raise ConfigError, "Member ##{idx} out of range for #{cluster_id} (1..#{total})" if idx <= 0 || idx > total
          unless seen.include?(idx)
            seen << idx
            selected << idx
          end
        else
          raise ConfigError, "Invalid --member specification '#{tok}' (expected N or A..B)"
        end
      end
    end
    selected
  end

  def bucket_matches_pattern?(bucket, pat)
    bid = bucket["bucket_id"].to_s
    sig = bucket["signature"].to_s
    bid == pat || sig == pat ||
      (pat.include?("/") || pat.match?(/[*?\[]/) ? File.fnmatch?(pat, bid, File::FNM_PATHNAME) : bid.include?(pat))
  end

  def resolve_triage_state(options, cache)
    return cache[:clusters] if cache[:clusters]

    report, metadata, = FuzzInspect.load_triage_report(
      triage_dir: options[:triage_dir],
      clusters_file: options[:clusters_file],
      metadata_path: options[:metadata_path]
    )
    cache[:clusters] = FuzzInspect.enrich_clusters(report, metadata, triage_dir: options[:triage_dir], read_files: true)
  end

  def direct_cluster_name_match?(cluster, pat)
    cid = cluster["cluster_id"].to_s
    cid_num = cid[/\d+\z/]&.to_i
    (pat.match?(/\A\d{1,15}\z/) && !cid_num.nil? && cid_num == pat.to_i) ||
      cid.casecmp?(pat) ||
      File.fnmatch?(pat.downcase, cid.downcase, File::FNM_PATHNAME)
  end

  def collect_entries(options, positional)
    entries = []
    cache = {}

    options[:inline_codes].each_with_index do |code, i|
      raw_bytes = code.b
      if options[:raw] == true
        body, cmd_flags = strip_fuzz_header(raw_bytes)
        entries << { label: "<inline:#{i + 1}>", raw_input: true, raw_bytes: raw_bytes, body: body, cmd_flags: cmd_flags }
      else
        entries << { label: "<inline:#{i + 1}>", raw_input: false, raw_bytes: raw_bytes, body: raw_bytes, cmd_flags: [] }
      end
    end

    if options[:stdin]
      raw_bytes = $stdin.binmode.read
      raw_in = options[:raw] == true
      body, cmd_flags = raw_in ? strip_fuzz_header(raw_bytes) : [raw_bytes, []]
      entries << { label: "<stdin>", raw_input: raw_in, raw_bytes: raw_bytes, body: body, cmd_flags: cmd_flags }
    end

    triage_clusters = options[:clusters].dup
    triage_buckets = options[:buckets].dup

    positional.each do |arg|
      if arg == "-"
        raw_bytes = $stdin.binmode.read
        raw_in = options[:raw] == true
        body, cmd_flags = raw_in ? strip_fuzz_header(raw_bytes) : [raw_bytes, []]
        entries << { label: "<stdin>", raw_input: raw_in, raw_bytes: raw_bytes, body: body, cmd_flags: cmd_flags }
        next
      end

      if File.file?(arg)
        raw_bytes = File.binread(arg)
        raw_in = raw_input_file?(arg, options)
        body, cmd_flags = raw_in ? strip_fuzz_header(raw_bytes) : [raw_bytes, []]
        entries << { label: arg, raw_input: raw_in, raw_bytes: raw_bytes, body: body, cmd_flags: cmd_flags }
        next
      end

      if arg.match?(/\Acluster-\d+\z/i) || arg.match?(/\A\d+\z/)
        triage_clusters << arg
        next
      end

      # Check whether positional argument matches a cluster or member bucket in triage metadata.
      clusters = resolve_triage_state(options, cache)
      is_cluster_pat = clusters.any? { |c| direct_cluster_name_match?(c, arg) }
      if is_cluster_pat
        triage_clusters << arg
      else
        matched_bucket = clusters.any? { |c| Array(c["buckets"]).any? { |b| bucket_matches_pattern?(b, arg) } }
        if matched_bucket
          triage_buckets << arg
        else
          raise ConfigError, "Input file or triage cluster/bucket not found: #{arg}"
        end
      end
    end

    selected_clusters = []
    if !triage_clusters.empty? || !triage_buckets.empty? || !options[:groups].empty?
      clusters = resolve_triage_state(options, cache)
      groups = options[:groups].map { |g| FuzzInspect.normalize_group_filter(g) }

      # If a pattern in CLUSTER= names a specific member bucket directly (e.g. ABRT/<sig>)
      # and no explicit --bucket/--member/--all-buckets was set, treat it as a bucket selector.
      resolved_cluster_pats = []
      implied_bucket_pats = []
      triage_clusters.each do |pat|
        if !options[:all_buckets] && triage_buckets.empty? && options[:members].empty? &&
           clusters.none? { |c| direct_cluster_name_match?(c, pat) } &&
           clusters.any? { |c| Array(c["buckets"]).any? { |b| b["bucket_id"].to_s == pat || b["signature"].to_s == pat } }
          implied_bucket_pats << pat
        else
          resolved_cluster_pats << pat
        end
      end

      effective_buckets = triage_buckets + implied_bucket_pats
      matched_clusters = clusters.select do |c|
        next false unless groups.empty? || groups.include?(c["group"].to_s.downcase)
        next false unless resolved_cluster_pats.empty? || FuzzInspect.matches_cluster_filter?(c, resolved_cluster_pats)
        next true if effective_buckets.empty?

        Array(c["buckets"]).any? { |b| effective_buckets.any? { |pat| bucket_matches_pattern?(b, pat) } }
      end

      if !triage_clusters.empty? && matched_clusters.empty?
        raise ConfigError, "No clusters matched #{triage_clusters.join(', ')}"
      end
      if !triage_buckets.empty? && matched_clusters.empty?
        raise ConfigError, "No buckets matched #{triage_buckets.join(', ')}"
      end

      selected_clusters = matched_clusters

      if options[:list_members]
        return [{ list_members: true, clusters: selected_clusters }]
      end

      seen_bids = Set.new
      matched_clusters.each do |c|
        ordered = ordered_cluster_buckets(c)
        chosen =
          if !options[:members].empty?
            idxs = parse_member_specs(options[:members], ordered.size, c["cluster_id"])
            idxs.map { |idx| [ordered[idx - 1], idx] }
          elsif options[:all_buckets] || !effective_buckets.empty?
            ordered.each_with_index.filter_map do |b, idx0|
              next unless effective_buckets.empty? || effective_buckets.any? { |pat| bucket_matches_pattern?(b, pat) }
              [b, idx0 + 1]
            end
          else
            rep_b = ordered.first
            rep_b ? [[rep_b, 1]] : []
          end

        chosen.each do |b, member_idx|
          bid = b["bucket_id"].to_s
          next if bid.empty? || seen_bids.include?(bid)

          seen_bids << bid
          min_path = File.join(options[:triage_dir], bid, "input.min")
          raise ConfigError, "Missing input.min for bucket #{bid} at #{min_path}" unless File.file?(min_path)

          raw_bytes = File.binread(min_path)
          body, cmd_flags = strip_fuzz_header(raw_bytes)
          rep_bid = c.dig("representative", "bucket_id").to_s
          meta_path = File.join(options[:triage_dir], bid, "meta.json")
          bucket_meta = PrismFuzzer::Common.read_json(meta_path, context: "FuzzExplain")
          bucket_meta = nil unless bucket_meta.is_a?(Hash)
          target_sources = bucket_meta&.dig("target", "sources").is_a?(Hash) ? bucket_meta.dig("target", "sources") : nil
          entries << {
            label: "#{c['cluster_id']}:#{bid}",
            path: min_path,
            raw_input: true,
            raw_bytes: raw_bytes,
            body: body,
            cmd_flags: cmd_flags,
            cluster_id: c["cluster_id"],
            cluster_group: c["group"],
            cluster_bucket_count: c["bucket_count"].to_i,
            cluster_occurrences: c["occurrences"].to_i,
            bucket_id: bid,
            member_index: member_idx,
            member_total: ordered.size,
            is_representative: bid == rep_bid,
            verify_profile: b["verify_profile"] || c.dig("representative", "verify_profile"),
            target_sources: target_sources,
            headline: b["headline"] || c.dig("representative", "headline"),
            options_label: b["options_label"] || c.dig("representative", "options_label"),
            loupe_url: b["loupe_url"] || c.dig("representative", "loupe_url")
          }
        end
      end
    elsif options[:list_members]
      raise ConfigError, "--list-members requires a cluster/bucket/group target"
    end

    raise ConfigError, "No inputs given (pass a cluster, bucket, file, -e, or --stdin)" if entries.empty?

    entries = entries.first(options[:limit]) if options[:limit] && options[:limit] >= 0
    entries
  end

  def entry_needs_stream_diff?(entry)
    entry[:headline].to_s.include?("INVARIANT[stream_diff]")
  end

  def entry_needs_serialize?(entry)
    prof = entry[:verify_profile].to_s
    hl = entry[:headline].to_s
    grp = entry[:cluster_group].to_s
    prof == "arm32_oracle" || prof == "ppc_oracle" || prof == "diff_prism" || grp == "diff_prism" ||
      hl.include?("INVARIANT[oracle_") || hl.include?("INVARIANT[diff_prism]")
  end

  def resolve_c_explain_bin_for_source(source_id, options:, target: :a)
    default_bin = target == :b ? options[:explain_b_bin] : options[:explain_bin]
    return default_bin if source_id.nil? || source_id.to_s.empty?

    topo = defined?(PrismFuzzer::Topology) ? PrismFuzzer::Topology.discover(triage_dir: options[:triage_dir], start_dir: REPO_ROOT) : nil
    rel = topo&.dig("explain_binaries", source_id.to_s)
    if rel && !rel.empty?
      cand = File.expand_path(rel, REPO_ROOT)
      return cand if File.executable?(cand)
    end
    ws_build = (topo && defined?(PrismFuzzer::Topology)) ? PrismFuzzer::Topology.workspace_paths(topo, fuzz_root: REPO_ROOT)[:build_dir] : File.join(REPO_ROOT, "tmp", "fuzz", "build")
    named = File.join(ws_build, "fuzz.explain.#{source_id}")
    return named if File.executable?(named)

    default_bin
  end

  def workspace_paths_for(options = {})
    return nil unless defined?(PrismFuzzer::Topology)

    t = PrismFuzzer::Topology.discover(triage_dir: options[:triage_dir], start_dir: REPO_ROOT)
    PrismFuzzer::Topology.workspace_paths(t, fuzz_root: REPO_ROOT) if t
  end

  def resolve_topology_source_path(options = {}, ws = nil)
    return nil unless defined?(PrismFuzzer::Topology)

    [ENV["CAMPAIGN"], ENV["TOPOLOGY_FILE"], ENV["TOPOLOGY"]].each do |env_p|
      next if env_p.nil? || env_p.to_s.strip.empty?

      exp = File.expand_path(env_p.to_s.strip, REPO_ROOT)
      return exp if File.file?(exp)
    end

    cands = []
    if ws
      cands << File.join(ws[:build_dir], "topology.ir.json") if ws[:build_dir]
      cands << File.join(ws[:fuzz_dir], "topology.json") if ws[:fuzz_dir]
    end
    PrismFuzzer::Topology.triage_workspace_candidates(options[:triage_dir]).each do |t_root|
      cands << File.join(t_root, "build", "topology.ir.json")
      cands << File.join(t_root, "topology.json")
      cands << File.join(t_root, "bin", "topology.json")
    end

    cands.compact.uniq.each do |cand|
      exp = File.expand_path(cand, REPO_ROOT)
      next unless File.file?(exp)

      begin
        PrismFuzzer::Topology.load_ir(exp, fuzz_root: REPO_ROOT)
        return exp
      rescue PrismFuzzer::Topology::TopologyError
        next
      end
    end
    nil
  end

  def ensure_c_explain_bin(options, target: :a)
    bin = target == :b ? options[:explain_b_bin] : options[:explain_bin]
    return bin if File.executable?(bin)

    topo = defined?(PrismFuzzer::Topology) ? PrismFuzzer::Topology.discover(triage_dir: options[:triage_dir], start_dir: REPO_ROOT) : nil
    ws = (topo && defined?(PrismFuzzer::Topology)) ? PrismFuzzer::Topology.workspace_paths(topo, fuzz_root: REPO_ROOT) : nil
    topo_src = resolve_topology_source_path(options, ws)
    src_id = if target == :b
               "prism_b"
             elsif topo
               topo.dig("sources", "prism_a") ? "prism_a" : topo.fetch("sources", {}).find { |_, s| s.is_a?(Hash) && s["kind"] == "prism" }&.first
             end

    if defined?(PrismFuzzer::Topology) && (topo_src || !topo) && File.file?(File.join(REPO_ROOT, "bin", "topology.rb"))
      build_args = ["ruby", "./bin/topology.rb", "build-explain", "--arch", "host"]
      build_args.push("--source", src_id) if src_id
      build_args.push("--topology", topo_src) if topo_src
      build_args.push("--build-dir", ws[:build_dir]) if ws && ws[:build_dir]
      build_args.push("--output", bin) if bin && !bin.empty?
      res = run_with_timeout(build_args, timeout_sec: 120.0, chdir: REPO_ROOT)
      return bin if res[:exitstatus] == 0 && File.executable?(bin)

      if ws && File.executable?(File.join(ws[:build_dir], File.basename(bin)))
        return File.join(ws[:build_dir], File.basename(bin))
      end
    elsif defined?(PrismFuzzer::Topology) && topo
      plan = PrismFuzzer::Topology.ensure_resolved_view(topo, fuzz_root: REPO_ROOT)
      resolved_src_id = if target == :b
                          plan.dig("sources", "prism_b") ? "prism_b" : nil
                        else
                          plan.dig("sources", "prism_a") ? "prism_a" : plan.fetch("sources", {}).find { |_, s| s.is_a?(Hash) && s["kind"] == "prism" }&.first
                        end
      if resolved_src_id && (src = plan.dig("sources", resolved_src_id))
        unless src["path"] && File.file?(File.join(src["path"], "include/prism.h"))
          plan = PrismFuzzer::Topology.sync_plan!(plan, fuzz_root: REPO_ROOT, build_dir: ws[:build_dir])
        end
        bname = target == :b ? "fuzz.explain.b" : "fuzz.explain"
        out_rel = plan.dig("explain_binaries", resolved_src_id) || PrismFuzzer::Topology.path_relative_or_abs(File.join(ws[:build_dir], bname), REPO_ROOT)
        PrismFuzzer::Topology.build_explain_for_source!(resolved_src_id, out_rel, plan: plan, fuzz_root: REPO_ROOT, build_dir: ws[:build_dir])
        built = File.expand_path(out_rel, REPO_ROOT)
        return built if File.executable?(built)
      end
    end

    bname = target == :b ? "fuzz.explain.b" : "fuzz.explain"
    target_bin = ws ? File.join(ws[:build_dir], bname) : File.join(REPO_ROOT, "tmp", "fuzz", "build", bname)
    build_args = ["ruby", "./bin/topology.rb", "build-explain", "--arch", "host", "--output", target_bin]
    build_args.push("--source", src_id) if src_id
    build_args.push("--build-dir", ws[:build_dir]) if ws && ws[:build_dir]
    res = run_with_timeout(build_args, timeout_sec: 120.0, chdir: REPO_ROOT)
    return target_bin if res[:exitstatus] == 0 && File.executable?(target_bin)

    detail = [res[:stderr], res[:stdout]].reject(&:empty?).join("\n").strip
    raise ConfigError, "Could not build '#{bin}': #{detail}"
  end

  def detect_entry_cross_arch(entry)
    prof = entry[:verify_profile].to_s
    hl = entry[:headline].to_s
    return "arm32" if prof == "arm32_oracle" || hl.include?("INVARIANT[oracle_arm32]")
    return "ppc" if prof == "ppc_oracle" || hl.include?("INVARIANT[oracle_ppc]")

    nil
  end

  def resolve_entry_cross_arch(entry, options)
    return nil if options[:cross_arch] == false

    options[:arch] || detect_entry_cross_arch(entry)
  end

  def ensure_cross_explain_bin(arch, options = {})
    spec = CROSS_ARCH_SPECS.fetch(arch) do
      raise ConfigError, "Unsupported cross-arch target '#{arch}' (expected arm32 or ppc)"
    end

    env_bin = ENV[spec[:env_bin]].to_s.strip
    return env_bin if !env_bin.empty? && File.executable?(env_bin)

    bname = "fuzz.explain.#{arch}"
    if defined?(PrismFuzzer::Topology) && (topo = PrismFuzzer::Topology.discover(triage_dir: options[:triage_dir], start_dir: REPO_ROOT))
      ws = PrismFuzzer::Topology.workspace_paths(topo, fuzz_root: REPO_ROOT)
      [File.join(ws[:bin_dir], bname), File.join(ws[:build_dir], bname)].each do |cand|
        return cand if File.executable?(cand)
      end

      begin
        plan = PrismFuzzer::Topology.ensure_resolved_view(topo, fuzz_root: REPO_ROOT)
        src = plan.dig("sources", "prism_a") || plan.fetch("sources").values.find { |s| s["kind"] == "prism" }
        unless src && src["path"] && File.file?(File.join(src["path"], "include/prism.h"))
          plan = PrismFuzzer::Topology.sync_plan!(plan, fuzz_root: REPO_ROOT, build_dir: ws[:build_dir])
        end
        return PrismFuzzer::Topology.build_cross_explain!(arch, plan: plan, fuzz_root: REPO_ROOT, build_dir: ws[:build_dir])
      rescue PrismFuzzer::Topology::TopologyError => e
        raise ConfigError, e.message
      end
    end

    return spec[:bin] if File.executable?(spec[:bin])

    res = run_with_timeout(["ruby", "./bin/topology.rb", "build-explain", "--arch", arch, "--output", spec[:bin]], timeout_sec: 120.0, chdir: REPO_ROOT)
    bin = spec[:bin]
    if res[:exitstatus] != 0 || !File.executable?(bin)
      detail = [res[:stderr], res[:stdout]].reject(&:empty?).join("\n").strip
      raise ConfigError, "Could not build '#{bin}': #{detail}"
    end
    bin
  end

  def cross_cmd_prefix(arch, bin)
    spec = CROSS_ARCH_SPECS.fetch(arch)
    elf = File.file?(bin) && File.binread(bin, 4) == "\x7fELF".b
    if elf && File.executable?(spec[:qemu])
      [spec[:qemu], "-L", spec[:sysroot], bin]
    else
      [bin]
    end
  end

  def build_c_explain_args(entry, options)
    args = []
    if entry[:raw_input]
      args << "--raw"
    else
      args << "--snippet"
    end
    args.push("--header", options[:header]) if options[:header]
    args << "--stream" if options[:stream]

    want_stream_cmp = options[:compare_stream] == true || (options[:compare_stream] == :auto && entry_needs_stream_diff?(entry))
    args << "--compare-stream" if want_stream_cmp

    want_ser = options[:serialize] == true || (options[:serialize] == :auto && (entry_needs_serialize?(entry) || !options[:arch].nil? || resolve_diff_prism_enabled([entry], options)))
    args << "--serialize" if want_ser

    args << "--no-ast" unless options[:ast]
    args << "--no-anomalies" unless options[:anomalies]
    args << "--json" if options[:ast_json]
    args << "--line-offsets" if options[:line_offsets]
    args << "--no-errors-format" unless options[:errors_format]
    args
  end

  def exec_c_explain(cmd_prefix, entry, options)
    args = build_c_explain_args(entry, options)

    Tempfile.create(["fuzz-explain", ".bin"], binmode: true) do |tf|
      tf.write(entry[:raw_input] ? entry[:raw_bytes] : entry[:body])
      tf.flush
      cmd = [*cmd_prefix, *args, tf.path]

      res = run_with_timeout(cmd, timeout_sec: options[:timeout])
      out_lines = res[:stdout].lines
      # Replace temporary filename on the first banner line with the logical label when present.
      if out_lines.first&.start_with?("== ")
        out_lines[0] = out_lines[0].sub(tf.path, entry[:label].to_s)
      end

      {
        "ok" => !res[:timed_out] && res[:exitstatus] == 0,
        "timed_out" => res[:timed_out],
        "exitstatus" => res[:exitstatus],
        "termsig" => res[:termsig],
        "stdout" => out_lines.join,
        "stderr" => res[:stderr].strip
      }
    end
  end

  def run_c_explain(entry, options, explain_bin)
    exec_c_explain([explain_bin], entry, options)
  end

  def run_cross_explain_entry(entry, arch, options, bin_cache:, source:)
    spec = CROSS_ARCH_SPECS.fetch(arch)
    bin = (bin_cache[arch] ||= ensure_cross_explain_bin(arch, options))
    res = exec_c_explain(cross_cmd_prefix(arch, bin), entry, options)
    res["arch"] = arch
    res["target_label"] = spec[:label]
    res["source"] = source
    res
  end

  def all_cross_env_overrides_present?(arches)
    arches.all? do |arch|
      spec = CROSS_ARCH_SPECS[arch]
      env_bin = spec ? ENV[spec[:env_bin]].to_s.strip : ""
      !env_bin.empty? && File.executable?(env_bin)
    end
  end

  def run_cross_explanations(entries, options)
    targets = []
    entries.each_with_index do |entry, i|
      arch = resolve_entry_cross_arch(entry, options)
      targets << [i, entry, arch] if arch
    end
    return {} if targets.empty?

    arches = targets.map { |_, _, a| a }.uniq
    if running_in_container? || all_cross_env_overrides_present?(arches)
      bin_cache = {}
      out = {}
      targets.each do |idx, entry, arch|
        out[idx] = run_cross_explain_entry(entry, arch, options, bin_cache: bin_cache, source: "local")
      end
      return out
    end

    if ENV["EXPLAIN_NO_DOCKER"] == "1"
      if options[:arch]
        raise ConfigError, "Cross-arch '#{options[:arch]}' requires Docker image '#{DEFAULT_DOCKER_IMAGE}' and EXPLAIN_NO_DOCKER=1 is set; pass '--no-cross-arch'"
      end
      return {}
    end

    image = ENV.fetch("FUZZ_DOCKER_IMAGE", DEFAULT_DOCKER_IMAGE)
    ensure_docker_image!(image, timeout_sec: options[:timeout], purpose: "32-bit cross-arch explain (#{arches.join('/')})")

    tmpfs_flags = Shellwords.split(ENV.fetch("FUZZ_TMPFS_FLAGS", "--tmpfs /tmp:rw,exec,mode=1777"))
    mount_args = []
    t_abs = options[:triage_dir] && !options[:triage_dir].to_s.empty? ? File.expand_path(options[:triage_dir]) : nil
    triage_arg = options[:triage_dir]
    if defined?(PrismFuzzer::Topology) && (topo = PrismFuzzer::Topology.discover(triage_dir: options[:triage_dir], start_dir: REPO_ROOT))
      ws = PrismFuzzer::Topology.workspace_paths(topo, fuzz_root: REPO_ROOT)
      topo_src = resolve_topology_source_path(options, ws)
      mount_args = PrismFuzzer::Topology.docker_mount_args(topo, topology_path: topo_src, fuzz_root: REPO_ROOT)
    end
    if t_abs
      mounted_pairs = [[File.expand_path(REPO_ROOT), "/prism-fuzzer"]]
      mount_args.each_with_index do |tok, idx|
        next unless tok == "-v" && mount_args[idx + 1]

        host_p, guest_p = mount_args[idx + 1].split(":", 2)
        next unless host_p && guest_p

        mounted_pairs << [File.expand_path(host_p), guest_p.sub(/:(?:ro|rw)\z/, "")]
      end

      matched = mounted_pairs.sort_by { |(h, _)| -h.length }.find do |h, _|
        t_abs == h || t_abs.start_with?("#{h}/")
      end

      if matched
        h, g = matched
        guest_abs = (t_abs == h) ? g : File.join(g, t_abs.delete_prefix("#{h}/"))
        triage_arg = guest_abs.start_with?("/prism-fuzzer/") ? guest_abs.delete_prefix("/prism-fuzzer/") : guest_abs
      elsif File.directory?(t_abs)
        mount_args.push("-v", "#{t_abs}:/external/explain_triage:ro")
        triage_arg = "/external/explain_triage"
      end
    end
    cmd = [
      "docker", "run", "--rm", "-i", "--init",
      *tmpfs_flags,
      *mount_args,
      "-v", "#{REPO_ROOT}:/prism-fuzzer",
      "-w", "/prism-fuzzer",
      image,
      "ruby", "./triage/explain.rb", "--cross-worker",
      "--timeout", options[:timeout].to_s
    ]
    cmd.push("--triage-dir", triage_arg) if triage_arg && !triage_arg.empty?
    cmd.push("--header", options[:header]) if options[:header]
    cmd << "--stream" if options[:stream]
    cmd << "--compare-stream" if options[:compare_stream] == true
    cmd << "--no-compare-stream" if options[:compare_stream] == false
    cmd << "--serialize" if options[:serialize] == true
    cmd << "--no-serialize" if options[:serialize] == false
    cmd << "--no-ast" unless options[:ast]
    cmd << "--no-anomalies" unless options[:anomalies]
    cmd << "--ast-json" if options[:ast_json]
    cmd << "--line-offsets" if options[:line_offsets]
    cmd << "--no-errors-format" unless options[:errors_format]
    cmd.push("--arch", options[:arch]) if options[:arch]

    req = {
      "entries" => targets.map do |idx, e, arch|
        bytes = e[:raw_input] ? e[:raw_bytes] : e[:body]
        {
          "index" => idx,
          "arch" => arch,
          "label" => e[:label],
          "raw_input" => !!e[:raw_input],
          "verify_profile" => e[:verify_profile],
          "headline" => e[:headline],
          "bytes_b64" => Base64.strict_encode64(bytes.to_s.b)
        }
      end
    }
    worker_timeout = [options[:timeout] * targets.size * 3.0 + 45.0, 90.0].max
    res = run_with_timeout(cmd, timeout_sec: worker_timeout, chdir: REPO_ROOT, stdin_data: JSON.generate(req))
    if res[:timed_out] || res[:exitstatus] != 0
      detail = [res[:stderr], res[:stdout]].reject(&:empty?).join("\n").strip
      raise ConfigError, "Docker cross-arch explain failed (#{detail.empty? ? "exit=#{res[:exitstatus]}" : detail})"
    end

    parsed = JSON.parse(res[:stdout])
    out = {}
    Hash(parsed["results"]).each do |k, v|
      out[k.to_i] = v
    end
    out
  rescue JSON::ParserError => e
    raise ConfigError, "Invalid JSON from Docker cross-arch worker: #{e.message}"
  end

  def resolve_compare_enabled(entries, options)
    return false if options[:compare] == false
    return true if options[:compare] == true

    entries.any? { |e| e[:cluster_group] == "diff_parse_y" }
  end

  def resolve_diff_prism_enabled(entries, options)
    return false if options[:diff_prism] == false
    return true if options[:diff_prism] == true

    entries.any? do |e|
      e[:cluster_group] == "diff_prism" ||
        e[:verify_profile].to_s == "diff_prism" ||
        e[:headline].to_s.include?("INVARIANT[diff_prism]")
    end
  end

  def format_members_listing(clusters)
    lines = []
    clusters.each_with_index do |c, idx|
      lines << "" if idx > 0
      lines << "#{c['cluster_id']} (#{c['group']} | #{c['bucket_count']} bucket(s), #{c['occurrences']} occurrences):"
      ordered = ordered_cluster_buckets(c)
      rep_bid = c.dig("representative", "bucket_id").to_s
      ordered.each_with_index do |b, m_idx|
        tag = b["bucket_id"].to_s == rep_bid ? "rep" : "   "
        opts = b["options_label"] ? " | #{b['options_label']}" : ""
        lines << format(
          "  [%3d] %s %-24s  occ=%-5d size=%-4s%s  src=%s",
          m_idx + 1,
          tag,
          b["bucket_id"],
          b["occurrences"].to_i,
          b["min_size_bytes"] ? "#{b['min_size_bytes']}B" : "?",
          opts,
          b["source_preview"].to_s.inspect
        )
      end
    end
    lines.join("\n")
  end

  def format_compare_block(comp, ruby_banner:, options:)
    lines = ["cruby_compare (#{ruby_banner}): parity=#{comp['parity']}"]
    syn = comp["syntax"]
    lines << "  syntax:    #{syn['status']}"
    if syn["status"] != "both_ok"
      lines << "    parse.y: ok=#{syn.dig('parse_y', 'ok')} #{syn.dig('parse_y', 'stderr').to_s.lines.first&.strip}"
      lines << "    prism:   ok=#{syn.dig('prism', 'ok')} #{syn.dig('prism', 'stderr').to_s.lines.first&.strip}"
    end

    if (pe = comp.dig("prism_parse", "errors")) && !pe.empty?
      lines << "  prism_parse.errors (#{pe.size}): #{pe.map { |e| "#{e['type']}(#{e['message']})" }.join('; ')}"
    end

    iseq = comp["iseq"]
    lines << "  iseq:      #{iseq['status']}"
    if iseq["status"] != "match"
      unless iseq.dig("parse_y", "ok")
        lines << "    parse.y compile err: #{iseq.dig('parse_y', 'error_class')}: #{iseq.dig('parse_y', 'error_message')}"
      end
      unless iseq.dig("prism", "ok")
        lines << "    prism   compile err: #{iseq.dig('prism', 'error_class')}: #{iseq.dig('prism', 'error_message')}"
      end
    end

    if iseq["disasm_diff"] && !iseq["disasm_diff"].empty?
      lines << "  disasm diff:"
      iseq["disasm_diff"].each_line(chomp: true) { |dl| lines << "    #{dl}" }
    elsif options[:disasm] && iseq["disasm"]
      label = iseq["disasm_parser"] ? "#{iseq['disasm_parser']} disasm" : "disasm"
      lines << "  #{label}:"
      iseq["disasm"].each_line(chomp: true) { |dl| lines << "    #{dl}" }
    end

    if (ev = comp["eval"])
      lines << "  eval:      #{ev['status']} (parse.y exit=#{ev.dig('parse_y', 'exitstatus')}, prism exit=#{ev.dig('prism', 'exitstatus')})"
      if ev["status"] != "match"
        lines << "    parse.y stdout: #{ev.dig('parse_y', 'stdout').inspect} stderr: #{ev.dig('parse_y', 'stderr').lines.first&.strip}"
        lines << "    prism   stdout: #{ev.dig('prism', 'stdout').inspect} stderr: #{ev.dig('prism', 'stderr').lines.first&.strip}"
      end
    end

    lines.join("\n")
  end

  def format_c_explain_failure(ce)
    return [] if ce["ok"]

    sig = ce["termsig"] ? " signal=#{ce['termsig']}" : ""
    out = ["c_explain:   aborted (exit=#{ce['exitstatus'].inspect}#{sig})"]
    out << ce["stderr"] unless ce["stderr"].to_s.empty?
    out
  end

  def split_explain_preamble(c_stdout)
    lines = c_stdout.to_s.lines
    lines = lines.drop(1) if lines.first&.start_with?("== ")
    preamble = []
    rest = lines.drop_while do |ln|
      if ln.start_with?("header:", "options:", "source:")
        preamble << ln.chomp
        true
      else
        false
      end
    end
    [preamble, rest.join]
  end

  def format_text_output(results, ruby_banner:, compare_ran:)
    blocks = []
    if compare_ran
      matched = results.count { |r| r["parity"] == "match" }
      mismatched = results.size - matched
      blocks << "CRuby: #{ruby_banner}\nChecked #{results.size} input(s): match=#{matched}, mismatch=#{mismatched}"
    end

    results.each do |r|
      lines = []
      if r["cluster_id"]
        role = r["is_representative"] ? "rep " : ""
        meta = ["#{role}[#{r['member_index']}/#{r['member_total']}]"]
        meta << "group=#{r['cluster_group']}" if r["cluster_group"]
        meta << "profile=#{r['verify_profile']}" if r["verify_profile"]
        meta << "#{r['cluster_bucket_count']} bkts, #{r['cluster_occurrences']} occ"
        meta << "options: #{r['options_label']}" if r["options_label"] && !r["options_label"].empty?
        lines << "== #{r['label']} (#{meta.join(' | ')}) =="
        lines << "headline:    #{r['headline']}" if r["headline"] && !r["headline"].empty?
        lines << "loupe:       #{r['loupe_url']}" if r["loupe_url"] && !r["loupe_url"].empty?
        if r["member_total"].to_i > 1 && r["is_representative"]
          lines << "siblings:    #{r['member_total']} bucket(s) in cluster; pass --member N / --bucket PAT / --all-buckets / --list-members"
        end
      end

      xe = r["cross_explain"]
      pb = r["prism_b_explain"]
      if (ce = r["c_explain"])
        c_out = ce["stdout"].to_s
        if xe || pb
          preamble, body = split_explain_preamble(c_out)
          lines.concat(preamble) unless preamble.empty?
          lines << ""
          lines << (pb ? "--- prism_a (build/fuzz.explain) ---" : "--- 64-bit host (build/fuzz.explain) ---")
          lines << body.rstrip unless body.strip.empty?
        else
          # Drop duplicate == label == header when cluster banner already identified this entry.
          if r["cluster_id"] && c_out.start_with?("== ")
            c_out = c_out.lines.drop(1).join
          end
          lines << c_out.rstrip unless c_out.empty?
        end
        lines.concat(format_c_explain_failure(ce))
      end

      if pb
        _, pb_body = split_explain_preamble(pb["stdout"].to_s)
        lines << "" unless lines.empty?
        lines << "--- prism_b (build/fuzz.explain.b) ---"
        lines << pb_body.rstrip unless pb_body.strip.empty?
        lines.concat(format_c_explain_failure(pb))
        if ce && !ce["stdout"].to_s.empty? && !pb["stdout"].to_s.empty?
          _, pa_body = split_explain_preamble(ce["stdout"].to_s)
          delta = simple_line_diff(pa_body, pb_body, label_a: "prism_a", label_b: "prism_b")
          lines << ""
          lines << "--- diff (prism_a vs prism_b) ---"
          lines << (delta.empty? ? "(identical fuzz.explain output)" : delta)
        end
      end

      if xe
        _, x_body = split_explain_preamble(xe["stdout"].to_s)
        lines << "" unless lines.empty?
        lines << "--- #{xe['target_label'] || xe['arch']} ---"
        lines << x_body.rstrip unless x_body.strip.empty?
        lines.concat(format_c_explain_failure(xe))
      end

      if r["syntax"]
        comp = r.slice("syntax", "prism_parse", "iseq", "eval", "parity")
        lines << format_compare_block(comp, ruby_banner: ruby_banner, options: r["_compare_opts"] || {})
      end

      blocks << lines.join("\n")
    end

    blocks.join("\n\n")
  end

  def default_options
    ws = if defined?(PrismFuzzer::Topology)
           t = PrismFuzzer::Topology.discover(triage_dir: ENV["TRIAGE_DIR"], start_dir: REPO_ROOT)
           PrismFuzzer::Topology.workspace_paths(t, fuzz_root: REPO_ROOT) if t
         end
    default_triage = ws ? PrismFuzzer::Topology.path_relative_or_abs(ws[:triage_dir], Dir.pwd) : "tmp/fuzz/report/triage"
    {
      triage_dir: ENV.fetch("TRIAGE_DIR", default_triage),
      clusters_file: ENV["CLUSTERS_FILE"]&.strip,
      metadata_path: nil,
      clusters: FuzzInspect.parse_csv_env("CLUSTER"),
      buckets: FuzzInspect.parse_csv_env("BUCKET"),
      members: [],
      groups: [],
      all_buckets: false,
      list_members: false,
      limit: nil,
      inline_codes: [],
      stdin: false,
      raw: nil,
      header: nil,
      stream: false,
      compare_stream: :auto,
      serialize: :auto,
      ast: true,
      anomalies: true,
      ast_json: false,
      line_offsets: false,
      errors_format: true,
      diff_prism: :auto,
      compare: :auto,
      compare_only: false,
      ruby: ENV.fetch("COMPARE_RUBY", RbConfig.ruby),
      ruby_explicit: false,
      disasm: false,
      ignore_locations: false,
      eval: false,
      apply_cmd_flags: false,
      timeout: DEFAULT_TIMEOUT_SECONDS,
      fail_on_mismatch: false,
      json: false,
      arch: nil,
      cross_arch: true,
      cross_worker: false,
      cruby_worker: false,
      explain_bin: ENV["EXPLAIN_BIN"]&.strip,
      explain_b_bin: ENV["EXPLAIN_B_BIN"]&.strip,
      explain_bin_explicit: !ENV["EXPLAIN_BIN"].to_s.strip.empty?,
      explain_b_bin_explicit: !ENV["EXPLAIN_B_BIN"].to_s.strip.empty?
    }
  end

  def resolve_default_explain_bin(name, ws:)
    return File.join(REPO_ROOT, "tmp", "fuzz", "build", name) unless ws

    bin_cand = File.join(ws[:bin_dir], name)
    return bin_cand if File.executable?(bin_cand)

    File.join(ws[:build_dir], name)
  end

  def parse_options(argv)
    options = default_options
    positional = []

    parser = OptionParser.new do |opts|
      opts.banner = "Usage: explain.rb [OPTIONS] [TARGET ...]"
      opts.separator ""
      opts.separator "Unified fuzzer triage & Ruby snippet explainer."
      opts.separator "Targets may be cluster IDs/numbers (cluster-13, 13; defaults to representative),"
      opts.separator "bucket IDs/signatures (ABRT/6ba0e914352b20ba), input files, -e CODE, or '-' stdin."
      opts.separator ""

      opts.separator "Targets & Member Selection:"
      opts.on("-c", "--cluster PATTERN", "Select cluster(s) by ID, number, or member bucket (repeatable)") { |v| options[:clusters].concat(v.split(",").map(&:strip)) }
      opts.on("-b", "--bucket PATTERN", "Select matching bucket_id/signature within clusters (repeatable)") { |v| options[:buckets].concat(v.split(",").map(&:strip)) }
      opts.on("-m", "--member SPEC", "Select 1-based member index or range within cluster (e.g. 2 or 2..5; 1 = rep)") { |v| options[:members] << v }
      opts.on("-g", "--group GROUP", "Select clusters by group (prism_flaw | diff_parse_y | diff_prism | cruby_crash; repeatable)") { |v| options[:groups] << v }
      opts.on("--all-buckets", "Explain every member bucket in selected clusters instead of representative only") { options[:all_buckets] = true }
      opts.on("--list-members", "List numbered member buckets for selected cluster(s) and exit") { options[:list_members] = true }
      opts.on("-n", "--limit N", Integer, "Limit total inputs inspected") { |v| options[:limit] = v }
      opts.on("-e", "--code CODE", "Inline Ruby snippet (repeatable)") { |v| options[:inline_codes] << v }
      opts.on("--stdin", "Read input from stdin") { options[:stdin] = true }

      opts.separator ""
      opts.separator "Prism C Inspection (build/fuzz.explain):"
      opts.on("--raw", "Treat input as 4-byte fuzzer header + Ruby payload") { options[:raw] = true }
      opts.on("-s", "--snippet", "Treat file/stdin input as plain Ruby source (no 4-byte header)") { options[:raw] = false }
      opts.on("--header HEX", "8-hex-digit fuzz options header override (e.g. 40000301)") { |v| options[:header] = v }
      opts.on("--stream", "Force pm_parse_stream mode") { options[:stream] = true }
      opts.on("--compare-stream", "Compare pm_parse vs pm_parse_stream in build/fuzz.explain") { options[:compare_stream] = true }
      opts.on("--no-compare-stream", "Disable automatic --compare-stream on stream_diff clusters") { options[:compare_stream] = false }
      opts.on("--serialize", "Print pm_serialize byte length and hex dump") { options[:serialize] = true }
      opts.on("--no-serialize", "Disable automatic --serialize on 32-bit oracle clusters") { options[:serialize] = false }
      opts.on("--no-ast", "Omit annotated AST dump") { options[:ast] = false }
      opts.on("--no-anomalies", "Disable AST span/relation/invariant anomaly checks") { options[:anomalies] = false }
      opts.on("--ast-json", "Include pm_dump_json AST output from build/fuzz.explain") { options[:ast_json] = true }
      opts.on("--line-offsets", "Print every line offset entry") { options[:line_offsets] = true }
      opts.on("--no-errors-format", "Omit pm_errors_format source snippet block") { options[:errors_format] = false }
      opts.on("--explain-bin PATH", "Path to compiled build/fuzz.explain binary") do |v|
        options[:explain_bin] = v
        options[:explain_bin_explicit] = true
      end
      opts.on("--explain-b-bin PATH", "Path to compiled build/fuzz.explain.b binary") do |v|
        options[:explain_b_bin] = v
        options[:explain_b_bin_explicit] = true
      end

      opts.separator ""
      opts.separator "Prism vs Prism Comparison (auto for diff_prism; runs fuzz.explain vs fuzz.explain.b):"
      opts.on("--diff-prism", "Force side-by-side build/fuzz.explain (prism_a) vs build/fuzz.explain.b (prism_b)") { options[:diff_prism] = true }
      opts.on("--no-diff-prism", "Skip prism_b side-by-side comparison") { options[:diff_prism] = false }

      opts.separator ""
      opts.separator "CRuby parse.y vs prism Comparison (auto for diff_parse_y; runs via Docker if needed):"
      opts.on("--compare", "Force CRuby --parser=parse.y vs --parser=prism parity check") { options[:compare] = true }
      opts.on("--no-compare", "Skip CRuby parse.y vs prism comparison (stay local)") { options[:compare] = false }
      opts.on("--compare-only", "Run CRuby comparison only (skip local build/fuzz.explain)") { options[:compare_only] = true; options[:compare] = true }
      opts.on("--disasm", "Compare and print CRuby InstructionSequence disassembly (implies --compare)") { options[:disasm] = true; options[:compare] = true if options[:compare] == :auto }
      opts.on("--ignore-locations", "Ignore ISeq header location ranges when comparing disasm (implies --compare)") { options[:ignore_locations] = true; options[:compare] = true if options[:compare] == :auto }
      opts.on("--eval", "Also execute under both CRuby parsers (implies --compare)") { options[:eval] = true; options[:compare] = true if options[:compare] == :auto }
      opts.on("--apply-cmd-flags", "Forward -a/-l/-n/-p/-x from 4-byte fuzz header to CRuby checks (implies --compare)") { options[:apply_cmd_flags] = true; options[:compare] = true if options[:compare] == :auto }
      opts.on("--ruby PATH", "Local CRuby binary supporting --parser=parse.y (implies --compare)") { |v| options[:ruby] = v; options[:ruby_explicit] = true; options[:compare] = true if options[:compare] == :auto }
      opts.on("--timeout SEC", Float, "Per-command timeout in seconds (default: #{DEFAULT_TIMEOUT_SECONDS})") { |v| options[:timeout] = v }
      opts.on("--fail-on-mismatch", "Exit 1 if any checked input diverges between parse.y and prism (implies --compare)") { options[:fail_on_mismatch] = true; options[:compare] = true if options[:compare] == :auto }

      opts.separator ""
      opts.separator "Cross-Arch Inspection (auto for oracle_arm32 / oracle_ppc; runs qemu via Docker if needed):"
      opts.on("--arch ARCH", "Force 32-bit target explain alongside host (arm32 | ppc)") do |v|
        arch = v.to_s.strip.downcase
        raise OptionParser::InvalidArgument, "expected arm32 or ppc" unless CROSS_ARCH_SPECS.key?(arch)

        options[:arch] = arch
      end
      opts.on("--no-cross-arch", "Skip 32-bit qemu cross-arch inspection (stay local 64-bit only)") { options[:cross_arch] = false }

      opts.separator ""
      opts.separator "Metadata & Output:"
      opts.on("--triage-dir DIR", "Triage directory (default: #{options[:triage_dir]})") { |v| options[:triage_dir] = v }
      opts.on("--clusters-file PATH", "Explicit clusters.json path") { |v| options[:clusters_file] = v }
      opts.on("--metadata PATH", "Explicit metadata.json path") { |v| options[:metadata_path] = v }
      opts.on("--json", "Emit structured JSON report") { options[:json] = true }
      opts.on("--cross-worker", "Internal: read JSON payloads on stdin and emit cross-arch explain JSON") { options[:cross_worker] = true }
      opts.on("--cruby-worker", "Internal: read JSON payloads on stdin and emit CRuby comparison JSON") { options[:cruby_worker] = true }
    end

    parser.order!(argv) do |arg|
      positional << arg
    end

    options[:clusters].reject!(&:empty?)
    options[:buckets].reject!(&:empty?)
    options[:clusters_file] = nil if options[:clusters_file]&.empty?
    ws_eff = workspace_paths_for(options)
    unless options[:explain_bin_explicit]
      options[:explain_bin] = resolve_default_explain_bin("fuzz.explain", ws: ws_eff)
    end
    unless options[:explain_b_bin_explicit]
      options[:explain_b_bin] = resolve_default_explain_bin("fuzz.explain.b", ws: ws_eff)
    end
    [options, positional]
  end

  def run_cruby_worker(options)
    req = JSON.parse($stdin.read)
    ruby_banner = check_ruby_parser_support(options[:ruby], timeout_sec: options[:timeout])
    entries = Array(req["entries"]).map do |e|
      {
        label: e["label"],
        body: Base64.decode64(e["body_b64"].to_s),
        cmd_flags: Array(e["cmd_flags"])
      }
    end
    results = entries.map { |e| compare_entry(e, options) }
    puts JSON.generate({ "ruby" => ruby_banner, "results" => results })
    0
  end

  def run_cross_worker(options)
    req = JSON.parse($stdin.read)
    bin_cache = {}
    out = {}
    Array(req["entries"]).each do |e|
      raw_in = e["raw_input"] == true
      bytes = Base64.decode64(e["bytes_b64"].to_s)
      entry = {
        label: e["label"],
        raw_input: raw_in,
        raw_bytes: raw_in ? bytes : "".b,
        body: raw_in ? "".b : bytes,
        verify_profile: e["verify_profile"],
        headline: e["headline"]
      }
      arch = e["arch"].to_s
      out[e["index"].to_s] = run_cross_explain_entry(entry, arch, options, bin_cache: bin_cache, source: "docker")
    end
    puts JSON.generate({ "results" => out })
    0
  end

  def run(argv = ARGV)
    options, positional = parse_options(argv)
    return run_cruby_worker(options) if options[:cruby_worker]
    return run_cross_worker(options) if options[:cross_worker]

    entries = collect_entries(options, positional)
    if entries.size == 1 && entries.first[:list_members]
      clusters = entries.first[:clusters]
      if options[:json]
        payload = {
          "schema_version" => 1,
          "clusters" => clusters.map do |c|
            rep_bid = c.dig("representative", "bucket_id").to_s
            {
              "cluster_id" => c["cluster_id"],
              "group" => c["group"],
              "members" => ordered_cluster_buckets(c).each_with_index.map do |b, idx|
                {
                  "index" => idx + 1,
                  "representative" => b["bucket_id"].to_s == rep_bid,
                  "bucket_id" => b["bucket_id"],
                  "occurrences" => b["occurrences"],
                  "min_size_bytes" => b["min_size_bytes"],
                  "options_label" => b["options_label"],
                  "source_preview" => b["source_preview"]
                }.compact
              end
            }
          end
        }
        puts JSON.pretty_generate(payload)
      else
        puts format_members_listing(clusters)
      end
      return 0
    end

    compare_enabled = resolve_compare_enabled(entries, options)
    diff_prism_enabled = resolve_diff_prism_enabled(entries, options)
    c_bin = options[:compare_only] ? nil : ensure_c_explain_bin(options, target: :a)
    c_b_bin = (!options[:compare_only] && diff_prism_enabled) ? ensure_c_explain_bin(options, target: :b) : nil
    cross_results = options[:compare_only] ? {} : run_cross_explanations(entries, options)

    comp_payload = compare_enabled ? run_cruby_comparisons(entries, options) : nil
    comp_results = comp_payload ? comp_payload["results"] : nil
    ruby_banner = comp_payload ? comp_payload["ruby"] : nil

    results = entries.each_with_index.map do |entry, i|
      r = {
        "label" => entry[:label],
        "cluster_id" => entry[:cluster_id],
        "cluster_group" => entry[:cluster_group],
        "cluster_bucket_count" => entry[:cluster_bucket_count],
        "cluster_occurrences" => entry[:cluster_occurrences],
        "bucket_id" => entry[:bucket_id],
        "member_index" => entry[:member_index],
        "member_total" => entry[:member_total],
        "is_representative" => entry.key?(:is_representative) ? entry[:is_representative] : nil,
        "verify_profile" => entry[:verify_profile],
        "headline" => entry[:headline],
        "options_label" => entry[:options_label],
        "loupe_url" => entry[:loupe_url],
        "bytes" => entry[:body].bytesize,
        "source_preview" => FuzzInspect.format_source_preview(entry[:body]),
        "cmd_flags" => Array(entry[:cmd_flags])
      }.compact

      src_a_id = entry.dig(:target_sources, "prism_a") || entry.dig(:target_sources, "prism") || entry.dig(:target_sources, "source")
      src_b_id = entry.dig(:target_sources, "prism_b")
      entry_a_bin = c_bin ? resolve_c_explain_bin_for_source(src_a_id, options: options, target: :a) : nil
      entry_b_bin = c_b_bin ? resolve_c_explain_bin_for_source(src_b_id, options: options, target: :b) : nil
      r["c_explain"] = run_c_explain(entry, options, entry_a_bin) if entry_a_bin
      r["prism_b_explain"] = run_c_explain(entry, options, entry_b_bin) if entry_b_bin
      r["cross_explain"] = cross_results[i] if cross_results[i]

      if comp_results && comp_results[i]
        r.merge!(comp_results[i])
        r["_compare_opts"] = options unless options[:json]
      end
      r
    end

    mismatched = compare_enabled ? results.count { |r| r["parity"] != "match" } : 0

    if options[:json]
      payload = {
        "schema_version" => 1,
        "results" => results
      }
      if compare_enabled
        payload["ruby"] = ruby_banner
        payload["compare_source"] = comp_payload["source"]
        payload["summary"] = {
          "total" => results.size,
          "matched" => results.size - mismatched,
          "mismatched" => mismatched
        }
      end
      puts JSON.pretty_generate(payload)
    else
      puts format_text_output(results, ruby_banner: ruby_banner, compare_ran: compare_enabled)
    end

    (options[:fail_on_mismatch] && mismatched > 0) ? 1 : 0
  rescue OptionParser::ParseError, ConfigError => e
    warn "Error: #{e.message}"
    1
  end
end

exit(FuzzExplain.run(ARGV)) if __FILE__ == $PROGRAM_NAME
