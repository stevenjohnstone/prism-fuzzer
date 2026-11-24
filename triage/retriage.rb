#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "optparse"
require "rbconfig"
require "set"
require "tmpdir"

require_relative "triage"
require_relative "../runtime/common"
require_relative "lib/verify_profile"

# Post-fix triage refresh: verifies existing buckets, removes cured buckets with
# #skip sentinels, and re-triages surviving inputs into fresh buckets and clusters.
module FuzzRetriage
  module_function

  def parse_csv_env(name)
    ENV.fetch(name, "").split(",").map(&:strip).reject(&:empty?)
  end

  def locate_fuzz_root
    PrismFuzzer::Common.locate_fuzz_root(__dir__) || File.expand_path("..", __dir__)
  end

  # Collect all unique raw input SHA-256 hashes and their latest occurrence metadata
  # from a bucket directory before removing it from disk.
  def collect_bucket_provenance(bucket_dir)
    hashes = Set.new
    occ_by_sha = {}

    occ_path = File.join(bucket_dir, "occurrences.jsonl")
    if File.file?(occ_path)
      File.foreach(occ_path) do |line|
        next if line.strip.empty?

        rec = JSON.parse(line)
        next unless rec.is_a?(Hash)

        sha = rec["sha256"]
        next unless sha && !sha.empty?

        hashes.add(sha)
        occ_by_sha[sha] ||= rec
      rescue JSON::ParserError, EncodingError => e
        warn "FuzzRetriage: malformed JSONL line in #{occ_path}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
        next
      end
    end

    meta_path = File.join(bucket_dir, "meta.json")
    meta = PrismFuzzer::Common.read_json(meta_path, context: "FuzzRetriage")
    meta = nil unless meta.is_a?(Hash)
    if meta.is_a?(Hash)
      raw_sha = meta.dig("input", "raw_sha256")
      hashes.add(raw_sha) if raw_sha && !raw_sha.empty?
    end

    archive_path = File.join(bucket_dir, FuzzTriage::INPUTS_ARCHIVE_FILE)
    if File.file?(archive_path)
      FuzzTriage.read_tar_gz_entries(archive_path, include_bytes: false)[:entries].each_key { |sha| hashes.add(sha) }
    end

    FuzzTriage.read_pending_inputs(bucket_dir).each { |sha, _| hashes.add(sha) }

    Dir.glob(File.join(bucket_dir, "id*")).each do |id_path|
      next unless File.file?(id_path)

      hashes.add(Digest::SHA256.file(id_path).hexdigest)
    end

    { meta: meta, hashes: hashes, occ_by_sha: occ_by_sha }
  end

  def resolve_reclassify_executable(meta, profile, build_rel: nil)
    FuzzVerifyProfile.resolve_reclassify_executable(meta, profile, build_rel: build_rel, fuzz_root: locate_fuzz_root)
  end

  def collect_survivor_files(bucket_survivor_dir)
    return [] unless File.directory?(bucket_survivor_dir)

    files = Dir.children(bucket_survivor_dir)
      .map { |name| File.join(bucket_survivor_dir, name) }
      .select { |path| File.file?(path) }
      .sort

    archived = files.reject { |path| File.basename(path) == "input.min" }
    archived.empty? ? files : archived
  end

  def build_verify_command(verify_rb, options, survivors_dir, verify_json_path)
    cmd = [
      RbConfig.ruby,
      verify_rb,
      "--triage-dir", options[:triage_dir],
      "--timeout", options[:timeout].to_s,
      "--max-failures", "0",
      "--extract-survivors", survivors_dir,
      "--json", verify_json_path
    ]
    cmd.push("--clusters-file", options[:clusters_file]) if options[:clusters_file]
    options[:clusters].each { |pat| cmd.push("--cluster", pat) }
    options[:buckets].each { |pat| cmd.push("--bucket", pat) }
    options[:reasons].each { |pat| cmd.push("--reason", pat) }
    cmd << "--include-unreproducible" if options[:include_unreproducible]
    cmd << "--rebuild-verifiers" if options[:rebuild]
    cmd << "--quiet" if options[:quiet]
    cmd
  end

  def prune_empty_reason_dirs(triage_dir, bucket_ids)
    bucket_ids.map { |bid| bid.split("/", 2).first }.uniq.each do |reason|
      next if reason.nil? || reason.empty? || reason.start_with?(".")

      reason_dir = File.join(triage_dir, reason)
      Dir.rmdir(reason_dir) if File.directory?(reason_dir) && Dir.empty?(reason_dir)
    end
  end

  def default_options(fuzz_root = locate_fuzz_root)
    ws_default_triage = if defined?(PrismFuzzer::Topology)
                          t = PrismFuzzer::Topology.discover(start_dir: fuzz_root)
                          t ? PrismFuzzer::Topology.path_relative_or_abs(PrismFuzzer::Topology.workspace_paths(t, fuzz_root: fuzz_root)[:triage_dir], Dir.pwd) : "tmp/fuzz/report/triage"
                        else
                          "tmp/fuzz/report/triage"
                        end
    {
      triage_dir: ENV.fetch("TRIAGE_DIR", ws_default_triage),
      clusters: parse_csv_env("CLUSTER"),
      clusters_file: ENV["CLUSTERS_FILE"]&.strip,
      buckets: parse_csv_env("BUCKET"),
      reasons: parse_csv_env("REASON"),
      include_unreproducible: ENV["VERIFY_UNREPRODUCIBLE"] == "1",
      timeout: Integer(ENV.fetch("VERIFY_TIMEOUT", "5")),
      rebuild: ENV["VERIFY_REBUILD"] == "1",
      build: ENV.fetch("RETRIAGE_BUILD", "1") != "0",
      dry_run: ENV["RETRIAGE_DRY_RUN"] == "1",
      verbose: ENV["VERIFY_VERBOSE"] == "1",
      quiet: ENV["VERIFY_QUIET"] == "1"
    }
  end

  def parse_options(argv, fuzz_root = locate_fuzz_root)
    options = default_options(fuzz_root)
    normalized_argv = argv.map do |arg|
      case arg
      when "--rebuild" then "--rebuild-verifiers"
      when "--no-build" then "--skip-fuzzer-build"
      else arg
      end
    end
    OptionParser.new do |opts|
      opts.banner = "Usage: retriage.rb [OPTIONS]"
      opts.on("--triage-dir DIR", "Triage directory (default: tmp/fuzz/report/triage)") { |v| options[:triage_dir] = v }
      opts.on("--cluster PATTERN", "Only retriage buckets in matching cluster(s) (repeatable)") { |v| options[:clusters] << v }
      opts.on("--clusters-file PATH", "Path to clusters.json (default: <triage-dir>/clusters.json)") { |v| options[:clusters_file] = v }
      opts.on("--bucket PATTERN", "Only retriage buckets matching pattern (repeatable)") { |v| options[:buckets] << v }
      opts.on("--reason REASON", "Only retriage buckets in reason directory (repeatable)") { |v| options[:reasons] << v }
      opts.on("--include-unreproducible", "Include unreproducible/ buckets in verification") { options[:include_unreproducible] = true }
      opts.on("--timeout SEC", Integer, "Per-input verify timeout in seconds (default: 5)") { |v| options[:timeout] = v }
      opts.on("--rebuild-verifiers", "Force recompilation of verify_runner binaries (bypasses source fingerprint cache)") { options[:rebuild] = true }
      opts.on("--skip-fuzzer-build", "Skip rebuilding campaign fuzzer binaries when surviving inputs remain") { options[:build] = false }
      opts.on("--dry-run", "Verify and report what would be removed/re-triaged without modifying disk") { options[:dry_run] = true }
      opts.on("--verbose", "Print detailed progress") { options[:verbose] = true }
      opts.on("--quiet", "Suppress detailed verification lines") { options[:quiet] = true }
    end.parse!(normalized_argv)
    argv.replace(normalized_argv)

    options[:clusters_file] = nil if options[:clusters_file]&.empty?
    options
  end

  def rebuild_fuzzer_binaries!(fuzz_root, quiet: false)
    in_container = File.exist?("/.dockerenv") || File.exist?("/run/.containerenv")
    campaign_cli = File.join(fuzz_root, "bin", "campaign.rb")
    has_campaign_env = %w[CAMPAIGN TOPOLOGY].any? { |k| !ENV[k].to_s.strip.empty? }

    if File.file?(campaign_cli) && has_campaign_env
      cmd = [RbConfig.ruby, campaign_cli, "build", "--skip-sync"]
      cmd << "--in-container-step" if in_container
      puts "Rebuilding campaign fuzzer binaries (#{cmd.drop(1).join(' ')})..." unless quiet
      ok = Dir.chdir(fuzz_root) { system(*cmd) }
      abort "Campaign fuzzer build failed; leaving triage buckets unmodified." unless ok
    else
      target = in_container ? "_build-all" : "build"
      puts "Rebuilding fuzzer binaries against current working tree (make #{target})..." unless quiet
      ok = Dir.chdir(fuzz_root) { system("make", target) }
      abort "make #{target} failed; leaving triage buckets unmodified." unless ok
    end
  end

  def run(argv = ARGV)
    fuzz_root = locate_fuzz_root
    options = parse_options(argv.dup, fuzz_root)

    verify_rb = File.join(__dir__, "verify.rb")
    abort "Missing verify.rb at #{verify_rb}" unless File.file?(verify_rb)

    triage_dir = options[:triage_dir]
    ws_topo = defined?(PrismFuzzer::Topology) ? PrismFuzzer::Topology.discover(triage_dir: triage_dir, start_dir: fuzz_root) : nil
    ws_build_rel = (ws_topo && defined?(PrismFuzzer::Topology)) ? PrismFuzzer::Topology.workspace_paths(ws_topo, fuzz_root: fuzz_root)[:build_rel] : "./tmp/fuzz/build"
    unless File.directory?(triage_dir)
      warn "Triage directory not found: #{triage_dir}"
      return 0
    end

    Dir.mktmpdir("prism-retriage-") do |workdir|
      survivors_dir = File.join(workdir, "survivors")
      verify_json_path = File.join(workdir, "verify.json")
      verify_cmd = build_verify_command(verify_rb, options, survivors_dir, verify_json_path)

      system(*verify_cmd)
      verify_rc = $?.exitstatus

      if verify_rc == 0 && !File.file?(verify_json_path)
        puts "Nothing to retriage under #{triage_dir}."
        return 0
      end

      unless [0, 1].include?(verify_rc) && File.file?(verify_json_path)
        abort "Verification failed (exit=#{verify_rc}); leaving #{triage_dir} unmodified."
      end

      verify_report = JSON.parse(File.read(verify_json_path))
      checked_buckets = verify_report.fetch("buckets")
      if checked_buckets.empty?
        puts "No matching buckets checked; leaving #{triage_dir} unmodified."
        return 0
      end

      cured_buckets = []
      failing_buckets = []
      buckets_to_remove = []
      cured_hashes = Set.new
      survivors_by_sha = {}
      surviving_all_shas = Set.new
      occ_overrides = {}
      fuzz_versions_overrides = {}

      checked_buckets.each do |b|
        bucket_id = b["bucket_id"]
        bucket_dir = File.join(triage_dir, bucket_id)
        provenance = collect_bucket_provenance(bucket_dir)

        buckets_to_remove << bucket_id
        cured_hashes.merge(provenance[:hashes])

        if %w[PASS EMPTY].include?(b["status"])
          cured_buckets << bucket_id
          next
        end

        failing_buckets << bucket_id
        bucket_survivor_dir = File.join(survivors_dir, bucket_id)
        files = collect_survivor_files(bucket_survivor_dir)
        if b["failed"].to_i > 0 && files.empty?
          abort "Bucket #{bucket_id} reported #{b["failed"]} failures, but no survivors were extracted; leaving #{triage_dir} unmodified."
        end

        executable = resolve_reclassify_executable(provenance[:meta], b["profile"], build_rel: ws_build_rel)
        default_queue = provenance[:meta]&.dig("reason") == "hang" ? "hangs" : "crashes"
        orig_meta = provenance[:meta]
        orig_fuzz_prov = if orig_meta.is_a?(Hash)
                           if orig_meta.dig("versions", "fuzz").is_a?(Hash)
                             fv = orig_meta.dig("versions", "fuzz").dup
                             fv["container"] ||= orig_meta.dig("versions", "container") if orig_meta.dig("versions", "container")
                             fv.compact
                           elsif orig_meta["versions"].is_a?(Hash) && !orig_meta["versions"].empty?
                             {
                               "binary" => orig_meta["reproduced_by"],
                               "prism" => orig_meta.dig("versions", "prism"),
                               "ruby_parse_y" => orig_meta.dig("versions", "ruby_parse_y"),
                               "container" => orig_meta.dig("versions", "container")
                             }.compact
                           end
                         end

        files.each do |file_path|
          bname = File.basename(file_path)
          content_sha = Digest::SHA256.file(file_path).hexdigest
          # Archived tar entries use the pre-normalized raw crash SHA-256 (differs from content_sha for IJON inputs).
          orig_sha = bname.match?(/\A[0-9a-f]{64}\z/i) ? bname : content_sha
          occ = provenance[:occ_by_sha][orig_sha] || provenance[:occ_by_sha][content_sha]
          if occ
            occ_overrides[content_sha] ||= occ.merge("sha256" => content_sha)
          end
          fuzz_versions_overrides[content_sha] ||= orig_fuzz_prov if orig_fuzz_prov && !orig_fuzz_prov.empty?

          surviving_all_shas.add(orig_sha)
          surviving_all_shas.add(content_sha)

          entry = (survivors_by_sha[content_sha] ||= {
            sha: content_sha,
            orig_shas: Set.new,
            path: file_path,
            executable: executable,
            queue: occ&.dig("queue") == "hangs" ? "hangs" : default_queue
          })
          entry[:orig_shas].add(orig_sha) if orig_sha != content_sha
        end
      end

      cured_hashes.subtract(surviving_all_shas)

      unless options[:quiet]
        puts ""
        puts format(
          "Retriage plan for %s: %d bucket(s) cured/empty (to remove, %d unique input hashes skipped), %d failing/partial bucket(s) (%d surviving inputs to re-triage)",
          triage_dir,
          cured_buckets.size,
          cured_hashes.size,
          failing_buckets.size,
          survivors_by_sha.size
        )
      end

      if options[:dry_run]
        puts "Dry run (--dry-run): no changes made to #{triage_dir}."
        return 0
      end

      # Rebuild classifying fuzzer binaries before modifying triage_dir so a compile failure
      # never discards existing triage buckets or archived survivors.
      if !survivors_by_sha.empty? && options[:build]
        rebuild_fuzzer_binaries!(fuzz_root, quiet: options[:quiet])
      end

      buckets_to_remove.each do |bucket_id|
        FileUtils.rm_rf(File.join(triage_dir, bucket_id))
      end
      prune_empty_reason_dirs(triage_dir, buckets_to_remove)

      processed_dir = File.join(triage_dir, ".processed")
      FileUtils.mkdir_p(processed_dir)
      FuzzTriage.invalidate_sentinel_index(triage_dir) if FuzzTriage.respond_to?(:invalidate_sentinel_index)
      cured_hashes.each do |sha|
        File.write(File.join(processed_dir, sha), "#skip\n")
      end
      surviving_all_shas.each do |sha|
        FileUtils.rm_f(File.join(processed_dir, sha))
      end

      retriage_cov_bin = ENV.key?("TRIAGE_COVERAGE_BIN") ? ENV["TRIAGE_COVERAGE_BIN"] : File.join(ws_build_rel, "fuzz")

      if survivors_by_sha.empty?
        FuzzTriage.finalize_triage_metadata(triage_dir, coverage_bin: retriage_cov_bin)
      else
        staged_root = File.join(workdir, "staged")
        survivors_by_sha.values.group_by { |s| [s[:executable], s[:queue]] }.each_with_index do |((executable, queue), items), group_idx|
          worker_dir = File.join(staged_root, "retriage_#{group_idx}")
          crash_dir = File.join(worker_dir, queue)
          FileUtils.mkdir_p(crash_dir)
          File.write(File.join(worker_dir, "cmdline"), "#{executable}\n")

          items.each_with_index do |item, idx|
            dst = File.join(crash_dir, format("id:%06d,%s", idx, item[:sha][0, 12]))
            FileUtils.cp(item[:path], dst)
          end
        end

        FuzzTriage.run_triage_pipeline(
          output_dirs: [staged_root],
          testcases_dir: triage_dir,
          occurrence_overrides: occ_overrides,
          fuzz_versions_overrides: fuzz_versions_overrides,
          coverage_bin: retriage_cov_bin
        )

        # Mirror new bucket sentinels back to any pre-normalized raw crash hashes (e.g. IJON
        # stream-bit inputs) so subsequent `report` / `triage.rb` passes recognize them as processed.
        survivors_by_sha.each_value do |item|
          next if item[:orig_shas].empty?

          content_sentinel = File.join(processed_dir, item[:sha])
          next unless File.file?(content_sentinel)

          sentinel_body = File.read(content_sentinel)
          item[:orig_shas].each do |orig_sha|
            File.write(File.join(processed_dir, orig_sha), sentinel_body)
          end
        end
        FuzzTriage.invalidate_sentinel_index(triage_dir) if FuzzTriage.respond_to?(:invalidate_sentinel_index)
      end

      clusters_path = File.join(triage_dir, "clusters.json")
      unless options[:quiet]
        puts ""
        if File.file?(clusters_path)
          updated = JSON.parse(File.read(clusters_path))
          puts FuzzClustering.format_summary_table(updated)
        end
        puts format(
          "Retriage complete: removed %d cured bucket(s), replaced %d failing bucket(s) (%d surviving input(s)) under %s",
          cured_buckets.size,
          failing_buckets.size,
          survivors_by_sha.size,
          triage_dir
        )
      end
    end
    0
  end
end

if __FILE__ == $PROGRAM_NAME
  $stdout.sync = true
  $stderr.sync = true
  exit(FuzzRetriage.run(ARGV))
end
