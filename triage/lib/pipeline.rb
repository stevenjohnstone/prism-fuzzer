# frozen_string_literal: true

module FuzzTriage
  # Orchestrates parallel crash deduplication, in-flight coalescing,
  # minimization, atomic bucket publication, and metadata finalization.
  module Pipeline
    include Config
    include CrashParser
    include Minimizer
    include MetadataBuilder
    extend self

    DUPLICATE_LOG_CAP_PER_BUCKET = 3

    def ensure_bucket_hashes_loaded!(bucket_dir, loaded_buckets, bucket_load_mutex, semaphore, recorded_hashes, archived_hashes)
      return if semaphore.synchronize { loaded_buckets.include?(bucket_dir) }

      bucket_load_mutex.synchronize do
        return if semaphore.synchronize { loaded_buckets.include?(bucket_dir) }

        rec_h, arch_h = load_bucket_recorded_and_archived_hashes(bucket_dir)
        semaphore.synchronize do
          recorded_hashes.merge(rec_h)
          archived_hashes.merge(arch_h)
          loaded_buckets.add(bucket_dir)
        end
      end
    end

    def queue_sentinel!(sentinel_path, value, sentinel_states: nil, buffered_sentinels: nil)
      if buffered_sentinels
        buffered_sentinels[sentinel_path] = value
      else
        write_processed_sentinel(sentinel_path, value)
      end
      return unless sentinel_states

      sha = File.basename(sentinel_path)
      sentinel_states[sha] = if value == "#skip"
                               { status: :skip }
                             elsif value.to_s.empty?
                               { status: :empty }
                             else
                               { status: :bucket, bucket_id: value }
                             end
    end

    def process_crash(
      crash_dir,
      crash,
      executable,
      semaphore,
      in_progress,
      pending_sentinels,
      pending_occurrences,
      pending_inputs,
      recorded_hashes = Set.new,
      archived_hashes = Set.new,
      testcases_dir: TESTCASES_DIR,
      occurrence_overrides: nil,
      fuzz_versions_overrides: nil,
      pending_hashes: {},
      pending_retries: {},
      recount: nil,
      minimize_enabled: nil,
      sentinel_states: nil,
      published_buckets: nil,
      loaded_buckets: nil,
      bucket_load_mutex: nil,
      buffered_occurrences: nil,
      buffered_inputs: nil,
      buffered_sentinels: nil,
      dup_log_counts: nil,
      active_minimizations: nil
    )
      prev_active_triage_dir = Thread.current[:active_triage_dir]
      Thread.current[:active_triage_dir] = testcases_dir
      recount_enabled = recount.nil? ? env_recount? : recount
      should_minimize = minimize_enabled.nil? ? env_minimize? : minimize_enabled
      verbose_dups = ENV["TRIAGE_VERBOSE"] == "1"
      raw_crash = File.binread(crash)
      crash_hash = Digest::SHA2.hexdigest(raw_crash)
      worker_executable = executable
      sentinel = File.join(testcases_dir, ".processed", crash_hash)
      handed_off_to_leader = false
      released_in_progress = false

      # Fast lock-only check when sentinel_states is preloaded; lazily loads bucket hashes only if recount is active.
      if recount_enabled && sentinel_states && loaded_buckets && bucket_load_mutex
        pre_state = semaphore.synchronize { sentinel_states[crash_hash] || { status: :absent } }
        if pre_state[:status] == :bucket && pre_state[:bucket_id]
          ensure_bucket_hashes_loaded!(
            File.join(testcases_dir, pre_state[:bucket_id]),
            loaded_buckets,
            bucket_load_mutex,
            semaphore,
            recorded_hashes,
            archived_hashes
          )
        end
      end

      recount_only = false
      cached_bucket_id = nil
      claimed = semaphore.synchronize do
        state = if sentinel_states
                  sentinel_states[crash_hash] || { status: :absent }
                else
                  read_sentinel_state(sentinel, testcases_dir)
                end
        if state[:status] != :absent
          if recount_enabled && state[:status] != :skip &&
             (!recorded_hashes.include?(crash_hash) || !archived_hashes.include?(crash_hash)) &&
             !in_progress.include?(crash_hash)
            recount_only = true
            cached_bucket_id = state[:bucket_id]
            in_progress.add(crash_hash)
            true
          else
            false
          end
        else
          !in_progress.add?(crash_hash).nil?
        end
      end
      return unless claimed

      normalized_crash_file = nil
      begin
        fspec_norm = resolve_topology_fuzzer(executable: executable, triage_dir: testcases_dir)
        suppresses_stream = fuzzer_suppresses_stream?(fspec_norm, executable: executable)
        normalized_bytes = suppresses_stream ? normalize_ijon_crash_bytes(raw_crash) : nil
        effective_raw_bytes = normalized_bytes || raw_crash
        occ_record = occurrence_overrides&.dig(crash_hash) || build_occurrence_record(crash_dir, crash, crash_hash)

        if recount_only && cached_bucket_id
          target_directory = File.join(testcases_dir, cached_bucket_id)
          if loaded_buckets && bucket_load_mutex
            ensure_bucket_hashes_loaded!(target_directory, loaded_buckets, bucket_load_mutex, semaphore, recorded_hashes, archived_hashes)
          end
          semaphore.synchronize do
            unless recorded_hashes.include?(crash_hash)
              if buffered_occurrences
                buffered_occurrences[target_directory] << occ_record
              else
                append_occurrences(target_directory, [occ_record])
              end
              recorded_hashes.add(crash_hash)
            end
            unless archived_hashes.include?(crash_hash)
              if buffered_inputs
                buffered_inputs[target_directory] << [crash_hash, effective_raw_bytes]
              else
                append_pending_inputs(target_directory, [[crash_hash, effective_raw_bytes]])
              end
              archived_hashes.add(crash_hash)
            end
          end
          return
        end

        crash_input = crash
        if normalized_bytes
          normalized_crash_file = Tempfile.new(["ijon-crash-", ".bin"])
          normalized_crash_file.binmode
          normalized_crash_file.write(normalized_bytes)
          normalized_crash_file.close
          crash_input = normalized_crash_file.path
        end

        info = classify_crash_execution(crash_dir, crash_input, executable, triage_dir: testcases_dir)
        if info[:transient_timeout]
          puts "Skipping #{crash} (transient timeout)"
          semaphore.synchronize do
            queue_sentinel!(sentinel, "#skip", sentinel_states: sentinel_states, buffered_sentinels: buffered_sentinels)
          end
          return
        end

        reason = info[:reason]
        executable = info[:executable]
        testcase_output = info[:testcase_output]
        timed_out = info[:timed_out]
        unreproducible = info[:unreproducible]
        sig_lines = info[:sig_lines]

        if unreproducible && File.basename(crash).include?("sig:09")
          puts "Skipping #{crash} (external SIGKILL / OOM)"
          semaphore.synchronize do
            queue_sentinel!(sentinel, "#skip", sentinel_states: sentinel_states, buffered_sentinels: buffered_sentinels)
          end
          return
        end

        signature = unreproducible ? crash_hash[0, 16] : testcase_output_signature(testcase_output, sig_lines)
        bucket_dir_name = unreproducible ? "unreproducible" : reason
        bucket_id = "#{bucket_dir_name}/#{signature}"
        target_directory = File.join(testcases_dir, bucket_dir_name, signature)

        if loaded_buckets && bucket_load_mutex && published_buckets &&
           semaphore.synchronize { published_buckets.include?(target_directory) }
          ensure_bucket_hashes_loaded!(target_directory, loaded_buckets, bucket_load_mutex, semaphore, recorded_hashes, archived_hashes)
        end

        log_msg = nil
        skip_duplicate = semaphore.synchronize do
          already_published = if published_buckets
                                published_buckets.include?(target_directory)
                              else
                                File.directory?(target_directory) && !Dir.empty?(target_directory)
                              end

          if already_published
            if dup_log_counts && !verbose_dups
              c = (dup_log_counts[target_directory] += 1)
              log_msg = "#{crash} is a duplicate of #{target_directory}" if c <= DUPLICATE_LOG_CAP_PER_BUCKET
            else
              log_msg = "#{crash} is a duplicate of #{target_directory}"
            end
            unless recorded_hashes.include?(crash_hash)
              if buffered_occurrences
                buffered_occurrences[target_directory] << occ_record
              else
                append_occurrences(target_directory, [occ_record])
              end
              recorded_hashes.add(crash_hash)
            end
            unless archived_hashes.include?(crash_hash)
              if buffered_inputs
                buffered_inputs[target_directory] << [crash_hash, effective_raw_bytes]
              else
                append_pending_inputs(target_directory, [[crash_hash, effective_raw_bytes]])
              end
              archived_hashes.add(crash_hash)
            end
            queue_sentinel!(sentinel, bucket_id, sentinel_states: sentinel_states, buffered_sentinels: buffered_sentinels)
            true
          elsif pending_sentinels.key?(target_directory)
            if dup_log_counts && !verbose_dups
              c = (dup_log_counts[target_directory] += 1)
              log_msg = "#{crash} is a duplicate of in-progress #{target_directory}" if c <= DUPLICATE_LOG_CAP_PER_BUCKET
            else
              log_msg = "#{crash} is a duplicate of in-progress #{target_directory}"
            end
            coalesced_hashes = (pending_hashes[target_directory] ||= Set.new)
            unless coalesced_hashes.include?(crash_hash)
              coalesced_hashes.add(crash_hash)
              pending_sentinels[target_directory] << sentinel
              pending_occurrences[target_directory] ||= []
              pending_occurrences[target_directory] << occ_record unless recorded_hashes.include?(crash_hash)
              pending_inputs[target_directory] ||= []
              pending_inputs[target_directory] << [crash_hash, effective_raw_bytes] unless archived_hashes.include?(crash_hash)
              pending_retries[target_directory] ||= []
              pending_retries[target_directory] << {
                crash_dir: crash_dir,
                crash: crash,
                executable: worker_executable
              }
              handed_off_to_leader = true
            end
            true
          else
            log_msg = "#{crash} is new"
            pending_sentinels[target_directory] = [sentinel]
            pending_occurrences[target_directory] = []
            pending_inputs[target_directory] = []
            pending_hashes[target_directory] = Set.new
            pending_retries[target_directory] = []
            false
          end
        end
        puts log_msg if log_msg
        return if skip_duplicate

        parent_dir = File.dirname(target_directory)
        semaphore.synchronize { FileUtils.mkdir_p(parent_dir) }
        staging_dir = Dir.mktmpdir(".tmp-", parent_dir)
        published = false
        begin
          minimized_input = File.join(staging_dir, "input.min")
          minimized_matches_sig = nil

          if !should_minimize || unreproducible
            FileUtils.cp(crash_input, minimized_input)
            if !unreproducible && reason != "hang" && !info[:symbolized]
              sym_out, sym_crashed, = run_testcase(executable, minimized_input, symbolize: true)
              testcase_output = sym_out if sym_crashed
            end
          else
            semaphore.synchronize { active_minimizations[crash] = Process.clock_gettime(Process::CLOCK_MONOTONIC) } if active_minimizations
            begin
              minimize(crash_input, reason, minimized_input, executable, sig_lines)
            ensure
              semaphore.synchronize { active_minimizations.delete(crash) } if active_minimizations
            end
            if reason != "hang"
              min_output, min_crashed, = run_testcase(executable, minimized_input, symbolize: true)
              if min_crashed
                minimized_matches_sig = testcase_output_signature(min_output, sig_lines) == signature
                testcase_output = min_output
              else
                minimized_matches_sig = false
              end
            end
          end

          clean_crash_output = utf8_safe(testcase_output)
          effective_output = unreproducible ? "" : clean_crash_output
          c_verify = verify_script(
            reason: bucket_dir_name,
            executable: executable,
            crash_output: effective_output,
            triage_dir: testcases_dir
          )

          verify_path = File.join(staging_dir, "verify.sh")
          File.write(verify_path, c_verify)
          File.chmod(0o755, verify_path)
          FileUtils.cp(crash, File.join(staging_dir, File.basename(crash)))
          append_occurrences(staging_dir, [occ_record])
          append_pending_inputs(staging_dir, [[crash_hash, effective_raw_bytes]])
          initial_meta = build_bucket_metadata(
            bucket_id: bucket_id,
            reason: bucket_dir_name,
            signature: signature,
            reproducible: !unreproducible,
            timed_out: timed_out,
            executable: executable,
            worker_executable: worker_executable,
            fuzz_versions_override: fuzz_versions_overrides&.dig(crash_hash),
            crash_output: effective_output,
            minimized_input: minimized_input,
            raw_size_bytes: occ_record["size_bytes"],
            raw_sha256: crash_hash,
            minimized_matches_signature: minimized_matches_sig,
            occurrences: summarize_occurrences(staging_dir),
            coverage: nil,
            triage_dir: testcases_dir
          )
          write_json_atomic(File.join(staging_dir, "meta.json"), initial_meta)
          File.chmod(0o777 & ~File.umask, staging_dir)

          semaphore.synchronize do
            Dir.rmdir(target_directory) if File.directory?(target_directory) && Dir.empty?(target_directory)
            unless File.directory?(target_directory)
              File.rename(staging_dir, target_directory)
              published = true
            end
            published_buckets&.add(target_directory)
            loaded_buckets&.add(target_directory)
            extra_occurrences = pending_occurrences.delete(target_directory) || []
            extra_inputs = pending_inputs.delete(target_directory) || []
            if published
              if buffered_occurrences && !extra_occurrences.empty?
                buffered_occurrences[target_directory].concat(extra_occurrences)
              else
                append_occurrences(target_directory, extra_occurrences)
              end
              if buffered_inputs && !extra_inputs.empty?
                buffered_inputs[target_directory].concat(extra_inputs)
              else
                append_pending_inputs(target_directory, extra_inputs)
              end
            else
              new_occs = recorded_hashes.include?(crash_hash) ? extra_occurrences : [occ_record] + extra_occurrences
              new_items = archived_hashes.include?(crash_hash) ? extra_inputs : [[crash_hash, effective_raw_bytes]] + extra_inputs
              if buffered_occurrences
                buffered_occurrences[target_directory].concat(new_occs) unless new_occs.empty?
              else
                append_occurrences(target_directory, new_occs)
              end
              if buffered_inputs
                buffered_inputs[target_directory].concat(new_items) unless new_items.empty?
              else
                append_pending_inputs(target_directory, new_items)
              end
            end
            recorded_hashes.add(crash_hash)
            extra_occurrences.each { |r| recorded_hashes.add(r["sha256"]) if r["sha256"] }
            archived_hashes.add(crash_hash)
            extra_inputs.each { |sha, _| archived_hashes.add(sha) if sha }
            sentinels = pending_sentinels.delete(target_directory) || [sentinel]
            sentinels.uniq.each do |s|
              queue_sentinel!(s, bucket_id, sentinel_states: sentinel_states, buffered_sentinels: buffered_sentinels)
            end
            coalesced_hashes = pending_hashes.delete(target_directory)
            coalesced_hashes&.each { |h| in_progress.delete(h) }
            pending_retries.delete(target_directory)
          end
        ensure
          FileUtils.rm_rf(staging_dir) if !published && staging_dir && File.exist?(staging_dir)
          orphaned_retries = nil
          unless published
            semaphore.synchronize do
              pending_sentinels.delete(target_directory)
              pending_occurrences.delete(target_directory)
              pending_inputs.delete(target_directory)
              orphaned_hashes = pending_hashes.delete(target_directory)
              orphaned_hashes&.each { |h| in_progress.delete(h) }
              orphaned_retries = pending_retries.delete(target_directory)
              in_progress.delete(crash_hash) unless handed_off_to_leader
              released_in_progress = true
            end
          end
          Array(orphaned_retries).each do |item|
            process_crash(
              item[:crash_dir],
              item[:crash],
              item[:executable],
              semaphore,
              in_progress,
              pending_sentinels,
              pending_occurrences,
              pending_inputs,
              recorded_hashes,
              archived_hashes,
              testcases_dir: testcases_dir,
              occurrence_overrides: occurrence_overrides,
              fuzz_versions_overrides: fuzz_versions_overrides,
              pending_hashes: pending_hashes,
              pending_retries: pending_retries,
              recount: recount,
              minimize_enabled: minimize_enabled,
              sentinel_states: sentinel_states,
              published_buckets: published_buckets,
              loaded_buckets: loaded_buckets,
              bucket_load_mutex: bucket_load_mutex,
              buffered_occurrences: buffered_occurrences,
              buffered_inputs: buffered_inputs,
              buffered_sentinels: buffered_sentinels,
              dup_log_counts: dup_log_counts,
              active_minimizations: active_minimizations
            )
          rescue StandardError => retry_err
            warn "Error recovering coalesced crash #{item[:crash]}: #{retry_err.class}: #{retry_err.message}"
          end
        end
        puts "#{crash} complete => #{target_directory}"
      ensure
        normalized_crash_file&.close!
        semaphore.synchronize { in_progress.delete(crash_hash) unless handed_off_to_leader || released_in_progress }
        Thread.current[:active_triage_dir] = prev_active_triage_dir
      end
    end

    def run_triage_pipeline(
      output_dirs: OUTPUT_DIRS,
      testcases_dir: TESTCASES_DIR,
      occurrence_overrides: nil,
      fuzz_versions_overrides: nil,
      coverage_bin: nil,
      coverage_ids: nil,
      diff_coverage_bin: nil,
      diff_coverage_ids: nil,
      corpus_dir: nil,
      recount: nil,
      minimize_enabled: nil,
      threads: nil
    )
      with_cached_topology do
        resolved_output_dirs = resolve_triage_output_dirs(output_dirs: output_dirs, testcases_dir: testcases_dir)
        FileUtils.mkdir_p(File.join(testcases_dir, ".processed"))
        effective_threads = [threads.nil? ? env_triage_threads : threads.to_i, 1].max
        use_pool = defined?(Concurrent) && effective_threads > 1
        pool = use_pool ? Concurrent::FixedThreadPool.new(effective_threads) : nil
        semaphore = Mutex.new
        bucket_load_mutex = Mutex.new
        in_progress = Set.new
        pending_sentinels = {}
        pending_occurrences = {}
        pending_inputs = {}
        pending_hashes = {}
        pending_retries = {}
        existing_bucket_dirs = discover_bucket_dirs(testcases_dir)
        published_buckets = existing_bucket_dirs.to_set
        loaded_buckets = Set.new
        sentinel_states, sentinel_raw_map = preload_sentinel_states(testcases_dir, existing_bucket_dirs: existing_bucket_dirs)
        recorded_hashes = Set.new
        archived_hashes = Set.new
        buffered_occurrences = Hash.new { |h, k| h[k] = [] }
        buffered_inputs = Hash.new { |h, k| h[k] = [] }
        buffered_sentinels = {}
        dup_log_counts = Hash.new(0)
        active_minimizations = {}

        dispatch = lambda do |crash_dir, crash, executable|
          work = lambda do
            process_crash(
              crash_dir,
              crash,
              executable,
              semaphore,
              in_progress,
              pending_sentinels,
              pending_occurrences,
              pending_inputs,
              recorded_hashes,
              archived_hashes,
              testcases_dir: testcases_dir,
              occurrence_overrides: occurrence_overrides,
              fuzz_versions_overrides: fuzz_versions_overrides,
              pending_hashes: pending_hashes,
              pending_retries: pending_retries,
              recount: recount,
              minimize_enabled: minimize_enabled,
              sentinel_states: sentinel_states,
              published_buckets: published_buckets,
              loaded_buckets: loaded_buckets,
              bucket_load_mutex: bucket_load_mutex,
              buffered_occurrences: buffered_occurrences,
              buffered_inputs: buffered_inputs,
              buffered_sentinels: buffered_sentinels,
              dup_log_counts: dup_log_counts,
              active_minimizations: active_minimizations
            )
          rescue StandardError => e
            warn "Error processing #{crash}: #{e.class}: #{e.message}\n#{e.backtrace.join("\n")}"
          end

          pool ? pool.post(&work) : work.call
        end

        begin
          resolved_output_dirs.flat_map { |d| Dir.glob(File.join(d, "**/{crashes*,hangs*}")) }.each do |crash_dir|
            cmdline_file = File.join(crash_dir, "../cmdline")
            next unless File.exist?(cmdline_file)

            executable = resolve_cmdline_executable(File.read(cmdline_file))
            Dir.glob(File.join(crash_dir, "/id*")) do |crash|
              dispatch.call(crash_dir, crash, executable)
            end
          end
        ensure
          if pool
            pool.shutdown
            heartbeat_interval = Float(ENV.fetch("TRIAGE_HEARTBEAT_SECONDS", "10"))
            until pool.wait_for_termination(heartbeat_interval)
              now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
              inflight = semaphore.synchronize do
                active_minimizations.map { |path, started| [path, now - started] }
              end
              next if inflight.empty?

              sample = inflight.sort_by { |_, dt| -dt }.first(3).map do |path, dt|
                "#{File.basename(File.dirname(File.dirname(path)))}/#{File.basename(path)} (#{format('%.0fs', dt)})"
              end.join(", ")
              puts "[triage] still minimizing #{inflight.size} bucket(s): #{sample}"
            end
          end
          buffered_occurrences.each do |bdir, recs|
            append_occurrences(bdir, recs) if !recs.empty? && File.directory?(bdir)
          end
          buffered_inputs.each do |bdir, items|
            append_pending_inputs(bdir, items) if !items.empty? && File.directory?(bdir)
          end
          flush_processed_sentinels(testcases_dir, buffered_sentinels, sentinel_raw_map) unless buffered_sentinels.empty?

          suppressed = dup_log_counts.values.sum { |c| c > DUPLICATE_LOG_CAP_PER_BUCKET ? (c - DUPLICATE_LOG_CAP_PER_BUCKET) : 0 }
          if suppressed > 0
            capped_buckets = dup_log_counts.count { |_, c| c > DUPLICATE_LOG_CAP_PER_BUCKET }
            puts "Coalesced #{suppressed} additional duplicate crash log line(s) across #{capped_buckets} bucket(s)"
          end
        end

        finalize_triage_metadata(
          testcases_dir,
          coverage_bin: coverage_bin,
          coverage_ids: coverage_ids,
          output_dirs: resolved_output_dirs,
          diff_coverage_bin: diff_coverage_bin,
          diff_coverage_ids: diff_coverage_ids,
          corpus_dir: corpus_dir,
          recount: recount,
          digest_workers: effective_threads
        )
      end
    end
  end
end
