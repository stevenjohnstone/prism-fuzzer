# frozen_string_literal: true

module FuzzTriage
  # Builds and finalizes bucket meta.json, occurrences.jsonl, .processed
  # sentinels, inputs.tar.gz archives, metadata.json, and clusters.json.
  module MetadataBuilder
    include Config
    include ProvenanceResolver
    include CrashParser
    include Minimizer
    include CoverageMap
    include DigestEnricher
    extend self

    SOURCE_PREVIEW_MAX_CHARS = 160

    def format_source_preview(source_bytes, max_chars: SOURCE_PREVIEW_MAX_CHARS)
      bytes = source_bytes.to_s.b
      return "" if bytes.empty?

      limit = [max_chars.to_i, 4].max
      max_scan_bytes = (limit + 1) * 4
      scan_bytes = bytes.bytesize > max_scan_bytes ? bytes.byteslice(0, max_scan_bytes) : bytes
      out = +""
      truncated = false

      scan_bytes.dup.force_encoding(Encoding::UTF_8).each_char do |ch|
        tok = if ch.valid_encoding?
                case ch
                when "\0" then "\\0"
                when "\n" then "\\n"
                when "\r" then "\\r"
                when "\t" then "\\t"
                when "\\" then "\\\\"
                else
                  ord = ch.ord
                  ord < 0x20 || ord == 0x7f ? format("\\x%02x", ord) : ch
                end
              else
                ch.bytes.map { |b| format("\\x%02x", b) }.join
              end

        if out.length + tok.length > limit
          truncated = true
          break
        end
        out << tok
      end

      return "#{out[0, [limit - 3, 0].max]}..." if truncated || bytes.bytesize > scan_bytes.bytesize

      out
    end

    def input_and_options_metadata(minimized_input, reason:, crash_output:, raw_size_bytes: nil, raw_sha256: nil, minimized_matches_signature: nil, executable: "")
      raw_min = File.binread(minimized_input)
      h = decode_fuzz_header(raw_min)
      is_diff = diff_bucket?(executable: executable, crash_output: crash_output)
      loupe_url = is_diff ? build_diff_loupe_url(h[:source]) : build_prism_loupe_url(h[:padded_raw], sanitize: sanitizer_loupe_crash?(reason, crash_output))
      min_sha256 = Digest::SHA256.hexdigest(raw_min)
      payload_sha256 = Digest::SHA256.hexdigest(h[:source])
      source_preview = format_source_preview(h[:source])

      options_meta = if is_diff
                       {
                         "ruby_version" => "4.1",
                         "start_line" => 1,
                         "start_line_expr" => nil,
                         "encoding" => nil,
                         "encoding_locked" => false,
                         "freeze" => false,
                         "partial_script" => false,
                         "attach_comments" => false,
                         "main_script" => false,
                         "stream_mode" => false,
                         "frozen_string_literal" => nil,
                         "command_line_flags" => [],
                         "filepath" => nil,
                         "shebang_callback" => false,
                         "stack_budget" => "SIZE_MAX",
                         "scopes_count" => 0,
                         "forwarding_scope" => nil,
                         "forwarding_flags" => []
                       }
                     else
                       {
                         "ruby_version" => h[:version],
                         "start_line" => h[:start_line],
                         "start_line_expr" => h[:has_limit_opts] ? h[:start_line_c] : nil,
                         "encoding" => h[:encoding],
                         "encoding_locked" => h[:encoding_locked],
                         "freeze" => h[:freeze],
                         "partial_script" => h[:partial_script],
                         "attach_comments" => h[:attach_comments],
                         "main_script" => h[:main_script],
                         "stream_mode" => h[:stream_mode],
                         "frozen_string_literal" => h[:has_frozen_string_literal] ? h[:frozen_string_literal] : nil,
                         "command_line_flags" => h[:command_line_chars],
                         "filepath" => h[:filepath],
                         "shebang_callback" => h[:shebang_callback],
                         "stack_budget" => h[:stack_budget],
                         "scopes_count" => h[:scopes_count],
                         "forwarding_scope" => h[:forwarding_scope],
                         "forwarding_flags" => h[:forwarding_chars]
                       }
                     end

      {
        "input" => {
          "raw_size_bytes" => raw_size_bytes,
          "raw_sha256" => raw_sha256,
          "min_size_bytes" => raw_min.bytesize,
          "min_sha256" => min_sha256,
          "payload_size_bytes" => h[:source].bytesize,
          "payload_sha256" => payload_sha256,
          "source_preview" => source_preview,
          "header_bytes" => h[:header_bytes],
          "header_hex" => h[:header_bytes].map { |b| format("%02x", b) }.join,
          "valid_header" => h[:valid_header],
          "has_shebang_prefix" => h[:has_shebang_prefix],
          "minimized_matches_signature" => minimized_matches_signature,
          "loupe_url" => loupe_url
        },
        "options" => options_meta
      }
    end

    def occurrence_time_ms(name_or_path)
      return FuzzClustering.parse_afl_time_ms(name_or_path) if defined?(FuzzClustering)
      return nil if name_or_path.nil?

      m = File.basename(name_or_path.to_s).match(/(?:\A|,)time:(\d+)(?:,|\z)/)
      m ? m[1].to_i : nil
    end

    def build_occurrence_record(crash_dir, crash, crash_hash)
      filename = utf8_safe(File.basename(crash))
      worker_dir = File.dirname(crash_dir)
      rec = {
        "sha256" => crash_hash,
        "path" => utf8_safe(crash),
        "filename" => filename,
        "fuzzer" => utf8_safe(File.basename(File.dirname(worker_dir))),
        "worker" => utf8_safe(File.basename(worker_dir)),
        "queue" => utf8_safe(File.basename(crash_dir)),
        "size_bytes" => File.size(crash),
        "mtime" => File.mtime(crash).utc.iso8601
      }
      time_ms = occurrence_time_ms(filename)
      rec["time_ms"] = time_ms unless time_ms.nil?
      rec
    end

    def append_occurrences(bucket_dir, records)
      return if records.nil? || records.empty?

      occ_path = File.join(bucket_dir, "occurrences.jsonl")
      File.open(occ_path, "a") do |f|
        records.each { |rec| f.puts(JSON.generate(rec)) }
        f.flush
      end
    end

    def read_occurrences(bucket_dir)
      occ_path = File.join(bucket_dir, "occurrences.jsonl")
      return [] unless File.file?(occ_path)

      by_sha = {}
      File.foreach(occ_path) do |line|
        line = line.strip
        next if line.empty?

        rec = JSON.parse(line)
        sha = rec["sha256"]
        next if sha.nil? || sha.empty?

        by_sha[sha] ||= rec
      rescue JSON::ParserError
        next
      end

      by_sha.values.sort_by do |r|
        t_ms = r["time_ms"] || occurrence_time_ms(r["filename"] || r["path"])
        [r["mtime"].to_s, t_ms.nil? ? Float::INFINITY : t_ms.to_i, r["sha256"].to_s]
      end
    end

    def summarize_occurrences(bucket_dir)
      records = read_occurrences(bucket_dir)
      by_fuzzer = Hash.new(0)
      by_worker = Hash.new(0)
      by_queue = Hash.new(0)
      mtimes = []

      records.each do |rec|
        by_fuzzer[rec["fuzzer"] || "unknown"] += 1
        by_worker[rec["worker"] || "unknown"] += 1
        by_queue[rec["queue"] || "unknown"] += 1
        mtimes << rec["mtime"] if rec["mtime"]
      end

      first_rec = records.first
      first_elapsed_ms = first_rec && (first_rec["time_ms"] || occurrence_time_ms(first_rec["filename"] || first_rec["path"]))

      {
        "count" => records.size,
        "by_fuzzer" => by_fuzzer.sort.to_h,
        "by_worker" => by_worker.sort.to_h,
        "by_queue" => by_queue.sort.to_h,
        "first_seen" => mtimes.min,
        "first_elapsed_ms" => first_elapsed_ms,
        "last_seen" => mtimes.max,
        "sample_crashes" => records.first(5).map do |r|
          {
            "sha256" => r["sha256"],
            "fuzzer" => r["fuzzer"],
            "worker" => r["worker"],
            "path" => r["path"],
            "mtime" => r["mtime"]
          }
        end
      }
    end

    def build_bucket_metadata(bucket_id:, reason:, signature:, reproducible:, timed_out:, executable:, worker_executable: nil, fuzz_versions_override: nil, crash_output:, minimized_input:, raw_size_bytes:, raw_sha256:, minimized_matches_signature:, occurrences:, coverage: nil, archive: nil, verify_profile: nil, triage_dir: TESTCASES_DIR)
      parsed = parse_crash_output(crash_output)
      io_meta = input_and_options_metadata(
        minimized_input,
        reason: reason,
        crash_output: crash_output,
        raw_size_bytes: raw_size_bytes,
        raw_sha256: raw_sha256,
        minimized_matches_signature: minimized_matches_signature,
        executable: executable
      )
      is_diff = diff_bucket?(executable: executable, crash_output: crash_output, triage_dir: triage_dir)
      versions_meta = resolve_versions_metadata(
        executable: executable,
        worker_executable: worker_executable,
        triage_dir: triage_dir,
        is_diff: is_diff,
        target_ruby_version: io_meta.dig("options", "ruby_version"),
        fuzz_versions_override: fuzz_versions_override
      )
      fspec = resolve_topology_fuzzer(executable: worker_executable, triage_dir: triage_dir) ||
              resolve_topology_fuzzer(executable: executable, triage_dir: triage_dir)
      target_meta = if fspec
                      {
                        "id" => fspec["id"],
                        "shape" => fspec["shape"],
                        "binary" => fspec["binary"],
                        "sources" => fspec["sources_map"]
                      }.compact
                    end

      meta = {
        "schema_version" => META_SCHEMA_VERSION,
        "bucket_id" => bucket_id,
        "reason" => reason,
        "signature" => signature,
        "reproducible" => reproducible,
        "timed_out" => timed_out,
        "reproduced_by" => File.basename(executable.to_s),
        "verify_profile" => verify_profile || bucket_verify_profile(reason: reason, executable: executable, crash_output: crash_output, triage_dir: triage_dir),
        "occurrences" => occurrences,
        "archive" => archive,
        "input" => io_meta["input"],
        "options" => io_meta["options"],
        "symptom" => parsed["symptom"],
        "frames" => parsed["frames"],
        "coverage" => coverage
      }
      meta["target"] = target_meta if target_meta && !target_meta.empty?
      meta["versions"] = versions_meta if versions_meta
      meta
    end

    def discover_bucket_dirs(triage_dir)
      return [] unless File.directory?(triage_dir)

      Dir.glob(File.join(triage_dir, "*", "*")).select do |d|
        next false unless File.directory?(d)

        reason_name = File.basename(File.dirname(d))
        sig_name = File.basename(d)
        !reason_name.start_with?(".") && !sig_name.start_with?(".") &&
          (File.file?(File.join(d, "input.min")) || File.file?(File.join(d, "meta.json")))
      end.sort
    end

    SENTINEL_INDEX_FILE = ".index.tsv"

    def parse_sentinel_raw_value(raw, existing_bucket_ids)
      val = raw.to_s.strip
      return { status: :skip } if val == "#skip"
      return { status: :empty } if val.empty?

      if val.match?(%r{\A[^/\n]+/[^/\n]+\z}) && existing_bucket_ids.include?(val)
        return { status: :bucket, bucket_id: val }
      end

      { status: :empty }
    end

    def invalidate_sentinel_index(triage_dir)
      idx = File.join(triage_dir, ".processed", SENTINEL_INDEX_FILE)
      FileUtils.rm_f(idx) if File.exist?(idx)
    end

    def preload_sentinel_states(triage_dir, existing_bucket_dirs: nil)
      processed_dir = File.join(triage_dir, ".processed")
      return [{}, {}] unless File.directory?(processed_dir)

      bdirs = existing_bucket_dirs || discover_bucket_dirs(triage_dir)
      bucket_ids = bdirs.each_with_object(Set.new) do |d, s|
        s.add("#{File.basename(File.dirname(d))}/#{File.basename(d)}")
      end

      children = Dir.children(processed_dir)
      children.delete(SENTINEL_INDEX_FILE)
      raw_map = {}
      idx_path = File.join(processed_dir, SENTINEL_INDEX_FILE)

      loaded_from_index = false
      if children.size > 64 && File.file?(idx_path)
        begin
          if File.mtime(idx_path) >= File.mtime(processed_dir)
            File.foreach(idx_path, encoding: "BINARY") do |line|
              sha, val = line.chomp.split("\t", 2)
              raw_map[sha] = val.to_s if sha && !sha.empty?
            end
            loaded_from_index = (raw_map.size == children.size)
            raw_map.clear unless loaded_from_index
          end
        rescue SystemCallError, IOError
          raw_map.clear
          loaded_from_index = false
        end
      end

      unless loaded_from_index
        children.each do |name|
          next if name.start_with?(".")

          p = File.join(processed_dir, name)
          begin
            raw_map[name] = File.read(p, encoding: "BINARY").strip
          rescue SystemCallError, IOError
            next
          end
        end
      end

      states = {}
      raw_map.each do |sha, val|
        states[sha] = parse_sentinel_raw_value(val, bucket_ids)
      end
      [states, raw_map]
    end

    def flush_processed_sentinels(triage_dir, pending_writes, raw_map = nil)
      processed_dir = File.join(triage_dir, ".processed")
      FileUtils.mkdir_p(processed_dir)

      pending_writes.each do |sentinel_path, content|
        body = content.to_s.empty? ? "" : "#{content.to_s.chomp}\n"
        File.write(sentinel_path, body)
        raw_map[File.basename(sentinel_path)] = content.to_s.chomp if raw_map
      end

      return unless raw_map && raw_map.size > 64

      idx_path = File.join(processed_dir, SENTINEL_INDEX_FILE)
      tmp_path = File.join(processed_dir, ".index.tsv.tmp.#{Process.pid}.#{Thread.current.object_id}")
      begin
        File.open(tmp_path, "wb") do |f|
          raw_map.each { |sha, val| f.write("#{sha}\t#{val}\n") }
        end
        File.rename(tmp_path, idx_path)
      rescue SystemCallError, IOError
        FileUtils.rm_f(tmp_path) if File.exist?(tmp_path)
      end
    end

    def load_bucket_recorded_and_archived_hashes(bucket_dir)
      rec_hashes = Set.new
      arch_hashes = Set.new
      read_occurrences(bucket_dir).each { |rec| rec_hashes.add(rec["sha256"]) if rec["sha256"] }
      tar_path = File.join(bucket_dir, INPUTS_ARCHIVE_FILE)
      if File.file?(tar_path)
        read_tar_gz_entries(tar_path, include_bytes: false)[:entries].each_key { |sha| arch_hashes.add(sha) }
      end
      read_pending_inputs(bucket_dir).each_key { |sha| arch_hashes.add(sha) }
      [rec_hashes, arch_hashes]
    end

    def load_all_recorded_occurrence_hashes(triage_dir)
      hashes = Set.new
      discover_bucket_dirs(triage_dir).each do |bucket_dir|
        read_occurrences(bucket_dir).each { |rec| hashes.add(rec["sha256"]) if rec["sha256"] }
      end
      hashes
    end

    def read_sentinel_state(sentinel_path, triage_dir)
      return { status: :absent } unless File.exist?(sentinel_path)

      raw = File.read(sentinel_path).strip
      return { status: :skip } if raw == "#skip"
      return { status: :empty } if raw.empty?

      if raw.match?(%r{\A[^/\n]+/[^/\n]+\z}) && File.directory?(File.join(triage_dir, raw))
        return { status: :bucket, bucket_id: raw }
      end

      { status: :empty }
    rescue SystemCallError
      { status: :empty }
    end

    def write_processed_sentinel(sentinel_path, content = "")
      File.write(sentinel_path, content.empty? ? "" : "#{content.chomp}\n")
      invalidate_sentinel_index(File.dirname(File.dirname(sentinel_path)))
    end

    def append_pending_inputs(bucket_dir, items)
      return if items.nil? || items.empty?

      pending_path = File.join(bucket_dir, PENDING_INPUTS_FILE)
      File.open(pending_path, "ab") do |f|
        items.each do |sha, bytes|
          next if sha.nil? || sha.empty? || bytes.nil?

          b = bytes.b
          f.write("#{sha}\t#{b.bytesize}\n")
          f.write(b)
          f.write("\n")
        end
        f.flush
      end
    end

    def read_pending_inputs(bucket_dir)
      pending_path = File.join(bucket_dir, PENDING_INPUTS_FILE)
      entries = {}
      return entries unless File.file?(pending_path)

      File.open(pending_path, "rb") do |f|
        while (header = f.gets("\n"))
          header = header.chomp
          next if header.empty?

          sha, len_str = header.split("\t", 2)
          break if sha.nil? || len_str.nil? || !len_str.match?(/\A\d+\z/)

          sz = Integer(len_str)
          data = sz > 0 ? f.read(sz) : "".b
          break if data.nil? || data.bytesize < sz

          nl = f.read(1)
          f.seek(-1, IO::SEEK_CUR) if nl && nl != "\n"
          entries[sha] ||= data.b
        end
      end
      entries
    end

    def read_tar_gz_entries(archive_path, include_bytes: true)
      entries = {}
      total_bytes = 0
      return { entries: entries, total_bytes: 0 } unless File.file?(archive_path)

      Zlib::GzipReader.open(archive_path) do |gz|
        Gem::Package::TarReader.new(gz) do |tar|
          tar.each do |entry|
            next unless entry.file?

            name = File.basename(entry.full_name.to_s)
            next if name.empty?

            sz = entry.header.size.to_i
            if include_bytes
              entries[name] ||= (entry.read || "".b).b
            else
              entries[name] = true
            end
            total_bytes += sz
          end
        end
      end
      { entries: entries, total_bytes: total_bytes }
    rescue Zlib::Error, Gem::Package::TarInvalidError
      { entries: {}, total_bytes: 0 }
    end

    def load_all_archived_input_hashes(triage_dir)
      hashes = Set.new
      discover_bucket_dirs(triage_dir).each do |bucket_dir|
        tar_path = File.join(bucket_dir, INPUTS_ARCHIVE_FILE)
        if File.file?(tar_path)
          read_tar_gz_entries(tar_path, include_bytes: false)[:entries].each_key { |sha| hashes.add(sha) }
        end
        read_pending_inputs(bucket_dir).each_key { |sha| hashes.add(sha) }
      end
      hashes
    end

    def legacy_bucket_ijon?(bucket_dir)
      tc_path = File.join(bucket_dir, "testcase.c")
      return false unless File.file?(tc_path)

      head = utf8_safe(File.binread(tc_path, 4096))
      crash_line = head[/^(?:Crash|Unreproducible crash):\s*(.+)$/, 1]
      !crash_line.nil? && crash_line.include?("/afl-ijon/")
    end

    def sync_bucket_archive(bucket_dir, existing_archive = nil)
      tar_path = File.join(bucket_dir, INPUTS_ARCHIVE_FILE)
      pending_path = File.join(bucket_dir, PENDING_INPUTS_FILE)
      has_pending = File.file?(pending_path) && File.size(pending_path) > 0

      if !has_pending && File.file?(tar_path) &&
         existing_archive.is_a?(Hash) &&
         existing_archive["file"] == INPUTS_ARCHIVE_FILE &&
         existing_archive["archive_bytes"] == File.size(tar_path) &&
         existing_archive["count"].is_a?(Integer)
        return existing_archive
      end

      if !has_pending && File.file?(tar_path)
        stats = read_tar_gz_entries(tar_path, include_bytes: false)
        return {
          "file" => INPUTS_ARCHIVE_FILE,
          "count" => stats[:entries].size,
          "total_bytes" => stats[:total_bytes],
          "archive_bytes" => File.size(tar_path)
        }
      end

      merged = File.file?(tar_path) ? read_tar_gz_entries(tar_path, include_bytes: true)[:entries] : {}
      if !File.file?(tar_path)
        from_ijon = legacy_bucket_ijon?(bucket_dir)
        Dir.glob(File.join(bucket_dir, "id*")).select { |p| File.file?(p) }.sort.each do |raw_path|
          raw = File.binread(raw_path)
          sha = Digest::SHA256.hexdigest(raw)
          next if merged.key?(sha)

          effective = from_ijon ? (normalize_ijon_crash_bytes(raw) || raw) : raw
          merged[sha] = effective.b
        end
      end

      read_pending_inputs(bucket_dir).each do |sha, bytes|
        merged[sha] ||= bytes.b
      end

      return nil if merged.empty?

      dir = File.dirname(tar_path)
      tmp_path = File.join(dir, ".#{INPUTS_ARCHIVE_FILE}.tmp.#{Process.pid}.#{Thread.current.object_id}")
      total_bytes = 0
      Zlib::GzipWriter.open(tmp_path) do |gz|
        Gem::Package::TarWriter.new(gz) do |tar|
          merged.keys.sort.each do |sha|
            data = merged[sha]
            total_bytes += data.bytesize
            tar.add_file_simple(sha, 0o644, data.bytesize) { |io| io.write(data) }
          end
        end
      end
      File.chmod(0o666 & ~File.umask, tmp_path)
      File.rename(tmp_path, tar_path)
      FileUtils.rm_f(pending_path) if File.exist?(pending_path)

      {
        "file" => INPUTS_ARCHIVE_FILE,
        "count" => merged.size,
        "total_bytes" => total_bytes,
        "archive_bytes" => File.size(tar_path)
      }
    ensure
      FileUtils.rm_f(tmp_path) if tmp_path && File.exist?(tmp_path)
    end

    # Populates occurrences.jsonl for buckets created before metadata tracking existed.
    def seed_legacy_occurrences(bucket_dir)
      occ_path = File.join(bucket_dir, "occurrences.jsonl")
      return if File.file?(occ_path)

      tc_path = File.join(bucket_dir, "testcase.c")
      recorded_crash_path = nil
      if File.file?(tc_path)
        head = utf8_safe(File.binread(tc_path, 4096))
        recorded_crash_path = head[/^(?:Crash|Unreproducible crash):\s*(.+)$/, 1]&.strip
      end

      raw_files = Dir.glob(File.join(bucket_dir, "id*")).select { |p| File.file?(p) }.sort
      records = raw_files.each_with_index.map do |raw_path, idx|
        sha = Digest::SHA256.hexdigest(File.binread(raw_path))
        crash_path = (idx == 0 && recorded_crash_path) ? recorded_crash_path : raw_path
        parts = crash_path.split(File::SEPARATOR)
        queue_name = parts[-2] || "crashes"
        worker_name = parts[-3] || "unknown"
        fuzzer_name = parts[-4] || "afl"
        if idx > 0 || recorded_crash_path.nil?
          fuzzer_name = "triage"
          worker_name = "legacy"
          queue_name = "crashes"
        end
        {
          "sha256" => sha,
          "path" => utf8_safe(crash_path),
          "filename" => utf8_safe(File.basename(raw_path)),
          "fuzzer" => utf8_safe(fuzzer_name),
          "worker" => utf8_safe(worker_name),
          "queue" => utf8_safe(queue_name),
          "size_bytes" => File.size(raw_path),
          "mtime" => File.mtime(raw_path).utc.iso8601
        }
      end

      append_occurrences(bucket_dir, records)
    end

    def backfill_bucket_meta(bucket_dir, triage_dir: File.dirname(File.dirname(bucket_dir)))
      sig = File.basename(bucket_dir)
      reason = File.basename(File.dirname(bucket_dir))
      bucket_id = "#{reason}/#{sig}"
      min_path = File.join(bucket_dir, "input.min")
      occurrences = summarize_occurrences(bucket_dir)
      first_occ = occurrences["sample_crashes"]&.first
      raw_file = Dir.glob(File.join(bucket_dir, "id*")).select { |p| File.file?(p) }.min
      raw_size_bytes = raw_file ? File.size(raw_file) : (File.file?(min_path) ? File.size(min_path) : nil)
      raw_sha256 = first_occ ? first_occ["sha256"] : (raw_file ? Digest::SHA256.hexdigest(File.binread(raw_file)) : nil)

      crash_output = ""
      reproducible = reason != "unreproducible"
      timed_out = false
      used_exec = "unknown"

      if reproducible && File.file?(min_path)
        build_sh = File.join(bucket_dir, "build.sh")
        build_text = File.file?(build_sh) ? File.read(build_sh) : ""
        verify_sh = File.join(bucket_dir, "verify.sh")
        verify_text = File.file?(verify_sh) ? File.read(verify_sh) : ""
        bdir = workspace_build_rel(triage_dir: File.dirname(File.dirname(bucket_dir)))
        cov_bin_cand, = resolve_coverage_target(triage_dir: triage_dir)
        candidates = []
        candidates << File.join(bdir, "fuzz.prism_diff") if verify_text.include?("diff_prism")
        candidates << File.join(bdir, "fuzz.diff") if verify_text.include?("diff_parse_y")
        candidates << File.join(bdir, "fuzz.arm32.repro") if verify_text.include?("arm32_oracle") || build_text.include?("arm-linux-gnueabihf")
        candidates << File.join(bdir, "fuzz.ppc.repro") if verify_text.include?("ppc_oracle") || build_text.include?("powerpc-linux-gnu")
        candidates << File.join(bdir, "fuzz.msan") if verify_text.include?("msan_slow") || build_text.include?("-fsanitize=memory")
        candidates << File.join(bdir, "fuzz.lsan") if verify_text.include?("lsan_slow") || build_text.include?("-fsanitize=leak")
        candidates << File.join(bdir, "fuzz.slow") if verify_text.include?("asan_ubsan_slow") || build_text.include?("-DSLOW")
        candidates << cov_bin_cand unless cov_bin_cand.empty?
        candidates.concat(%w[fuzz fuzz.slow fuzz.msan fuzz.lsan fuzz.native fuzz.diff].map { |n| File.join(bdir, n) })
        candidates.uniq!

        candidates.each do |cand|
          next unless File.executable?(cand)

          cand_timeout = reason == "hang" ? env_hang_timeout_seconds : env_crash_timeout_seconds
          out, crashed, t_out = with_testcase_timeout(cand_timeout) { run_testcase(cand, min_path) }
          if crashed || (reason == "hang" && t_out)
            crash_output = utf8_safe(out)
            timed_out = t_out
            used_exec = cand
            break
          end
        end
        reproducible = (used_exec != "unknown")
      end

      build_bucket_metadata(
        bucket_id: bucket_id,
        reason: reason,
        signature: sig,
        reproducible: reproducible,
        timed_out: timed_out,
        executable: used_exec,
        crash_output: crash_output,
        minimized_input: min_path,
        raw_size_bytes: raw_size_bytes,
        raw_sha256: raw_sha256,
        minimized_matches_signature: nil,
        occurrences: occurrences,
        coverage: nil,
        triage_dir: triage_dir
      )
    end

    def finalize_triage_metadata(
      triage_dir,
      coverage_bin: nil,
      coverage_ids: nil,
      output_dirs: nil,
      diff_coverage_bin: nil,
      diff_coverage_ids: nil,
      corpus_dir: nil,
      recount: nil,
      digest_workers: env_triage_threads
    )
      cov_bin, cov_ids_path = resolve_coverage_target(
        triage_dir: triage_dir,
        output_dirs: output_dirs,
        coverage_bin: coverage_bin,
        coverage_ids: coverage_ids
      )
      diff_cov_bin, diff_cov_ids_path = resolve_diff_coverage_target(
        triage_dir: triage_dir,
        output_dirs: output_dirs,
        diff_coverage_bin: diff_coverage_bin,
        diff_coverage_ids: diff_coverage_ids,
        coverage_bin: coverage_bin
      )
      bucket_dirs = discover_bucket_dirs(triage_dir)

      metas_by_dir = {}
      dirty_dirs = Set.new
      bucket_dirs.each do |bucket_dir|
        seed_legacy_occurrences(bucket_dir)
        occ_summary = summarize_occurrences(bucket_dir)
        meta_path = File.join(bucket_dir, "meta.json")
        meta = nil
        if File.file?(meta_path)
          begin
            meta = JSON.parse(File.read(meta_path))
          rescue JSON::ParserError
            meta = nil
          end
        end

        if meta.nil? || meta["schema_version"] != META_SCHEMA_VERSION
          meta = backfill_bucket_meta(bucket_dir, triage_dir: triage_dir)
          dirty_dirs.add(bucket_dir)
        elsif meta["occurrences"] != occ_summary
          meta["occurrences"] = occ_summary
          dirty_dirs.add(bucket_dir)
        end
        if !meta["versions"].is_a?(Hash) || meta["versions"].empty?
          is_diff_meta = diff_bucket?(executable: meta["reproduced_by"].to_s, crash_output: meta.dig("symptom", "headline").to_s, triage_dir: triage_dir)
          repro_name = File.basename(meta["reproduced_by"].to_s)
          snap_bin_cand = triage_ws_roots(triage_dir).map { |r| File.join(r, "bin", repro_name) }.find { |p| !repro_name.empty? && File.file?(p) }
          repro_exec = snap_bin_cand || meta["reproduced_by"].to_s
          backfilled_versions = resolve_versions_metadata(
            executable: repro_exec,
            is_diff: is_diff_meta,
            target_ruby_version: meta.dig("options", "ruby_version")
          )
          if backfilled_versions
            meta["versions"] = backfilled_versions
            dirty_dirs.add(bucket_dir)
          end
        end

        min_path = File.join(bucket_dir, "input.min")
        if meta["input"].is_a?(Hash) && File.file?(min_path) &&
           (meta["input"]["payload_sha256"].nil? || !meta["input"].key?("source_preview"))
          h = decode_fuzz_header(File.binread(min_path))
          meta["input"]["payload_sha256"] ||= Digest::SHA256.hexdigest(h[:source])
          meta["input"]["source_preview"] = format_source_preview(h[:source]) unless meta["input"].key?("source_preview")
          dirty_dirs.add(bucket_dir)
        end

        archive_info = sync_bucket_archive(bucket_dir, meta["archive"])
        if meta["archive"] != archive_info
          meta["archive"] = archive_info
          dirty_dirs.add(bucket_dir)
        end

        crash_output = meta.dig("symptom", "headline").to_s
        reproduced_by = meta["reproduced_by"].to_s
        expected_profile = bucket_verify_profile(
          reason: meta["reason"].to_s,
          executable: reproduced_by,
          crash_output: crash_output,
          triage_dir: triage_dir
        )
        if meta["verify_profile"] != expected_profile
          meta["verify_profile"] = expected_profile
          dirty_dirs.add(bucket_dir)
        end

        ensure_bucket_verify_script(
          bucket_dir,
          reason: meta["reason"].to_s,
          executable: reproduced_by,
          crash_output: crash_output,
          triage_dir: triage_dir
        )
        metas_by_dir[bucket_dir] = meta
      end

      effective_corpus_dir = if corpus_dir && !corpus_dir.empty?
                               corpus_dir
                             elsif ENV["TRIAGE_CORPUS_DIR"] && !ENV["TRIAGE_CORPUS_DIR"].empty?
                               ENV["TRIAGE_CORPUS_DIR"]
                             else
                               workspace_default_corpus_dir(triage_dir)
                             end
      showmap_path = find_executable_in_path(env_showmap_bin)
      ref_binary_meta, corpus_info = populate_coverage_stage(
        bin_path: cov_bin,
        ids_path: cov_ids_path,
        empty_reason: "TRIAGE_COVERAGE_BIN is empty",
        showmap_path: showmap_path,
        metas_by_dir: metas_by_dir,
        target_dirs: metas_by_dir.keys,
        dirty_dirs: dirty_dirs,
        field_key: "coverage",
        cache_path: File.join(triage_dir, ".corpus-coverage.json"),
        stage_label: "prism",
        corpus_dir: effective_corpus_dir
      )

      diff_dirs = metas_by_dir.select { |_, meta| diff_parse_y_invariant_meta?(meta) }.keys
      diff_ref_binary_meta = nil
      diff_corpus_info = nil
      if !diff_dirs.empty? || !ENV.fetch("TRIAGE_DIFF_COVERAGE_BIN", "").empty? || (diff_coverage_bin && !diff_coverage_bin.empty?)
        diff_ref_binary_meta, diff_corpus_info = populate_coverage_stage(
          bin_path: diff_cov_bin,
          ids_path: diff_cov_ids_path,
          empty_reason: "TRIAGE_DIFF_COVERAGE_BIN is empty",
          showmap_path: showmap_path,
          metas_by_dir: metas_by_dir,
          target_dirs: diff_dirs,
          dirty_dirs: dirty_dirs,
          field_key: "diff_coverage",
          cache_path: File.join(triage_dir, ".diff-corpus-coverage.json"),
          stage_label: "diff_parse_y",
          corpus_dir: effective_corpus_dir
        )
      end

      enrich_bucket_digests!(
        metas_by_dir,
        triage_dir: triage_dir,
        dirty_dirs: dirty_dirs,
        workers: digest_workers,
        force: recount.nil? ? env_recount? : recount
      )

      dirty_dirs.each do |dir|
        write_json_atomic(File.join(dir, "meta.json"), metas_by_dir[dir])
      end

      buckets = metas_by_dir.values.sort_by { |m| [-(m.dig("occurrences", "count") || 0), m["bucket_id"].to_s] }
      by_reason = Hash.new(0)
      by_worker = Hash.new(0)
      total_occurrences = 0
      buckets.each do |b|
        occ_count = b.dig("occurrences", "count") || 0
        total_occurrences += occ_count
        by_reason[b["reason"]] += 1
        (b.dig("occurrences", "by_worker") || {}).each { |w, c| by_worker[w] += c }
      end

      versions_meta = resolve_versions_metadata(
        triage_dir: triage_dir,
        coverage_bin: cov_bin,
        include_ruby_oracle: true,
        include_diff_binary: true,
        fuzz_buckets: buckets
      )
      corpus_payload = corpus_info.reject { |k, _| %w[corpus_fingerprint ids_sha256].include?(k) }
      index_data = {
        "schema_version" => META_SCHEMA_VERSION,
        "generated_at" => Time.now.utc.iso8601,
        "triage_dir" => normalize_repo_path(triage_dir),
        "reference_binary" => ref_binary_meta
      }
      index_data["diff_reference_binary"] = diff_ref_binary_meta if diff_ref_binary_meta
      index_data["versions"] = versions_meta if versions_meta
      index_data["corpus"] = corpus_payload
      if diff_corpus_info
        index_data["diff_corpus"] = diff_corpus_info.reject { |k, _| %w[corpus_fingerprint ids_sha256].include?(k) }
      end
      index_data.merge!(
        "summary" => {
          "bucket_count" => buckets.size,
          "total_occurrences" => total_occurrences,
          "by_reason" => by_reason.sort.to_h,
          "by_worker" => by_worker.sort.to_h
        },
        "buckets" => buckets
      )

      metadata_path = File.join(triage_dir, "metadata.json")
      write_json_atomic(metadata_path, index_data)
      if defined?(FuzzClustering)
        clusters_report = FuzzClustering.cluster_metadata(index_data, metadata_path: normalize_repo_path(metadata_path))
        write_json_atomic(File.join(triage_dir, "clusters.json"), clusters_report)
      end
    end
  end
end
