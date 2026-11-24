# frozen_string_literal: true

require "cgi/escape"
require "digest"
require "json"
require_relative "helpers"
require_relative "stats_ingest"
require_relative "../../runtime/common"
require_relative "../../runtime/fuzz_header"

module PrismFuzzerReport
  module Lineage
    module_function

    def decode_fuzz_header(raw)
      PrismFuzzer::FuzzHeader.format_summary(raw)
    end

    def encode_loupe_scope_local(bytes)
      PrismFuzzer::LoupeUrl.encode_scope_local(bytes)
    end

    def build_prism_loupe_url(raw, sanitize: false)
      PrismFuzzer::LoupeUrl.prism_url(raw, sanitize: sanitize)
    end

    def crash_file_bt_text(path)
      bt_path = "#{path}.bt"
      return "" unless path && File.file?(bt_path)

      PrismFuzzer::Common.utf8_safe(File.binread(bt_path, 65_536))
    rescue Errno::ENOENT, Errno::ESTALE
      ""
    rescue SystemCallError, IOError => e
      warn "Lineage: failed to read backtrace #{bt_path}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
      ""
    end

    def crash_filename_signal_reason(path)
      return "" if path.nil? || path.to_s.empty?

      base = PrismFuzzer::Common.utf8_safe(File.basename(path.to_s))
      sig_num = base[/\Aid:\d+,sig:(\d+)(?:,|\z)/, 1]&.to_i
      return "" unless sig_num && (1..64).include?(sig_num)

      Signal.signame(sig_num).to_s
    rescue ArgumentError
      ""
    end

    def parse_testcase_file(path, max_preview_bytes = 512, sanitize: nil, diff: false)
      return { preview: nil, opts_desc: nil, loupe_url: nil } unless path && File.file?(path)

      raw = File.binread(path) || "".b
      opts_desc = decode_fuzz_header(raw)
      ruby_bytes = raw.bytesize > 4 ? raw.byteslice(4..) : "".b

      if sanitize.nil?
        if File.basename(File.dirname(path)) == "crashes"
          bt_text = crash_file_bt_text(path)
          diff ||= bt_text.include?("INVARIANT[diff_parse_y]") || bt_text.include?("CRASH[diff_parse_y]")
          sig_reason = crash_filename_signal_reason(path)
          sanitize = !diff && PrismFuzzer::LoupeUrl.sanitizer_crash?(sig_reason, bt_text)
        else
          sanitize = false
        end
      end

      loupe_url = if diff
                    PrismFuzzer::LoupeUrl.diff_url(ruby_bytes)
                  else
                    build_prism_loupe_url(raw, sanitize: !!sanitize)
                  end

      slice = ruby_bytes.bytesize > max_preview_bytes ? ruby_bytes.byteslice(0, max_preview_bytes) : ruby_bytes
      formatted = slice.bytes.map do |b|
        case b
        when 0x0A then "\n"
        when 0x09 then "\t"
        when 0x20..0x7E then b.chr
        else format("\\x%02X", b)
        end
      end.join
      formatted << "\n... (#{ruby_bytes.bytesize - max_preview_bytes} more bytes)" if ruby_bytes.bytesize > max_preview_bytes

      {
        preview: formatted,
        opts_desc: opts_desc,
        loupe_url: loupe_url
      }
    rescue Errno::ENOENT, Errno::ESTALE
      { preview: nil, opts_desc: nil, loupe_url: nil }
    rescue SystemCallError, IOError => e
      warn "Lineage: failed to parse testcase #{path}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
      { preview: nil, opts_desc: nil, loupe_url: nil }
    end

    def describe_afl_step_op(base, kind, consumer_worker: nil, topo_ctx: nil)
      return "Root Corpus Seed" if kind == "corpus"
      return "Grammar Generated Seed (lrama-fuzz)" if kind == "seed"

      parts = []
      is_sync = false
      if base =~ /\Aid:\d+(?:,sig:\d+)?,sync:([^,]+),src:(?:id:)?([^,+]+)/
        is_sync = true
        raw_src = Regexp.last_match(1)
        src_id = Regexp.last_match(2)
        src_w = StatsIngest.normalize_sync_source(raw_src, consumer_worker: consumer_worker, topo_ctx: topo_ctx)
        is_gram = Helpers.grammar_worker?(src_w, topo_ctx: topo_ctx)
        is_foreign = raw_src != src_w || is_gram
        parts << if is_gram
                   "Foreign Sync (-F) from #{src_w} (#{src_id})"
                 elsif is_foreign
                   "Foreign Sync (-F) from #{src_w} (id:#{src_id})"
                 else
                   "Peer Sync from #{src_w} (id:#{src_id})"
                 end
      elsif base =~ /\Aid:\d+(?:,sig:\d+)?,src:(\d+)\+(\d+)/
        parts << "Splice (id:#{Regexp.last_match(1)} + id:#{Regexp.last_match(2)})"
      elsif base =~ /\Aid:\d+(?:,sig:\d+)?,src:lrama-fuzz\b/
        parts << "Grammar Evolution (lrama-fuzz)"
      elsif base =~ /\Aid:\d+(?:,time:\d+,execs:\d+)?,orig:([^,]+)/
        parts << "Initial Seed (#{Regexp.last_match(1)})"
      end
      if !is_sync && base =~ /,op:([^,]+)/
        op = Regexp.last_match(1)
        rep = base[/,rep:(\d+)/, 1]
        pos = base[/,pos:(\d+)/, 1]
        detail = op
        detail += " (rep:#{rep})" if rep
        detail += " @ byte #{pos}" if pos
        parts << "Mutate: #{detail}"
      end
      parts << "+cov" if base.include?(",+cov")
      if base =~ /\Aid:\d+,sig:(\d+),/
        parts << "CRASH (sig:#{Regexp.last_match(1)})"
      elsif kind == "hangs"
        parts << "HANG"
      end
      parts.empty? ? kind : parts.join(" &bull; ")
    end

    def load_lineage_triage_crashes(triage_dir)
      index = {}
      return index if triage_dir.nil? || triage_dir.to_s.empty? || !File.directory?(triage_dir)

      record_for_bucket = lambda do |b|
        reason = b["reason"].to_s
        headline = b.dig("symptom", "headline").to_s
        is_diff = b["verify_profile"].to_s == "diff_parse_y" ||
                  b.dig("target", "shape").to_s == "prism_diff_ruby" ||
                  headline.include?("diff_parse_y")
        { reason: reason, headline: headline, is_diff: is_diff }
      end

      register_occ = lambda do |rec, occ|
        next unless occ.is_a?(Hash)

        p = occ["path"].to_s
        unless p.empty?
          index[p] ||= rec
          index[File.expand_path(p)] ||= rec
          w = occ["worker"].to_s
          index["#{w}/#{File.basename(p)}"] ||= rec unless w.empty?
        end
        sha = occ["sha256"].to_s
        index["sha256:#{sha}"] ||= rec unless sha.empty?
      end

      meta_path = File.join(triage_dir, "metadata.json")
      meta = PrismFuzzer::Common.read_json(meta_path, context: "Lineage")
      if meta.is_a?(Hash)
        Array(meta["buckets"]).each do |b|
          next unless b.is_a?(Hash)

          rec = record_for_bucket.call(b)
          Array(b.dig("occurrences", "sample_crashes")).each { |occ| register_occ.call(rec, occ) }
        end
      end

      Dir.glob(File.join(triage_dir, "*", "*", "occurrences.jsonl")).each do |occ_path|
        bdir = File.dirname(occ_path)
        bmeta_path = File.join(bdir, "meta.json")
        bmeta = PrismFuzzer::Common.read_json(bmeta_path, context: "Lineage")
        rec = if bmeta.is_a?(Hash)
                record_for_bucket.call(bmeta)
              else
                { reason: File.basename(File.dirname(bdir)), headline: "", is_diff: false }
              end
        begin
          File.foreach(occ_path) do |line|
            next if line.strip.empty?

            occ = begin
                    JSON.parse(line)
                  rescue JSON::ParserError, EncodingError => e
                    warn "Lineage: malformed JSONL line in #{occ_path}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
                    next
                  end
            register_occ.call(rec, occ)
          end
        rescue Errno::ENOENT, Errno::ESTALE
          next
        rescue SystemCallError, IOError => e
          warn "Lineage: failed to read #{occ_path}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
          next
        end
      end

      index
    rescue SystemCallError, IOError => e
      warn "Lineage: failed to load triage crashes from #{triage_dir}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
      {}
    end

    def worker_diff_flags_for(afl_dir, topo_ctx: nil)
      flags = {}
      topo = topo_ctx && topo_ctx[:topology]
      if topo.is_a?(Hash)
        Array(topo["workers"]).each do |w|
          next unless w.is_a?(Hash)

          fspec = topo.dig("fuzzers", w["fuzzer"].to_s)
          if fspec.is_a?(Hash) && (fspec["shape"].to_s == "prism_diff_ruby" || fspec["verify_profile"].to_s == "diff_parse_y")
            flags[w["id"].to_s] = true
          end
        end
      end
      StatsIngest.discover_fuzzer_dirs(afl_dir, topo_ctx: topo_ctx).each do |wname, dir|
        stats = StatsIngest.parse_fuzzer_stats(File.join(dir, "fuzzer_stats"))
        banner = stats["afl_banner"].to_s
        cmd = stats["command_line"].to_s
        if File.basename(banner) == "fuzz.diff" || cmd.match?(%r{(?:\A|[/\s])fuzz\.diff(?:\s|\z)})
          flags[wname] = true
        end
      end
      flags
    rescue SystemCallError, IOError => e
      warn "Lineage: failed to inspect worker diff flags in #{afl_dir}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
      {}
    end

    def hydrate_chain_steps(chain, triage_crashes: nil, worker_diff_flags: nil, topo_ctx: nil)
      hydrated = chain.map do |s|
        p = s[:path]
        sz = (p && File.file?(p)) ? File.size(p) : nil
        parsed = if s[:kind] == "crashes" && p && File.file?(p)
                   bt_text = crash_file_bt_text(p)
                   trec = triage_crashes && (triage_crashes[p] || triage_crashes[File.expand_path(p)] || triage_crashes["#{s[:worker]}/#{s[:base]}"])
                   if !trec && triage_crashes && !triage_crashes.empty?
                     sha = begin
                             Digest::SHA256.file(p).hexdigest
                           rescue Errno::ENOENT, Errno::ESTALE
                             nil
                           rescue SystemCallError, IOError => e
                             warn "Lineage: failed to hash #{p}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
                             nil
                           end
                     trec = triage_crashes["sha256:#{sha}"] if sha
                   end
                   sig_reason = crash_filename_signal_reason(p)
                   reason = trec ? trec[:reason] : sig_reason
                   crash_output = bt_text.empty? ? (trec ? trec[:headline] : "") : bt_text
                   is_diff = (trec && trec[:is_diff]) ||
                             bt_text.include?("INVARIANT[diff_parse_y]") ||
                             bt_text.include?("CRASH[diff_parse_y]") ||
                             (worker_diff_flags && worker_diff_flags[s[:worker].to_s])
                   is_san = !is_diff && PrismFuzzer::LoupeUrl.sanitizer_crash?(reason, crash_output)
                   parse_testcase_file(p, sanitize: is_san, diff: is_diff)
                 else
                   parse_testcase_file(p, sanitize: false, diff: false)
                 end
        s.merge(
          size: sz,
          op_desc: describe_afl_step_op(s[:base].to_s, s[:kind].to_s, consumer_worker: s[:worker].to_s, topo_ctx: topo_ctx),
          preview: parsed[:preview],
          opts_desc: parsed[:opts_desc],
          loupe_url: parsed[:loupe_url]
        )
      end
      # If Step 0 is a virtual root node (corpus or grammar) and Step 1 is its imported seed copy, share Step 1's source/metadata
      if hydrated.size >= 2
        hydrated[0][:preview] ||= hydrated[1][:preview]
        hydrated[0][:opts_desc] ||= hydrated[1][:opts_desc]
        hydrated[0][:size] ||= hydrated[1][:size]
        hydrated[0][:loupe_url] ||= hydrated[1][:loupe_url]
      end
      hydrated
    end

    def analyze_fleet_lineage(afl_dir, triage_dir: nil, topo_ctx: nil)
      triage_crashes = load_lineage_triage_crashes(triage_dir)
      worker_diff_flags = worker_diff_flags_for(afl_dir, topo_ctx: topo_ctx)
      fuzz_root = File.dirname(afl_dir)
      default_corpus_dir = File.join(fuzz_root, "corpus")
      corpus_dirs_by_gen = {}
      corpus_dirs = []
      gen_dirs = []
      topo = topo_ctx && topo_ctx[:topology]
      if topo && topo["generators"].is_a?(Hash)
        ws_raw = topo.dig("workspace", "dir")
        topo["generators"].each do |gid, g|
          next unless g.is_a?(Hash)

          if g["kind"].to_s == "corpus"
            cdir = if defined?(PrismFuzzer::Topology) && PrismFuzzer::Topology.respond_to?(:resolve_corpus_generator_dir)
                     PrismFuzzer::Topology.resolve_corpus_generator_dir(
                       g["dir"],
                       fuzz_dir: fuzz_root,
                       ws_raw_dir: ws_raw,
                       default_corpus_dir: default_corpus_dir
                     )
                   elsif g["dir"] && !g["dir"].to_s.strip.empty?
                     File.expand_path(g["dir"].to_s, fuzz_root)
                   else
                     default_corpus_dir
                   end
            corpus_dirs_by_gen[gid.to_s] = cdir
            corpus_dirs << cdir
          elsif g["seeds_dir"]
            gen_dirs << g["seeds_dir"]
          end
        end
      end
      corpus_dirs << default_corpus_dir
      corpus_dirs.uniq!
      worker_corpus_dir = {}
      if topo && topo["workers"].is_a?(Array)
        topo["workers"].each do |wspec|
          next unless wspec.is_a?(Hash)

          from_gid = wspec.dig("seeds", "from")&.to_s
          cdir = from_gid && corpus_dirs_by_gen[from_gid]
          worker_corpus_dir[wspec["id"].to_s] = cdir if cdir
        end
      end
      gen_seed_dirs_by_worker = Hash.new { |h, k| h[k] = [] }
      if topo_ctx && topo_ctx[:generators].is_a?(Hash)
        topo_ctx[:generators].each do |gwid, gcfg|
          gen_seed_dirs_by_worker[gwid] << gcfg[:seeds_dir] if gcfg[:seeds_dir]
          gen_seed_dirs_by_worker[gwid] << File.join(fuzz_root, "seeds", gcfg[:gid].to_s) if gcfg[:gid]
        end
      end
      seeds_dirs = (gen_dirs + gen_seed_dirs_by_worker.values.flatten + ["/tmp/afl-tmpdir/grammar/seeds", File.join(fuzz_root, "seeds")]).uniq.select { |d| Dir.exist?(d) }
      seed_by_prefix = {}
      seed_by_prefix_by_worker = Hash.new { |h, k| h[k] = {} }
      index_seed_dir = lambda do |sd, target_map|
        return unless sd && Dir.exist?(sd)

        Dir.children(sd).each do |sf|
          next if sf.start_with?(".")
          full = File.join(sd, sf)
          next unless File.file?(full)
          target_map[sf] ||= full
          target_map[sf[0, 20]] ||= full if sf.length > 20
        end
      rescue Errno::ENOENT, Errno::ENOTDIR
        nil
      rescue SystemCallError => e
        warn "Lineage: failed to scan seeds directory #{sd}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
        nil
      end
      gen_seed_dirs_by_worker.each do |gwid, dirs|
        dirs.uniq.each { |sd| index_seed_dir.call(sd, seed_by_prefix_by_worker[gwid]) }
      end
      seeds_dirs.each { |sd| index_seed_dir.call(sd, seed_by_prefix) }
      roots = StatsIngest.worker_root_dirs(afl_dir, topo_ctx: topo_ctx)

      q_index = {}
      roots.flat_map { |r| Dir.glob(File.join(r, "*/queue")) }.each do |qdir|
        next if File.symlink?(qdir)

        w = File.basename(File.dirname(qdir))
        Dir.glob(File.join(qdir, "id:*")).each do |p|
          next unless File.file?(p)
          id = File.basename(p)[/\Aid:(\d+)/, 1]
          q_index[[w, id.to_i]] = p if id
        end
      end

      is_gram_worker = ->(wn) { Helpers.grammar_worker?(wn, topo_ctx: topo_ctx) }

      rank_parent_chain = lambda do |ch|
        return [-1, 0, 0] if ch.nil? || ch.empty?
        is_grammar = is_gram_worker.call(ch.first[:worker]) ? 1 : 0
        distinct_workers = ch.map { |s| s[:worker] }.uniq.size
        [is_grammar, distinct_workers, ch.size]
      end

      memo = {}
      trace_chain = lambda do |path, seen = {}|
        return memo[path] if memo.key?(path)
        return [] if seen[path]

        seen = seen.merge(path => true)
        base = File.basename(path)
        w = File.basename(File.dirname(File.dirname(path)))
        kind = File.basename(File.dirname(path))
        step = { path: path, worker: w, kind: kind, base: base, id: base[/\Aid:(\d+)/, 1] }

        gram_sync_tag = nil
        gram_seed_id = nil
        if base =~ /\Aid:\d+(?:,sig:\d+)?,sync:([^,]+),src:([^,+]+)/
          cand_tag = Regexp.last_match(1)
          cand_src = Regexp.last_match(2)
          if (resolved_gw = Helpers.resolve_grammar_sync_worker(w, cand_tag, topo_ctx: topo_ctx))
            gram_sync_tag = resolved_gw
            gram_seed_id = cand_src
          end
        elsif base =~ /\Aid:\d+(?:,time:\d+,execs:\d+)?,orig:(seed_[^,]+)/
          gram_seed_id = Regexp.last_match(1)
          gram_sync_tag = Helpers.resolve_grammar_sync_worker(w, "seeds", topo_ctx: topo_ctx) || "grammar"
        end

        chain = if gram_seed_id
                  gen_w = gram_sync_tag || "grammar"
                  w_map = seed_by_prefix_by_worker[gen_w]
                  root_path = (w_map && w_map[gram_seed_id]) || seed_by_prefix[gram_seed_id] || path
                  [{ path: root_path, worker: gen_w, kind: "seed", base: gram_seed_id, id: gram_seed_id }, step]
                elsif base =~ /\Aid:\d+(?:,sig:\d+)?,sync:([^,]+),src:(?:id:)?(\d+)/
                  peer = StatsIngest.normalize_sync_source(Regexp.last_match(1), consumer_worker: w, topo_ctx: topo_ctx)
                  src_id = Regexp.last_match(2)
                  parent = q_index[[peer, src_id.to_i]]
                  parent ? (trace_chain.call(parent, seen) + [step]) : [{ path: path, worker: peer, kind: "sync_root", base: "id:#{src_id}", id: src_id }, step]
                elsif base =~ /\Aid:\d+(?:,sig:\d+)?,src:(\d+)(?:\+(\d+))?/
                  p1 = q_index[[w, Regexp.last_match(1).to_i]]
                  p2 = Regexp.last_match(2) ? q_index[[w, Regexp.last_match(2).to_i]] : nil
                  ch1 = p1 ? trace_chain.call(p1, seen) : nil
                  ch2 = p2 ? trace_chain.call(p2, seen) : nil
                  best = if ch1 && ch2
                           (rank_parent_chain.call(ch2) <=> rank_parent_chain.call(ch1)) > 0 ? ch2 : ch1
                         else
                           ch1 || ch2
                         end
                  best && !best.empty? ? (best + [step]) : [step]
                elsif base =~ /\Aid:\d+(?:,time:\d+,execs:\d+)?,orig:([^,]+)/
                  orig_name = Regexp.last_match(1)
                  cand_cdirs = worker_corpus_dir[w] ? [worker_corpus_dir[w], *corpus_dirs].uniq : corpus_dirs
                  corpus_file = cand_cdirs.map { |cd| File.join(cd, orig_name) }.find { |cp| File.file?(cp) }
                  root_path = corpus_file || path
                  [{ path: root_path, worker: "corpus", kind: "corpus", base: orig_name, id: orig_name }, step]
                else
                  [step]
                end
        memo[path] = chain if kind == "queue"
        chain
      end

      # 1. Grammar queue propagation pathways across the fleet (and per generator worker)
      grammar_queue_pathways = {}
      gen_q_items_by_worker = Hash.new(0)
      gen_q_pathways_by_worker = Hash.new { |h, k| h[k] = [] }
      total_grammar_queue_items = 0
      q_index.each_value do |qpath|
        ch = trace_chain.call(qpath)
        next unless ch.first && is_gram_worker.call(ch.first[:worker])
        gen_w = ch.first[:worker].to_s
        total_grammar_queue_items += 1
        gen_q_items_by_worker[gen_w] += 1
        hops = []
        ch.each { |s| hops << s[:worker] if hops.empty? || hops.last != s[:worker] }
        qp_entry = (grammar_queue_pathways[hops] ||= {
          hops: hops,
          origin_worker: gen_w,
          count: 0,
          sample_raw_chain: ch
        })
        qp_entry[:count] += 1
        qp_entry[:sample_raw_chain] = ch if ch.size > qp_entry[:sample_raw_chain].size
      end

      # 2. Crash & hang lineage across all workers
      crash_files = roots.flat_map { |r| Dir.glob(File.join(r, "*/{crashes,hangs}/id:*")) }.select do |p|
        File.file?(p) && !p.end_with?(".bt", ".min", ".md")
      end.sort

      pathways = {}
      grammar_seed_crashes = {}
      gen_seed_crashes_by_worker = Hash.new { |h, k| h[k] = {} }
      gen_crashes_by_worker = Hash.new(0)
      gen_roots_by_worker = Hash.new { |h, k| h[k] = Hash.new(0) }
      corpus_roots = Hash.new(0)
      grammar_roots = Hash.new(0)
      total_grammar_crashes = 0
      total_corpus_crashes = 0
      total_multi_worker_crashes = 0

      crash_files.each do |cpath|
        ch = trace_chain.call(cpath)
        next if ch.empty?

        hops = []
        ch.each { |s| hops << s[:worker] if hops.empty? || hops.last != s[:worker] }
        root_origin = hops.first
        root_seed = ch.first[:base].to_s
        crash_worker = hops.last
        parent_step = ch[-2] || ch.first

        # Number of distinct fuzzer workers (excluding "corpus" and grammar generator seed origins)
        fuzzer_hops = hops.reject { |h| h == "corpus" || is_gram_worker.call(h) }.uniq
        total_multi_worker_crashes += 1 if fuzzer_hops.size >= 2

        if is_gram_worker.call(root_origin)
          total_grammar_crashes += 1
          gen_crashes_by_worker[root_origin] += 1
          grammar_roots["#{root_origin}:#{root_seed}"] += 1
          gen_roots_by_worker[root_origin][root_seed] += 1

          [grammar_seed_crashes, gen_seed_crashes_by_worker[root_origin]].each_with_index do |target_hash, h_idx|
            skey = h_idx.zero? ? "#{root_origin}:#{root_seed}" : root_seed
            g_entry = (target_hash[skey] ||= {
              seed: root_seed,
              origin_worker: root_origin,
              count: 0,
              hops: hops,
              parents: {},
              sample_raw_chain: ch
            })
            g_entry[:count] += 1
            g_entry[:parents][[parent_step[:worker], parent_step[:id]]] = true
            if ch.size > g_entry[:sample_raw_chain].size
              g_entry[:sample_raw_chain] = ch
              g_entry[:hops] = hops
            end
          end
        elsif root_origin == "corpus"
          total_corpus_crashes += 1
          corpus_roots[root_seed] += 1
        end

        p_entry = (pathways[hops] ||= {
          hops: hops,
          root_origin: root_origin,
          is_grammar_origin: is_gram_worker.call(root_origin),
          crash_worker: crash_worker,
          fuzzer_hop_count: fuzzer_hops.size,
          count: 0,
          parents: {},
          roots: Hash.new(0),
          max_steps: 0,
          sample_raw_chain: ch
        })
        p_entry[:count] += 1
        p_entry[:parents][[parent_step[:worker], parent_step[:id]]] = true
        p_entry[:roots][root_seed] += 1
        if ch.size > p_entry[:max_steps]
          p_entry[:max_steps] = ch.size
          p_entry[:sample_raw_chain] = ch
        end
      end

      pathways.each_value do |p|
        p[:sample_chain] = hydrate_chain_steps(p[:sample_raw_chain], triage_crashes: triage_crashes, worker_diff_flags: worker_diff_flags, topo_ctx: topo_ctx)
        p.delete(:sample_raw_chain)
      end
      grammar_seed_crashes.each_value do |g|
        g[:sample_chain] = hydrate_chain_steps(g[:sample_raw_chain], triage_crashes: triage_crashes, worker_diff_flags: worker_diff_flags, topo_ctx: topo_ctx)
        g.delete(:sample_raw_chain)
      end
      gen_seed_crashes_by_worker.each_value do |sub_h|
        sub_h.each_value do |g|
          g[:sample_chain] = hydrate_chain_steps(g[:sample_raw_chain], triage_crashes: triage_crashes, worker_diff_flags: worker_diff_flags, topo_ctx: topo_ctx)
          g.delete(:sample_raw_chain)
        end
      end
      grammar_queue_pathways.each_value do |qp|
        qp[:sample_chain] = hydrate_chain_steps(qp[:sample_raw_chain], triage_crashes: triage_crashes, worker_diff_flags: worker_diff_flags, topo_ctx: topo_ctx)
        qp.delete(:sample_raw_chain)
        gen_q_pathways_by_worker[qp[:origin_worker]] << qp if qp[:origin_worker]
      end

      sorted_pathways = pathways.values.sort_by do |p|
        [p[:is_grammar_origin] ? 0 : 1, -p[:count], -p[:fuzzer_hop_count], p[:hops].join("->")]
      end

      all_gen_names = (
        gen_q_items_by_worker.keys +
        gen_crashes_by_worker.keys +
        Array(topo_ctx && topo_ctx[:grammar_workers])
      ).uniq
      by_generator = {}
      all_gen_names.each do |gw|
        by_generator[gw] = {
          total_grammar_crashes: gen_crashes_by_worker[gw],
          unique_grammar_crash_seeds: gen_roots_by_worker[gw].size,
          total_grammar_queue_items: gen_q_items_by_worker[gw],
          grammar_queue_pathways: gen_q_pathways_by_worker[gw].sort_by { |qp| -qp[:count] },
          pathways: sorted_pathways.select { |p| p[:hops].include?(gw) },
          grammar_seed_crashes: gen_seed_crashes_by_worker[gw].values.sort_by { |g| [-g[:count], g[:seed]] }
        }
      end

      {
        total_crashes: crash_files.size,
        total_grammar_crashes: total_grammar_crashes,
        total_corpus_crashes: total_corpus_crashes,
        total_multi_worker_crashes: total_multi_worker_crashes,
        unique_grammar_crash_seeds: grammar_roots.size,
        unique_corpus_crash_seeds: corpus_roots.size,
        total_grammar_queue_items: total_grammar_queue_items,
        grammar_queue_pathways: grammar_queue_pathways.values.sort_by { |qp| -qp[:count] },
        pathways: sorted_pathways,
        grammar_seed_crashes: grammar_seed_crashes.values.sort_by { |g| [-g[:count], g[:seed]] },
        by_generator: by_generator
      }
    rescue SystemCallError, IOError => e
      warn "Lineage: failed to analyze fleet lineage in #{afl_dir}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
      {
        total_crashes: 0,
        total_grammar_crashes: 0,
        total_corpus_crashes: 0,
        total_multi_worker_crashes: 0,
        unique_grammar_crash_seeds: 0,
        unique_corpus_crash_seeds: 0,
        total_grammar_queue_items: 0,
        grammar_queue_pathways: [],
        pathways: [],
        grammar_seed_crashes: []
      }
    end

    def worker_step_color(w, color_by_name, topo_ctx: nil)
      topo_colors = (topo_ctx && topo_ctx[:colors]) || {}
      if w == "corpus"
        "#fbbf24"
      elsif Helpers.grammar_worker?(w, topo_ctx: topo_ctx)
        color_by_name[w] || topo_colors[w] || "#34d399"
      else
        color_by_name[w] || topo_colors[w] || "#9ca3af"
      end
    end

    def render_pathway_pills(hops, color_by_name, topo_ctx: nil)
      hops.map do |w|
        color = worker_step_color(w, color_by_name, topo_ctx: topo_ctx)
        star = Helpers.grammar_worker?(w, topo_ctx: topo_ctx) ? "&#9733; " : ""
        if color_by_name.key?(w)
          %(<span class="hop-pill clickable-pill" onclick="event.stopPropagation(); selectTab(#{Helpers.topo_js_arg(w)})" title="Open #{CGI.escapeHTML(w)} tab"><span class="legend-dot" style="background:#{color}"></span>#{star}#{CGI.escapeHTML(w)}</span>)
        elsif w == "corpus"
          %(<span class="hop-pill" title="Initial Seed Corpus"><span class="legend-dot" style="background:#{color}"></span>corpus</span>)
        else
          %(<span class="hop-pill"><span class="legend-dot" style="background:#{color}"></span>#{CGI.escapeHTML(w)}</span>)
        end
      end.join('<span class="hop-arrow">&rarr;</span>')
    end

    def render_evolution_chain_steps(chain, color_by_name, topo_ctx: nil)
      return "" if chain.nil? || chain.empty?

      steps_html = chain.each_with_index.map do |s, idx|
        w = s[:worker].to_s
        color = worker_step_color(w, color_by_name, topo_ctx: topo_ctx)
        is_last = (idx == chain.size - 1)
        step_cls = if idx == 0
                     "evo-step evo-step-root"
                   elsif is_last && (s[:kind] == "crashes" || s[:kind] == "hangs")
                     "evo-step evo-step-crash"
                   else
                     "evo-step"
                   end
        opts_badge = s[:opts_desc] ? %(<span class="sched-pill" title="4-byte fuzz_options_t header (decoded into pm_options_t query params for Prism Loupe)">opts: #{CGI.escapeHTML(s[:opts_desc])}</span>) : ""
        size_badge = s[:size] ? %(<span class="evo-size">#{Helpers.format_int(s[:size])} B</span>) : ""
        loupe_btn = if s[:loupe_url]
                      %(<a class="cov-link" href="#{CGI.escapeHTML(s[:loupe_url])}" target="_blank" rel="noopener" onclick="event.stopPropagation()" title="Animate this step's Ruby parse in Prism Loupe with its exact pm_options_t">Animate in Prism Loupe &nearr;</a>)
                    else
                      ""
                    end
        preview_block = if s[:preview]
                          %(<pre class="evo-preview">#{CGI.escapeHTML(s[:preview])}</pre>)
                        else
                          ""
                        end
        <<~STEP
          <div class="#{step_cls}">
            <div class="evo-step-head">
              <span class="evo-step-num">Step #{idx}</span>
              <span class="hop-pill"><span class="legend-dot" style="background:#{color}"></span>#{CGI.escapeHTML(w)}</span>
              <code class="evo-fname">#{CGI.escapeHTML(s[:base].to_s)}</code>
              <span class="evo-op">#{s[:op_desc]}</span>
              #{opts_badge}
              <span style="margin-left:auto;display:inline-flex;align-items:center;gap:10px;">
                #{size_badge}
                #{loupe_btn}
              </span>
            </div>
            #{preview_block}
          </div>
        STEP
      end.join('<div class="evo-connector">&darr;</div>')

      %(<div class="evo-chain-wrap">#{steps_html}</div>)
    end

    def render_crash_lineage_table(pathways, total_crashes, color_by_name, id_prefix:, title:, subtitle:, filter_controls: false, topo_ctx: nil)
      return "" if pathways.nil? || pathways.empty?

      max_count = [pathways.map { |p| p[:count] }.max.to_i, 1].max
      rows_html = pathways.each_with_index.map do |p, idx|
        drawer_id = "#{id_prefix}-drawer-#{idx}"
        top_root, top_root_cnt = p[:roots].max_by { |_, c| c } || ["-", 0]
        pct_of_total = total_crashes > 0 ? (p[:count] * 100.0 / total_crashes) : 0.0
        bar_w = (p[:count] * 100.0 / max_count).round(1)
        is_gram_root = p[:is_grammar_origin] || Helpers.grammar_worker?(p[:root_origin], topo_ctx: topo_ctx)
        bar_color = is_gram_root ? "#34d399" : "#fb7185"
        row_tags = []
        row_tags << "grammar" if is_gram_root
        row_tags << "multihop" if p[:fuzzer_hop_count] >= 2
        row_tags << "singlehop" if p[:fuzzer_hop_count] < 2
        crash_step = (p[:sample_chain] || []).last || {}
        loupe_cell = if crash_step[:loupe_url]
                       %(<a class="cov-link" href="#{CGI.escapeHTML(crash_step[:loupe_url])}" target="_blank" rel="noopener" onclick="event.stopPropagation()" title="Animate representative crash in Prism Loupe">Prism Loupe &nearr;</a>)
                     else
                       "<span class=\"muted\">&mdash;</span>"
                     end

        <<~ROW
          <tr class="clickable-row lineage-row" data-lineage-prefix="#{id_prefix}" data-lineage-tags="#{row_tags.join(' ')}" onclick="toggleHunkDrawer('#{drawer_id}')">
            <td>
              <span id="caret-#{drawer_id}" class="muted" style="display:inline-block;width:14px;">&#9656;</span>
              #{render_pathway_pills(p[:hops], color_by_name, topo_ctx: topo_ctx)}
            </td>
            <td class="num">
              <div style="display:flex;align-items:center;justify-content:flex-end;gap:8px;">
                <div style="width:70px;height:7px;background:#0b0f19;border:1px solid #1f2937;border-radius:4px;overflow:hidden;">
                  <div style="width:#{bar_w}%;height:100%;background:#{bar_color};"></div>
                </div>
                <strong>#{Helpers.format_int(p[:count])}</strong>
                <span class="muted" style="min-width:44px;text-align:right;">(#{format("%.1f%%", pct_of_total)})</span>
              </div>
            </td>
            <td class="num">#{Helpers.format_int(p[:parents].size)}</td>
            <td class="num">#{Helpers.format_int(p[:roots].size)}</td>
            <td class="num">#{p[:max_steps]} steps</td>
            <td><code>#{CGI.escapeHTML(top_root.to_s)}</code> <span class="muted">(#{Helpers.format_int(top_root_cnt)})</span></td>
            <td class="num">#{loupe_cell}</td>
          </tr>
          <tr id="#{drawer_id}" class="hunk-drawer-row" style="display:none;">
            <td colspan="7" class="hunk-drawer-cell">
              <div class="origin-hunk-title">
                <span>Representative Testcase Evolution: #{render_pathway_pills(p[:hops], color_by_name, topo_ctx: topo_ctx)}</span>
                <span class="muted">#{Helpers.format_int(p[:count])} crashes from #{Helpers.format_int(p[:parents].size)} parent queue items (#{Helpers.format_int(p[:roots].size)} root seeds)</span>
              </div>
              #{render_evolution_chain_steps(p[:sample_chain], color_by_name, topo_ctx: topo_ctx)}
            </td>
          </tr>
        ROW
      end.join("\n")

      controls_html = if filter_controls
                        <<~CTRL
                          <div style="display:flex;gap:6px;flex-wrap:wrap;">
                            <button class="cov-btn" onclick="filterLineageRows('#{id_prefix}', 'all', this)">All Pathways (#{pathways.size})</button>
                            <button class="cov-btn cov-btn-secondary" onclick="filterLineageRows('#{id_prefix}', 'grammar', this)">&#9733; Grammar Rooted</button>
                            <button class="cov-btn cov-btn-secondary" onclick="filterLineageRows('#{id_prefix}', 'multihop', this)">Multi-Fuzzer Hops (&ge;2)</button>
                            <button class="cov-btn cov-btn-secondary" data-expand-label="Expand All Evolution Chains" data-collapse-label="Collapse All Evolution Chains" onclick="toggleAllHunks(this, '#{id_prefix}-drawer-')">Expand All Evolution Chains</button>
                          </div>
                        CTRL
                      else
                        <<~CTRL
                          <div>
                            <button class="cov-btn cov-btn-secondary" data-expand-label="Expand All Evolution Chains" data-collapse-label="Collapse All Evolution Chains" onclick="toggleAllHunks(this, '#{id_prefix}-drawer-')">Expand All Evolution Chains</button>
                          </div>
                        CTRL
                      end

      <<~HTML
        <div class="table-card" style="margin-top: 18px;">
          <div class="table-card-header">
            <div>
              <h3>#{title}</h3>
              <p class="chart-sub">#{subtitle}</p>
            </div>
            #{controls_html}
          </div>
          <table>
            <thead>
              <tr>
                <th>Lineage Pathway (Origin &rarr; Worker Hops &rarr; Crash Discoverer)</th>
                <th class="num">Crashes</th>
                <th class="num">Queue Parents</th>
                <th class="num">Root Seeds</th>
                <th class="num">Max Depth</th>
                <th>Top Root Seed (Crashes)</th>
                <th class="num">Parse Animator</th>
              </tr>
            </thead>
            <tbody id="#{id_prefix}-tbody">
              #{rows_html}
            </tbody>
          </table>
        </div>
      HTML
    end

    def render_loupe_pair_links(chain, last_label:)
      first_step = chain.first || {}
      last_step = chain.last || {}
      links = []
      if first_step[:loupe_url]
        links << %(<a class="cov-link" href="#{CGI.escapeHTML(first_step[:loupe_url])}" target="_blank" rel="noopener" onclick="event.stopPropagation()" title="Animate original grammar seed in Prism Loupe">Prism Loupe (Seed) &nearr;</a>)
      end
      if last_step[:loupe_url]
        links << %(<a class="cov-link" href="#{CGI.escapeHTML(last_step[:loupe_url])}" target="_blank" rel="noopener" onclick="event.stopPropagation()" title="Animate #{CGI.escapeHTML(last_label.downcase)} input in Prism Loupe">Prism Loupe (#{CGI.escapeHTML(last_label)}) &nearr;</a>)
      end
      links.empty? ? '<span class="muted">&mdash;</span>' : links.join(" &bull; ")
    end

    def render_grammar_seed_crashes_card(fleet_lineage, color_by_name, generator_name: nil, topo_ctx: nil)
      gen_label = generator_name || "grammar"
      safe_gen = CGI.escapeHTML(gen_label)
      dom_slug = gen_label.gsub(/[^a-zA-Z0-9_-]/, "_")
      drawer_prefix = generator_name ? "gram-seed-crash-#{dom_slug}-" : "gram-seed-crash-"
      g_crashes = fleet_lineage[:grammar_seed_crashes] || []
      seed_rows_html = g_crashes.each_with_index.map do |g, idx|
        drawer_id = "#{drawer_prefix}#{idx}"
        last_step = g[:sample_chain].last || {}
        sample_crash_short = last_step[:id] ? "#{last_step[:worker]} id:#{last_step[:id]}" : last_step[:base].to_s
        <<~ROW
          <tr class="clickable-row" onclick="toggleHunkDrawer('#{drawer_id}')">
            <td>
              <span id="caret-#{drawer_id}" class="muted" style="display:inline-block;width:14px;">&#9656;</span>
              <code>#{CGI.escapeHTML(g[:seed])}</code>
            </td>
            <td>#{render_pathway_pills(g[:hops], color_by_name, topo_ctx: topo_ctx)}</td>
            <td class="num"><strong class="text-danger">#{Helpers.format_int(g[:count])}</strong></td>
            <td class="num">#{Helpers.format_int(g[:parents].size)}</td>
            <td class="num">#{g[:sample_chain].size} steps</td>
            <td><code title="#{CGI.escapeHTML(last_step[:base].to_s)}">#{CGI.escapeHTML(sample_crash_short)}</code></td>
            <td class="num" style="white-space:nowrap;">#{render_loupe_pair_links(g[:sample_chain], last_label: "Crash")}</td>
          </tr>
          <tr id="#{drawer_id}" class="hunk-drawer-row" style="display:none;">
            <td colspan="7" class="hunk-drawer-cell">
              <div class="origin-hunk-title">
                <span>Grammar Seed <code>#{CGI.escapeHTML(g[:seed])}</code> &rarr; Crash Evolution</span>
                <span class="muted">#{Helpers.format_int(g[:count])} crashes</span>
              </div>
              #{render_evolution_chain_steps(g[:sample_chain], color_by_name, topo_ctx: topo_ctx)}
            </td>
          </tr>
        ROW
      end.join("\n")

      crashes_table = if g_crashes.any?
                        <<~TBL
                          <table>
                            <thead>
                              <tr>
                                <th>Grammar Seed ID</th>
                                <th>Deepest Pathway</th>
                                <th class="num">Crashes</th>
                                <th class="num">Queue Intermediates</th>
                                <th class="num">Max Depth</th>
                                <th>Sample Crash</th>
                                <th class="num">Parse Animator</th>
                              </tr>
                            </thead>
                            <tbody>
                              #{seed_rows_html}
                            </tbody>
                          </table>
                        TBL
                      else
                        %(<div style="padding:12px 16px;" class="muted">No crashes traced to <code>#{safe_gen}</code> seeds yet.</div>)
                      end

      expand_btn = if g_crashes.any?
                     %(<button class="cov-btn cov-btn-secondary" data-expand-label="Expand All Seed Crash Chains" data-collapse-label="Collapse All Seed Crash Chains" onclick="toggleAllHunks(this, '#{drawer_prefix}')">Expand All Seed Crash Chains</button>)
                   else
                     ""
                   end

      dot_col = color_by_name[gen_label] || "#34d399"
      <<~HTML
        <div class="table-card" style="margin-top: 18px;">
          <div class="table-card-header">
            <div>
              <h3><span class="legend-dot" style="background:#{dot_col}"></span> Per-Seed Crash Breakdown (#{Helpers.format_int(fleet_lineage[:total_grammar_crashes])} Crashes from #{Helpers.format_int(fleet_lineage[:unique_grammar_crash_seeds])} Grammar Seeds)</h3>
              <p class="chart-sub">
                <strong class="#{fleet_lineage[:total_grammar_crashes] > 0 ? 'text-danger' : ''}">#{Helpers.format_int(fleet_lineage[:total_grammar_crashes])} crashes</strong>
                across the fleet traced back to <strong>#{Helpers.format_int(fleet_lineage[:unique_grammar_crash_seeds])}</strong> <code>#{safe_gen}</code>-generated seeds.
                Click any seed row below to inspect the generated Ruby code and the mutation steps from seed to crash, or open directly in Prism Loupe.
              </p>
            </div>
            <div>
              #{expand_btn}
            </div>
          </div>
          #{crashes_table}
        </div>
      HTML
    end

    def render_grammar_queue_pathways_card(fleet_lineage, color_by_name, preview_limit: 15, generator_name: nil, topo_ctx: nil)
      q_paths = fleet_lineage[:grammar_queue_pathways] || []
      return "" if q_paths.empty?

      gen_label = generator_name || "grammar"
      safe_gen = CGI.escapeHTML(gen_label)
      dom_slug = gen_label.gsub(/[^a-zA-Z0-9_-]/, "_")
      drawer_prefix = generator_name ? "gram-queue-path-#{dom_slug}-" : "gram-queue-path-"
      tbody_id = generator_name ? "gram-queue-paths-#{dom_slug}-tbody" : "gram-queue-paths-tbody"

      total_q = [fleet_lineage[:total_grammar_queue_items].to_i, 1].max
      max_q = [q_paths.map { |qp| (qp.is_a?(Hash) ? qp[:count] : qp[1]).to_i }.max.to_i, 1].max

      rows_html = q_paths.each_with_index.map do |qp, idx|
        hops = qp.is_a?(Hash) ? qp[:hops] : qp[0]
        cnt = (qp.is_a?(Hash) ? qp[:count] : qp[1]).to_i
        chain = qp.is_a?(Hash) ? (qp[:sample_chain] || []) : []
        drawer_id = "#{drawer_prefix}#{idx}"
        last_step = chain.last || {}
        sample_short = last_step[:id] ? "#{last_step[:worker]} id:#{last_step[:id]}" : last_step[:base].to_s
        pct_of_total = cnt * 100.0 / total_q
        bar_w = (cnt * 100.0 / max_q).round(1)
        is_extra = idx >= preview_limit
        row_cls = is_extra ? "clickable-row extra-toggle-row" : "clickable-row"
        row_style = is_extra ? ' style="display:none;"' : ""

        <<~ROW
          <tr class="#{row_cls}" data-drawer-id="#{drawer_id}"#{row_style} onclick="toggleHunkDrawer('#{drawer_id}')">
            <td>
              <span id="caret-#{drawer_id}" class="muted" style="display:inline-block;width:14px;">&#9656;</span>
              #{render_pathway_pills(hops, color_by_name, topo_ctx: topo_ctx)}
            </td>
            <td class="num">
              <div style="display:flex;align-items:center;justify-content:flex-end;gap:8px;">
                <div style="width:70px;height:7px;background:#0b0f19;border:1px solid #1f2937;border-radius:4px;overflow:hidden;">
                  <div style="width:#{bar_w}%;height:100%;background:#34d399;"></div>
                </div>
                <strong style="color:#34d399;">#{Helpers.format_int(cnt)}</strong>
                <span class="muted" style="min-width:44px;text-align:right;">(#{format("%.1f%%", pct_of_total)})</span>
              </div>
            </td>
            <td class="num">#{chain.size} steps</td>
            <td><code title="#{CGI.escapeHTML(last_step[:base].to_s)}">#{CGI.escapeHTML(sample_short)}</code></td>
            <td class="num" style="white-space:nowrap;">#{render_loupe_pair_links(chain, last_label: "Queue")}</td>
          </tr>
          <tr id="#{drawer_id}" class="hunk-drawer-row" style="display:none;">
            <td colspan="5" class="hunk-drawer-cell">
              <div class="origin-hunk-title">
                <span>Representative Queue Evolution: #{render_pathway_pills(hops, color_by_name, topo_ctx: topo_ctx)}</span>
                <span class="muted">#{Helpers.format_int(cnt)} queue entries across fleet</span>
              </div>
              #{render_evolution_chain_steps(chain, color_by_name, topo_ctx: topo_ctx)}
            </td>
          </tr>
        ROW
      end.join("\n")

      show_all_btn = if q_paths.size > preview_limit
                       %(<button class="cov-btn cov-btn-secondary" data-show-label="Show All #{Helpers.format_int(q_paths.size)} Pathways" data-hide-label="Show Top #{preview_limit} Pathways" onclick="toggleExtraTableRows(this, '#{tbody_id}')">Show All #{Helpers.format_int(q_paths.size)} Pathways</button>)
                     else
                       ""
                     end

      dot_col = color_by_name[gen_label] || "#34d399"
      <<~HTML
        <div class="table-card" style="margin-top: 18px;">
          <div class="table-card-header">
            <div>
              <h3><span class="legend-dot" style="background:#{dot_col}"></span> Queue Propagation Pathways Across Fleet (#{Helpers.format_int(fleet_lineage[:total_grammar_queue_items])} Queue Entries across #{Helpers.format_int(q_paths.size)} Pathways)</h3>
              <p class="chart-sub">
                <strong>#{Helpers.format_int(fleet_lineage[:total_grammar_queue_items])}</strong> interesting queue entries across the fleet trace their ancestry back to <code>#{safe_gen}</code>
                (via foreign <code>-F</code> sync and subsequent peer mutations), independent of crashes.
                Click any pathway row to inspect a representative seed-to-queue evolution chain or open in Prism Loupe.
              </p>
            </div>
            <div style="display:flex;gap:6px;flex-wrap:wrap;">
              #{show_all_btn}
              <button class="cov-btn cov-btn-secondary" data-expand-label="Expand Visible Evolution Chains" data-collapse-label="Collapse Evolution Chains" onclick="toggleVisibleHunks(this, '#{tbody_id}')">Expand Visible Evolution Chains</button>
            </div>
          </div>
          <table>
            <thead>
              <tr>
                <th>Propagation Pathway (<code>#{safe_gen}</code> &rarr; Fleet Hops)</th>
                <th class="num">Queue Entries</th>
                <th class="num">Sample Depth</th>
                <th>Sample Queue Entry</th>
                <th class="num">Parse Animator</th>
              </tr>
            </thead>
            <tbody id="#{tbody_id}">
              #{rows_html}
            </tbody>
          </table>
        </div>
      HTML
    end

    def render_grammar_lineage_section(fleet_lineage, color_by_name, generator_name: nil, topo_ctx: nil)
      scoped = if generator_name && fleet_lineage[:by_generator] && fleet_lineage[:by_generator][generator_name]
                 fleet_lineage[:by_generator][generator_name]
               else
                 fleet_lineage
               end
      gen_label = generator_name || "grammar"
      safe_gen = CGI.escapeHTML(gen_label)
      dom_slug = gen_label.gsub(/[^a-zA-Z0-9_-]/, "_")

      q_paths = scoped[:grammar_queue_pathways] || []
      g_crashes = scoped[:grammar_seed_crashes] || []
      return "" if q_paths.empty? && g_crashes.empty?

      grammar_paths = if generator_name
                        (scoped[:pathways] || []).select { |p| p[:hops].include?(generator_name) }
                      else
                        (scoped[:pathways] || []).select { |p| p[:hops].any? { |h| Helpers.grammar_worker?(h, topo_ctx: topo_ctx) } }
                      end
      grammar_pathway_table = if grammar_paths.any?
                                render_crash_lineage_table(
                                  grammar_paths,
                                  grammar_paths.sum { |p| p[:count] },
                                  color_by_name,
                                  id_prefix: "w-lineage-#{dom_slug}",
                                  title: "Crash Lineage Involving <code>#{safe_gen}</code> (#{Helpers.format_int(scoped[:total_grammar_crashes])} Crashes from #{Helpers.format_int(scoped[:unique_grammar_crash_seeds])} Seeds across #{grammar_paths.size} Pathways)",
                                  subtitle: "Pathways where #{safe_gen}-generated seeds were imported via -F foreign sync and mutated into crashes across the fuzzer fleet.",
                                  topo_ctx: topo_ctx
                                )
                              else
                                ""
                              end

      <<~HTML
        #{grammar_pathway_table}
        #{render_grammar_seed_crashes_card(scoped, color_by_name, generator_name: generator_name, topo_ctx: topo_ctx)}
        #{render_grammar_queue_pathways_card(scoped, color_by_name, generator_name: generator_name, topo_ctx: topo_ctx)}
      HTML
    end

    def render_overview_crash_lineage(fleet_lineage, color_by_name, topo_ctx: nil)
      return "" unless fleet_lineage[:total_crashes] > 0

      multi_pct = (fleet_lineage[:total_multi_worker_crashes] * 100.0 / fleet_lineage[:total_crashes]).round(1)
      render_crash_lineage_table(
        fleet_lineage[:pathways],
        fleet_lineage[:total_crashes],
        color_by_name,
        id_prefix: "ov-lineage",
        title: "Crash Lineage &amp; Multi-Worker Evolution (#{Helpers.format_int(fleet_lineage[:total_crashes])} Crashes across #{fleet_lineage[:pathways].size} Pathways)",
        subtitle: "Backwards walk from every crash file through local mutations (src:) and peer syncs (sync:) to its root origin: " \
                  "#{Helpers.format_int(fleet_lineage[:total_grammar_crashes])} crashes from #{fleet_lineage[:unique_grammar_crash_seeds]} grammar seeds (#{Helpers.format_int(fleet_lineage[:total_grammar_queue_items])} grammar-rooted queue items fleet-wide) &bull; " \
                  "#{Helpers.format_int(fleet_lineage[:total_corpus_crashes])} crashes from #{fleet_lineage[:unique_corpus_crash_seeds]} initial corpus seeds &bull; " \
                  "#{Helpers.format_int(fleet_lineage[:total_multi_worker_crashes])} (#{multi_pct}%) involved &ge;2 fuzzers. Click any pathway to view step-by-step testcase evolution.",
        filter_controls: true,
        topo_ctx: topo_ctx
      )
    end
  end
end
