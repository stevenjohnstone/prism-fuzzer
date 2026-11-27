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
          diff ||= bt_text.include?("INVARIANT[diff_parse_y]") ||
                   bt_text.include?("CRASH[diff_parse_y]") ||
                   bt_text.include?("INVARIANT[cruby_compile]") ||
                   bt_text.include?("CRASH[cruby_compile]") ||
                   bt_text.include?("INVARIANT[cruby_pipeline]") ||
                   bt_text.include?("CRASH[cruby_pipeline]")
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

      parts = []
      is_sync = false
      if base =~ /\Aid:\d+(?:,sig:\d+)?,sync:([^,]+),src:(?:id:)?([^,+]+)/
        is_sync = true
        raw_src = Regexp.last_match(1)
        src_id = Regexp.last_match(2)
        src_w = StatsIngest.normalize_sync_source(raw_src, consumer_worker: consumer_worker, topo_ctx: topo_ctx)
        is_foreign = raw_src != src_w
        parts << if is_foreign
                   "Foreign Sync (-F) from #{src_w} (id:#{src_id})"
                 else
                   "Peer Sync from #{src_w} (id:#{src_id})"
                 end
      elsif base =~ /\Aid:\d+(?:,sig:\d+)?,src:(\d+)\+(\d+)/
        parts << "Splice (id:#{Regexp.last_match(1)} + id:#{Regexp.last_match(2)})"
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
        is_diff = %w[diff_parse_y cruby_compile cruby_pipeline].include?(b["verify_profile"].to_s) ||
                  %w[prism_diff_ruby cruby_compile cruby_pipeline_diff].include?(b.dig("target", "shape").to_s) ||
                  headline.include?("diff_parse_y") ||
                  headline.include?("cruby_compile") ||
                  headline.include?("cruby_pipeline")
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
          if fspec.is_a?(Hash) && (%w[prism_diff_ruby cruby_compile cruby_pipeline_diff].include?(fspec["shape"].to_s) || %w[diff_parse_y cruby_compile cruby_pipeline].include?(fspec["verify_profile"].to_s))
            flags[w["id"].to_s] = true
          end
        end
      end
      StatsIngest.discover_fuzzer_dirs(afl_dir, topo_ctx: topo_ctx).each do |wname, dir|
        stats = StatsIngest.parse_fuzzer_stats(File.join(dir, "fuzzer_stats"))
        banner = stats["afl_banner"].to_s
        cmd = stats["command_line"].to_s
        if %w[fuzz.diff fuzz.compile fuzz.pipeline].include?(File.basename(banner)) || cmd.match?(%r{(?:\A|[/\s])fuzz\.(?:diff|compile|pipeline)(?:\s|\z)})
          flags[wname] = true
        end
      end
      flags
    rescue SystemCallError, IOError => e
      warn "Lineage: failed to inspect worker diff flags in #{afl_dir}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
      {}
    end

    def hydrate_single_step(s, triage_crashes: nil, worker_diff_flags: nil, topo_ctx: nil)
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
                           bt_text.include?("INVARIANT[cruby_compile]") ||
                           bt_text.include?("CRASH[cruby_compile]") ||
                           bt_text.include?("INVARIANT[cruby_pipeline]") ||
                           bt_text.include?("CRASH[cruby_pipeline]") ||
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

    def hydrate_chain_steps(chain, triage_crashes: nil, worker_diff_flags: nil, topo_ctx: nil, step_cache: nil)
      hydrated = chain.map do |s|
        if step_cache
          cache_key = [s[:path], s[:worker], s[:kind], s[:base]]
          cached = (step_cache[cache_key] ||= hydrate_single_step(s, triage_crashes: triage_crashes, worker_diff_flags: worker_diff_flags, topo_ctx: topo_ctx))
          cached.dup
        else
          hydrate_single_step(s, triage_crashes: triage_crashes, worker_diff_flags: worker_diff_flags, topo_ctx: topo_ctx)
        end
      end
      # If Step 0 is a virtual root node (corpus) and Step 1 is its imported seed copy, share Step 1's source/metadata
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

      rank_parent_chain = lambda do |ch|
        return [-1, 0] if ch.nil? || ch.empty?
        distinct_workers = ch.map { |s| s[:worker] }.uniq.size
        [distinct_workers, ch.size]
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

        chain = if base =~ /\Aid:\d+(?:,sig:\d+)?,sync:([^,]+),src:(?:id:)?(\d+)/
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

      # Crash & hang lineage across all workers
      crash_files = roots.flat_map { |r| Dir.glob(File.join(r, "*/{crashes,hangs}/id:*")) }.select do |p|
        File.file?(p) && !p.end_with?(".bt", ".min", ".md")
      end.sort

      pathways = {}
      corpus_roots = Hash.new(0)
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

        # Number of distinct fuzzer workers (excluding "corpus" seed origins)
        fuzzer_hops = hops.reject { |h| h == "corpus" }.uniq
        total_multi_worker_crashes += 1 if fuzzer_hops.size >= 2

        if root_origin == "corpus"
          total_corpus_crashes += 1
          corpus_roots[root_seed] += 1
        end

        p_entry = (pathways[hops] ||= {
          hops: hops,
          root_origin: root_origin,
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

      step_cache = {}
      pathways.each_value do |p|
        p[:sample_chain] = hydrate_chain_steps(p[:sample_raw_chain], triage_crashes: triage_crashes, worker_diff_flags: worker_diff_flags, topo_ctx: topo_ctx, step_cache: step_cache)
        p.delete(:sample_raw_chain)
      end

      sorted_pathways = pathways.values.sort_by do |p|
        [-p[:count], -p[:fuzzer_hop_count], p[:hops].join("->")]
      end

      {
        total_crashes: crash_files.size,
        total_corpus_crashes: total_corpus_crashes,
        total_multi_worker_crashes: total_multi_worker_crashes,
        unique_corpus_crash_seeds: corpus_roots.size,
        pathways: sorted_pathways
      }
    rescue SystemCallError, IOError => e
      warn "Lineage: failed to analyze fleet lineage in #{afl_dir}: #{e.class}: #{e.message}" unless ENV["FUZZ_QUIET"] == "1"
      {
        total_crashes: 0,
        total_corpus_crashes: 0,
        total_multi_worker_crashes: 0,
        unique_corpus_crash_seeds: 0,
        pathways: []
      }
    end

    def worker_step_color(w, color_by_name, topo_ctx: nil)
      topo_colors = (topo_ctx && topo_ctx[:colors]) || {}
      if w == "corpus"
        "#fbbf24"
      else
        color_by_name[w] || topo_colors[w] || "#9ca3af"
      end
    end

    def render_pathway_pills(hops, color_by_name, topo_ctx: nil)
      hops.map do |w|
        color = worker_step_color(w, color_by_name, topo_ctx: topo_ctx)
        if color_by_name.key?(w)
          %(<span class="hop-pill clickable-pill" onclick="event.stopPropagation(); selectTab(#{Helpers.topo_js_arg(w)})" title="Open #{CGI.escapeHTML(w)} tab"><span class="legend-dot" style="background:#{color}"></span>#{CGI.escapeHTML(w)}</span>)
        elsif w == "corpus"
          %(<span class="hop-pill" title="Initial Seed Corpus"><span class="legend-dot" style="background:#{color}"></span>corpus</span>)
        else
          %(<span class="hop-pill"><span class="legend-dot" style="background:#{color}"></span>#{CGI.escapeHTML(w)}</span>)
        end
      end.join('<span class="hop-arrow">&rarr;</span>')
    end

    def format_evo_step_tail(s, color_by_name, topo_ctx: nil)
      w = s[:worker].to_s
      color = worker_step_color(w, color_by_name, topo_ctx: topo_ctx)
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
      <<~TAIL.chomp
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
      TAIL
    end

    def render_evolution_chain_steps(chain, color_by_name, topo_ctx: nil)
      return "" if chain.nil? || chain.empty?

      steps_html = chain.each_with_index.map do |s, idx|
        is_last = (idx == chain.size - 1)
        step_cls = if idx == 0
                     "evo-step evo-step-root"
                   elsif is_last && (s[:kind] == "crashes" || s[:kind] == "hangs")
                     "evo-step evo-step-crash"
                   else
                     "evo-step"
                   end
        tail = format_evo_step_tail(s, color_by_name, topo_ctx: topo_ctx)
        <<~STEP
          <div class="#{step_cls}">
            <div class="evo-step-head">
              <span class="evo-step-num">Step #{idx}</span>
              #{tail}
          </div>
        STEP
      end.join('<div class="evo-connector">&darr;</div>')

      %(<div class="evo-chain-wrap">#{steps_html}</div>)
    end

    def render_evo_drawer_row(drawer_id, colspan:, title_html:, chain:, color_by_name:, topo_ctx: nil, chunker: nil)
      safe_chain = Array(chain)
      if chunker && !safe_chain.empty?
        step_ids = safe_chain.map { |s| chunker.intern_evo_step(format_evo_step_tail(s, color_by_name, topo_ctx: topo_ctx)) }
        last_s = safe_chain.last
        crash_last = !!(last_s && (last_s[:kind] == "crashes" || last_s[:kind] == "hangs"))
        shard_id = chunker.register_evo_drawer(
          drawer_id,
          colspan: colspan,
          title_html: title_html,
          step_ids: step_ids,
          crash_last: crash_last
        )
        %(<tr id="#{drawer_id}" class="hunk-drawer-row" data-drawer-shard="#{CGI.escapeHTML(shard_id)}" style="display:none;"></tr>)
      else
        <<~DROW.chomp
          <tr id="#{drawer_id}" class="hunk-drawer-row" style="display:none;">
            <td colspan="#{colspan}" class="hunk-drawer-cell">
              <div class="origin-hunk-title">
                #{title_html}
              </div>
              #{render_evolution_chain_steps(safe_chain, color_by_name, topo_ctx: topo_ctx)}
            </td>
          </tr>
        DROW
      end
    end

    def partition_rows_for_chunker(row_items, preview_limit:, chunker:)
      if chunker && preview_limit && row_items.size > preview_limit
        vis = row_items.first(preview_limit).join("\n")
        extra_shards = chunker.register_extra_rows(row_items.drop(preview_limit))
        attr = extra_shards.empty? ? "" : %( data-extra-row-shards="#{CGI.escapeHTML(extra_shards.join(','))}")
        [vis, attr]
      else
        [row_items.join("\n"), ""]
      end
    end

    def render_crash_lineage_table(pathways, total_crashes, color_by_name, id_prefix:, title:, subtitle:, filter_controls: false, preview_limit: 50, topo_ctx: nil, chunker: nil)
      return "" if pathways.nil? || pathways.empty?

      tbody_id = "#{id_prefix}-tbody"
      eff_limit = chunker ? preview_limit : nil
      max_count = [pathways.map { |p| p[:count] }.max.to_i, 1].max
      row_items = pathways.each_with_index.map do |p, idx|
        drawer_id = "#{id_prefix}-drawer-#{idx}"
        top_root, top_root_cnt = p[:roots].max_by { |_, c| c } || ["-", 0]
        pct_of_total = total_crashes > 0 ? (p[:count] * 100.0 / total_crashes) : 0.0
        bar_w = (p[:count] * 100.0 / max_count).round(1)
        bar_color = "#fb7185"
        row_tags = []
        row_tags << "multihop" if p[:fuzzer_hop_count] >= 2
        row_tags << "singlehop" if p[:fuzzer_hop_count] < 2
        crash_step = (p[:sample_chain] || []).last || {}
        loupe_cell = if crash_step[:loupe_url]
                       %(<a class="cov-link" href="#{CGI.escapeHTML(crash_step[:loupe_url])}" target="_blank" rel="noopener" onclick="event.stopPropagation()" title="Animate representative crash in Prism Loupe">Prism Loupe &nearr;</a>)
                     else
                       "<span class=\"muted\">&mdash;</span>"
                     end
        is_extra = eff_limit && idx >= eff_limit
        row_cls = is_extra ? "clickable-row lineage-row extra-toggle-row" : "clickable-row lineage-row"
        row_style = is_extra ? ' style="display:none;"' : ""

        drawer_title = <<~DTITLE.chomp
          <span>Representative Testcase Evolution: #{render_pathway_pills(p[:hops], color_by_name, topo_ctx: topo_ctx)}</span>
          <span class="muted">#{Helpers.format_int(p[:count])} crashes from #{Helpers.format_int(p[:parents].size)} parent queue items (#{Helpers.format_int(p[:roots].size)} root seeds)</span>
        DTITLE
        drawer_html = render_evo_drawer_row(
          drawer_id,
          colspan: 7,
          title_html: drawer_title,
          chain: p[:sample_chain],
          color_by_name: color_by_name,
          topo_ctx: topo_ctx,
          chunker: chunker
        )

        <<~ROW
          <tr class="#{row_cls}" data-drawer-id="#{drawer_id}" data-lineage-prefix="#{id_prefix}" data-lineage-tags="#{row_tags.join(' ')}"#{row_style} onclick="toggleHunkDrawer('#{drawer_id}')">
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
          #{drawer_html}
        ROW
      end

      rows_html, tbody_extra_attr = partition_rows_for_chunker(row_items, preview_limit: eff_limit, chunker: chunker)
      show_all_btn = if eff_limit && pathways.size > eff_limit
                       %(<button class="cov-btn cov-btn-secondary" data-show-label="Show All #{Helpers.format_int(pathways.size)} Pathways" data-hide-label="Show Top #{eff_limit} Pathways" onclick="toggleExtraTableRows(this, '#{tbody_id}')">Show All #{Helpers.format_int(pathways.size)} Pathways</button>)
                     else
                       ""
                     end

      controls_html = if filter_controls
                        <<~CTRL
                          <div style="display:flex;gap:6px;flex-wrap:wrap;">
                            <button class="cov-btn" onclick="filterLineageRows('#{id_prefix}', 'all', this)">All Pathways (#{pathways.size})</button>
                            <button class="cov-btn cov-btn-secondary" onclick="filterLineageRows('#{id_prefix}', 'multihop', this)">Multi-Fuzzer Hops (&ge;2)</button>
                            #{show_all_btn}
                            <button class="cov-btn cov-btn-secondary" data-expand-label="Expand All Evolution Chains" data-collapse-label="Collapse All Evolution Chains" onclick="toggleAllHunks(this, '#{id_prefix}-drawer-')">Expand All Evolution Chains</button>
                          </div>
                        CTRL
                      else
                        <<~CTRL
                          <div style="display:flex;gap:6px;flex-wrap:wrap;">
                            #{show_all_btn}
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
            <tbody id="#{tbody_id}"#{tbody_extra_attr}>
              #{rows_html}
            </tbody>
          </table>
        </div>
      HTML
    end

    def render_overview_crash_lineage(fleet_lineage, color_by_name, topo_ctx: nil, chunker: nil)
      return "" unless fleet_lineage[:total_crashes] > 0

      multi_pct = (fleet_lineage[:total_multi_worker_crashes] * 100.0 / fleet_lineage[:total_crashes]).round(1)
      render_crash_lineage_table(
        fleet_lineage[:pathways],
        fleet_lineage[:total_crashes],
        color_by_name,
        id_prefix: "ov-lineage",
        title: "Crash Lineage &amp; Multi-Worker Evolution (#{Helpers.format_int(fleet_lineage[:total_crashes])} Crashes across #{fleet_lineage[:pathways].size} Pathways)",
        subtitle: "Backwards walk from every crash file through local mutations (src:) and peer syncs (sync:) to its root origin: " \
                  "#{Helpers.format_int(fleet_lineage[:total_corpus_crashes])} crashes from #{fleet_lineage[:unique_corpus_crash_seeds]} initial corpus seeds &bull; " \
                  "#{Helpers.format_int(fleet_lineage[:total_multi_worker_crashes])} (#{multi_pct}%) involved &ge;2 fuzzers. Click any pathway to view step-by-step testcase evolution.",
        filter_controls: true,
        topo_ctx: topo_ctx,
        chunker: chunker
      )
    end
  end
end
