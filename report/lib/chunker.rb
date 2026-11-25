# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"

module PrismFuzzerReport
  # Splits large HTML report sections, expandable lineage/triage drawers,
  # deduplicated testcase evolution steps, and overflow table rows into
  # size-bounded JavaScript chunk files loadable over both https:// (GitHub Pages)
  # and file:// without CORS restrictions.
  class Chunker
    DEFAULT_MAX_CHUNK_BYTES = 8 * 1024 * 1024
    MIN_MAX_CHUNK_BYTES = 32 * 1024

    attr_reader :max_chunk_bytes, :target_shard_bytes

    def self.json_for_script(obj)
      JSON.generate(obj)
        .gsub("&", "\\u0026")
        .gsub("<", "\\u003c")
        .gsub(">", "\\u003e")
        .gsub("\u2028", "\\u2028")
        .gsub("\u2029", "\\u2029")
    end

    def self.safe_slug(text, fallback: "chunk")
      slug = text.to_s.downcase.gsub(/[^a-z0-9_-]+/, "-").gsub(/\A-+|-+\z/, "")
      slug = fallback if slug.empty?
      slug[0, 48]
    end

    def initialize(max_chunk_bytes: DEFAULT_MAX_CHUNK_BYTES)
      raw_max = max_chunk_bytes.to_i
      @max_chunk_bytes = [raw_max, MIN_MAX_CHUNK_BYTES].max
      @target_shard_bytes = [[(@max_chunk_bytes * 0.45).to_i, 16 * 1024].max, 4 * 1024 * 1024].min

      @step_id_by_tail = {}
      @step_shards = []
      @current_step_shard = nil
      @shard_by_step_id = []

      @drawer_shards = []
      @current_drawer_shard = nil

      @row_shards = []
      @tabs = []
    end

    # Deduplicates a rendered evolution step tail (everything inside evo-step after
    # `<span class="evo-step-num">Step N</span>`) and assigns an integer step ID.
    def intern_evo_step(step_tail_html)
      key = step_tail_html.to_s
      existing = @step_id_by_tail[key]
      return existing if existing

      key = -key
      sid = @shard_by_step_id.length
      @step_id_by_tail[key] = sid

      est_bytes = key.bytesize + 24
      if @current_step_shard.nil? ||
         (!@current_step_shard[:items].empty? && @current_step_shard[:bytes] + est_bytes > @target_shard_bytes)
        idx = @step_shards.length
        @current_step_shard = {
          id: "steps:#{idx}",
          slug: format("steps-%03d", idx),
          items: {},
          bytes: 64
        }
        @step_shards << @current_step_shard
      end

      @current_step_shard[:items][sid.to_s] = key
      @current_step_shard[:bytes] += est_bytes
      @shard_by_step_id << @current_step_shard[:id]
      sid
    end

    def register_evo_drawer(drawer_id, colspan:, title_html:, step_ids:, crash_last:)
      deps = step_ids.map { |sid| @shard_by_step_id[sid] }.compact.uniq
      entry = {
        "c" => colspan.to_i,
        "t" => title_html.to_s,
        "s" => step_ids,
        "k" => crash_last ? 1 : 0,
        "deps" => deps
      }
      append_drawer_entry(drawer_id.to_s, entry)
    end

    def register_html_drawer(drawer_id, inner_td_html)
      entry = { "html" => inner_td_html.to_s }
      append_drawer_entry(drawer_id.to_s, entry)
    end

    def register_extra_rows(row_html_list)
      return [] if row_html_list.nil? || row_html_list.empty?

      shard_ids = []
      cur_rows = []
      cur_bytes = 64

      flush_rows = lambda do
        return if cur_rows.empty?

        idx = @row_shards.length
        sid = "rows:#{idx}"
        @row_shards << {
          id: sid,
          slug: format("rows-%03d", idx),
          html: cur_rows.join("\n")
        }
        shard_ids << sid
        cur_rows = []
        cur_bytes = 64
      end

      row_html_list.each do |row_html|
        s = row_html.to_s
        flush_rows.call if !cur_rows.empty? && (cur_bytes + s.bytesize + 2 > @target_shard_bytes)
        cur_rows << s
        cur_bytes += s.bytesize + 2
      end
      flush_rows.call
      shard_ids
    end

    def register_tab(tab_name, inner_html, sankey_meta: nil, sankey_initial: nil)
      chunk_id = "tab:#{tab_name}"
      payload = { "kind" => "tab", "html" => inner_html.to_s }
      payload["sankeyMeta"] = sankey_meta if sankey_meta
      payload["sankeyInitial"] = sankey_initial if sankey_initial
      @tabs << {
        id: chunk_id,
        slug: "tab-#{self.class.safe_slug(tab_name, fallback: 'panel')}",
        payload: payload
      }
      chunk_id
    end

    def finalize_artifacts
      return @finalized if @finalized

      manifest = {}
      files = {}

      logical_chunks = []
      @step_shards.each do |sh|
        logical_chunks << [sh[:id], sh[:slug], { "kind" => "steps", "steps" => sh[:items] }]
      end
      @drawer_shards.each do |sh|
        logical_chunks << [sh[:id], sh[:slug], { "kind" => "drawers", "drawers" => sh[:items] }]
      end
      @row_shards.each do |sh|
        logical_chunks << [sh[:id], sh[:slug], { "kind" => "rows", "html" => sh[:html] }]
      end
      @tabs.each do |tb|
        logical_chunks << [tb[:id], tb[:slug], tb[:payload]]
      end

      logical_chunks.each do |chunk_id, base_slug, payload|
        id_js = self.class.json_for_script(chunk_id)
        payload_js = self.class.json_for_script(payload)
        single_js = "window.__PRISM_FUZZER_ON_CHUNK__(#{id_js}, #{payload_js});\n"

        if single_js.bytesize <= @max_chunk_bytes
          sha8 = Digest::SHA256.hexdigest(single_js)[0, 8]
          fname = "#{base_slug}.#{sha8}.js"
          files[fname] = single_js
          manifest[chunk_id] = ["chunks/#{fname}"]
        else
          raw_json = JSON.generate(payload)
          slices = slice_json_for_parts(chunk_id, raw_json)
          total = slices.length
          part_rels = slices.each_with_index.map do |slice_str, part_idx|
            part_js = "window.__PRISM_FUZZER_ON_CHUNK_PART__(#{id_js}, #{part_idx}, #{total}, #{self.class.json_for_script(slice_str)});\n"
            sha8 = Digest::SHA256.hexdigest(part_js)[0, 8]
            fname = format("%s.part%03d.%s.js", base_slug, part_idx, sha8)
            files[fname] = part_js
            "chunks/#{fname}"
          end
          manifest[chunk_id] = part_rels
        end
      end

      @finalized = { manifest: manifest, files: files }
    end

    def manifest_script_js
      manifest = finalize_artifacts[:manifest]
      "window.__PRISM_FUZZER_CHUNK_MANIFEST__ = #{self.class.json_for_script(manifest)};\n"
    end

    def write_chunks!(out_dir)
      artifacts = finalize_artifacts
      chunks_dir = File.join(out_dir, "chunks")
      FileUtils.mkdir_p(chunks_dir)

      written = []
      artifacts[:files].each do |fname, content|
        dest = File.join(chunks_dir, fname)
        tmp = "#{dest}.tmp.#{Process.pid}"
        File.binwrite(tmp, content)
        File.rename(tmp, dest)
        written << dest
      end
      written
    end

    def prune_stale_chunks!(out_dir)
      chunks_dir = File.join(out_dir, "chunks")
      return unless File.directory?(chunks_dir)

      keep = finalize_artifacts[:files].keys.each_with_object({}) { |k, h| h[k] = true }
      Dir.children(chunks_dir).each do |entry|
        next if keep[entry] || entry.include?(".tmp.")

        path = File.join(chunks_dir, entry)
        FileUtils.rm_f(path) if File.file?(path)
      end
    end

    # Converts an already-rendered monolithic `index.html` into a chunked `index.html`
    # plus `Chunker` instance without requiring original AFL++ queue directories.
    def self.split_monolithic_html(raw_html, max_chunk_bytes: DEFAULT_MAX_CHUNK_BYTES, report_js:, sankey_js: "")
      return nil if raw_html.include?("window.__PRISM_FUZZER_CHUNK_MANIFEST__ = {")

      script_idx = raw_html.rindex("<script>")
      return nil unless script_idx

      script_end = raw_html.index("</script>", script_idx)
      return nil unless script_end

      head_and_body = raw_html[0, script_idx]
      trailing_script = raw_html[script_idx, (script_end + 9) - script_idx]
      tail_after_script = raw_html[(script_end + 9)..] || ""

      sankey_meta = nil
      sankey_initial = nil
      if (m_idx = trailing_script.rindex("mountSankeyView({"))
        args_start = m_idx + "mountSankeyView(".length
        args_end = trailing_script.index(");\n", args_start) || trailing_script.rindex(");")
        if args_end && args_end > args_start
          parsed_args = JSON.parse("[#{trailing_script[args_start...args_end]}]")
          sankey_meta, sankey_initial = parsed_args
        end
      end

      chunker = new(max_chunk_bytes: max_chunk_bytes)

      # 1. Extract and deduplicate all lineage hunk-drawer-row elements (skipping triage-drawer-* which contain nested bucket tables and move with tab:triage).
      transformed = head_and_body.gsub(%r{<tr id="((?!triage-drawer-)[^"]+)" class="hunk-drawer-row"[^>]*>(.*?)</tr>}m) do
        drawer_id = Regexp.last_match(1)
        inner = Regexp.last_match(2)
        if inner =~ %r{\A\s*<td colspan="(\d+)" class="hunk-drawer-cell">\s*<div class="origin-hunk-title">(.*?)</div>\s*<div class="evo-chain-wrap">(.*)</div>\s*</td>\s*\z}m
          colspan = Regexp.last_match(1).to_i
          title_html = Regexp.last_match(2).strip
          wrap_inner = Regexp.last_match(3)
          raw_steps = wrap_inner.split(%r{<div class="evo-connector">&darr;</div>})
          crash_last = raw_steps.last.to_s.include?("evo-step-crash")
          step_ids = raw_steps.map do |st_html|
            if st_html =~ %r{\A\s*<div class="evo-step[^"]*">\s*<div class="evo-step-head">\s*<span class="evo-step-num">Step \d+</span>\s*(.*)\s*</div>\s*\z}m
              chunker.intern_evo_step(Regexp.last_match(1))
            else
              chunker.intern_evo_step(st_html)
            end
          end
          shard_id = chunker.register_evo_drawer(
            drawer_id,
            colspan: colspan,
            title_html: title_html,
            step_ids: step_ids,
            crash_last: crash_last
          )
        else
          shard_id = chunker.register_html_drawer(drawer_id, inner.strip)
        end
        %(<tr id="#{drawer_id}" class="hunk-drawer-row" data-drawer-shard="#{shard_id}" style="display:none;"></tr>)
      end

      # 2. Extract extra-toggle-row overflow rows from tbody elements.
      transformed.gsub!(%r{<tbody id="([^"]+)">(.*?)</tbody>}m) do
        tbody_id = Regexp.last_match(1)
        tbody_inner = Regexp.last_match(2)
        if tbody_inner.include?("extra-toggle-row")
          trs = tbody_inner.scan(%r{<tr\b.*?</tr>}m)
          first_extra = trs.index { |tr| tr.include?("extra-toggle-row") }
          if first_extra && first_extra > 0
            vis = trs[0...first_extra].join("\n")
            extra_shards = chunker.register_extra_rows(trs[first_extra..])
            attr = extra_shards.empty? ? "" : %( data-extra-row-shards="#{extra_shards.join(',')}")
            %(<tbody id="#{tbody_id}"#{attr}>\n#{vis}\n</tbody>)
          else
            Regexp.last_match(0)
          end
        else
          Regexp.last_match(0)
        end
      end

      # 3. Extract all non-active tab-panel sections into lazy tab chunks.
      transformed.gsub!(%r{<section id="tab-([^"]+)" class="tab-panel">(.*?)</section>}m) do
        raw_id = Regexp.last_match(1)
        inner = Regexp.last_match(2)
        tab_name = CGI.unescapeHTML(raw_id)
        cid = if tab_name == "sankey" && sankey_meta
                chunker.register_tab(tab_name, inner, sankey_meta: sankey_meta, sankey_initial: sankey_initial)
              else
                chunker.register_tab(tab_name, inner)
              end
        %(<section id="tab-#{raw_id}" class="tab-panel" data-tab-chunk="#{CGI.escapeHTML(cid)}"></section>)
      end

      new_script = +"<script>\n"
      new_script << chunker.manifest_script_js
      new_script << "#{sankey_js}\n" if sankey_meta && !sankey_js.to_s.empty?
      new_script << "#{report_js}\n</script>"

      [transformed + new_script + tail_after_script, chunker]
    end

    private

    def append_drawer_entry(drawer_id, entry)
      est_bytes = JSON.generate(entry).bytesize + drawer_id.bytesize + 16
      if @current_drawer_shard.nil? ||
         (!@current_drawer_shard[:items].empty? && @current_drawer_shard[:bytes] + est_bytes > @target_shard_bytes)
        idx = @drawer_shards.length
        @current_drawer_shard = {
          id: "drawers:#{idx}",
          slug: format("drawers-%03d", idx),
          items: {},
          bytes: 64
        }
        @drawer_shards << @current_drawer_shard
      end

      @current_drawer_shard[:items][drawer_id] = entry
      @current_drawer_shard[:bytes] += est_bytes
      @current_drawer_shard[:id]
    end

    # Splits a serialized UTF-8 JSON string into character-safe slices whose
    # escaped JS wrapper stays strictly <= @max_chunk_bytes.
    def slice_json_for_parts(chunk_id, raw_json)
      id_js = self.class.json_for_script(chunk_id)
      overhead = "window.__PRISM_FUZZER_ON_CHUNK_PART__(#{id_js}, 9999, 9999, \"\");\n".bytesize + 256
      avail = [@max_chunk_bytes - overhead, 4096].max
      # Escaping quotes/backslashes/<>& inside a JSON string literal can expand bytes by ~2x worst-case;
      # start at avail / 2 and shrink dynamically if an escaped slice ever exceeds @max_chunk_bytes.
      step_bytes = [avail / 2, 1024].max

      slices = []
      bytes = raw_json.b
      total_len = bytes.bytesize
      pos = 0

      while pos < total_len
        cur_limit = [step_bytes, total_len - pos].min
        loop do
          end_pos = pos + cur_limit
          if end_pos < total_len
            while end_pos > pos && (bytes.getbyte(end_pos) & 0xC0) == 0x80
              end_pos -= 1
            end
            end_pos = pos + 1 if end_pos <= pos
          end

          cand = bytes.byteslice(pos, end_pos - pos).force_encoding("UTF-8")
          wrapped_len = self.class.json_for_script(cand).bytesize + overhead - 256
          if wrapped_len <= @max_chunk_bytes || end_pos - pos <= 16
            slices << cand
            pos = end_pos
            break
          end
          cur_limit = [cur_limit * 3 / 4, 16].max
        end
      end

      slices
    end
  end
end
