#!/usr/bin/env ruby
# frozen_string_literal: true

require "cgi"
require "erb"
require "fileutils"
require "json"
require "open3"
require "optparse"
require "shellwords"
require "time"

topology_lib = File.expand_path("../runtime/topology.rb", __dir__)
require topology_lib if File.file?(topology_lib)

module PrismFuzzerPublish
  Object.const_set(:RubyFuzzPublish, self) unless Object.const_defined?(:RubyFuzzPublish, false)

  module_function

  def read_json(path)
    return nil unless path && File.file?(path)

    JSON.parse(File.read(path, encoding: "UTF-8"))
  rescue Errno::ENOENT, Errno::ENOTDIR, SystemCallError, IOError, JSON::ParserError, EncodingError
    nil
  end

  def h(text)
    CGI.escapeHTML(text.to_s)
  end

  def resolve_versions(fuzz_root:, bin_dir:, triage_dir:)
    versions = {}
    topo = defined?(PrismFuzzer::Topology) ? PrismFuzzer::Topology.discover(bin_dir: bin_dir, triage_dir: triage_dir, start_dir: fuzz_root) : nil
    ws_build = if topo && defined?(PrismFuzzer::Topology)
                 PrismFuzzer::Topology.workspace_paths(topo, fuzz_root: fuzz_root)[:build_dir]
               elsif bin_dir && File.basename(File.expand_path(bin_dir)) == "bin"
                 File.join(File.dirname(File.expand_path(bin_dir)), "build")
               else
                 File.join(fuzz_root, "tmp", "fuzz", "build")
               end

    [
      File.join(bin_dir, "versions.json"),
      File.join(ws_build, "fuzz.versions.json"),
      File.join(ws_build, "versions.json")
    ].each do |p|
      data = read_json(p)
      next unless data.is_a?(Hash)

      versions["manifest"] ||= data
      versions["prism_a"] ||= data["prism"] if data["prism"]
      versions["prism_b"] ||= data["prism_b"] if data["prism_b"]
      versions["ruby"] ||= data["ruby_parse_y"] if data["ruby_parse_y"]
      versions["fuzz_repo"] ||= data["fuzz_repo"] if data["fuzz_repo"]
    end

    target_a = read_json(File.join(ws_build, "targets", "prism_a.json"))
    target_b = read_json(File.join(ws_build, "targets", "prism_b.json"))
    target_ruby = read_json(File.join(ws_build, "targets", "ruby.json"))
    clusters = read_json(File.join(triage_dir, "clusters.json"))
    metadata = read_json(File.join(triage_dir, "metadata.json"))

    if topo && topo["sources"].is_a?(Hash)
      versions["topology"] = {
        "name" => topo["name"],
        "sources" => topo["sources"].transform_values { |s| s.is_a?(Hash) ? s.slice("kind", "commit", "requested_ref", "mode", "applied_patches", "skipped_patches").compact : s }
      }.compact
    end

    versions["prism_a"] ||= clusters&.dig("versions", "prism") || metadata&.dig("versions", "prism") || target_a
    versions["prism_b"] ||= clusters&.dig("versions", "prism_b") || metadata&.dig("versions", "prism_b") || target_b
    versions["ruby"] ||= clusters&.dig("versions", "ruby_parse_y") || metadata&.dig("versions", "ruby_parse_y") || target_ruby
    versions["fuzz_repo"] ||= clusters&.dig("versions", "fuzz_repo") || metadata&.dig("versions", "fuzz_repo")

    if target_a && versions["prism_a"].is_a?(Hash)
      versions["prism_a"]["commit"] ||= target_a["commit"]
      versions["prism_a"]["requested_ref"] ||= target_a["requested_ref"]
      versions["prism_a"]["applied_patches"] ||= target_a["applied_patches"]
    end
    if target_b && versions["prism_b"].is_a?(Hash)
      versions["prism_b"]["commit"] ||= target_b["commit"]
      versions["prism_b"]["requested_ref"] ||= target_b["requested_ref"]
    end
    versions.compact
  end

  def extract_coverage_summary(coverage_dir)
    json_path = File.join(coverage_dir, "coverage.json")
    summary_path = File.join(coverage_dir, "summary.txt")
    data = read_json(json_path)

    primary_totals = data&.dig("pairs", 0, "totals") || data&.dig("data", 0, "totals") || data&.dig("totals")
    out = {}
    if primary_totals.is_a?(Hash)
      %w[regions functions lines branches].each do |metric|
        next unless primary_totals[metric].is_a?(Hash)

        m = primary_totals[metric]
        out[metric] = {
          "covered" => m["covered"],
          "count" => m["count"],
          "percent" => m["percent"]&.round(2)
        }
      end
    elsif File.file?(summary_path)
      txt = File.read(summary_path, encoding: "UTF-8", invalid: :replace)
      if txt =~ /^TOTAL\s+(\d+)\s+(\d+)\s+([0-9.]+)%\s+(\d+)\s+(\d+)\s+([0-9.]+)%\s+(\d+)\s+(\d+)\s+([0-9.]+)%/
        out["regions"] = { "count" => Regexp.last_match(1).to_i, "covered" => Regexp.last_match(1).to_i - Regexp.last_match(2).to_i, "percent" => Regexp.last_match(3).to_f }
        out["functions"] = { "count" => Regexp.last_match(4).to_i, "covered" => Regexp.last_match(4).to_i - Regexp.last_match(5).to_i, "percent" => Regexp.last_match(6).to_f }
        out["lines"] = { "count" => Regexp.last_match(7).to_i, "covered" => Regexp.last_match(7).to_i - Regexp.last_match(8).to_i, "percent" => Regexp.last_match(9).to_f }
      end
    end

    if data.is_a?(Hash) && data["pairs"].is_a?(Array) && !data["pairs"].empty?
      pairs_summary = {}
      data["pairs"].each do |pair|
        next unless pair.is_a?(Hash) && pair["id"]

        pt = pair["totals"]
        next unless pt.is_a?(Hash)

        pm = {}
        %w[regions functions lines branches].each do |metric|
          next unless pt[metric].is_a?(Hash)

          m = pt[metric]
          pm[metric] = {
            "covered" => m["covered"],
            "count" => m["count"],
            "percent" => m["percent"]&.round(2)
          }
        end
        pairs_summary[pair["id"].to_s] = {
          "source" => pair["source"],
          "target" => pair["target"],
          "label" => pair["label"],
          "input_count" => pair["input_count"]
        }.merge(pm).compact
      end
      out["pairs"] = pairs_summary unless pairs_summary.empty?
    end
    out.empty? ? nil : out
  end

  def extract_triage_summary(triage_dir)
    clusters = read_json(File.join(triage_dir, "clusters.json"))
    if clusters.is_a?(Hash) && clusters["clusters"].is_a?(Array)
      list = clusters["clusters"]
      return {
        "cluster_count" => clusters.dig("summary", "cluster_count") || list.size,
        "bucket_count" => clusters.dig("summary", "bucket_count") || list.sum { |c| c["bucket_count"].to_i },
        "total_occurrences" => clusters.dig("summary", "total_occurrences") || list.sum { |c| c["occurrences"].to_i },
        "groups" => clusters.dig("summary", "groups") || {},
        "top_clusters" => list.first(10).map do |c|
          {
            "cluster_id" => c["cluster_id"],
            "group" => c["group"],
            "bucket_count" => c["bucket_count"],
            "occurrences" => c["occurrences"],
            "headline" => c.dig("representative", "headline")
          }
        end
      }
    end

    meta = read_json(File.join(triage_dir, "metadata.json"))
    return nil unless meta.is_a?(Hash) && meta["summary"].is_a?(Hash)

    {
      "cluster_count" => nil,
      "bucket_count" => meta.dig("summary", "bucket_count"),
      "total_occurrences" => meta.dig("summary", "total_occurrences"),
      "by_reason" => meta.dig("summary", "by_reason")
    }
  end

  def copy_dir_contents!(src_dir, dst_dir, skip: [], exclude_abs: [])
    return unless src_dir && File.directory?(src_dir)

    FileUtils.mkdir_p(dst_dir)
    skip_set = skip.map(&:to_s)
    excl = exclude_abs.compact.map { |p| File.expand_path(p) }
    Dir.children(src_dir).sort.each do |entry|
      next if skip_set.include?(entry)

      src = File.join(src_dir, entry)
      src_abs = File.expand_path(src)
      next if excl.any? { |ep| src_abs == ep || ep.start_with?("#{src_abs}/") }

      FileUtils.cp_r(src, File.join(dst_dir, entry))
    end
  end

  def find_coverage_html_artifact(cov_out)
    legacy = File.join(cov_out, "report", "index.html")
    return "report/coverage/report/index.html" if File.file?(legacy)

    pair_html = Dir.glob(File.join(cov_out, "pairs", "*", "report", "index.html")).sort.first
    return nil unless pair_html

    pid = File.basename(File.dirname(File.dirname(pair_html)))
    "report/coverage/pairs/#{pid}/report/index.html"
  end

  def copy_campaign_artifacts!(run_dir:, report_dir:, coverage_dir:, triage_dir:, out_dir: nil)
    artifacts = {}
    rep_out = File.join(run_dir, "report")
    cov_out = File.join(rep_out, "coverage")
    triage_out = File.join(rep_out, "triage")
    excl = [out_dir, run_dir].compact

    if report_dir && File.directory?(report_dir)
      skip = []
      skip << "coverage" if coverage_dir && File.directory?(coverage_dir)
      skip << "triage" if triage_dir && File.directory?(triage_dir)
      copy_dir_contents!(report_dir, rep_out, skip: skip, exclude_abs: excl)
    end

    copy_dir_contents!(coverage_dir, cov_out, exclude_abs: excl) if coverage_dir && File.directory?(coverage_dir)
    copy_dir_contents!(triage_dir, triage_out, exclude_abs: excl) if triage_dir && File.directory?(triage_dir)

    artifacts["report"] = "report/index.html" if File.file?(File.join(rep_out, "index.html"))
    artifacts["sankey"] = "report/sankey.html" if File.file?(File.join(rep_out, "sankey.html"))

    cov_html = find_coverage_html_artifact(cov_out)
    artifacts["coverage_html"] = cov_html if cov_html
    %w[summary.txt coverage.json lcov.info].each do |fn|
      next unless File.file?(File.join(cov_out, fn))

      artifacts["coverage_#{fn.tr('.', '_')}"] = "report/coverage/#{fn}"
    end

    %w[clusters.json metadata.json].each do |fn|
      next unless File.file?(File.join(triage_out, fn))

      artifacts[fn.delete_suffix(".json")] = "report/triage/#{fn}"
    end

    artifacts
  end

  def short_ref(info)
    return "-" unless info.is_a?(Hash)

    sha = info["git_commit"] || info["commit"]
    req = info["requested_ref"]
    ver = info["version"]
    label = if sha && !sha.to_s.empty?
              sha.to_s[0, 10]
            elsif req && !req.to_s.empty?
              req.to_s
            else
              nil
            end
    if ver && !ver.to_s.empty? && label
      "#{ver} (#{label})"
    else
      label || ver || "-"
    end
  end

  def render_index_html(runs)
    rows = if runs.empty?
             '<tr><td colspan="7" class="empty">No published runs yet. Run <code>make publish</code> after a campaign.</td></tr>'
           else
             runs.map do |run|
               id = run["run_id"].to_s
               dir = "runs/#{ERB::Util.url_encode(id)}"
               cov = run.dig("coverage", "regions", "percent") || run.dig("coverage", "lines", "percent")
               cov_label = cov ? format("%.1f%%", cov.to_f) : "-"
               triage = run["triage"] || {}
               tri_label = if triage["cluster_count"]
                             "#{triage['cluster_count']} clusters / #{triage['bucket_count']} buckets"
                           elsif triage["bucket_count"]
                             "#{triage['bucket_count']} buckets"
                           else
                             "-"
                           end
               links = []
               arts = run["artifacts"] || {}
               links << %(<a href="#{dir}/#{arts['report']}">Report</a>) if arts["report"]
               links << %(<a href="#{dir}/#{arts['plots']}">Plots</a>) if arts["plots"] && !arts["report"]
               links << %(<a href="#{dir}/#{arts['sankey']}">Sankey</a>) if arts["sankey"]
               cov_link = arts["coverage_html"] || arts["coverage_summary_txt"]
               links << %(<a href="#{dir}/#{cov_link}">Coverage</a>) if cov_link
               links << %(<a href="#{dir}/#{arts['clusters']}">Clusters JSON</a>) if arts["clusters"]
               links << %(<a href="#{dir}/manifest.json">Manifest</a>)

               prism_a = short_ref(run.dig("versions", "prism_a"))
               prism_b = short_ref(run.dig("versions", "prism_b"))
               ruby_v = short_ref(run.dig("versions", "ruby"))

               <<~HTML
                 <tr>
                   <td><strong>#{h(id)}</strong>#{run['title'] ? "<div class=\"sub\">#{h(run['title'])}</div>" : ""}</td>
                   <td>#{h(run['published_at'])}</td>
                   <td><code>#{h(prism_a)}</code>#{prism_b != "-" ? "<div class=\"sub\">vs <code>#{h(prism_b)}</code></div>" : ""}</td>
                   <td><code>#{h(ruby_v)}</code></td>
                   <td>#{h(cov_label)}</td>
                   <td>#{h(tri_label)}</td>
                   <td class="links">#{links.join(" &middot; ")}</td>
                 </tr>
               HTML
             end.join("\n")
           end

    <<~HTML
      <!doctype html>
      <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>prism-fuzzer Campaign Reports</title>
        <style>
          :root { color-scheme: light dark; --bg: #0f172a; --card: #1e293b; --fg: #e2e8f0; --muted: #94a3b8; --accent: #38bdf8; --border: #334155; }
          @media (prefers-color-scheme: light) {
            :root { --bg: #f8fafc; --card: #ffffff; --fg: #0f172a; --muted: #64748b; --accent: #0284c7; --border: #e2e8f0; }
          }
          body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--fg); margin: 0; padding: 2rem; line-height: 1.5; }
          main { max-width: 1120px; margin: 0 auto; }
          header { margin-bottom: 1.5rem; }
          h1 { margin: 0 0 0.25rem; font-size: 1.75rem; }
          p.lead { margin: 0; color: var(--muted); }
          .card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; overflow-x: auto; box-shadow: 0 2px 10px rgba(0,0,0,0.08); }
          table { width: 100%; border-collapse: collapse; font-size: 0.92rem; }
          th, td { text-align: left; padding: 0.75rem 0.9rem; border-bottom: 1px solid var(--border); vertical-align: top; }
          th { font-weight: 600; color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; }
          tr:last-child td { border-bottom: none; }
          a { color: var(--accent); text-decoration: none; }
          a:hover { text-decoration: underline; }
          code { font-size: 0.85em; }
          .sub { color: var(--muted); font-size: 0.82rem; margin-top: 0.15rem; }
          .links { white-space: nowrap; }
          .empty { text-align: center; color: var(--muted); padding: 2rem; }
        </style>
      </head>
      <body>
        <main>
          <header>
            <h1>prism-fuzzer Campaign Reports</h1>
            <p class="lead">Unified post-campaign reports: AFL++ telemetry, LLVM source coverage, differential triage clusters, and origin Sankey diagrams across Prism &amp; CRuby targets.</p>
          </header>
          <section class="card">
            <table>
              <thead>
                <tr>
                  <th>Run</th>
                  <th>Published (UTC)</th>
                  <th>Prism Target(s)</th>
                  <th>CRuby Oracle</th>
                  <th>Coverage</th>
                  <th>Triage</th>
                  <th>Artifacts</th>
                </tr>
              </thead>
              <tbody>
                #{rows}
              </tbody>
            </table>
          </section>
        </main>
      </body>
      </html>
    HTML
  end

  EMPTY_TREE_SHA = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

  def run_git(repo_dir, *args)
    cmd = ["git", "-C", repo_dir, *args]
    stdout, stderr, st = Open3.capture3(*cmd)
    [stdout, stderr, st]
  end

  def run_git!(repo_dir, *args)
    stdout, stderr, st = run_git(repo_dir, *args)
    unless st.success?
      detail = stderr.to_s.strip
      detail = stdout.to_s.strip if detail.empty?
      raise "git #{args.join(' ')} failed in #{repo_dir}: #{detail}"
    end
    [stdout, stderr]
  end

  def ensure_gh_pages_worktree!(out_dir, fuzz_root:, branch: "gh-pages", remote: "origin")
    out_abs = File.expand_path(out_dir)
    root_abs = File.expand_path(fuzz_root)
    unless File.exist?(File.join(root_abs, ".git"))
      raise "#{root_abs} is not a git repository; cannot manage #{branch} worktree"
    end

    if File.exist?(File.join(out_abs, ".git"))
      cur_out, _, st = run_git(out_abs, "symbolic-ref", "--short", "-q", "HEAD")
      if st.success?
        cur_branch = cur_out.strip
        unless cur_branch == branch
          raise "Worktree at #{out_abs} is on branch '#{cur_branch}', expected '#{branch}'"
        end

        return out_abs
      end

      _, _, head_st = run_git(out_abs, "rev-parse", "--git-dir")
      if head_st.success?
        raise "Worktree at #{out_abs} has detached HEAD; expected branch '#{branch}'"
      end

      raise "#{out_abs}/.git exists but is unusable from this environment"
    end

    if File.exist?(out_abs)
      unless File.directory?(out_abs) && Dir.empty?(out_abs)
        raise "#{out_abs} already exists and is not a #{branch} git worktree (move/remove it or pass --no-gh-pages)"
      end

      Dir.rmdir(out_abs)
    end

    FileUtils.mkdir_p(File.dirname(out_abs))
    run_git(root_abs, "worktree", "prune")

    _, _, has_local = run_git(root_abs, "show-ref", "--verify", "--quiet", "refs/heads/#{branch}")
    if has_local.success?
      run_git!(root_abs, "worktree", "add", out_abs, branch)
      return out_abs
    end

    remotes_out, _, remotes_st = run_git(root_abs, "remote")
    has_remote = remotes_st.success? && remotes_out.lines.map(&:strip).include?(remote)
    if has_remote
      run_git(root_abs, "fetch", "--quiet", remote, branch)
      _, _, has_remote_ref = run_git(root_abs, "show-ref", "--verify", "--quiet", "refs/remotes/#{remote}/#{branch}")
      if has_remote_ref.success?
        run_git!(root_abs, "worktree", "add", "--track", "-b", branch, out_abs, "#{remote}/#{branch}")
        return out_abs
      end
    end

    _, _, orphan_st = run_git(root_abs, "worktree", "add", "--orphan", "-b", branch, out_abs)
    return out_abs if orphan_st.success?

    init_sha, = run_git!(root_abs, "commit-tree", EMPTY_TREE_SHA, "-m", "Initialize #{branch} branch")
    run_git!(root_abs, "update-ref", "refs/heads/#{branch}", init_sha.strip)
    run_git!(root_abs, "worktree", "add", out_abs, branch)
    out_abs
  end

  def commit_and_push_worktree!(out_dir, branch:, remote:, message:, commit:, push:)
    out_abs = File.expand_path(out_dir)
    run_git!(out_abs, "add", "-A")
    status_out, = run_git!(out_abs, "status", "--porcelain")
    if !status_out.strip.empty?
      run_git!(out_abs, "commit", "-m", message)
    else
      _, _, has_head = run_git(out_abs, "rev-parse", "--verify", "HEAD")
      puts "No new changes to commit in #{out_abs} (#{branch})." if has_head.success?
    end

    run_git!(out_abs, "push", "-u", remote, branch) if push
  end

  def run(argv = ARGV)
    opts = {
      fuzz_root: File.expand_path("..", __dir__),
      report_dir: nil,
      triage_dir: nil,
      coverage_dir: nil,
      bin_dir: nil,
      out_dir: nil,
      run_id: nil,
      title: nil,
      init_only: false,
      gh_pages: nil,
      branch: "gh-pages",
      remote: "origin",
      commit: false,
      push: false
    }

    OptionParser.new do |op|
      op.banner = "Usage: publish.rb [options]"
      op.on("--fuzz-root DIR", "Repository root for workspace discovery and gh-pages worktree") { |v| opts[:fuzz_root] = File.expand_path(v) }
      op.on("--report-dir DIR", "Campaign report output directory") { |v| opts[:report_dir] = File.expand_path(v) }
      op.on("--triage-dir DIR", "Triage output directory") { |v| opts[:triage_dir] = File.expand_path(v) }
      op.on("--coverage-dir DIR", "Coverage output directory") { |v| opts[:coverage_dir] = File.expand_path(v) }
      op.on("--bin-dir DIR", "Campaign bin snapshot directory") { |v| opts[:bin_dir] = File.expand_path(v) }
      op.on("--out-dir DIR", "GitHub Pages worktree/output root (default: reports)") { |v| opts[:out_dir] = File.expand_path(v) }
      op.on("--run-id ID", "Run directory identifier under runs/") { |v| opts[:run_id] = v }
      op.on("--title TEXT", "Optional campaign title/note") { |v| opts[:title] = v }
      op.on("--init", "Initialize empty index.html without adding a run") { opts[:init_only] = true }
      op.on("--[no-]gh-pages", "Manage out-dir as a gh-pages git worktree (default: auto for <root>/reports)") { |v| opts[:gh_pages] = v }
      op.on("--branch NAME", "Git branch for Pages worktree (default: gh-pages)") { |v| opts[:branch] = v }
      op.on("--remote NAME", "Git remote for --push (default: origin)") { |v| opts[:remote] = v }
      op.on("--commit", "Stage and commit published files in the Pages worktree") { opts[:commit] = true }
      op.on("--push", "Commit and push the Pages worktree branch to remote") { opts[:commit] = true; opts[:push] = true }
      op.on("-h", "--help", "Show help") { puts op; return 0 }
    end.parse!(argv)

    fuzz_root = opts[:fuzz_root]
    ws = if defined?(PrismFuzzer::Topology)
           t = PrismFuzzer::Topology.discover(start_dir: fuzz_root)
           PrismFuzzer::Topology.workspace_paths(t, fuzz_root: fuzz_root)
         end

    opts[:report_dir] ||= ws ? ws[:report_dir] : File.join(fuzz_root, "tmp", "fuzz", "report")
    opts[:triage_dir] ||= ws ? ws[:triage_dir] : File.join(opts[:report_dir], "triage")
    opts[:coverage_dir] ||= ws ? ws[:coverage_dir] : File.join(opts[:report_dir], "coverage")
    opts[:bin_dir] ||= ws ? ws[:bin_dir] : File.join(fuzz_root, "tmp", "fuzz", "bin")
    out_dir = opts[:out_dir] || (ws ? ws[:reports_dir] : File.join(fuzz_root, "reports"))

    default_reports_dir = File.expand_path(File.join(fuzz_root, "reports"))
    use_gh_pages = if opts[:gh_pages].nil?
                     (File.expand_path(out_dir) == default_reports_dir && File.exist?(File.join(fuzz_root, ".git"))) || opts[:commit] || opts[:push]
                   else
                     opts[:gh_pages]
                   end

    if use_gh_pages
      ensure_gh_pages_worktree!(out_dir, fuzz_root: fuzz_root, branch: opts[:branch], remote: opts[:remote])
    end

    runs_root = File.join(out_dir, "runs")
    FileUtils.mkdir_p(runs_root)
    FileUtils.touch(File.join(out_dir, ".nojekyll"))

    index_path = File.join(runs_root, "index.json")
    existing = read_json(index_path)
    runs = existing.is_a?(Array) ? existing : []
    run_id = nil

    unless opts[:init_only]
      versions = resolve_versions(fuzz_root: fuzz_root, bin_dir: opts[:bin_dir], triage_dir: opts[:triage_dir])
      sha_short = versions.dig("prism_a", "git_commit") || versions.dig("prism_a", "commit")
      default_id = Time.now.utc.strftime("%Y%m%d-%H%M%SZ")
      default_id = "#{default_id}-#{sha_short.to_s[0, 8]}" if sha_short && !sha_short.to_s.empty?
      run_id = (opts[:run_id] && !opts[:run_id].strip.empty?) ? opts[:run_id].strip : default_id
      raise "Invalid run_id '#{run_id}'" if run_id.include?("/") || run_id == "." || run_id == ".."

      run_dir = File.join(runs_root, run_id)
      FileUtils.rm_rf(run_dir)
      FileUtils.mkdir_p(run_dir)

      artifacts = copy_campaign_artifacts!(
        run_dir: run_dir,
        report_dir: opts[:report_dir],
        coverage_dir: opts[:coverage_dir],
        triage_dir: opts[:triage_dir],
        out_dir: out_dir
      )
      manifest = {
        "schema_version" => 1,
        "run_id" => run_id,
        "published_at" => Time.now.utc.iso8601,
        "title" => opts[:title],
        "versions" => versions,
        "coverage" => extract_coverage_summary(opts[:coverage_dir]),
        "triage" => extract_triage_summary(opts[:triage_dir]),
        "artifacts" => artifacts
      }.compact
      File.write(File.join(run_dir, "manifest.json"), "#{JSON.pretty_generate(manifest)}\n")

      runs.reject! { |r| r["run_id"] == run_id }
      runs.unshift(manifest)
      puts "Published run '#{run_id}' to #{run_dir}"
    end

    runs = runs.each_with_index.sort do |(a, ai), (b, bi)|
      cmp = b["published_at"].to_s <=> a["published_at"].to_s
      cmp.zero? ? ai <=> bi : cmp
    end.map(&:first)
    File.write(index_path, "#{JSON.pretty_generate(runs)}\n")
    File.write(File.join(out_dir, "index.html"), render_index_html(runs))

    if opts[:commit] || opts[:push]
      msg = opts[:init_only] ? "Initialize #{opts[:branch]} reports" : "Publish campaign report #{run_id}"
      commit_and_push_worktree!(
        out_dir,
        branch: opts[:branch],
        remote: opts[:remote],
        message: msg,
        commit: opts[:commit],
        push: opts[:push]
      )
    elsif use_gh_pages && !opts[:init_only]
      wt_esc = Shellwords.escape(out_dir)
      puts "Next (on #{opts[:branch]} worktree): git -C #{wt_esc} add -A && git -C #{wt_esc} commit -m #{Shellwords.escape("Publish #{run_id}")} && git -C #{wt_esc} push -u #{opts[:remote]} #{opts[:branch]}"
    end
    0
  end
end

exit(PrismFuzzerPublish.run(ARGV)) if __FILE__ == $PROGRAM_NAME
