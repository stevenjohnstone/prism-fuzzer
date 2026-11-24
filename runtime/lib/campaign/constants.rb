# frozen_string_literal: true

module PrismFuzzer
  module Campaign
    DEFAULT_DOCKER_IMAGE = ENV.fetch("FUZZ_DOCKER_IMAGE", "prism-fuzzer")
    DEFAULT_CCACHE_VOLUME = "prism-fuzzer-ccache"
    DOCKER_FORWARD_ENV_KEYS = %w[
      CAMPAIGN TOPOLOGY TOPOLOGY_FILE
      PRISM_REF PRISM_REPO PRISM_DIR PRISM_PATCHES PRISM_TEMPLATES
      PRISM_B_REF PRISM_B_REPO PRISM_B_DIR PRISM_B_PATCHES PRISM_B_TEMPLATES
      RUBY_REF RUBY_REPO RUBY_DIR TARGETS_OFFLINE
      FUZZ_MAX_INPUT_SIZE FUZZ_MAX_ALLOCATED FUZZ_FLAGS FUZZ_DIFF_BACKTRACE
      JOBS FUZZ_BUILD_JOBS FUZZ_CCACHE CCACHE_DIR
      TRIAGE_THREADS TRIAGE_MINIMIZE TRIAGE_RECOUNT TRIAGE_LIVE_SCRIPTS
    ].freeze

    LIVE_SEEDS_ARCHIVE_SCRIPT = <<~'RB'.freeze
      require "json"
      require "tmpdir"

      dirs = JSON.parse(ARGV[0])
      Dir.mktmpdir("live-seeds.") do |tmp|
        tar_out = File.join(tmp, "out.tar")
        list_file = File.join(tmp, "files.nul")
        dirs.each do |gid, sdir|
          gid_s = gid.to_s
          next if gid_s.empty? || gid_s.include?("/") || gid_s == "." || gid_s == ".."
          next unless Dir.exist?(sdir)

          files = Dir.children(sdir).select do |fn|
            !fn.start_with?(".") && File.file?(File.join(sdir, fn))
          end.sort.first(5000)
          next if files.empty?

          File.binwrite(list_file, "#{files.join("\0")}\0")
          xform_gid = gid_s.gsub(/([\\&|])/, '\\\\\1')
          system(
            "tar", "--atime-preserve=system", "--ignore-failed-read",
            "--warning=no-file-changed", "--warning=no-file-removed",
            "--verbatim-files-from", "-rf", tar_out, "-C", sdir,
            "--transform=s|^|#{xform_gid}/|", "--null", "-T", list_file,
            out: File::NULL, err: File::NULL
          )
        end
        if File.file?(tar_out) && !File.zero?(tar_out)
          $stdout.binmode
          $stdout.write(File.binread(tar_out))
        end
      end
    RB

    class CampaignError < StandardError; end

    @autorun_lock ||= Mutex.new
    @autorun_candidates ||= []
    @autorun_hook_installed = false unless defined?(@autorun_hook_installed)
  end
end
