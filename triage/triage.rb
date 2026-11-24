#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative "lib/config"
require_relative "lib/signature"
require_relative "lib/provenance_resolver"
require_relative "lib/crash_parser"
require_relative "lib/minimizer"
require_relative "lib/coverage_map"
require_relative "lib/digest_enricher"
require_relative "lib/metadata_builder"
require_relative "lib/pipeline"

# Public facade for triage, minimization, provenance, coverage, and metadata
# workflows; loads cleanly without filesystem or pipeline side effects.
module FuzzTriage
  include Config
  include ProvenanceResolver
  include CrashParser
  include Minimizer
  include CoverageMap
  include DigestEnricher
  include MetadataBuilder
  include Pipeline
  extend self

  def run_cli(_argv = ARGV)
    eff_triage_dir = (TESTCASES_DIR == "tmp/fuzz/report/triage") ? workspace_default_triage_dir : TESTCASES_DIR
    run_triage_pipeline(output_dirs: OUTPUT_DIRS, testcases_dir: eff_triage_dir)
  end
end

if __FILE__ == $PROGRAM_NAME
  FuzzTriage.run_cli(ARGV)
end
