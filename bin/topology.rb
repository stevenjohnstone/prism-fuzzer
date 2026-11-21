#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative "../runtime/lib/topology/cli"

exit(PrismFuzzer::TopologyCLI.run(ARGV)) if __FILE__ == $PROGRAM_NAME
