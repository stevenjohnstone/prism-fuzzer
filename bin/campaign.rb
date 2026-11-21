#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative "../runtime/campaign"

exit(PrismFuzzer::Campaign.run_cli(ARGV)) if __FILE__ == $PROGRAM_NAME
