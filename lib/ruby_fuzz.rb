# frozen_string_literal: true

# Backwards-compatibility entrypoint for campaign scripts using `require "ruby_fuzz"`
# and `RubyFuzz.campaign(...)`.
require_relative "prism_fuzzer"

Object.const_set(:RubyFuzz, PrismFuzzer) unless Object.const_defined?(:RubyFuzz, false)
