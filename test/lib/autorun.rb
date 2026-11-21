# frozen_string_literal: true

require_relative "test_helpers"
PrismFuzzerTest.sanitize_env!

Minitest::Test.include(PrismFuzzerTest::Helpers) unless Minitest::Test < PrismFuzzerTest::Helpers

unless defined?(PrismFuzzerTest::RUNNER_ACTIVE) && PrismFuzzerTest::RUNNER_ACTIVE
  require "minitest/autorun"
end
