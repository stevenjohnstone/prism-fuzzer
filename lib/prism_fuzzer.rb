# frozen_string_literal: true

lib_dir = __dir__
$LOAD_PATH.unshift(lib_dir) unless $LOAD_PATH.include?(lib_dir)

runtime_dir = File.expand_path("../runtime", __dir__)
$LOAD_PATH.unshift(runtime_dir) unless $LOAD_PATH.include?(runtime_dir)

require_relative "../runtime/campaign"
