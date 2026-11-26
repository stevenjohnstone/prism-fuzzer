#!/usr/bin/env ruby
# frozen_string_literal: true

# Syncs an upstream ruby/prism checkout into a CRuby source tree, mirroring
# ruby/ruby's tool/sync_default_gems.rb prism mapping and namespace fixup,
# while staying compatible with Ubuntu's bootstrap Ruby (>= 3.0).

require "fileutils"
require "find"

module PrismRubySync
  MAPPINGS = [
    ["ext/prism", "prism"],
    ["lib/prism.rb", "lib/ruby/prism.rb"],
    ["lib/prism", "lib/ruby/prism"],
    ["src", "prism"],
    ["include/prism", "prism"],
    ["include/prism.h", "prism/prism.h"],
    ["config.yml", "prism/config.yml"],
    ["templates", "prism/templates"],
  ].freeze

  EXCLUDED_PREFIXES = [
    "prism/templates/javascript/",
    "prism/templates/java/",
    "prism/templates/rbi/",
    "prism/templates/sig/",
  ].freeze

  EXCLUDED_FILES = [
    "prism/extconf.rb",
  ].freeze

  module_function

  def excluded?(rel)
    return true if EXCLUDED_FILES.include?(rel)
    return true if rel.start_with?("prism/srcs.mk")
    EXCLUDED_PREFIXES.any? { |p| rel.start_with?(p) }
  end

  def run(prism_dir, ruby_dir)
    prism_dir = File.expand_path(prism_dir)
    ruby_dir  = File.expand_path(ruby_dir)

    # Clear destination directories/files before copying, preserving CRuby-owned files.
    %w[lib/ruby/prism.rb lib/ruby/prism prism/templates].each do |rel|
      FileUtils.rm_rf(File.join(ruby_dir, rel))
    end

    # Remove old prism C/H files in /opt/ruby/prism except CRuby-owned build files.
    Dir.glob(File.join(ruby_dir, "prism", "**", "*")).sort.reverse_each do |path|
      next if File.directory?(path)
      rel = path.sub("#{ruby_dir}/", "")
      next if rel.start_with?("prism/srcs.mk") || rel == "prism/extconf.rb"
      FileUtils.rm_f(path)
    end

    MAPPINGS.each do |src_rel, dst_rel|
      src_root = File.join(prism_dir, src_rel)
      next unless File.exist?(src_root)

      if File.file?(src_root)
        next if excluded?(dst_rel)
        dst_path = File.join(ruby_dir, dst_rel)
        FileUtils.mkdir_p(File.dirname(dst_path))
        FileUtils.cp(src_root, dst_path)
      else
        Find.find(src_root) do |path|
          next if File.directory?(path)
          sub = path.sub("#{src_root}/", "")
          rel = "#{dst_rel}/#{sub}"
          next if excluded?(rel)
          dst_path = File.join(ruby_dir, rel)
          FileUtils.mkdir_p(File.dirname(dst_path))
          FileUtils.cp(path, dst_path)
        end
      end
    end

    # Mirror prism_do_fixup from ruby/ruby's tool/sync_default_gems.rb:
    # rewrite Prism -> Ruby::Prism for the interpreter's built-in library.
    fixup_files = Dir.glob([
      File.join(ruby_dir, "lib/ruby/prism.rb"),
      File.join(ruby_dir, "lib/ruby/prism/**/*.rb"),
      File.join(ruby_dir, "prism/templates/**/*.erb"),
      File.join(ruby_dir, "prism/templates/template.rb"),
      File.join(ruby_dir, "prism/*.c"),
    ])

    fixup_files.each do |file|
      src = File.binread(file)
      rewritten =
        if file.end_with?(".c")
          src.gsub(
            'rb_cPrism = rb_define_module("Prism")',
            'VALUE mRuby = rb_define_module("Ruby"); rb_cPrism = rb_define_module_under(mRuby, "Prism")'
          )
        else
          s = src.gsub(/\b(require|autoload\s+:\w+,)(\s*)(["'])prism(?=["'\/])/) { "#{$1}#{$2}#{$3}ruby/prism" }
          s.gsub(/(?<![\w:])(::)?Prism\b/) { "#{$1}Ruby::Prism" }
        end
      File.binwrite(file, rewritten) if rewritten != src
    end
  end
end

if __FILE__ == $PROGRAM_NAME
  abort "Usage: #{$PROGRAM_NAME} <prism_dir> <ruby_dir>" unless ARGV.length == 2
  PrismRubySync.run(ARGV[0], ARGV[1])
end
