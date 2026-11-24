#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "optparse"

# Probes a Prism C header tree (`<prism>/include/**/*.h`) and optional generated
# `node_locations.inc` to emit `prism_fuzz_compat.h` (and optional compiler flags)
# so harnesses compile cleanly across both mainline Prism and historical commits.
module PrismFuzzCompat
  STRUCTURAL_LEGACY_RE = /\APRISM_FUZZ_(?:LEGACY_(?!ENCODING_SET_2ARG\z|FILEPATH_SET_2ARG\z)|NO_)/

  module_function

  def strip_c_comments(raw)
    raw.gsub(%r{//[^\n]*|/\*.*?\*/}m, " ")
  end

  def sub_locations_compatible?(code, subloc_inc)
    return false unless subloc_inc && File.file?(subloc_inc)

    struct_fields = {}
    code.scan(/typedef\s+struct\s*[A-Za-z0-9_]*\s*\{([^}]*)\}\s*(pm_[A-Za-z0-9_]+_t)\s*;/) do |body, sname|
      struct_fields[sname] = body.scan(/\bpm_location_t\s+([A-Za-z_][A-Za-z0-9_]*)\s*;/).flatten
    end

    cur_struct = nil
    File.read(subloc_inc, encoding: "BINARY").each_line do |ln|
      if ln =~ /\bcase\s+(PM_[A-Z0-9_]+):/
        return false unless code.match?(/\b#{Regexp.last_match(1)}\b/)
      elsif ln =~ /\(\s*const\s+(pm_[a-z0-9_]+_t)\s*\*\)/
        cur_struct = Regexp.last_match(1)
        return false unless struct_fields.key?(cur_struct)
      elsif ln =~ /cast->([a-z0-9_]+)/
        return false unless cur_struct && struct_fields[cur_struct]&.include?(Regexp.last_match(1))
      end
    end

    true
  end

  def probe(include_dir, subloc_inc: nil, check_subloc: true)
    hdrs = Dir.glob(File.join(include_dir, "**", "*.h")).sort.map { |p| File.read(p, encoding: "BINARY") }.join("\n")
    code = strip_c_comments(hdrs)

    macros = []
    has_arena_initial_ifndef = code.match?(/#\s*ifndef\s+PM_ARENA_INITIAL_SIZE\b/)

    unless File.file?(File.join(include_dir, "prism", "internal", "buffer.h"))
      macros << "PRISM_FUZZ_NO_INTERNAL_BUFFER"
    end

    if check_subloc && !sub_locations_compatible?(code, subloc_inc)
      macros << "PRISM_FUZZ_NO_SUB_LOCATIONS"
    end

    # Options API
    unless code.match?(/\bpm_options_new\b/)
      macros << "PRISM_FUZZ_LEGACY_OPTIONS_STRUCT"
      macros << "PRISM_FUZZ_OPTIONS_CLEANUP" if code.match?(/\bpm_options_cleanup\b/)
    end
    macros << "PRISM_FUZZ_NO_COMMAND_LINE" unless code.match?(/\bpm_options_command_line_set\b/)
    macros << "PRISM_FUZZ_NO_MAIN_SCRIPT" unless code.match?(/\bpm_options_main_script_set\b/)
    macros << "PRISM_FUZZ_NO_FREEZE" unless code.match?(/\bpm_options_freeze_set\b/)
    macros << "PRISM_FUZZ_NO_PARTIAL_SCRIPT" unless code.match?(/\bpm_options_partial_script_set\b/)
    macros << "PRISM_FUZZ_NO_ATTACH_COMMENTS" unless code.match?(/\bpm_options_attach_comments_set\b/)
    macros << "PRISM_FUZZ_NO_ENCODING_LOCKED" unless code.match?(/\bpm_options_encoding_locked_set\b/)
    macros << "PRISM_FUZZ_NO_VERSION_SET" unless code.match?(/\bpm_options_version_set\b/)
    if (m = code.match(/\bpm_options_encoding_set\s*\(([^)]*)\)/m)) && !m[1].match?(/\bsize_t\b/)
      macros << "PRISM_FUZZ_LEGACY_ENCODING_SET_2ARG"
    end
    if (m = code.match(/\bpm_options_filepath_set\s*\(([^)]*)\)/m)) && !m[1].match?(/\bsize_t\b/)
      macros << "PRISM_FUZZ_LEGACY_FILEPATH_SET_2ARG"
    end
    macros << "PRISM_FUZZ_NO_FROZEN_STRING_LITERAL" unless code.match?(/\bpm_options_frozen_string_literal_set\b/)
    macros << "PRISM_FUZZ_NO_SHEBANG_CALLBACK" unless code.match?(/\bpm_options_shebang_callback_set\b/)
    macros << "PRISM_FUZZ_NO_STACK_BUDGET" unless code.match?(/\bpm_options_stack_budget_set\b/)
    macros << "PRISM_FUZZ_NO_SCOPE_FORWARDING" unless code.match?(/\bpm_options_scope_forwarding_set\b/)
    macros << "PRISM_FUZZ_VOID_SCOPES_INIT" if code.match?(/\bvoid\s+pm_options_scopes_init\b/)
    macros << "PRISM_FUZZ_VOID_SCOPE_INIT" if code.match?(/\bvoid\s+pm_options_scope_init\b/)
    unless code.match?(/\bpm_options_scope_mut\b/)
      macros << (code.match?(/\bpm_options_scope_get_mut\b/) ? "PRISM_FUZZ_SCOPE_GET_MUT" : "PRISM_FUZZ_SCOPE_DIRECT")
    end
    unless code.match?(/\bpm_options_scope_local_mut\b/)
      macros << (code.match?(/\bpm_options_scope_local_get_mut\b/) ? "PRISM_FUZZ_LOCAL_GET_MUT" : "PRISM_FUZZ_LOCAL_DIRECT")
    end

    # String init
    if !code.match?(/\bpm_string_init\b/) && code.match?(/\bpm_string_constant_init\b/)
      macros << "PRISM_FUZZ_LEGACY_STRING_INIT"
    end

    # Arena API
    if !code.match?(/\bpm_arena_t\b/)
      macros << "PRISM_FUZZ_LEGACY_NO_ARENA"
    elsif !code.match?(/\bpm_arena_new\b/)
      macros << "PRISM_FUZZ_LEGACY_ARENA_STRUCT"
      macros << "PRISM_FUZZ_ARENA_CLEANUP" if code.match?(/\bpm_arena_cleanup\b/)
    end

    # Parser, line offsets, locations, iterators, node type name
    has_parser_new = code.match?(/\bpm_parser_new\b/)
    unless has_parser_new
      macros << "PRISM_FUZZ_LEGACY_PARSER_INIT"
      if (m = code.match(/\bpm_parser_init\s*\(([^)]*)\)/m)) && m[1].include?("arena")
        macros << "PRISM_FUZZ_PARSER_INIT_ARENA"
      end
      macros << "PRISM_FUZZ_PARSER_CLEANUP" if code.match?(/\bpm_parser_cleanup\b/)
    end
    macros << "PRISM_FUZZ_LEGACY_PARSER_DATA_LOC" unless code.match?(/\bpm_parser_data_loc\b/)
    unless code.match?(/\bpm_parser_line_offsets\b/)
      macros << (code.match?(/\bpm_newline_list_t\b/) ? "PRISM_FUZZ_PARSER_NEWLINE_LIST" : "PRISM_FUZZ_LEGACY_PARSER_LINE_OFFSETS")
    end
    if (m = code.match(/typedef\s+struct\b[^{]*\{([^}]*)\}\s*pm_location_t\s*;/m)) && m[1].match?(/\*\s*start\b/)
      macros << "PRISM_FUZZ_POINTER_LOCATIONS"
    end
    unless code.match?(/\bpm_magic_comment_key\b/)
      if (m = code.match(/typedef\s+struct\b[^{]*\{([^}]*)\}\s*pm_magic_comment_t\s*;/m)) && m[1].match?(/\bkey_start\b/)
        macros << "PRISM_FUZZ_LEGACY_MAGIC_COMMENT_START"
      else
        macros << "PRISM_FUZZ_LEGACY_MAGIC_COMMENT_FIELDS"
      end
    end
    macros << "PRISM_FUZZ_LEGACY_DIAG_FIELDS" unless code.match?(/\bpm_diagnostic_location\b/)
    macros << "PRISM_FUZZ_NO_DIAGNOSTIC_TYPE" unless code.match?(/\bpm_diagnostic_type\b/)
    macros << "PRISM_FUZZ_LEGACY_COMMENT_FIELDS" unless code.match?(/\bpm_comment_location\b/)
    unless code.match?(/\bpm_parser_errors_first\b/)
      if code.match?(/\bpm_parser_errors_each\b/)
        macros << "PRISM_FUZZ_EACH_ITERATORS"
      elsif code.match?(/\bpm_diagnostics_iter_t\b/)
        macros << "PRISM_FUZZ_ITER_OBJS"
      else
        macros << "PRISM_FUZZ_LIST_ITERATORS"
      end
    end
    if !code.match?(/\bpm_node_type\s*\(/)
      macros << (code.match?(/\bpm_node_type_to_str\s*\(/) ? "PRISM_FUZZ_NODE_TYPE_TO_STR" : "PRISM_FUZZ_NO_NODE_TYPE_NAME")
    end
    macros << "PRISM_FUZZ_NO_VISIT_NODE" unless code.match?(/\bpm_visit_node\b/)
    macros << "PRISM_FUZZ_LEGACY_VISIT_BOOL" unless code.match?(/\bpm_visit_result_t\b/)
    unless code.match?(/\bpm_node_list_t\b/) &&
           code.match?(/\bpm_interpolated_symbol_node_t\b/) &&
           code.match?(/\bpm_interpolated_x_string_node_t\b/) &&
           code.match?(/\bpm_interpolated_regular_expression_node_t\b/) &&
           code.match?(/\bPM_ARRAY_NODE\b/)
      macros << "PRISM_FUZZ_NO_NODE_RELATIONS"
    end

    # Buffer, stream, errors_format, json
    unless code.match?(/\bpm_buffer_new\b/)
      macros << "PRISM_FUZZ_LEGACY_BUFFER_STRUCT"
      macros << "PRISM_FUZZ_BUFFER_CLEANUP" if code.match?(/\bpm_buffer_cleanup\b/)
    end
    macros << "PRISM_FUZZ_NO_BUFFER_CLEAR" unless code.match?(/\bpm_buffer_clear\b/)
    macros << "PRISM_FUZZ_NO_ERRORS_FORMAT" unless code.match?(/\bpm_errors_format\b/)
    unless code.match?(/\bpm_parser_errors_size\b/) &&
           code.match?(/\bPM_ERROR_RECOVERY_NODE\b/) &&
           code.match?(/\bPM_NODE_TYPE_P\b/)
      macros << "PRISM_FUZZ_NO_PARSER_ERRORS_SIZE"
    end
    if !has_parser_new || !File.file?(File.join(include_dir, "prism", "stream.h")) || !code.match?(/\bpm_source_stream_new\b/)
      macros << "PRISM_FUZZ_NO_STREAM"
    end
    macros << "PRISM_FUZZ_NO_JSON" unless code.match?(/\bpm_dump_json\b/)
    if code.match?(/\bbool\s+pattern_matching_newlines\s*;/)
      macros << "PRISM_FUZZ_HAS_PATTERN_MATCHING_NEWLINES"
    end

    macros.uniq!
    {
      macros: macros,
      has_arena_initial_ifndef: has_arena_initial_ifndef,
      has_legacy_shims: macros.any? { |m| m.match?(STRUCTURAL_LEGACY_RE) }
    }
  end

  def render_header(probe_result)
    lines = [
      "/* Generated by harnesses/prism/gen_api_compat.rb -- do not edit. */",
      "#ifndef PRISM_FUZZ_COMPAT_H",
      "#define PRISM_FUZZ_COMPAT_H"
    ]
    probe_result.fetch(:macros).each do |macro|
      lines << ""
      lines << "#ifndef #{macro}"
      lines << "#define #{macro} 1"
      lines << "#endif"
    end
    lines << ""
    lines << "#endif /* PRISM_FUZZ_COMPAT_H */"
    "#{lines.join("\n")}\n"
  end

  def write_if_changed(path, content)
    return false if File.file?(path) && File.read(path, encoding: "BINARY") == content.b

    FileUtils.mkdir_p(File.dirname(path))
    tmp = "#{path}.tmp.#{Process.pid}.#{Thread.current.object_id}"
    File.binwrite(tmp, content)
    File.rename(tmp, path)
    true
  ensure
    FileUtils.rm_f(tmp) if tmp && File.exist?(tmp)
  end

  def generate!(include_dir:, out_path:, subloc_inc: nil, check_subloc: true)
    eff_subloc = subloc_inc || (out_path ? File.join(File.dirname(out_path), "node_locations.inc") : nil)
    res = probe(include_dir, subloc_inc: eff_subloc, check_subloc: check_subloc)
    write_if_changed(out_path, render_header(res)) if out_path
    res
  end

  def cflags_for(probe_result)
    out = []
    out << "-DPM_ARENA_INITIAL_SIZE=0" if probe_result[:has_arena_initial_ifndef]
    probe_result.fetch(:macros).each { |m| out << "-D#{m}" }
    if probe_result[:has_legacy_shims]
      out.push("-Wno-shorten-64-to-32", "-Wno-implicit-function-declaration")
    end
    out
  end

  def run_cli(argv = ARGV)
    include_dir = nil
    subloc_inc = nil
    out_path = nil
    print_cflags = false
    check_subloc = nil

    OptionParser.new do |op|
      op.banner = "Usage: gen_api_compat.rb --include-dir DIR [--subloc-inc FILE] [--output FILE] [--cflags]"
      op.on("--include-dir DIR", "Prism include directory") { |v| include_dir = v }
      op.on("--subloc-inc FILE", "Generated node_locations.inc path") { |v| subloc_inc = v }
      op.on("--no-subloc-check", "Skip node_locations.inc compatibility check") { check_subloc = false }
      op.on("--output FILE", "Write prism_fuzz_compat.h to FILE") { |v| out_path = v }
      op.on("--cflags", "Print compiler flags one per line") { print_cflags = true }
    end.parse!(argv)

    if include_dir.nil? && argv.size >= 1
      include_dir = argv[0]
      out_path ||= argv[1]
    end
    abort "gen_api_compat.rb: --include-dir is required" if include_dir.nil? || !Dir.exist?(include_dir)

    eff_check = check_subloc.nil? ? true : check_subloc
    eff_subloc = subloc_inc || (out_path ? File.join(File.dirname(out_path), "node_locations.inc") : nil)
    res = probe(include_dir, subloc_inc: eff_subloc, check_subloc: eff_check)
    write_if_changed(out_path, render_header(res)) if out_path
    puts cflags_for(res) if print_cflags
    0
  end
end

exit(PrismFuzzCompat.run_cli(ARGV)) if __FILE__ == $PROGRAM_NAME
