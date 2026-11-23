# frozen_string_literal: true

module FuzzClustering
  SCHEMA_VERSION = 1
  DEFAULT_METADATA_PATH = "tmp/fuzz/report/triage/metadata.json"
  DEFAULT_OUTPUT_PATH = "tmp/fuzz/report/triage/clusters.json"

  DEFAULT_THRESHOLD = 0.225
  DEFAULT_REASON_WEIGHT = 0.10
  IDF_SMOOTHING = 5.0
  FRAME_DECAY = 0.5
  FRAME_BLEND_WEIGHT = 0.75
  FRAME_MISMATCH_PENALTY = 0.50
  SETUP_FUNCTION_WEIGHT = 0.0
  ENCODING_HELPER_WEIGHT = 0.25
  RECOVERY_FUNCTION_WEIGHT = 0.10
  DISPATCHER_WEIGHT = 0.5
  FUNCTION_EDGE_CAP = 150.0
  DIFF_CONFLICT_SCALE = 0.35
  DIFF_MATCH_BOOST = 0.15
  TIE_EPSILON = 1e-12

  # Algorithm 2 (differential parse.y divergences) uses dual-parser PCGUARD
  # coverage from fuzz.diff split into Prism and CRuby parse.y edge domains.
  DIFF_DEFAULT_THRESHOLD = 0.25
  DIFF_ENCODING_HELPER_WEIGHT = 0.25
  DIFF_IDENTIFIER_HELPER_WEIGHT = 0.15
  DIFF_LEXER_DISPATCHER_WEIGHT = 0.35
  DIFF_PRISM_DISPATCHER_WEIGHT = 0.50
  DIFF_FUNCTION_EDGE_CAP = 400.0
  DIFF_LOCALS_MISMATCH_PENALTY = 0.65
  DIFF_CRUBY_CLASS_MISMATCH_PENALTY = 0.50
  DIFF_DIAGNOSTIC_MATCH_BOOST = 0.10

  # Generated AST/diagnostic reflection tables and harness wrappers carry no
  # root-cause signal when comparing stack traces or edge vectors.
  VISITOR_FUNCTIONS = %w[
    pm_visit_node
    pm_visit_child_nodes
    pm_node_type
    pm_diagnostic_type
    pm_diagnostic_error_level
    pm_diagnostic_warning_level
  ].freeze

  BOILERPLATE_PREFIXES = %w[
    fuzz_
    check_
    pm_visit_
    pm_fuzz_
  ].freeze

  BOILERPLATE_FUNCTIONS = (%w[
    fuzz_invariant_fail
    fuzz_loc_in_bounds
    fuzz_span_violation_kind
    fuzz_heredoc_span_contains
    fuzz_line_offset_context
    fuzz_line_offset_visit
    fuzz_shebang_cb
    fuzz_stream_fgets
    fuzz_stream_feof
    check_node_location
    fuzz_check_sub_location
    fuzz_check_node_sub_locations
    check_diagnostic_locations
    check_comment_locations
    harness_parse
    harness
    LLVMFuzzerTestOneInput
    fuzz_oracle32_fail
    pm_token_str
    context_human
  ] + VISITOR_FUNCTIONS).freeze

  # Parser option initialization and encoding lookup execute identically for any
  # input with the same 4-byte fuzzer option header before parsing syntax.
  SETUP_FUNCTIONS = %w[
    pm_parser_init
    pm_parser_init_shebang
    pm_encoding_find
    pm_strncasecmp
  ].freeze

  # Encoding character-width helpers run across every lexed token under non-UTF-8
  # fuzz options; downweighting prevents unrelated bugs sharing e.g. ASCII-8BIT
  # from aliasing while keeping residual signal for encoding-specific parser paths.
  ENCODING_HELPER_FUNCTIONS = %w[
    pm_encoding_char_width
    pm_encoding_cesu_8_char_width
    pm_encoding_utf_8_char_width
    pm_encoding_property_char
  ].freeze

  # Generic parser syntax-error recovery/diagnostic helpers appear across
  # unrelated syntax bugs yet can be rare in afl-cmin corpora. Soft downweighting
  # suppresses cross-bug attraction while preserving signal if a bug lives inside them.
  RECOVERY_FUNCTIONS = %w[
    context_recoverable
    pm_error_recovery_node_new
    pm_error_recovery_node_create
    pm_error_recovery_node_create_unexpected
    pm_parse_err_is_fatal
    pm_diagnostic_list_append
  ].freeze

  # Monolithic parser/lexer dispatch loops account for a disproportionate share of
  # uncovered edges across distinct syntax bugs entering or exiting parsing.
  DISPATCHER_FUNCTIONS = %w[
    parser_lex
    parse_expression
    pm_parse
  ].freeze

  # Generic catch-all diagnostics shared by unrelated syntax discrepancies should
  # not boost similarity when comparing diff_parse_y symptoms.
  GENERIC_DIFF_ERRORS = %w[
    expect_eol_after_statement
    unexpected_token_ignore
    unexpected_token_close_context
    regexp_parse_error
    SyntaxError:other
  ].freeze

  # Boilerplate prefixes and functions excluded in Algorithm 2 (differential
  # fuzz.diff coverage): fuzzing runtime, diff comparator harness, Prism/CRuby
  # parser drivers, AST allocators/visitors, and Bison error-line formatters
  # that fire identically across unrelated diff_parse_y divergences.
  DIFF_BOILERPLATE_PREFIXES = %w[
    __sanitizer
    __afl
    asan.
    msan.
    ubsan.
    lsan.
    sancov.
    LLVMFuzzer
    diff_
    pm_arena_
    pm_buffer_
    pm_constant_
    pm_node_list_
    pm_list_
    pm_string_
  ].freeze

  DIFF_BOILERPLATE_FUNCTIONS = %w[
    LLVMFuzzerTestOneInput
    main
    pm_parser_init
    pm_parser_new
    pm_parser_free
    pm_parse
    pm_parse_stream
    pm_serialize_parse
    pm_parse_success_p
    pm_line_offset_list_init
    pm_line_offset_list_free
    pm_line_offset_list_append
    pm_options_new
    pm_options_free
    pm_options_version_set
    pm_options_version_parse
    pm_program_node_new
    pm_statements_node_new
    pm_statements_node_body_append
    pm_void_statement_check
    pm_void_statement_check_unwrap
    flush_block_exits
    pm_locals_order
    pm_parser_scope_push
    pm_diagnostic_type
    pm_diagnostic_list_append
    pm_diagnostic_list_append_format
    pm_parse_err_is_fatal
    pm_parser_errors_size
    pm_parser_errors_first
    pm_visit_child_nodes
    pm_node_destroy
    pm_node_type
    pm_token_type
    pm_token_str
    pm_parser_constant
    pm_parser_local_add
    pm_locals_find
    yycompile0
    rb_parser_compile_string
    rb_parser_parse_string
    rb_ruby_parser_new
    rb_parser_compile
    rb_ruby_parser_set_context
    rb_str_to_parser_string
    init_block_exit
    clear_block_exit
    nextline
    newtok
    nextc0
    pushback
    tokadd_mbchar
    local_push
    local_pop
    local_free
    lvar_defined
    dyna_push
    dyna_pop
    dyna_pop_1
    parser_add_delayed_token
    parser_dispatch_delayed_token
    parser_dispatch_scan_event
    void_stmts
    void_expr
    block_append
    rb_node_scope_new
    rb_node_scope_new2
    ruby_show_error_line
    rb_yytnamerr
    yysyntax_error
    parser_compile_error
    parser_yyerror
    parser_yyerror0
    yydestruct
    yy_symbol_value_print
    yy_symbol_print
    token_info_warn
  ].freeze

  DIFF_IDENTIFIER_FUNCTIONS = %w[
    parse_ident
    dvar_defined
    rb_parser_dvar_defined_ref
    dvar_curr
    local_id
    local_id_ref
  ].freeze

  DIFF_LEXER_DISPATCHERS = %w[
    parser_lex
    parser_yylex
  ].freeze

  DIFF_PRISM_DISPATCHERS = %w[
    parse_expression
    parse_statements
  ].freeze

  # Signal handlers, libc abort wrappers, and CRuby VM entry trampolines carry
  # no root-cause signal when comparing external CRuby parse.y crash traces.
  EXTERNAL_FRAME_BOILERPLATE = %w[
    rb_print_backtrace
    rb_vm_bugreport
    rb_bug_for_fatal_signal
    rb_bug
    sigsegv
    sigbus
    sigill
    sigfpe
    diff_fatal_signal_handler
    __kernel_rt_sigreturn
    __pthread_kill_implementation
    raise
    abort
    invoke_bf
    vm_invoke_builtin_delegate
    vm_exec_core
    rb_vm_exec
    vm_call0_cc
    rb_funcallv_scope
    rb_funcallv
    rb_funcall
    rb_protect
    __libc_start_main
    _start
  ].freeze

  DEFAULT_BUCKET_OPTIONS = {
    "ruby_version" => "4.1",
    "start_line" => 1,
    "start_line_expr" => nil,
    "encoding" => nil,
    "encoding_locked" => false,
    "freeze" => false,
    "partial_script" => false,
    "attach_comments" => false,
    "main_script" => false,
    "stream_mode" => false,
    "frozen_string_literal" => nil,
    "command_line_flags" => [],
    "filepath" => nil,
    "shebang_callback" => false,
    "stack_budget" => "SIZE_MAX",
    "scopes_count" => 0,
    "forwarding_scope" => nil,
    "forwarding_flags" => []
  }.freeze
end
