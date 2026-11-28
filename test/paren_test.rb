# frozen_string_literal: true

require_relative "lib/autorun"
require_relative "../bin/paren"
require_relative "../triage/triage"
require_relative "../report/lib/triage_view"

class ParenPrinterTest < Minitest::Test
  def assert_match_both(source, expected)
    py = ParenPrinter::ParseYRenderer.render(source)
    status, pr = ParenPrinter::PrismRenderer.render(source)

    assert_equal :ok, status
    assert_equal expected, py
    assert_equal expected, pr
  end

  def test_operator_precedence
    assert_match_both("1 + 2 * 3", "(1 + (2 * 3))")
    assert_match_both("a && b || c", "((a && b) || c)")
    assert_match_both("a || b && c", "(a || (b && c))")
  end

  def test_calls_and_blocks
    assert_match_both("foo(1, 2)", "(foo(1, 2))")
    assert_match_both("a.b(1) { x + y }", "(a.b(1) { (x + y) })")
    assert_match_both("a&.b(1)", "(a&.b(1))")
  end

  def test_single_line_pattern_match_inside_case
    assert_match_both("case x in 2; when true; end", "(case ((x in 2)); (when true; nil); end)")
  end

  def test_control_flow_and_modifiers
    assert_match_both("alias :a :b unless :c", "(unless :c then (alias :a :b) end)")
    assert_match_both("a = 1 + 2", "(a = (1 + 2))")
  end

  def test_version_summary
    summary = ParenPrinter.version_summary

    assert_includes summary, "parse.y=ruby "
    assert_includes summary, "prism=#{Prism::VERSION}"
  end

  def test_prism_error_reporting_and_recovery
    status, msg = ParenPrinter::PrismRenderer.render("1 +")

    assert_equal :error, status
    assert_match(/SyntaxError:/, msg)

    rec_status, rec_tree = ParenPrinter::PrismRenderer.render("1 +", recovered: true)

    assert_equal :recovered, rec_status
    assert_kind_of String, rec_tree
  end

  def test_digest_enricher_build_paren_diff
    # Identical grouping is omitted
    assert_nil FuzzTriage::DigestEnricher.build_paren_diff(
      y_ok: true, p_ok: true, y_paren: "(1 + 2)", p_paren: "(1 + 2)"
    )

    # Precedence divergence is emitted
    pd = FuzzTriage::DigestEnricher.build_paren_diff(
      y_ok: true, p_ok: true,
      y_paren: "(3 + ((A.A! {}) / []))",
      p_paren: "((3 + (A.A! {})) / [])",
      version: "parse.y=ruby 4.1.0dev | prism=2.1.0"
    )
    assert_equal "(3 + ((A.A! {}) / []))", pd["parse_y"]
    assert_equal "((3 + (A.A! {})) / [])", pd["prism"]
    assert_equal "parse.y=ruby 4.1.0dev | prism=2.1.0", pd["version"]

    # One-sided syntax error includes accepting parser's tree
    one_sided = FuzzTriage::DigestEnricher.build_paren_diff(
      y_ok: false, p_ok: true,
      y_paren: nil, p_paren: "(case ((A.A! {})); (in 2; nil); end)",
      y_err: "SyntaxError: unexpected 'end'"
    )
    assert_equal "SyntaxError: unexpected 'end'", one_sided["parse_y"]
    assert_equal "(case ((A.A! {})); (in 2; nil); end)", one_sided["prism"]
  end

  def test_triage_view_render_paren_diff_html
    assert_equal "", PrismFuzzerReport::TriageView.render_paren_diff_html({})

    html = PrismFuzzerReport::TriageView.render_paren_diff_html(
      {
        "paren_diff" => {
          "parse_y" => "SyntaxError: unexpected '<'",
          "prism" => "(case ((A.A! {})); (in 2; nil); end)",
          "version" => "parse.y=ruby 4.1.0dev | prism=2.1.0"
        }
      },
      compact: true
    )

    assert_includes html, "paren-diff-compact"
    assert_includes html, "paren-err"
    assert_includes html, "SyntaxError: unexpected &#39;&lt;&#39;"
    assert_includes html, "(case ((A.A! {})); (in 2; nil); end)"
    assert_includes html, 'title="parse.y=ruby 4.1.0dev | prism=2.1.0"'
  end
end
