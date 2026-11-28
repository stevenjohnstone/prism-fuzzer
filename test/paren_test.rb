# frozen_string_literal: true

require_relative "lib/autorun"
require_relative "../bin/paren"

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

  def test_prism_error_reporting_and_recovery
    status, msg = ParenPrinter::PrismRenderer.render("1 +")

    assert_equal :error, status
    assert_match(/SyntaxError:/, msg)

    rec_status, rec_tree = ParenPrinter::PrismRenderer.render("1 +", recovered: true)

    assert_equal :recovered, rec_status
    assert_kind_of String, rec_tree
  end
end
