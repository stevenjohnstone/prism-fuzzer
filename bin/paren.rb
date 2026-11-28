#!/usr/bin/env ruby
# frozen_string_literal: true

# Renders Ruby expressions with explicit (often redundant) parentheses using
# both CRuby's parse.y (RubyVM::AbstractSyntaxTree) and Prism, making operator
# precedence, block ownership, and grouping differences immediately obvious.
#
# Usage:
#   bin/paren.rb -e '3 + A::A!{} / []'
#   bin/paren.rb --docker -e 'case A::A!{} in 2; end'
#   bin/paren.rb path/to/file.rb
#   echo '1 + 2 * 3' | bin/paren.rb

require "optparse"
require "prism"

module ParenPrinter
  def self.version_summary
    ruby_ver = RUBY_DESCRIPTION[/\Aruby\s+(\S+)/, 1] || RUBY_VERSION
    rev = defined?(RUBY_REVISION) && RUBY_REVISION ? RUBY_REVISION[0, 10] : nil
    ruby_label = rev ? "ruby #{ruby_ver} (#{rev})" : "ruby #{ruby_ver}"
    "parse.y=#{ruby_label} | prism=#{Prism::VERSION}"
  end

  BINARY_OPS = %i[
    + - * / % ** << >> & | ^ == != === <=> < <= > >= =~ !~
  ].freeze

  UNARY_OPS = {
    :+@ => "+",
    :-@ => "-",
    :~ => "~",
    :! => "!"
  }.freeze

  # ---------------------------------------------------------------------------
  # parse.y (RubyVM::AbstractSyntaxTree) renderer
  # ---------------------------------------------------------------------------
  class ParseYRenderer
    def self.render(source)
      ast = RubyVM::AbstractSyntaxTree.parse(source)
      new.visit(ast)
    end

    def visit(node)
      return "nil" if node.nil?
      return node.inspect unless node.is_a?(RubyVM::AbstractSyntaxTree::Node)

      case node.type
      when :SCOPE
        _tbl, _args, body = node.children
        visit(body)
      when :BLOCK
        stmts = node.children.map { |c| visit(c) }
        stmts.size == 1 ? stmts.first : "(#{stmts.join("; ")})"
      when :BEGIN
        body = node.children[0]
        body.nil? ? "nil" : "(begin #{visit(body)} end)"
      when :LIT, :INTEGER, :FLOAT, :RATIONAL, :IMAGINARY, :SYM
        node.children[0].inspect
      when :STR, :XSTR
        node.type == :XSTR ? "`#{node.children[0]}`" : node.children[0].inspect
      when :DSTR, :DXSTR, :DSYM, :DREGX, :ONCE
        render_interpolated(node)
      when :NIL
        "nil"
      when :TRUE
        "true"
      when :FALSE
        "false"
      when :SELF
        "self"
      when :LVAR, :DVAR, :IVAR, :CVAR, :GVAR, :CONST
        node.children[0].to_s
      when :NTH_REF
        "$#{node.children[0]}"
      when :BACK_REF
        "$#{node.children[0]}"
      when :COLON2
        recv, name = node.children
        "#{visit(recv)}::#{name}"
      when :COLON3
        "::#{node.children[0]}"
      when :ZLIST, :ZARRAY
        "[]"
      when :LIST, :ARRAY
        elems = extract_list(node).map { |e| visit(e) }
        "[#{elems.join(", ")}]"
      when :HASH
        pairs = extract_list(node.children[0])
        items = []
        i = 0
        while i < pairs.size
          k = pairs[i]
          v = pairs[i + 1]
          if k.nil?
            items << "**#{visit(v)}"
          else
            items << "#{visit(k)} => #{visit(v)}"
          end
          i += 2
        end
        "{#{items.join(", ")}}"
      when :SPLAT
        "(*#{visit(node.children[0])})"
      when :OPCALL, :CALL, :QCALL
        render_call(node)
      when :FCALL
        name, args = node.children
        render_fcall(name, args)
      when :VCALL
        node.children[0].to_s
      when :ITER
        call_node, block_node = node.children
        render_iter(call_node, block_node)
      when :AND
        "(#{visit(node.children[0])} && #{visit(node.children[1])})"
      when :OR
        "(#{visit(node.children[0])} || #{visit(node.children[1])})"
      when :NOT
        "(!#{visit(node.children[0])})"
      when :DOT2
        "(#{visit(node.children[0])}..#{visit(node.children[1])})"
      when :DOT3
        "(#{visit(node.children[0])}...#{visit(node.children[1])})"
      when :IF
        cond, then_b, else_b = node.children
        parts = ["if #{visit(cond)} then #{visit(then_b)}"]
        parts << "else #{visit(else_b)}" if else_b
        "(#{parts.join(" ")} end)"
      when :UNLESS
        cond, then_b, else_b = node.children
        parts = ["unless #{visit(cond)} then #{visit(then_b)}"]
        parts << "else #{visit(else_b)}" if else_b
        "(#{parts.join(" ")} end)"
      when :WHILE
        cond, body, pre = node.children
        pre ? "(while #{visit(cond)} do #{visit(body)} end)" : "(begin #{visit(body)} end while #{visit(cond)})"
      when :UNTIL
        cond, body, pre = node.children
        pre ? "(until #{visit(cond)} do #{visit(body)} end)" : "(begin #{visit(body)} end until #{visit(cond)})"
      when :CASE, :CASE2, :CASE3
        render_case(node)
      when :IN
        # Single-line pattern match (`expr in pat`) vs case-in branch
        render_in(node)
      when :LASGN, :DASGN, :IASGN, :CVASGN, :GASGN
        name, val = node.children
        "(#{name} = #{visit(val)})"
      when :CDECL
        if node.children.size == 2
          name, val = node.children
          "(#{name.is_a?(Symbol) ? name : visit(name)} = #{visit(val)})"
        else
          recv, name, val = node.children
          "(#{visit(recv)}::#{name} = #{visit(val)})"
        end
      when :OP_ASGN_OR
        lhs, rhs = node.children
        "(#{visit(lhs)} ||= #{visit(rhs)})"
      when :OP_ASGN_AND
        lhs, rhs = node.children
        "(#{visit(lhs)} &&= #{visit(rhs)})"
      when :OP_ASGN2
        recv, _q, attr, op, val = node.children
        "(#{visit(recv)}.#{attr} #{op}= #{visit(val)})"
      when :OP_ASGN1
        recv, op, idx, val = node.children
        "(#{visit(recv)}[#{extract_args(idx).join(", ")}] #{op}= #{visit(val)})"
      when :ATTRASGN
        recv, name, args = node.children
        arg_strs = extract_args(args)
        if name == :[]=
          val = arg_strs.pop
          "(#{visit(recv)}[#{arg_strs.join(", ")}] = #{val})"
        else
          "(#{visit(recv)}.#{name.to_s.delete_suffix("=")} = #{arg_strs.join(", ")})"
        end
      when :MASGN
        val, lhs, rhs = node.children
        "(#{visit(lhs)} = #{visit(val || rhs)})"
      when :RESCUE
        body, resbody, else_b = node.children
        parts = ["begin #{visit(body)}"]
        parts << visit(resbody) if resbody
        parts << "else #{visit(else_b)}" if else_b
        "(#{parts.join(" ")} end)"
      when :RESBODY
        excs, body, nxt = node.children
        exc_str = excs ? " #{extract_args(excs).join(", ")}" : ""
        out = "rescue#{exc_str}; #{visit(body)}"
        out = "#{out} #{visit(nxt)}" if nxt
        out
      when :ENSURE
        body, ens = node.children
        "(begin #{visit(body)} ensure #{visit(ens)} end)"
      when :DEFN
        name, body = node.children
        "(def #{name} #{visit(body)} end)"
      when :DEFS
        recv, name, body = node.children
        "(def (#{visit(recv)}).#{name} #{visit(body)} end)"
      when :CLASS
        cpath, sup, body = node.children
        sup_str = sup ? " < #{visit(sup)}" : ""
        "(class #{visit(cpath)}#{sup_str}; #{visit(body)} end)"
      when :MODULE
        cpath, body = node.children
        "(module #{visit(cpath)}; #{visit(body)} end)"
      when :SCLASS
        recv, body = node.children
        "(class << (#{visit(recv)}); #{visit(body)} end)"
      when :LAMBDA
        "(-> #{visit(node.children[0])})"
      when :RETURN, :BREAK, :NEXT
        kw = node.type.to_s.downcase
        val = node.children[0]
        val ? "(#{kw} #{visit(val)})" : "(#{kw})"
      when :REDO, :RETRY
        "(#{node.type.to_s.downcase})"
      when :YIELD
        args = node.children[0]
        args ? "(yield(#{extract_args(args).join(", ")}))" : "(yield)"
      when :ZSUPER
        "(super)"
      when :SUPER
        "(super(#{extract_args(node.children[0]).join(", ")}))"
      when :ALIAS
        "(alias #{visit(node.children[0])} #{visit(node.children[1])})"
      when :VALIAS
        "(alias #{node.children[0]} #{node.children[1]})"
      when :UNDEF
        "(undef #{node.children.map { |c| visit(c) }.join(", ")})"
      when :DEFINED
        "(defined?(#{visit(node.children[0])}))"
      when :MATCH2, :MATCH3
        "(#{visit(node.children[0])} =~ #{visit(node.children[1])})"
      when :FOR
        iter_node, body = node.children
        "(for _ in #{visit(iter_node)} do #{visit(body)} end)"
      else
        "(#{node.type} #{node.children.compact.map { |c| visit(c) }.join(" ")})"
      end
    end

    private

    def render_call(node, block_str = nil)
      recv, name, args = node.children
      op_str = node.type == :QCALL ? "&." : "."
      arg_strs = extract_args(args)

      if block_str.nil? && node.type == :OPCALL && BINARY_OPS.include?(name) && arg_strs.size == 1
        return "(#{visit(recv)} #{name} #{arg_strs.first})"
      end

      if block_str.nil? && node.type == :OPCALL && UNARY_OPS.key?(name) && arg_strs.empty?
        return "(#{UNARY_OPS[name]}#{visit(recv)})"
      end

      if name == :[] && node.type != :QCALL
        base = "#{visit(recv)}[#{arg_strs.join(", ")}]"
        return block_str ? "(#{base} #{block_str})" : "(#{base})"
      end

      call_head =
        if recv.nil?
          name.to_s
        elsif name == :call && op_str == "&."
          "#{visit(recv)}&.call"
        else
          "#{visit(recv)}#{op_str}#{name}"
        end

      args_part = arg_strs.empty? && block_str ? "" : "(#{arg_strs.join(", ")})"
      blk_part = block_str ? " #{block_str}" : ""
      "(#{call_head}#{args_part}#{blk_part})"
    end

    def render_fcall(name, args, block_str = nil)
      arg_strs = extract_args(args)
      args_part = arg_strs.empty? && block_str ? "" : "(#{arg_strs.join(", ")})"
      blk_part = block_str ? " #{block_str}" : ""
      "(#{name}#{args_part}#{blk_part})"
    end

    def render_iter(call_node, block_node)
      body = block_node.is_a?(RubyVM::AbstractSyntaxTree::Node) && block_node.type == :SCOPE ? block_node.children[2] : block_node
      body_str = body ? visit(body) : "nil"
      blk_str = body_str == "nil" ? "{}" : "{ #{body_str} }"

      case call_node.type
      when :CALL, :QCALL, :OPCALL
        render_call(call_node, blk_str)
      when :FCALL
        render_fcall(call_node.children[0], call_node.children[1], blk_str)
      when :VCALL
        "(#{call_node.children[0]} #{blk_str})"
      when :ZSUPER
        "(super #{blk_str})"
      when :SUPER
        "(super(#{extract_args(call_node.children[0]).join(", ")}) #{blk_str})"
      else
        "(#{visit(call_node)} #{blk_str})"
      end
    end

    def render_case(node)
      if node.type == :CASE2
        branches = collect_branches(node.children[1])
        "(case; #{branches.join("; ")}; end)"
      elsif single_line_in?(node)
        pat = node.children[1].children[0]
        "(#{visit(node.children[0])} in #{visit(pat)})"
      else
        pred = visit(node.children[0])
        branches = collect_branches(node.children[1])
        "(case (#{pred}); #{branches.join("; ")}; end)"
      end
    end

    def single_line_in?(node)
      return false unless node.type == :CASE3

      in_node = node.children[1]
      return false unless in_node.is_a?(RubyVM::AbstractSyntaxTree::Node) && in_node.type == :IN

      _pat, body, nxt = in_node.children
      body.is_a?(RubyVM::AbstractSyntaxTree::Node) && body.type == :TRUE &&
        nxt.is_a?(RubyVM::AbstractSyntaxTree::Node) && nxt.type == :FALSE
    end

    def collect_branches(node)
      return [] if node.nil?

      case node.type
      when :WHEN
        conds, body, nxt = node.children
        cur = "(when #{extract_args(conds).join(", ")}; #{visit(body)})"
        [cur] + collect_branches(nxt)
      when :IN
        pat, body, nxt = node.children
        cur = "(in #{visit(pat)}; #{visit(body)})"
        [cur] + collect_branches(nxt)
      else
        ["(else #{visit(node)})"]
      end
    end

    def render_in(node)
      # Standalone `expr in pat` is represented in parse.y as CASE3(expr, IN(pat, true, false))
      pat, body, _nxt = node.children
      "(in #{visit(pat)}; #{visit(body)})"
    end

    def render_interpolated(node)
      parts = node.children.compact.map { |c| c.is_a?(String) ? c.inspect : visit(c) }
      "(#{node.type.to_s.downcase} #{parts.join(" + ")})"
    end

    def extract_list(node)
      return [] if node.nil?
      return [node] unless node.is_a?(RubyVM::AbstractSyntaxTree::Node)

      case node.type
      when :LIST, :ARRAY
        node.children.compact
      when :ZLIST, :ZARRAY
        []
      else
        [node]
      end
    end

    def extract_args(node)
      return [] if node.nil?

      case node.type
      when :LIST, :ARRAY
        node.children.compact.map { |c| visit(c) }
      when :ARGSCAT
        extract_args(node.children[0]) + ["(*#{visit(node.children[1])})"]
      when :ARGSPUSH
        extract_args(node.children[0]) + [visit(node.children[1])]
      when :SPLAT
        ["(*#{visit(node.children[0])})"]
      else
        [visit(node)]
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Prism renderer (mirrors ParseYRenderer's canonical parenthesization)
  # ---------------------------------------------------------------------------
  class PrismRenderer
    def self.render(source, recovered: false)
      result = Prism.parse(source)
      if !result.success? && !recovered
        msgs = result.errors.map { |e| "#{e.message} (line #{e.location.start_line}:#{e.location.start_column})" }
        return [:error, "SyntaxError: #{msgs.join("; ")}"]
      end
      status = result.success? ? :ok : :recovered
      [status, new.visit(result.value)]
    end

    def visit(node)
      return "nil" if node.nil?

      case node
      when Prism::ProgramNode
        visit(node.statements)
      when Prism::StatementsNode
        stmts = node.body.map { |s| visit(s) }
        return "nil" if stmts.empty?
        stmts.size == 1 ? stmts.first : "(#{stmts.join("; ")})"
      when Prism::ParenthesesNode
        node.body ? "(#{visit(node.body)})" : "()"
      when Prism::IntegerNode, Prism::FloatNode, Prism::RationalNode, Prism::ImaginaryNode
        node.slice
      when Prism::StringNode
        node.unescaped.inspect
      when Prism::SymbolNode
        node.unescaped.to_sym.inspect
      when Prism::RegularExpressionNode
        node.slice
      when Prism::NilNode
        "nil"
      when Prism::TrueNode
        "true"
      when Prism::FalseNode
        "false"
      when Prism::SelfNode
        "self"
      when Prism::LocalVariableReadNode, Prism::InstanceVariableReadNode,
           Prism::ClassVariableReadNode, Prism::GlobalVariableReadNode,
           Prism::ConstantReadNode
        node.name.to_s
      when Prism::NumberedReferenceReadNode
        "$#{node.number}"
      when Prism::BackReferenceReadNode
        node.slice
      when Prism::ConstantPathNode
        node.parent ? "#{visit(node.parent)}::#{node.name}" : "::#{node.name}"
      when Prism::ArrayNode
        "[#{node.elements.map { |e| visit(e) }.join(", ")}]"
      when Prism::HashNode, Prism::KeywordHashNode
        items = node.elements.map { |e| visit(e) }
        "{#{items.join(", ")}}"
      when Prism::AssocNode
        "#{visit(node.key)} => #{visit(node.value)}"
      when Prism::AssocSplatNode
        node.value ? "**#{visit(node.value)}" : "**"
      when Prism::SplatNode
        "(*#{visit(node.expression)})"
      when Prism::CallNode
        render_call(node)
      when Prism::AndNode
        "(#{visit(node.left)} && #{visit(node.right)})"
      when Prism::OrNode
        "(#{visit(node.left)} || #{visit(node.right)})"
      when Prism::RangeNode
        op = node.exclude_end? ? "..." : ".."
        "(#{visit(node.left)}#{op}#{visit(node.right)})"
      when Prism::IfNode
        parts = ["if #{visit(node.predicate)} then #{visit(node.statements)}"]
        parts << "else #{visit(node.subsequent)}" if node.subsequent
        "(#{parts.join(" ")} end)"
      when Prism::UnlessNode
        parts = ["unless #{visit(node.predicate)} then #{visit(node.statements)}"]
        parts << "else #{visit(node.else_clause)}" if node.else_clause
        "(#{parts.join(" ")} end)"
      when Prism::ElseNode
        visit(node.statements)
      when Prism::WhileNode
        if node.begin_modifier?
          "(begin #{visit(node.statements)} end while #{visit(node.predicate)})"
        else
          "(while #{visit(node.predicate)} do #{visit(node.statements)} end)"
        end
      when Prism::UntilNode
        if node.begin_modifier?
          "(begin #{visit(node.statements)} end until #{visit(node.predicate)})"
        else
          "(until #{visit(node.predicate)} do #{visit(node.statements)} end)"
        end
      when Prism::CaseNode
        pred = node.predicate ? " (#{visit(node.predicate)})" : ""
        branches = node.conditions.map { |c| visit(c) }
        branches << "(else #{visit(node.else_clause)})" if node.else_clause
        "(case#{pred}; #{branches.join("; ")}; end)"
      when Prism::CaseMatchNode
        pred = node.predicate ? " (#{visit(node.predicate)})" : ""
        branches = node.conditions.map { |c| visit(c) }
        branches << "(else #{visit(node.else_clause)})" if node.else_clause
        "(case#{pred}; #{branches.join("; ")}; end)"
      when Prism::WhenNode
        conds = node.conditions.map { |c| visit(c) }.join(", ")
        "(when #{conds}; #{visit(node.statements)})"
      when Prism::InNode
        "(in #{visit(node.pattern)}; #{visit(node.statements)})"
      when Prism::MatchPredicateNode
        "(#{visit(node.value)} in #{visit(node.pattern)})"
      when Prism::MatchRequiredNode
        "(#{visit(node.value)} => #{visit(node.pattern)})"
      when Prism::LocalVariableWriteNode, Prism::InstanceVariableWriteNode,
           Prism::ClassVariableWriteNode, Prism::GlobalVariableWriteNode,
           Prism::ConstantWriteNode
        "(#{node.name} = #{visit(node.value)})"
      when Prism::ConstantPathWriteNode
        "(#{visit(node.target)} = #{visit(node.value)})"
      when Prism::LocalVariableOrWriteNode, Prism::InstanceVariableOrWriteNode,
           Prism::ClassVariableOrWriteNode, Prism::GlobalVariableOrWriteNode,
           Prism::ConstantOrWriteNode
        "(#{node.name} ||= #{visit(node.value)})"
      when Prism::LocalVariableAndWriteNode, Prism::InstanceVariableAndWriteNode,
           Prism::ClassVariableAndWriteNode, Prism::GlobalVariableAndWriteNode,
           Prism::ConstantAndWriteNode
        "(#{node.name} &&= #{visit(node.value)})"
      when Prism::LocalVariableOperatorWriteNode, Prism::InstanceVariableOperatorWriteNode,
           Prism::ClassVariableOperatorWriteNode, Prism::GlobalVariableOperatorWriteNode,
           Prism::ConstantOperatorWriteNode
        "(#{node.name} #{node.binary_operator}= #{visit(node.value)})"
      when Prism::MultiWriteNode
        lhs = node.lefts.map { |l| visit(l) }.join(", ")
        "((#{lhs}) = #{visit(node.value)})"
      when Prism::LocalVariableTargetNode, Prism::InstanceVariableTargetNode,
           Prism::ClassVariableTargetNode, Prism::GlobalVariableTargetNode,
           Prism::ConstantTargetNode
        node.name.to_s
      when Prism::BeginNode
        parts = ["begin #{visit(node.statements)}"]
        parts << visit(node.rescue_clause) if node.rescue_clause
        parts << "else #{visit(node.else_clause)}" if node.else_clause
        parts << "ensure #{visit(node.ensure_clause)}" if node.ensure_clause
        "(#{parts.join(" ")} end)"
      when Prism::RescueNode
        excs = node.exceptions.empty? ? "" : " #{node.exceptions.map { |e| visit(e) }.join(", ")}"
        out = "rescue#{excs}; #{visit(node.statements)}"
        out = "#{out} #{visit(node.subsequent)}" if node.subsequent
        out
      when Prism::RescueModifierNode
        "(#{visit(node.expression)} rescue #{visit(node.rescue_expression)})"
      when Prism::EnsureNode
        visit(node.statements)
      when Prism::DefNode
        recv = node.receiver ? "(#{visit(node.receiver)})." : ""
        "(def #{recv}#{node.name} #{visit(node.body)} end)"
      when Prism::ClassNode
        sup = node.superclass ? " < #{visit(node.superclass)}" : ""
        "(class #{visit(node.constant_path)}#{sup}; #{visit(node.body)} end)"
      when Prism::ModuleNode
        "(module #{visit(node.constant_path)}; #{visit(node.body)} end)"
      when Prism::SingletonClassNode
        "(class << (#{visit(node.expression)}); #{visit(node.body)} end)"
      when Prism::LambdaNode
        "(-> { #{visit(node.body)} })"
      when Prism::ReturnNode
        node.arguments ? "(return #{visit(node.arguments)})" : "(return)"
      when Prism::BreakNode
        node.arguments ? "(break #{visit(node.arguments)})" : "(break)"
      when Prism::NextNode
        node.arguments ? "(next #{visit(node.arguments)})" : "(next)"
      when Prism::RedoNode
        "(redo)"
      when Prism::RetryNode
        "(retry)"
      when Prism::YieldNode
        node.arguments ? "(yield(#{visit(node.arguments)}))" : "(yield)"
      when Prism::SuperNode
        args = node.arguments ? "(#{visit(node.arguments)})" : "()"
        blk = node.block ? " #{render_block(node.block)}" : ""
        "(super#{args}#{blk})"
      when Prism::ForwardingSuperNode
        blk = node.block ? " #{render_block(node.block)}" : ""
        "(super#{blk})"
      when Prism::ArgumentsNode
        node.arguments.map { |a| visit(a) }.join(", ")
      when Prism::AliasMethodNode
        "(alias #{visit(node.new_name)} #{visit(node.old_name)})"
      when Prism::AliasGlobalVariableNode
        "(alias #{visit(node.new_name)} #{visit(node.old_name)})"
      when Prism::UndefNode
        "(undef #{node.names.map { |n| visit(n) }.join(", ")})"
      when Prism::DefinedNode
        "(defined?(#{visit(node.value)}))"
      when Prism::MatchWriteNode
        visit(node.call)
      when Prism::ForNode
        "(for #{visit(node.index)} in #{visit(node.collection)} do #{visit(node.statements)} end)"
      when Prism::InterpolatedStringNode, Prism::InterpolatedSymbolNode,
           Prism::InterpolatedRegularExpressionNode, Prism::InterpolatedXStringNode
        parts = node.parts.map { |p| visit(p) }
        "(#{node.class.name.split("::").last.delete_suffix("Node").downcase} #{parts.join(" + ")})"
      when Prism::EmbeddedStatementsNode
        "\#{#{visit(node.statements)}}"
      else
        "(#{node.class.name.split("::").last} #{node.slice.inspect})"
      end
    end

    private

    def render_block(block)
      case block
      when Prism::BlockNode
        block.body ? "{ #{visit(block.body)} }" : "{}"
      when Prism::BlockArgumentNode
        "&#{visit(block.expression)}"
      else
        visit(block)
      end
    end

    def render_call(node)
      recv = node.receiver
      name = node.name
      args = node.arguments ? node.arguments.arguments.map { |a| visit(a) } : []
      blk = node.block
      blk_str = blk.is_a?(Prism::BlockNode) ? render_block(blk) : nil
      args << render_block(blk) if blk.is_a?(Prism::BlockArgumentNode)

      if recv.nil? && args.empty? && blk_str.nil? && node.opening_loc.nil?
        return name.to_s
      end

      if recv && blk_str.nil? && node.call_operator_loc.nil? && BINARY_OPS.include?(name) && args.size == 1
        return "(#{visit(recv)} #{name} #{args.first})"
      end

      if recv && blk_str.nil? && node.call_operator_loc.nil? && UNARY_OPS.key?(name) && args.empty?
        return "(#{UNARY_OPS[name]}#{visit(recv)})"
      end

      if recv && name == :[] && !node.safe_navigation?
        base = "#{visit(recv)}[#{args.join(", ")}]"
        return blk_str ? "(#{base} #{blk_str})" : "(#{base})"
      end

      if recv && name == :[]= && !node.safe_navigation?
        val = args.pop
        return "(#{visit(recv)}[#{args.join(", ")}] = #{val})"
      end

      op_str =
        if node.safe_navigation?
          "&."
        elsif recv
          "."
        else
          ""
        end

      call_head = recv ? "#{visit(recv)}#{op_str}#{name}" : name.to_s
      args_part = args.empty? && blk_str ? "" : "(#{args.join(", ")})"
      blk_part = blk_str ? " #{blk_str}" : ""
      "(#{call_head}#{args_part}#{blk_part})"
    end
  end
end

# -----------------------------------------------------------------------------
# CLI entry point
# -----------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  options = {
    parser: "both",
    docker: nil,
    recovered: false,
    only_diff: false,
    expr: nil
  }

  OptionParser.new do |opts|
    opts.banner = "Usage: #{$PROGRAM_NAME} [options] [file]"
    opts.on("-e CODE", "Ruby expression/snippet to parenthesize") { |v| options[:expr] = v }
    opts.on("--parser=MODE", %w[both parse.y prism], "Which parser(s) to run (default: both)") { |v| options[:parser] = v }
    opts.on("--docker [IMAGE]", "Run inside Docker image (default: prism-fuzzer:ruby-latest)") do |v|
      options[:docker] = v || "prism-fuzzer:ruby-latest"
    end
    opts.on("--recovered", "Also show Prism's error-recovered tree on syntax errors") { options[:recovered] = true }
    opts.on("--only-diff", "Exit with status 1 if parse.y and prism differ") { options[:only_diff] = true }
  end.parse!

  source =
    if options[:expr]
      options[:expr]
    elsif !ARGV.empty?
      File.read(ARGV.first)
    else
      $stdin.read
    end

  if options[:docker]
    # Re-exec this exact script inside the target Docker image via stdin
    forwarded = ["--parser=#{options[:parser]}"]
    forwarded << "--recovered" if options[:recovered]
    forwarded << "--only-diff" if options[:only_diff]
    cmd = ["docker", "run", "--rm", "-i", options[:docker], "ruby", "-e", File.read(__FILE__), "--", *forwarded, "-e", source]
    exec(*cmd)
  end

  parse_y_out = nil
  prism_out = nil

  if %w[both parse.y].include?(options[:parser])
    parse_y_out =
      begin
        [:ok, ParenPrinter::ParseYRenderer.render(source)]
      rescue SyntaxError => e
        [:error, "SyntaxError: #{e.message.lines.first&.strip}"]
      end
  end

  if %w[both prism].include?(options[:parser])
    prism_out = ParenPrinter::PrismRenderer.render(source, recovered: options[:recovered])
  end

  puts "version: #{ParenPrinter.version_summary}"
  puts "source : #{source.inspect}"
  puts "parse.y: #{parse_y_out[1]}" if parse_y_out
  if prism_out
    tag = prism_out[0] == :recovered ? "prism* " : "prism  "
    puts "#{tag}: #{prism_out[1]}"
  end

  if parse_y_out && prism_out
    same = (parse_y_out == prism_out)
    puts "status : #{same ? "MATCH" : "DIFF"}"
    exit(1) if options[:only_diff] && !same
  end
end
