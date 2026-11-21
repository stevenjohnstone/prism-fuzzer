# frozen_string_literal: true

require "json"

module PrismFuzzer
  # Pure-stdlib JSON Schema validator supporting the Draft 2020-12 subset used
  # by prism-fuzzer schemas (`topology.schema.json`, etc.) with path-aware errors.
  module JsonSchema
    class ValidationError < StandardError
      attr_reader :errors

      def initialize(errors)
        @errors = Array(errors)
        preview = @errors.first(5).join("; ")
        preview += "; ... (#{@errors.size} total errors)" if @errors.size > 5
        super(preview)
      end
    end

    module_function

    def validate!(schema, data, root_schema: schema)
      errors = validate(schema, data, root_schema: root_schema)
      raise ValidationError, errors unless errors.empty?

      true
    end

    def validate(schema, data, path: "$", root_schema: schema)
      return ["#{path}: schema rejected value (false)"] if schema == false
      return [] if schema == true
      raise ArgumentError, "Expected schema Hash at #{path}" unless schema.is_a?(Hash)

      errors = []

      if schema.key?("$ref")
        target = resolve_pointer(root_schema, schema["$ref"])
        errors.concat(validate(target, data, path: path, root_schema: root_schema))
      end

      if schema.key?("type")
        allowed = Array(schema["type"])
        unless allowed.any? { |t| json_type_match?(t, data) }
          errors << "#{path}: expected #{allowed.join(' or ')}, got #{json_type_name(data)}"
          return errors
        end
      end

      if schema.key?("const") && !json_equal?(data, schema["const"])
        errors << "#{path}: expected #{schema['const'].inspect}, got #{data.inspect}"
      end

      if schema.key?("enum")
        vals = Array(schema["enum"])
        unless vals.any? { |cand| json_equal?(data, cand) }
          errors << "#{path}: expected one of #{vals.inspect}, got #{data.inspect}"
        end
      end

      validate_string(schema, data, path, errors) if data.is_a?(String)
      validate_number(schema, data, path, errors) if data.is_a?(Numeric)
      validate_array(schema, data, path, root_schema, errors) if data.is_a?(Array)
      validate_object(schema, data, path, root_schema, errors) if data.is_a?(Hash)

      validate_combinators(schema, data, path, root_schema, errors)
      errors
    end

    def resolve_pointer(root_schema, ref)
      ref_s = ref.to_s
      raise ArgumentError, "Only local '#/' JSON Schema $ref supported (got #{ref_s.inspect})" unless ref_s.start_with?("#")

      return root_schema if ref_s == "#" || ref_s == "#/"

      parts = ref_s.delete_prefix("#/").split("/", -1).map { |p| p.gsub("~1", "/").gsub("~0", "~") }
      cur = root_schema
      parts.each do |seg|
        cur = case cur
              when Hash then cur.fetch(seg)
              when Array then cur.fetch(Integer(seg))
              else raise KeyError, "Cannot traverse #{seg.inspect} in #{ref_s}"
              end
      end
      cur
    rescue KeyError, IndexError, ArgumentError => e
      raise ArgumentError, "Unresolvable schema $ref '#{ref_s}': #{e.message}"
    end

    def json_type_match?(type_name, data)
      case type_name.to_s
      when "null" then data.nil?
      when "boolean" then data == true || data == false
      when "object" then data.is_a?(Hash)
      when "array" then data.is_a?(Array)
      when "string" then data.is_a?(String)
      when "integer" then data.is_a?(Integer)
      when "number" then data.is_a?(Integer) || data.is_a?(Float)
      else false
      end
    end

    def json_type_name(data)
      case data
      when nil then "null"
      when true, false then "boolean"
      when Hash then "object"
      when Array then "array"
      when String then "string"
      when Integer then "integer"
      when Float then "number"
      else data.class.name
      end
    end

    def json_equal?(a, b)
      return a.nil? if b.nil?
      return a == b if [true, false].include?(b) || [true, false].include?(a)
      return false if b.is_a?(Integer) && !a.is_a?(Integer)
      return false if a.is_a?(Integer) && b.is_a?(Float)

      a == b
    end

    def compile_pattern(pat)
      s = pat.to_s
      anchored_start = s.start_with?("^")
      anchored_end = s.end_with?("$")
      body = s
      body = "\\A#{body[1..]}" if anchored_start
      body = "#{body[0..-2]}\\z" if anchored_end
      Regexp.new(body)
    end

    def validate_string(schema, data, path, errors)
      if schema.key?("minLength") && data.length < schema["minLength"].to_i
        errors << "#{path}: string length #{data.length} < minLength #{schema['minLength']}"
      end
      if schema.key?("maxLength") && data.length > schema["maxLength"].to_i
        errors << "#{path}: string length #{data.length} > maxLength #{schema['maxLength']}"
      end
      if schema.key?("pattern") && !compile_pattern(schema["pattern"]).match?(data)
        errors << "#{path}: string #{data.inspect} does not match pattern #{schema['pattern']}"
      end
    end

    def validate_number(schema, data, path, errors)
      if schema.key?("minimum") && data < schema["minimum"]
        errors << "#{path}: #{data} < minimum #{schema['minimum']}"
      end
      if schema.key?("maximum") && data > schema["maximum"]
        errors << "#{path}: #{data} > maximum #{schema['maximum']}"
      end
      if schema.key?("exclusiveMinimum") && data <= schema["exclusiveMinimum"]
        errors << "#{path}: #{data} <= exclusiveMinimum #{schema['exclusiveMinimum']}"
      end
      if schema.key?("exclusiveMaximum") && data >= schema["exclusiveMaximum"]
        errors << "#{path}: #{data} >= exclusiveMaximum #{schema['exclusiveMaximum']}"
      end
    end

    def validate_array(schema, data, path, root_schema, errors)
      if schema.key?("minItems") && data.length < schema["minItems"].to_i
        errors << "#{path}: array length #{data.length} < minItems #{schema['minItems']}"
      end
      if schema.key?("maxItems") && data.length > schema["maxItems"].to_i
        errors << "#{path}: array length #{data.length} > maxItems #{schema['maxItems']}"
      end
      if schema["uniqueItems"] && data.uniq.size != data.size
        errors << "#{path}: array items must be unique"
      end
      if schema["items"].is_a?(Hash) || schema["items"] == false
        data.each_with_index do |item, idx|
          errors.concat(validate(schema["items"], item, path: "#{path}[#{idx}]", root_schema: root_schema))
        end
      end
    end

    def validate_object(schema, data, path, root_schema, errors)
      if schema.key?("minProperties") && data.size < schema["minProperties"].to_i
        errors << "#{path}: object has #{data.size} properties < minProperties #{schema['minProperties']}"
      end
      if schema.key?("maxProperties") && data.size > schema["maxProperties"].to_i
        errors << "#{path}: object has #{data.size} properties > maxProperties #{schema['maxProperties']}"
      end
      Array(schema["required"]).each do |req|
        next if data.key?(req.to_s)

        errors << "#{path}: missing required property '#{req}'"
      end

      if schema["propertyNames"]
        data.each_key do |k|
          key_errs = validate(schema["propertyNames"], k.to_s, path: "#{path}[#{k.inspect}]", root_schema: root_schema)
          errors.concat(key_errs)
        end
      end

      props = schema["properties"].is_a?(Hash) ? schema["properties"] : {}
      pat_props = schema["patternProperties"].is_a?(Hash) ? schema["patternProperties"] : {}

      data.each do |k, v|
        ks = k.to_s
        child_path = ks.match?(/\A[A-Za-z_][A-Za-z0-9_]*\z/) ? "#{path}.#{ks}" : "#{path}[#{ks.inspect}]"
        matched = false

        if props.key?(ks)
          matched = true
          errors.concat(validate(props[ks], v, path: child_path, root_schema: root_schema))
        end

        pat_props.each do |pat, sub|
          next unless compile_pattern(pat).match?(ks)

          matched = true
          errors.concat(validate(sub, v, path: child_path, root_schema: root_schema))
        end

        next if matched

        add = schema["additionalProperties"]
        if add == false
          errors << "#{child_path}: additional property '#{ks}' is not allowed"
        elsif add.is_a?(Hash)
          errors.concat(validate(add, v, path: child_path, root_schema: root_schema))
        end
      end
    end

    def deref_branch(sub, root_schema)
      return sub unless sub.is_a?(Hash) && sub.key?("$ref")

      resolve_pointer(root_schema, sub["$ref"])
    end

    # When a tagged union (`oneOf` keyed by `kind` or `shape`) fails, pick the
    # matching variant so errors pinpoint the offending field directly.
    def narrow_one_of_branch(branches, data, root_schema)
      return nil unless data.is_a?(Hash)

      %w[shape kind].each do |disc|
        next unless data.key?(disc)

        val = data[disc]
        matches = branches.select do |b|
          resolved = deref_branch(b, root_schema)
          p = resolved.dig("properties", disc) if resolved.is_a?(Hash)
          p.is_a?(Hash) && p.key?("const") && json_equal?(val, p["const"])
        end
        return matches.first if matches.size == 1
      end
      nil
    end

    def validate_combinators(schema, data, path, root_schema, errors)
      if schema["allOf"].is_a?(Array)
        schema["allOf"].each do |sub|
          errors.concat(validate(sub, data, path: path, root_schema: root_schema))
        end
      end

      if schema["anyOf"].is_a?(Array)
        branch_errs = schema["anyOf"].map { |sub| validate(sub, data, path: path, root_schema: root_schema) }
        if branch_errs.none?(&:empty?)
          errors << "#{path}: value did not match any schema in anyOf (#{branch_errs.map(&:first).join(' | ')})"
        end
      end

      if schema["oneOf"].is_a?(Array)
        branches = schema["oneOf"]
        branch_errs = branches.map { |sub| validate(sub, data, path: path, root_schema: root_schema) }
        passing = branch_errs.count(&:empty?)
        if passing == 0
          narrowed = narrow_one_of_branch(branches, data, root_schema)
          if narrowed
            errors.concat(validate(narrowed, data, path: path, root_schema: root_schema))
          else
            summary = branch_errs.map { |be| be.first }.uniq.first(3).join(" | ")
            errors << "#{path}: value did not match any schema in oneOf (#{summary})"
          end
        elsif passing > 1
          errors << "#{path}: value matched #{passing} schemas in oneOf (expected exactly 1)"
        end
      end

      if schema.key?("not")
        not_errs = validate(schema["not"], data, path: path, root_schema: root_schema)
        errors << "#{path}: value matched forbidden schema in 'not'" if not_errs.empty?
      end

      if schema.key?("if")
        if_errs = validate(schema["if"], data, path: path, root_schema: root_schema)
        if if_errs.empty? && schema.key?("then")
          errors.concat(validate(schema["then"], data, path: path, root_schema: root_schema))
        elsif !if_errs.empty? && schema.key?("else")
          errors.concat(validate(schema["else"], data, path: path, root_schema: root_schema))
        end
      end
    end
  end
end
