#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "optparse"
require "tmpdir"

module PrismFuzzer
  # Initial seed corpus generator from Prism fixtures, pm_options_t header
  # variants, and multi-encoding snippets with optional afl-cmin minimization.
  module Corpus
    FUZZ_ROOT = File.expand_path("..", __dir__)

    # 4-byte options header consumed by harness() in harnesses/prism/parse.c:
    #   byte 0 (0x00): default opt_flags (encoding_locked=false, freeze=false, etc.)
    #   byte 1 (0x00): default cmd_flags=0, main_script=false
    #   byte 2 (0x03): version_idx=3 ("4.1"), scopes_count=0, forwarding=0
    #   byte 3 (0x01): start_line=1
    DEFAULT_HEADER = "\x00\x00\x03\x01".b

    OPTION_SEED_VARIANTS = [
      ["opt_ruby_3_3",      "\x00\x00\x00\x01".b, "def f(a = 1, &blk); it + a; end\n"],
      ["opt_ruby_3_4",      "\x00\x00\x01\x01".b, "[1, 2].map { it * 2 }\n"],
      ["opt_ruby_3_5",      "\x00\x00\x02\x01".b, "case x; in [Integer => a, *rest]; a; end\n"],
      ["opt_freeze",        "\x01\x00\x03\x01".b, "x = 'hello'; y = [1, :sym, /re/i]\n"],
      ["opt_partial",       "\x02\x00\x03\x01".b, "return 1 if retry_ok || break_ok\nyield 2\n"],
      ["opt_comments",      "\x04\x00\x03\x01".b, "# frozen_string_literal: true\n=begin\ndoc\n=end\nx = 1 # inline\n"],
      ["opt_enc_locked",    "\x08\x00\x03\x01".b, "# encoding: ASCII-8BIT\nx = \"\\x80\\xff\"\n"],
      ["opt_fsl_false",     "\x10\x00\x03\x01".b, "s = \"mutable \#{1 + 2}\"\n"],
      ["opt_fsl_true",      "\x30\x00\x03\x01".b, "s = \"frozen\" + 'lit'\n"],
      ["opt_cmd_nl_split",  "\x00\x1d\x03\x01".b, "puts $F.first if $. == 1\n"],
      ["opt_cmd_e",         "\x00\x02\x03\x01".b, "if /foo/ .. /bar/; print; end\n"],
      ["opt_cmd_x_main",    "\x04\x60\x03\x01".b, "junk before shebang\n#!ruby\nx = 1\n__END__\ndata\n"],
      ["opt_scope_fwd_all", "\x00\x00\xf7\x01".b, "bar(...); baz(*, **, &)\n"],
      ["opt_scope_depth2",  "\x00\x00\x7b\x01".b, "local_0 = 1; call(*, **)\n"],
      ["opt_neg_line",      "\x04\x00\x03\xff".b, "__LINE__ + 1\ndef m; __LINE__; end\n"],
      ["opt_stream_mode",   "\x40\x04\x03\x01".b, "def stream_fn(x)\n  x + 1\nend\n__END__\ntrailing\n"]
    ].freeze

    module_function

    def load_topology!
      topology_lib = File.join(__dir__, "topology.rb")
      return unless File.file?(topology_lib)

      require topology_lib
    rescue LoadError, SyntaxError
      # Minimal OSS-Fuzz builders may ship distro Ruby (< 3.0) that cannot parse
      # campaign_dsl.rb; corpus generation with explicit/env paths still works.
    end

    def default_fixtures_dir(build_root:, corpus_src_id:, corpus_src_dir:)
      [
        ENV["CORPUS_FIXTURES_DIR"],
        ENV["PRISM_A_DIR"] && File.join(ENV["PRISM_A_DIR"], "test/prism/fixtures"),
        corpus_src_dir && File.join(corpus_src_dir, "test/prism/fixtures"),
        File.join(build_root, "targets", corpus_src_id, "test/prism/fixtures"),
        File.join(build_root, "targets/prism_a/test/prism/fixtures"),
        File.join(FUZZ_ROOT, "test/prism/fixtures")
      ].compact.find { |d| !d.empty? && File.directory?(d) }
    end

    def split_payload_chunks(bytes, max_len)
      return [bytes] if bytes.bytesize <= max_len

      chunks = []
      pos = 0
      total = bytes.bytesize
      while pos < total
        rem = total - pos
        if rem <= max_len
          chunks << bytes.byteslice(pos, rem)
          break
        end

        window = bytes.byteslice(pos, max_len)
        nl = window.rindex("\n".b)
        take = nl && nl >= max_len / 2 ? nl + 1 : max_len
        chunks << bytes.byteslice(pos, take)
        pos += take
      end
      chunks
    end

    def parse_options(argv)
      opts = { minimize: true, fixtures_dir: nil, output_dir: nil }
      remaining = argv.dup
      OptionParser.new do |parser|
        parser.banner = "Usage: corpus.rb [options] [OUTPUT_DIR]"
        parser.on("--fixtures-dir DIR", "Path to Prism test/prism/fixtures") { |v| opts[:fixtures_dir] = v }
        parser.on("--no-minimize", "Copy generated seed files without running afl-cmin") do
          opts[:minimize] = false
        end
        parser.on("-h", "--help", "Show this help message") do
          puts parser
          exit 0
        end
      end.parse!(remaining)
      opts[:output_dir] = remaining[0]
      opts
    end

    def run(argv = ARGV)
      parsed = parse_options(argv)
      load_topology!

      topo = defined?(PrismFuzzer::Topology) ? PrismFuzzer::Topology.discover(start_dir: FUZZ_ROOT) : nil
      ws = (topo && defined?(PrismFuzzer::Topology)) ? PrismFuzzer::Topology.workspace_paths(topo, fuzz_root: FUZZ_ROOT) : nil
      corp_gen = topo&.dig("generators")&.values&.find { |g| g.is_a?(Hash) && g["kind"] == "corpus" }
      corpus_src_id = corp_gen&.dig("source") || topo&.dig("coverage", "source") || "prism_a"
      corpus_src_dir = topo&.dig("sources", corpus_src_id, "path")
      corpus_fuzzer = corp_gen&.dig("fuzzer")
      build_root = ws ? ws[:build_dir] : File.join(FUZZ_ROOT, "tmp", "fuzz", "build")

      minimize = parsed[:minimize]
      fixtures_dir = parsed[:fixtures_dir] || default_fixtures_dir(
        build_root: build_root,
        corpus_src_id: corpus_src_id,
        corpus_src_dir: corpus_src_dir
      )
      output_dir = File.absolute_path(parsed[:output_dir] || (ws ? ws[:corpus_dir] : File.join(FUZZ_ROOT, "tmp/fuzz/corpus")))
      max_input_size = Integer(ENV.fetch("FUZZ_MAX_INPUT_SIZE", "1024"))
      max_payload_size = [max_input_size - 4, 1].max

      default_fuzz_bin = if corpus_fuzzer
                           fspec_bin = topo&.dig("fuzzers", corpus_fuzzer, "binary")
                           fspec_bin ? File.expand_path(fspec_bin, FUZZ_ROOT) : File.join(build_root, File.basename(corpus_fuzzer))
                         else
                           File.join(build_root, "fuzz")
                         end
      FileUtils.mkdir_p(File.dirname(output_dir))
      executable = ENV.fetch("CORPUS_FUZZ_BIN", default_fuzz_bin)
      executable = File.absolute_path(executable) if minimize
      has_fixtures = fixtures_dir && File.directory?(fixtures_dir)
      FileUtils.mkdir_p(output_dir) unless has_fixtures

      puts "Generating corpus in directory: #{output_dir}"
      puts "------------------------------------------------"

      staging_dir = "#{output_dir}.tmp.#{Process.pid}"
      FileUtils.rm_rf(staging_dir)

      begin
        Dir.mktmpdir do |tmpdir|
          count = 0

          if has_fixtures
            Dir.chdir(fixtures_dir) do
              Dir.glob("**/*.txt") do |filename|
                next if File.directory?(filename)
                # Skip spanning_heredoc.txt until ruby/prism#4364 (duplicate InterpolatedSymbolNode
                # part locations across heredoc + %i/%I) is fixed so initial seed replay and afl-cmin pass.
                next if filename == "spanning_heredoc.txt"

                base = filename.gsub(/[^a-zA-Z0-9.-]/, "_")
                chunks = split_payload_chunks(File.binread(filename), max_payload_size)
                chunks.each_with_index do |chunk, idx|
                  suffix = chunks.size > 1 ? ".part#{idx}.rb" : ".rb"
                  target_filename = File.join(tmpdir, "#{base}#{suffix}")
                  File.binwrite(target_filename, DEFAULT_HEADER + chunk)
                  count += 1
                end
                puts "✅ Generated: #{base} (#{chunks.size} chunk#{'s' if chunks.size != 1})"
              end
            end
          end

          OPTION_SEED_VARIANTS.each do |name, hdr, snippet|
            payload = snippet.b.byteslice(0, max_payload_size)
            target_filename = File.join(tmpdir, "#{name}.rb")
            File.binwrite(target_filename, hdr + payload)
            puts "✅ Generated: #{target_filename}"
            count += 1
          end

          if max_payload_size >= 4200
            long_stream = ("x" * 4095) + "\nfoo\n__END__\nbar\n"
            target_filename = File.join(tmpdir, "opt_stream_long_line.rb")
            File.binwrite(target_filename, "\x40\x00\x03\x01".b + long_stream.b.byteslice(0, max_payload_size))
            puts "✅ Generated: #{target_filename}"
            count += 1
          end

          base_content = <<~RUBY
            # This acts as a standard variable assignment
            foo = "Standard: abc"

            # This tests Latin-1/Windows handling
            bar = "Accents: ü"
            baz = "Currency: €"

            # This tests multibyte/wide handling
            qux = "Japanese: あ"

            puts [foo, bar, baz, qux]
          RUBY

          Encoding.list.each do |target_enc|
            next if target_enc.dummy?

            encoded_body = base_content.encode(target_enc, invalid: :replace, undef: :replace, replace: "")
            magic_comment = "# encoding: #{target_enc.name}\n".encode(target_enc)
            full_script = (magic_comment + encoded_body).b.byteslice(0, max_payload_size)

            safe_name = target_enc.name.gsub(/[^a-zA-Z0-9.-]/, "_")
            filename = File.join(tmpdir, "corpus_#{safe_name}.rb")

            File.binwrite(filename, DEFAULT_HEADER + full_script)
            puts "✅ Generated: #{filename}"
            count += 1
          rescue Encoding::UndefinedConversionError
            puts "⚠️  Skipped:   #{target_enc.name} (cannot represent all characters)"
          rescue Encoding::ConverterNotFoundError
            puts "❌ Error:     #{target_enc.name} (converter not found)"
          end

          puts "------------------------------------------------"
          FileUtils.mkdir_p(staging_dir)
          if minimize
            puts "Total corpus size: #{count} files. Now minimizing"
            system("afl-cmin", "-o", staging_dir, "-i", tmpdir, "--", executable, "@@", exception: true)
          else
            puts "Total corpus size: #{count} files. Skipping minimization (--no-minimize)"
            FileUtils.cp_r(File.join(tmpdir, "."), staging_dir)
          end
          FileUtils.rm_rf(output_dir)
          File.rename(staging_dir, output_dir)
        end
      ensure
        FileUtils.rm_rf(staging_dir)
      end
    end
  end
end

if __FILE__ == $PROGRAM_NAME
  PrismFuzzer::Corpus.run(ARGV)
end
