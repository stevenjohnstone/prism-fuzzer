# frozen_string_literal: true

require "fileutils"
require "json"
require_relative "test_helpers"

module PrismFuzzerTest
  module Fixtures
    module_function

    # Creates a 3-commit synthetic upstream Prism git repository matching the
    # patch context expected by patches/prism/*:
    #   v1: unpatched upstream (all 3 repo patches apply cleanly)
    #   v2: v1 with 0002-accel-swar-backend-define.patch already upstream
    #   v3: v2 with a third source change in src/integer.c
    # Returns { repo:, v1:, v2:, v3: }.
    def build_synthetic_upstream_prism(dir, root_dir: PrismFuzzerTest::ROOT_DIR)
      FileUtils.mkdir_p([
        File.join(dir, "include/prism/internal"),
        File.join(dir, "include/prism/compiler"),
        File.join(dir, "src"),
        File.join(dir, "templates/src"),
        File.join(dir, "templates/include/prism")
      ])

      git = lambda do |*args|
        out, err, st = PrismFuzzerTest::Helpers.instance_method(:run_cmd).bind_call(Object.new, "git", "-C", dir, *args)
        raise "git #{args.join(' ')} failed: #{err}\n#{out}" unless st.success?

        out
      end

      _out, err, st = PrismFuzzerTest::Helpers.instance_method(:run_cmd).bind_call(Object.new, "git", "init", "-q", dir)
      raise "git init #{dir} failed: #{err}" unless st.success?

      git.call("config", "user.email", "fuzz-test@example.com")
      git.call("config", "user.name", "Fuzz Test")
      git.call("config", "commit.gpgsign", "false")
      git.call("config", "tag.gpgsign", "false")

      File.write(File.join(dir, "config.yml"), <<~YAML)
        nodes:
          - name: ProgramNode
            fields:
              - name: statements
                type: node
      YAML

      File.write(File.join(dir, "templates/template.rb"), <<~'RB')
        require "fileutils"
        FileUtils.mkdir_p("src")
        FileUtils.mkdir_p("include/prism")
        File.write("src/node.c", "/* generated */\nint pm_stub_node(void) { return 0; }\n")
        File.write("include/prism/ast.h", "#ifndef PRISM_AST_H\n#define PRISM_AST_H\ntypedef struct { int type; } pm_node_t;\n#endif\n")
      RB

      File.write(File.join(dir, "include/prism/version.h"), "#define PRISM_VERSION \"1.9.0\"\n")
      File.write(File.join(dir, "include/prism.h"), <<~C)
        #ifndef PRISM_H
        #define PRISM_H
        #include "prism/version.h"
        #include "prism/ast.h"
        #include "prism/internal/arena.h"
        #include "prism/compiler/accel.h"
        #endif
      C

      File.write(File.join(dir, "include/prism/internal/arena.h"), <<~C)
        #ifndef PRISM_INTERNAL_ARENA_H
        #define PRISM_INTERNAL_ARENA_H

        #include "prism/compiler/align.h"
        #include "prism/compiler/branch.h"
        #include "prism/compiler/flex_array.h"
        #include "prism/compiler/force_inline.h"
        #include "prism/compiler/inline.h"
        #include "prism/compiler/noreturn.h"

        #include "prism/arena.h"

        #include <stddef.h>
        #include <stdint.h>
        #include <string.h>

        /*
         * A single block of memory in the arena. Blocks are linked via prev pointers so
         * they can be freed by walking the chain.
         */
        typedef struct pm_arena_block {
            /* The previous block in the chain (for freeing). */
            struct pm_arena_block *prev;

            /* The total usable bytes in data[]. */
            size_t capacity;

            /* The number of bytes consumed so far. */
            size_t used;

            /* The block's data. */
            char data[PM_FLEX_ARRAY_LENGTH];
        } pm_arena_block_t;

        /*
         * end
         */
        #endif
      C

      File.write(File.join(dir, "include/prism/compiler/accel.h"), <<~C)
        #ifndef PRISM_COMPILER_ACCEL_H
        #define PRISM_COMPILER_ACCEL_H

        /*
         * Accelerated string scanning strategy selection.
         * Lines 1-14 header padding for patch context alignment.
         *
         *
         *
         *
         *
         *
         *
         *
         * each strategy relies only on instructions that the architecture baseline
         * guarantees: NEON is mandatory on AArch64 and SSE2 is mandatory on x86-64.
         */
        #if (defined(__aarch64__) && defined(__ARM_NEON)) || (defined(_MSC_VER) && defined(_M_ARM64))
        #   define PRISM_HAS_NEON
        #elif (defined(__x86_64__) && defined(__SSE2__)) || (defined(_MSC_VER) && defined(_M_X64))
        #   define PRISM_HAS_SSE2
        #endif

        #endif
      C

      integer_lines = ["#include \"prism.h\"", ""]
      (3..26).each { |n| integer_lines << "/* line #{n} */" }
      integer_lines.concat([
        " * once it gets really long because we start to see the impact of an O(n^1.58)",
        " * vs an O(n^2) algorithm.",
        " */",
        "#define PM_INTEGER_DIVIDE_THRESHOLD 224",
        "",
        "/**",
        " * When printing integers of many words, we switch to a divide-and-conquer",
        " */",
        "int pm_integer_stub(void) { return PM_INTEGER_DIVIDE_THRESHOLD; }",
        ""
      ])
      File.write(File.join(dir, "src/integer.c"), integer_lines.join("\n"))

      git.call("add", "-A")
      git.call("commit", "-q", "-m", "Upstream v1 (unpatched)")
      v1 = git.call("rev-parse", "HEAD").strip

      git.call("apply", File.join(root_dir, "patches/prism/0002-accel-swar-backend-define.patch"))
      git.call("add", "-A")
      git.call("commit", "-q", "-m", "Upstream v2 (with PRISM_ACCEL_SWAR)")
      v2 = git.call("rev-parse", "HEAD").strip

      File.write(File.join(dir, "src/integer.c"), File.read(File.join(dir, "src/integer.c")) + "\n/* v3 */\n")
      git.call("add", "-A")
      git.call("commit", "-q", "-m", "Upstream v3")
      v3 = git.call("rev-parse", "HEAD").strip

      { repo: dir, v1: v1, v2: v2, v3: v3 }
    end

    def build_good_ruby_dir(dir)
      FileUtils.mkdir_p(dir)
      File.write(File.join(dir, "parse.c"), "/* ruby parse.c stub */\n")
      File.write(File.join(dir, "libruby-static.a"), "!<arch>\n")
      dir
    end
  end
end
