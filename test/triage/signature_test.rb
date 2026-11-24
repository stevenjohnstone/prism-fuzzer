# frozen_string_literal: true

require_relative "../lib/autorun"
require_relative "../../triage/lib/signature"

require "open3"
require "shellwords"

# Migrated from stage_signature ([1/8] and [2/8]) of test/test_triage.sh.
# Verifies triage/signature.sh normalization and SIGPIPE safety, and
# triage/halfempty.sh payload minimization, 4-byte option header preservation,
# crash-signature drift protection, INVARIANT symmetry breaking, silent SIGSEGV,
# non-crashing rejection, and <=4-byte handling.
class TriageSignatureTest < Minitest::Test
  SYNTH_TARGET_C = <<~'C'
    #define _GNU_SOURCE
    #include <signal.h>
    #include <stdint.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>

    __attribute__((noreturn, noinline))
    static void fail_invariant_at_shared_site(const char *diag_type, size_t start, size_t parsed_size) {
        fprintf(
            stderr,
            "INVARIANT[diagnostic]: list=error type=%s kind=end_oob [detail: level=0 start=%zu length=4 parsed_size=%zu]\n"
            "    #0 0x1000 in fail_invariant_at_shared_site /prism/harnesses/prism/parse.c:90:5\n"
            "    #1 0x1010 in harness_parse /prism/harnesses/prism/parse.c:550:13\n",
            diag_type,
            start,
            parsed_size
        );
        fflush(stderr);
        abort();
    }

    int main(int argc, char **argv) {
        if (argc < 2) return 0;
        FILE *f = fopen(argv[1], "rb");
        if (!f) return 0;
        if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 0; }
        long n = ftell(f);
        if (n < 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return 0; }
        uint8_t *buf = malloc((size_t)(n > 0 ? n : 1));
        if (!buf) { fclose(f); return 0; }
        if (n > 0 && fread(buf, 1, (size_t)n, f) != (size_t)n) {
            free(buf);
            fclose(f);
            return 0;
        }
        fclose(f);

        if (n < 4) {
            free(buf);
            return 0;
        }

        const uint8_t *body = buf + 4;
        size_t body_len = (size_t)(n - 4);

        if ((buf[0] & 0x08) && body_len == 0) {
            fprintf(stderr, "fuzz: src/prism.c:11: empty_body: Assertion `0' failed.\n");
            free(buf);
            abort();
        }
        if ((buf[0] & 0x02) && body_len >= 4 && memmem(body, body_len, "BOOM", 4) != NULL) {
            fprintf(stderr, "fuzz: src/prism.c:42: bug_a: Assertion `0' failed.\n");
            free(buf);
            abort();
        }
        if (body_len >= 9 && memmem(body, body_len, "ALT_CRASH", 9) != NULL) {
            fprintf(stderr, "fuzz: src/prism.c:84: bug_b: Assertion `0' failed.\n");
            free(buf);
            abort();
        }
        if ((buf[0] & 0x04) && body_len >= 4 && memmem(body, body_len, "SEGV", 4) != NULL) {
            free(buf);
            raise(SIGSEGV);
        }
        if (buf[0] & 0x10) {
            const uint8_t *target = body_len >= 10 ? (const uint8_t *)memmem(body, body_len, "INV_TARGET", 10) : NULL;
            if (target != NULL) {
                size_t off = (size_t)(target - body);
                free(buf);
                fail_invariant_at_shared_site("heredoc_term", off, body_len);
            }
            const uint8_t *decoy = body_len >= 9 ? (const uint8_t *)memmem(body, body_len, "INV_DECOY", 9) : NULL;
            if (decoy != NULL) {
                size_t off = (size_t)(decoy - body);
                free(buf);
                fail_invariant_at_shared_site("escape_invalid_meta", off, body_len);
            }
        }

        free(buf);
        return 0;
    }
  C

  UBSAN_DRIFT_MOCK_C = <<~'C'
    #include <stdint.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>

    int main(int argc, char **argv) {
        if (argc < 2) return 0;
        FILE *f = fopen(argv[1], "rb");
        if (!f) return 0;
        uint8_t buf[512];
        size_t n = fread(buf, 1, sizeof(buf), f);
        fclose(f);
        if (n < 4) return 0;

        const char *marker = getenv("DRIFT_MARKER");
        if (marker && marker[0] != '\0') {
            FILE *mf = fopen(marker, "r");
            if (mf) {
                fclose(mf);
                fprintf(stderr, "fuzz: src/prism.c:99: drifted: Assertion `0' failed.\n");
                abort();
            }
            mf = fopen(marker, "w");
            if (mf) {
                fputs("1", mf);
                fclose(mf);
            }
            fprintf(stderr, "fuzz: src/prism.c:42: orig: Assertion `0' failed.\n");
            abort();
        }

        if ((buf[0] & 0x01) && n >= 8 && memcmp(buf + n - 4, "BOOM", 4) == 0) {
            volatile int x = 0x7fffffff;
            volatile int y = x + 1;
            (void)y;
        }
        return 0;
    }
  C

  def test_signature_sh_normalization_and_sigpipe_safety
    with_tmpdir("triage-sig-") do |workdir|
      # UBSan: distinct integer operands at same source location match; distinct lines diverge.
      s1 = run_signature(
        "src/prism.c:10:5: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int32_t'\n#0 0x1234 in foo\n",
        siglines: 3
      )
      s2 = run_signature(
        "src/prism.c:10:5: runtime error: signed integer overflow: 2147483600 + 99 cannot be represented in type 'int32_t'\n#0 0x9999 in foo\n",
        siglines: 3
      )
      s3 = run_signature(
        "src/prism.c:20:5: runtime error: signed integer overflow: 2147483600 + 99 cannot be represented in type 'int32_t'\n#0 0x9999 in foo\n",
        siglines: 3
      )
      assert_equal s1, s2, "UBSAN signatures differed for distinct integer operands at same location"
      refute_equal s1, s3, "UBSAN signatures collided across distinct source lines"

      # Additional UBSan operand normalizations: index N out of bounds, negative shift exponent, member call on null.
      idx1 = run_signature(
        "src/prism.c:12:9: runtime error: index 4 out of bounds for type 'int[8]'\n#0 0x1111 in foo\n",
        siglines: 3
      )
      idx2 = run_signature(
        "src/prism.c:12:9: runtime error: index 99 out of bounds for type 'int[12]'\n#0 0x2222 in foo\n",
        siglines: 3
      )
      idx3 = run_signature(
        "src/prism.c:13:9: runtime error: index 99 out of bounds for type 'int[12]'\n#0 0x2222 in foo\n",
        siglines: 3
      )
      assert_equal idx1, idx2, "UBSAN index out-of-bounds signatures differed across distinct indices"
      refute_equal idx1, idx3, "UBSAN index out-of-bounds signatures collided across distinct lines"

      neg1 = run_signature("src/prism.c:15:3: runtime error: shift exponent -1 is negative\n#0 0x1111 in foo\n", siglines: 3)
      neg2 = run_signature("src/prism.c:15:3: runtime error: shift exponent -42 is negative\n#0 0x2222 in foo\n", siglines: 3)
      neg3 = run_signature("src/prism.c:16:3: runtime error: shift exponent -42 is negative\n#0 0x2222 in foo\n", siglines: 3)
      assert_equal neg1, neg2, "UBSAN negative shift exponent signatures differed across negative operands"
      refute_equal neg1, neg3, "UBSAN negative shift exponent signatures collided across distinct lines"

      mc1 = run_signature("src/prism.c:30:7: runtime error: member call on null pointer of type 'struct Foo'\n#0 0xaaaa in bar\n", siglines: 3)
      mc2 = run_signature("src/prism.c:30:7: runtime error: member call on null pointer of type 'struct Foo'\n#0 0xbbbb in bar\n", siglines: 3)
      mc3 = run_signature("src/prism.c:31:7: runtime error: member call on null pointer of type 'struct Foo'\n#0 0xbbbb in bar\n", siglines: 3)
      assert_equal mc1, mc2, "UBSAN member call on null signatures differed across addresses"
      refute_equal mc1, mc3, "UBSAN member call on null signatures collided across distinct lines"

      # LeakSanitizer byte/object totals normalization.
      l1 = run_signature("Direct leak of 48 byte(s) in 3 object(s) allocated from:\n#0 0x11 in bar\n", siglines: 5)
      l2 = run_signature("Direct leak of 16 byte(s) in 1 object(s) allocated from:\n#0 0x22 in bar\n", siglines: 5)
      assert_equal l1, l2, "LeakSanitizer signatures differed across byte/object counts"

      ls1 = run_signature("SUMMARY: AddressSanitizer: 48 byte(s) leaked in 3 object(s)\n", siglines: 5)
      ls2 = run_signature("SUMMARY: AddressSanitizer: 256 byte(s) leaked in 12 object(s)\n", siglines: 5)
      assert_equal ls1, ls2, "LeakSanitizer summary totals failed to normalize"

      # ASan READ/WRITE size, address, thread, PID, and byte allocations normalization.
      a1 = run_signature("READ of size 4 at 0x602000000014 thread T0\n", siglines: 5)
      a2 = run_signature("READ of size 19 at 0x602000009998 thread T2\n", siglines: 5)
      assert_equal a1, a2, "ASAN READ size/address/thread normalization failed"

      ab1 = run_signature(
        "==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000014 at pc 0x1111 bp 0x2222 sp 0x3333\n" \
        "READ of size 4 at 0x602000000014 thread T0\n" \
        "0x602000000014 is located 0 bytes inside of 16-byte region [0x602000000010,0x602000000020)\n",
        siglines: 5
      )
      ab2 = run_signature(
        "==9999==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000009998 at pc 0xaaaa bp 0xbbbb sp 0xcccc\n" \
        "READ of size 19 at 0x602000009998 thread T2\n" \
        "0x602000009998 is located 12 bytes inside of 64-byte region [0x602000009980,0x6020000099c0)\n",
        siglines: 5
      )
      ab_write = run_signature(
        "==9999==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000009998 at pc 0xaaaa bp 0xbbbb sp 0xcccc\n" \
        "WRITE of size 19 at 0x602000009998 thread T2\n" \
        "0x602000009998 is located 12 bytes inside of 64-byte region [0x602000009980,0x6020000099c0)\n",
        siglines: 5
      )
      assert_equal ab1, ab2, "ASan byte allocation and PID normalization failed"
      refute_equal ab1, ab_write, "ASan READ and WRITE collided"

      # Binary name/path prefix normalization (including header/suffix variants like 00000301).
      b1 = run_signature("fuzz: src/prism.c:12: bar: Assertion `0' failed.\n", siglines: 5)
      b2 = run_signature("./build/fuzz.ijon: src/prism.c:12: bar: Assertion `0' failed.\n", siglines: 5)
      b3 = run_signature("/prism/build/fuzz.native: src/prism.c:12: bar: Assertion `0' failed.\n", siglines: 5)
      b4 = run_signature("/prism/tmp/fuzz/bin/fuzz.00000301: src/prism.c:12: bar: Assertion `0' failed.\n", siglines: 5)
      assert_equal b1, b2, "binary name normalization failed for ./build/fuzz.ijon"
      assert_equal b1, b3, "binary name normalization failed for /prism/build/fuzz.native"
      assert_equal b1, b4, "binary name normalization failed for /prism/tmp/fuzz/bin/fuzz.00000301"

      # INVARIANT[diagnostic] precedence and [detail: ...] stripping.
      i1 = run_signature(
        "INVARIANT[diagnostic]: list=error type=escape_invalid_meta kind=end_oob [detail: level=0 start=1 length=3 parsed_size=3]\n" \
        "AddressSanitizer:DEADLYSIGNAL\n#0 0x1111 in abort\n",
        siglines: 15
      )
      i2 = run_signature(
        "Reading 487 bytes from /tmp/c\n" \
        "INVARIANT[diagnostic]: list=error type=escape_invalid_meta kind=end_oob [detail: level=0 start=481 length=3 parsed_size=483]\n",
        siglines: 15
      )
      i3 = run_signature(
        "INVARIANT[diagnostic]: list=error type=regexp_term kind=end_oob [detail: level=0 start=1 length=3 parsed_size=3]\n" \
        "AddressSanitizer:DEADLYSIGNAL\n#0 0x1111 in abort\n",
        siglines: 15
      )
      i4 = run_signature(
        "INVARIANT[diagnostic]: list=error type=escape_invalid_meta kind=length_underflow [detail: level=0 start=1 length=4294967295 parsed_size=3]\n" \
        "AddressSanitizer:DEADLYSIGNAL\n#0 0x1111 in abort\n",
        siglines: 15
      )
      i_late = run_signature(
        ("preamble noise\n" * 10) +
        "INVARIANT[diagnostic]: list=error type=escape_invalid_meta kind=end_oob [detail: level=9 start=99 length=1 parsed_size=99]\n",
        siglines: 3
      )
      assert_equal i1, i2, "INVARIANT[diagnostic] signature varied across offsets or sanitizer frames"
      assert_equal i1, i_late, "INVARIANT[diagnostic] did not take precedence beyond SIGLINES"
      refute_equal i1, i3, "INVARIANT[diagnostic] collided across distinct diagnostic types"
      refute_equal i1, i4, "INVARIANT[diagnostic] collided across distinct violation kinds"

      # INVARIANT[node_location].
      n1 = run_signature(
        "INVARIANT[node_location]: type=PM_REGULAR_EXPRESSION_NODE kind=end_oob [detail: parent=PM_LOCAL_VARIABLE_WRITE_NODE start=8 length=4 parsed_size=11]\n" \
        "#0 0x1 in check_node_location\n#1 0x2 in check_node_location\n#2 0x3 in check_node_location\n",
        siglines: 15
      )
      n2 = run_signature(
        "INVARIANT[node_location]: type=PM_REGULAR_EXPRESSION_NODE kind=end_oob [detail: parent=PM_STATEMENTS_NODE start=0 length=4 parsed_size=3]\n" \
        "#0 0x9 in check_node_location\n",
        siglines: 15
      )
      n3 = run_signature(
        "INVARIANT[node_location]: type=PM_CALL_NODE kind=end_oob [detail: parent=PM_STATEMENTS_NODE start=0 length=4 parsed_size=3]\n" \
        "#0 0x9 in check_node_location\n",
        siglines: 15
      )
      assert_equal n1, n2, "INVARIANT[node_location] varied across parent wrapper or AST recursion depth"
      refute_equal n1, n3, "INVARIANT[node_location] collided across distinct node types"
      refute_equal i1, n1, "INVARIANT[diagnostic] collided with INVARIANT[node_location]"

      # INVARIANT[node_sub_location].
      sl1 = run_signature(
        "INVARIANT[node_sub_location]: type=PM_CALL_NODE field=message_loc kind=length_underflow [detail: parent=PM_STATEMENTS_NODE start=8 length=4294967292 parsed_size=20]\n" \
        "#0 0x1 in fuzz_check_sub_location\n",
        siglines: 15
      )
      sl2 = run_signature(
        "INVARIANT[node_sub_location]: type=PM_CALL_NODE field=message_loc kind=length_underflow [detail: parent=PM_CALL_NODE start=0 length=4294967290 parsed_size=12]\n" \
        "#0 0x9 in fuzz_check_sub_location\n",
        siglines: 15
      )
      sl3 = run_signature(
        "INVARIANT[node_sub_location]: type=PM_CALL_NODE field=opening_loc kind=length_underflow [detail: parent=PM_STATEMENTS_NODE start=8 length=4294967292 parsed_size=20]\n",
        siglines: 15
      )
      sl4 = run_signature(
        "INVARIANT[node_sub_location]: type=PM_CALL_NODE field=message_loc kind=end_oob [detail: parent=PM_STATEMENTS_NODE start=8 length=4294967292 parsed_size=20]\n",
        siglines: 15
      )
      assert_equal sl1, sl2, "INVARIANT[node_sub_location] varied across offsets or parent"
      refute_equal sl1, sl3, "INVARIANT[node_sub_location] collided across distinct fields"
      refute_equal sl1, sl4, "INVARIANT[node_sub_location] collided across distinct violation kinds"
      refute_equal sl1, n3, "INVARIANT[node_sub_location] collided with INVARIANT[node_location]"

      # Empty stderr / fully-stripped preamble produces a stable deterministic signature without failing.
      empty_sig = run_signature("", siglines: 10)
      stripped_sig = run_signature("Reading 12 bytes from /tmp/c\nExecution successful.\n", siglines: 10)
      newline_sig = run_signature("\n", siglines: 10)
      assert_equal empty_sig, stripped_sig, "stripped-only output should match empty stderr signature"
      refute_equal empty_sig, newline_sig
      refute_equal empty_sig, i1

      # SIGPIPE safety on 5,000-line traces via file stdin, IO.pipe streaming, and head -n 1 under pipefail.
      big_trace_path = File.join(workdir, "big_trace.txt")
      big_inv_trace_path = File.join(workdir, "big_inv_trace.txt")
      File.write(big_trace_path, "stack frame 0xdeadbeef in fn\n" * 5000)
      File.write(
        big_inv_trace_path,
        "INVARIANT[stream]: kind=parsed_size_oob [detail: parsed_size=9 size=4]\n" +
          ("stack frame 0xdeadbeef in fn\n" * 5000)
      )

      expected_big_sig = run_signature("stack frame 0x1234 in fn\n" * 3, siglines: 3)
      expected_inv_sig = run_signature("INVARIANT[stream]: kind=parsed_size_oob [detail: parsed_size=1 size=99]\n", siglines: 15)

      assert_equal expected_big_sig, run_signature_from_pipe(big_trace_path, siglines: 3)
      assert_equal expected_inv_sig, run_signature_from_pipe(big_inv_trace_path, siglines: 15)

      pipefail_out, = assert_cmd(
        "bash", "-o", "pipefail", "-c",
        "#{Shellwords.escape(signature_sh)} < #{Shellwords.escape(big_trace_path)} | head -n 1",
        env: { "SIGLINES" => "3" }
      )
      assert_equal expected_big_sig, pipefail_out.strip

      # Verify pure-Ruby XXH64 + Signature.compute parity on >32B multi-stripe inputs, CRLF, and arbitrary binary bytes.
      [
        ["", 10],
        ["abc", 10],
        ["0123456789abcdef0123456789abcdef", 10],
        ["0123456789abcdef0123456789abcdef_tail_bytes_12345\n", 10],
        ["line1\r\nline2\r\n\x80\xff\xfe binary runtime error: value -99 bad\n", 5],
        [File.binread(big_trace_path), 3],
        [File.binread(big_inv_trace_path), 15]
      ].each do |sample, sl|
        assert_equal run_signature_sh_only(sample, siglines: sl), FuzzTriage::Signature.compute(sample, sl)
      end
    end
  end

  def test_halfempty_sh_minimization_header_and_drift_protection
    with_tmpdir("triage-sig-") do |workdir|
      synth_target = compile_synth_target(workdir)
      he_env = { "TMPDIR" => workdir }

      # 2a. Non-crashing input and <4-byte input must be rejected cleanly.
      noncrash_in = File.join(workdir, "noncrash.in")
      noncrash_min = File.join(workdir, "noncrash.min")
      File.binwrite(noncrash_in, "\x00\x00\x03\x01hello world\n".b)
      _out, _err, st = run_cmd(halfempty_sh, synth_target, noncrash_in, noncrash_min, env: he_env)
      refute st.success?, "halfempty.sh succeeded on a non-crashing input"
      refute_path_exists noncrash_min

      short_in = File.join(workdir, "short.in")
      short_min = File.join(workdir, "short.min")
      File.binwrite(short_in, "\x00\x00\x03".b)
      _out, _err, short_st = run_cmd(halfempty_sh, synth_target, short_in, short_min, env: he_env)
      refute short_st.success?, "halfempty.sh succeeded on a <4-byte input"
      refute_path_exists short_min

      # 2b. Noisy input containing both ALT_CRASH and BOOM with non-default header \x2a\x11\x22\x33:
      #     must preserve exact 4-byte header, reject drifting to ALT_CRASH, and shrink around BOOM.
      boom_in = File.join(workdir, "boom.in")
      boom_min = File.join(workdir, "boom.min")
      boom_hdr = "\x2a\x11\x22\x33".b
      boom_body = ("x = 1 + 2\n".b * 15) + "ALT_CRASH\n".b + ("m = 0\n".b * 15) + "BOOM\n".b + ("y = 3 + 4\n".b * 15)
      File.binwrite(boom_in, boom_hdr + boom_body)

      assert_cmd(halfempty_sh, synth_target, boom_in, boom_min, env: he_env)
      mini_boom = File.binread(boom_min)
      assert_equal boom_hdr, mini_boom.byteslice(0, 4), "4-byte header mutated: #{mini_boom.byteslice(0, 4).dump}"
      mini_boom_body = mini_boom.byteslice(4..)
      assert_includes mini_boom_body, "BOOM".b, "expected crash token BOOM missing: #{mini_boom.dump}"
      refute_includes mini_boom_body, "ALT_CRASH".b, "secondary token ALT_CRASH not minimized away: #{mini_boom.dump}"
      assert_operator mini_boom.bytesize, :<=, 12,
                      "expected <= 12 bytes from #{File.size(boom_in)} bytes, got #{mini_boom.bytesize}: #{mini_boom.dump}"

      orig_boom_sig = crash_signature_for_input(synth_target, boom_in)
      min_boom_sig = crash_signature_for_input(synth_target, boom_min)
      assert_equal orig_boom_sig, min_boom_sig, "minimized crash signature drifted (#{orig_boom_sig} != #{min_boom_sig})"

      # 2c. Silent SIGSEGV (empty stderr) must not be minimized into a non-crashing 0-byte body.
      segv_in = File.join(workdir, "segv.in")
      segv_min = File.join(workdir, "segv.min")
      segv_hdr = "\x04\xaa\xbb\xcc".b
      segv_body = ("a = 1\n".b * 12) + "SEGV".b + ("\nb = 2\n".b * 12)
      File.binwrite(segv_in, segv_hdr + segv_body)

      assert_cmd(halfempty_sh, synth_target, segv_in, segv_min, env: he_env)
      mini_segv = File.binread(segv_min)
      assert_equal segv_hdr, mini_segv.byteslice(0, 4), "4-byte header mutated on SIGSEGV: #{mini_segv.byteslice(0, 4).dump}"
      assert_includes mini_segv.byteslice(4..), "SEGV".b, "empty-stderr SIGSEGV wiped out crash token: #{mini_segv.dump}"
      assert_operator mini_segv.bytesize, :<=, 12,
                      "expected <= 12 bytes on SIGSEGV, got #{mini_segv.bytesize}: #{mini_segv.dump}"

      _sout, _serr, segv_st = run_cmd(synth_target, segv_min)
      refute segv_st.success?, "segv.min no longer crashes"
      assert_equal Signal.list["SEGV"], segv_st.termsig, "expected SIGSEGV on segv.min, got #{segv_st.inspect}"

      # 2d. Exact 4-byte crash (0-byte Ruby body) must preserve the 4-byte input cleanly.
      empty_body_in = File.join(workdir, "empty_body.in")
      empty_body_min = File.join(workdir, "empty_body.min")
      File.binwrite(empty_body_in, "\x08\xde\xad\x01".b)
      assert_cmd(halfempty_sh, synth_target, empty_body_in, empty_body_min, env: he_env)
      assert_equal File.binread(empty_body_in), File.binread(empty_body_min), "4-byte input was altered by halfempty.sh"

      # 2e. Two INVARIANT[...] failures sharing the exact same C call stack and shifting offsets:
      #     must preserve INV_TARGET (heredoc_term), delete INV_DECOY (escape_invalid_meta), and shrink prefix/suffix.
      inv_in = File.join(workdir, "inv.in")
      inv_min = File.join(workdir, "inv.min")
      inv_hdr = "\x10\x44\x55\x66".b
      inv_body = ("p = 1\n".b * 15) + "INV_DECOY\n".b + ("q = 2\n".b * 15) + "INV_TARGET\n".b + ("r = 3\n".b * 15)
      File.binwrite(inv_in, inv_hdr + inv_body)

      assert_cmd(halfempty_sh, synth_target, inv_in, inv_min, env: he_env.merge("SIGLINES" => "15"))
      mini_inv = File.binread(inv_min)
      assert_equal inv_hdr, mini_inv.byteslice(0, 4), "4-byte header mutated on INVARIANT: #{mini_inv.byteslice(0, 4).dump}"
      mini_inv_body = mini_inv.byteslice(4..)
      assert_includes mini_inv_body, "INV_TARGET".b, "target invariant token INV_TARGET missing: #{mini_inv.dump}"
      refute_includes mini_inv_body, "INV_DECOY".b, "decoy invariant token INV_DECOY not minimized away: #{mini_inv.dump}"
      assert_operator mini_inv.bytesize, :<=, 18,
                      "expected <= 18 bytes from #{File.size(inv_in)} bytes, got #{mini_inv.bytesize}: #{mini_inv.dump}"
      assert_equal(
        crash_signature_for_input(synth_target, inv_in, siglines: 15),
        crash_signature_for_input(synth_target, inv_min, siglines: 15),
        "INVARIANT crash signature drifted after minimization"
      )

      # 2f. ASan+UBSan mock crasher minimization + halfempty bisect fallback on signature drift.
      ubsan_mock = compile_ubsan_drift_mock(workdir)
      ubsan_in = File.join(workdir, "ubsan.in")
      ubsan_min = File.join(workdir, "ubsan.min")
      ubsan_hdr = "\x01\x00\x03\x01".b
      File.binwrite(ubsan_in, ubsan_hdr + ("padding_".b * 4) + "BOOM".b)

      assert_cmd(halfempty_sh, ubsan_mock, ubsan_in, ubsan_min, env: he_env.merge("SIGLINES" => "3"))
      assert_equal ubsan_hdr + "BOOM".b, File.binread(ubsan_min),
                   "expected UBSan mock to shrink cleanly while preserving 4-byte header"

      drift_in = File.join(workdir, "drift.in")
      drift_min = File.join(workdir, "drift.min")
      drift_marker = File.join(workdir, "drift.marker")
      File.binwrite(drift_in, "\x01\x12\x34\x56payload_to_preserve\n".b)
      assert_cmd(
        halfempty_sh, ubsan_mock, drift_in, drift_min,
        env: he_env.merge("DRIFT_MARKER" => drift_marker)
      )
      assert_equal File.binread(drift_in), File.binread(drift_min),
                   "expected halfempty.sh to fall back to exact original input when bisect rejects signature drift"
    end
  end

  private

  def signature_sh
    repo_path("triage/signature.sh")
  end

  def halfempty_sh
    repo_path("triage/halfempty.sh")
  end

  def default_cc
    cc = ENV["CC"].to_s.strip
    return cc unless cc.empty?

    find_executable("clang") || find_executable("cc") || flunk("no C compiler (clang or cc) found in PATH")
  end

  def run_signature_sh_only(input, siglines: 10)
    out, err, st = run_cmd(signature_sh, env: { "SIGLINES" => siglines.to_s }, input: input)
    assert st.success?, "signature.sh failed (status=#{st.exitstatus || st.termsig}): stderr=#{err}"
    sig = out.strip
    assert_match(/\A[0-9a-f]{16}\z/, sig, "expected 16-char hex signature, got #{out.inspect}")
    sig
  end

  def run_signature(input, siglines: 10)
    sh_sig = run_signature_sh_only(input, siglines: siglines)
    rb_sig = FuzzTriage::Signature.compute(input, siglines)
    assert_equal sh_sig, rb_sig, "FuzzTriage::Signature.compute diverged from signature.sh (siglines=#{siglines}) on:\n#{input.dump}"
    sh_sig
  end

  def run_signature_from_pipe(path, siglines:)
    in_r, in_w = IO.pipe
    out_r, out_w = IO.pipe
    err_r, err_w = IO.pipe
    pid = Process.spawn({ "SIGLINES" => siglines.to_s }, signature_sh, in: in_r, out: out_w, err: err_w)
    in_r.close
    out_w.close
    err_w.close

    writer = Thread.new do
      File.open(path, "rb") { |f| IO.copy_stream(f, in_w) }
    ensure
      in_w.close unless in_w.closed?
    end

    out = out_r.read
    err = err_r.read
    writer.join
    _, st = Process.waitpid2(pid)

    assert st.success?, "signature.sh failed on piped trace #{path} (status=#{st.exitstatus || st.termsig}): #{err}"
    assert_nil st.termsig, "signature.sh terminated by signal #{st.termsig}"
    sig = out.strip
    assert_match(/\A[0-9a-f]{16}\z/, sig, "expected 16-char hex signature, got #{out.inspect}")
    sig
  ensure
    [in_r, in_w, out_r, out_w, err_r, err_w].each { |io| io.close if io && !io.closed? }
  end

  def crash_signature_for_input(exe, input_path, siglines: 10)
    out, _st = Open3.capture2e(exe, input_path)
    run_signature(out, siglines: siglines)
  end

  def compile_synth_target(workdir)
    src = File.join(workdir, "synth_target.c")
    bin = File.join(workdir, "synth_target")
    File.write(src, SYNTH_TARGET_C)
    assert_cmd(default_cc, "-O2", "-std=c99", src, "-o", bin)
    bin
  end

  def compile_ubsan_drift_mock(workdir)
    src = File.join(workdir, "ubsan_drift_mock.c")
    bin = File.join(workdir, "ubsan_drift_mock")
    File.write(src, UBSAN_DRIFT_MOCK_C)
    assert_cmd(
      default_cc, "-O1", "-g", "-std=c99",
      "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
      src, "-o", bin
    )
    bin
  end
end
