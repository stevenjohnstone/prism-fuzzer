# Fuzz Triage Investigation Cheatsheet

How to translate cryptic AFL++ / sanitizer / differential failures in a campaign workspace (`<ws>/report/triage/`, defaulting to `tmp/fuzz/report/triage/` for `campaigns/default.rb`) into plain-Ruby explanations, verify or bisect fixes, and deduplicate against upstream issues (`github.com/ruby/prism/issues` and `bugs.ruby-lang.org`) — without diving into `<ws>/build/targets/*/src/*.c`.

Triage stores minimized raw inputs (`input.min`), raw crash archives (`inputs.tar.gz`), `occurrences.jsonl`, structured `meta.json`, and executable `verify.sh` wrappers (per-bucket `testcase.c` and `build.sh` reproducers are no longer synthesized). Primary inspection, verification, and bisection tools (shown via `./campaigns/default.rb`, or use your custom campaign script `./my_campaign.rb` / `make <target> CAMPAIGN=...` for isolated workspaces):
- [`triage/inspect.rb`](../triage/inspect.rb) (`./campaigns/default.rb inspect -- ...` / `make inspect`)
- [`triage/explain.rb`](../triage/explain.rb) + [`harnesses/prism/explain.c`](../harnesses/prism/explain.c) (`./campaigns/default.rb explain -- ...` / `make explain`)
- [`triage/match.rb`](../triage/match.rb) (`./campaigns/default.rb match -- ...` / `make match`)
- [`triage/verify.rb`](../triage/verify.rb) (`./campaigns/default.rb verify -- ...` / `make verify`)
- [`triage/bisect.rb`](../triage/bisect.rb) (`./campaigns/default.rb bisect -- ...` / `make bisect`)
- [`bin/paren.rb`](../bin/paren.rb) (`./bin/paren.rb --docker -e '...'` — side-by-side `parse.y` vs. `prism` fully-parenthesized expression renderer for precedence, block-ownership, and one-sided `SyntaxError` diffs)

Examples A–F below are verbatim transcripts captured from an earlier `tmp/fuzz/triage/` crop (`46` clusters in the refreshed Step 0 `inspect` snapshot after digest backfill, where `cluster-12/24/26` correspond to `cluster-13/25/27` in Examples E–F).

---

## 1. Quick Decision Cheat Sheet

| What `inspect` shows | Run next | How to interpret in Ruby terms |
| :--- | :--- | :--- |
| `node_location` / `node_relation` / `error_recovery` | `./campaigns/default.rb explain -- <cluster>` (or `make explain CLUSTER=<cluster>`) | Inspect `anomalies:` and inline `<-- [! ...]` AST callouts against `errors:` — flags length underflow, OOB sub-locations, `closing_before_opening`, parent escapes, and overlapping/out-of-order siblings. Check `options:` (`encoding=`, `cmd=`, `scopes=`) when non-default. |
| `recursion_depth` | `./campaigns/default.rb explain -- <cluster> --no-ast --no-errors-format` | Check `options:` (`cmd=`) and `anomalies:` (`depth_exceeded`) to see what syntax loop recursed past the depth limit without a `nesting_too_deep` error. |
| `stream_diff` | `./campaigns/default.rb explain -- <cluster>` | Automatically runs `--compare-stream`, comparing buffer (`pm_parse`) vs line-by-line stream (`pm_parse_stream`) on `parsed_size`, `data_loc`, annotated `prettyprint`, and `serialize` (usually diverges at `__END__`, `\r\n`, or early EOF). |
| `oracle_arm32` / `oracle_ppc` | `./campaigns/default.rb explain -- <cluster>` | Automatically runs `--serialize` on both the 64-bit host `<ws>/build/fuzz.explain` and the 32-bit target (`arm32` via `qemu-arm` / `ppc` via `qemu-ppc` inside `prism-fuzzer` Docker), placing both ASTs, error counts, and serialized payloads side by side (`arm32_len` vs `oracle64_len` at `first_diff`). |
| `diff_parse_y` (`syntax_mismatch`) | `./campaigns/default.rb explain -- <cluster> --disasm` | Automatically runs CRuby in `prism-fuzzer` Docker (`--parser=parse.y` vs `--parser=prism`) alongside Prism's local `AST` and `errors:`, plus `prism disasm:` when Prism accepts the input; probe smaller variants with `-e ... --compare` and confirm cluster identity via `match`. |
| `diff_parse_y` (`ast_*_mismatch`) | `./campaigns/default.rb explain -- <cluster> --disasm --eval` | Compares bytecode disassembly (`disasm diff:`) and sandboxed runtime output (`--eval` inside Docker) to separate AST shape differences (`iseq: match`), compiler diffs (`disasm_diff`), and semantics bugs (`stdout_mismatch`). |
| `diff_prism` (`--group diff_prism`) | `./campaigns/default.rb explain -- <cluster>` | Automatically enables `--serialize` and compares `<ws>/build/fuzz.explain` (`prism_a`) vs `<ws>/build/fuzz.explain.b` (`prism_b`) side by side (`--- diff (prism_a vs prism_b) ---`; override with `--diff-prism` / `--no-diff-prism`). Check `<bucket>/meta.json` `target.sources` and run `bisect` to find the diverging commit. |
| `cruby_crash` (`--group cruby_crash`) | `./campaigns/default.rb explain -- <cluster> --no-compare` | Crash or sanitizer failure inside CRuby `--parser=parse.y` under `fuzz.diff`; inspect `meta.json` `symptom` and `frames` alongside `source` and `options:` (`cmd=`). |

Cluster selection in `explain`:
- Default when selecting a cluster (`--cluster cluster-01`, positional `cluster-01`, numeric `1`, or `make explain CLUSTER=cluster-01`): explains its canonical **representative** bucket.
- Target other buckets in the cluster with `--list-members`, `--member 2` (or `--member 2..4`; `1` is always representative), `--bucket <id|sig>`, positional `ABRT/<sig>`, or `--all-buckets`.

---

## 2. Step-by-Step Workflow with Crop Examples

### Step 0 — Survey the triage crop (`inspect`)

Triage records compact per-bucket digests (`<ws>/build/fuzz.explain --digest` AST/anomaly/stream-compare summaries plus CRuby `parse.y` vs `prism` syntax/ISeq parity for `diff_parse_y`) up front in `meta.json` and surfaces them in `inspect` alongside multi-frame `trace:` and cluster `variants:`.

Start with a quick scan split by group or digest filter (pass `--samples N` to preview extra member inputs, or `--brief` to hide `digest:`/`variants:`):

```bash
./campaigns/default.rb inspect -- --group prism_flaw
./campaigns/default.rb inspect -- --group diff_parse_y --iseq disasm_diff --limit 10
./campaigns/default.rb inspect -- --anomaly length_underflow --samples 2
# Or with Make: make inspect INSPECT_ARGS="--group prism_flaw"
```

Selected clusters from the `46`-cluster refreshed crop (matching Examples A–F below, where `cluster-12/24/26` correspond to `cluster-13/25/27` in the earlier `47`-cluster transcripts):

```bash
./campaigns/default.rb inspect -- --cluster cluster-01 --cluster cluster-02 --cluster cluster-04 --cluster cluster-12 --cluster cluster-24 --cluster cluster-26 --samples 2
```

```text
Clusters shown: 6/46 (total occurrences=22229)

cluster-01 (prism_flaw | 108 bkts | 16323 occ | sim=0.42..0.52 | size=15..57B | first=0h02m02s | profile=asan_ubsan | ABRT=108)
  rep:      ABRT/76f90594e445df61 (fuzz)  size=16B  hdr=00000301
  options:  encoding=ASCII-8BIT filepath=fuzz.rb | scopes=3(fwd=2)
  headline: INVARIANT[node_location]: type=PM_EMBEDDED_STATEMENTS_NODE kind=length_underflow [detail: parent=PM_INTERPOLATED_STRING_NODE start=5 length=4294967295 parsed_size=12]
  digest:   parsed=12B  err=8  warn=1  anomalies=length_underflow(57),outside_node(50),child_before_parent(49),child_before_opening(48)
  variants: node_relation:PM_ARRAY_NODE:start_after_child (31 bkt/441 occ); node_relation:PM_ARRAY_NODE:sibling_overlap (15 bkt/355 occ); node_relation:PM_INTERPOLATED_STRING_NODE:sibling_overlap (3 bkt/298 occ); node_location:PM_EMBEDDED_STATEMENTS_NODE:length_underflow (1 bkt/9870 occ); +4 more
  source:   <<C<\n#{y=>{ 
  sample:   ABRT/a4aedd62c964f56a (26B): <<B\n#{[b{<<k=>{\n#{{3}\n
  loupe:    https://stevenjohnstone.github.io/prism-loupe/?code=PDxDPAoje3k9Pnsg&ruby_ver=4.1

cluster-02 (prism_flaw | 3 bkts | 5435 occ | sim=0.27..0.32 | size=16..26B | first=0h03m21s | profile=msan_slow | ABRT=3)
  rep:      ABRT/8bea44e4dc1b51e3 (fuzz.msan)  size=26B  hdr=40000301
  options:  stream_mode | stream_mode cmd=-x
  headline: INVARIANT[stream_diff]: kind=ast_mismatch [detail: parsed_size=21 size=22 stream_pp=1406 full_pp=1404]
  digest:   parsed=21B(stream)  err=5  anomalies=child_after_parent(1)  stream_compare=mismatch(size=22/21,pp,ser@33)
  variants: stream_diff:ast_mismatch (1 bkt/5303 occ); stream_diff:warning_count_mismatch (1 bkt/75 occ); stream_diff:data_loc_mismatch (1 bkt/57 occ)
  source:   class ensure\n__END__\nx
  sample:   ABRT/c557bc3f949e7f60 (16B): if\n__END__\n 
  loupe:    https://stevenjohnstone.github.io/prism-loupe/?code=Y2xhc3MgZW5zdXJlCl9fRU5EX18KeA%3D%3D&ruby_ver=4.1&stream=1

cluster-04 (prism_flaw | 3 bkts | 319 occ | sim=0.25..0.35 | size=13..17B | first=0h00m03s | profile=arm32_oracle | ABRT=3)
  rep:      ABRT/c867e29c8d2abea1 (fuzz.arm32.repro)  size=13B  hdr=00000301
  options:  stream_mode
  headline: INVARIANT[oracle_arm32]: kind=ast_size_mismatch stream=0 [detail: arm32_len=81 oracle64_len=315 first_diff=30 byte32=0x00 byte64=0x02]
  digest:   parsed=9B  err=2  warn=1
  variants: oracle_arm32:ast_size_mismatch (2 bkt/318 occ); oracle_arm32:ast_byte_mismatch (1 bkt/1 occ)
  source:   _END_^   
  sample:   ABRT/f0661b0e67dd7392 (13B): D_^\n     
  loupe:    https://stevenjohnstone.github.io/prism-loupe/?code=X0VORF9eICAg&ruby_ver=4.1

cluster-12 (diff_parse_y | 2 bkts | 95 occ | sim=0.82..0.82 | size=13..19B | first=0h00m26s | profile=diff_parse_y | ABRT=2)
  rep:      ABRT/6ba0e914352b20ba (fuzz.diff)  size=13B  hdr=00000301
  headline: INVARIANT[diff_parse_y]: kind=syntax_mismatch sub=prism_ok_cruby_err nul=0 utf8=1 prism=ok cruby=SyntaxError:unexpected_punct [detail: prism_errs=0 cruby=SyntaxError: syntax error, unexpected '<']
  digest:   syntax=prism_ok_parse_y_err  iseq=prism_ok_parse_y_compile_err  parsed=9B  parse.y="/usr/local/bin/ruby: /tmp/fuzz-cmp-src20261121-7979-6a9fku.rb:1: syntax error, unexpected '<' (SyntaxError)"
  variants: prism_ok_cruby_err prism=ok cruby=SyntaxError:unexpected_punct iseq=prism_ok_parse_y_compile_err (2 bkt/95 occ)
  source:   x"#{}":<2
  sample:   ABRT/6b4480bff6bec06e (19B): ""#\xe8\nb"#{}":<2 
  loupe:    https://stevenjohnstone.github.io/prism-loupe/?code=eCIje30iOjwy&ruby_ver=4.1

cluster-24 (diff_parse_y | 4 bkts | 29 occ | sim=0.29..0.33 | size=20..24B | first=0h01m53s | profile=diff_parse_y | ABRT=4)
  rep:      ABRT/c7bc325cdad1e4ed (fuzz.diff)  size=20B  hdr=00000301
  headline: INVARIANT[diff_parse_y]: kind=ast_tree_mismatch sub=tag prism=PAIR_SPLAT cruby=PAIR [detail: idx=20 prev=CLOSE prism_len=38 cruby_len=34 prism_tok=PAIR_SPLAT cruby_tok=PAIR]
  digest:   syntax=both_ok  iseq=disasm_diff  parsed=16B  diff="-0006 putobject :\"\" => +0006 newhash 2"
  variants: tag prism=PAIR_SPLAT cruby=PAIR iseq=disasm_diff (1 bkt/25 occ); locals_count_mismatch iseq=disasm_diff (1 bkt/2 occ); tag prism=PAIR_SPLAT cruby=CLOSE iseq=disasm_diff (1 bkt/1 occ); tag prism=SLOT cruby=PARAMS iseq=disasm_diff (1 bkt/1 occ)
  source:   {a=>d,**{"":b}}\n
  sample:   ABRT/a260c73f1f9d43a4 (24B): p do{_1:}end\n{"":l}\n
  loupe:    https://stevenjohnstone.github.io/prism-loupe/?code=e2E9PmQsKip7IiI6Yn19Cg%3D%3D&ruby_ver=4.1

cluster-26 (diff_parse_y | 2 bkts | 28 occ | sim=0.59..0.59 | size=15..21B | first=0h00m36s | profile=diff_parse_y | ABRT=2)
  rep:      ABRT/ea36789a04ee9588 (fuzz.diff)  size=21B  hdr=00000301
  headline: INVARIANT[diff_parse_y]: kind=ast_tree_mismatch sub=tag prism=RANGE cruby=FLIP [detail: idx=20 prev=CLOSE prism_len=42 cruby_len=42 prism_tok=RANGE:.. cruby_tok=FLIP:..]
  digest:   syntax=both_ok  iseq=disasm_diff  parsed=17B  diff="-0008 branchunless 31 => +0008 branchunless 17"
  variants: tag prism=RANGE cruby=FLIP iseq=disasm_diff (1 bkt/23 occ); tag prism=FLIP cruby=RANGE iseq=disasm_diff (1 bkt/5 occ)
  source:   not (o\nn and..r) 
  sample:   ABRT/e412a3a6fec1643c (15B): not (;n..) 
  loupe:    https://stevenjohnstone.github.io/prism-loupe/?code=bm90IChvCm4gYW5kLi5yKSA%3D&ruby_ver=4.1
```

---

### Example A — `node_location`: Broken AST span during error recovery (`cluster-01`)

Command (host-native; defaults to canonical representative; pass `--member 2` or `--list-members` to explore the 108 sibling buckets):

```bash
./campaigns/default.rb explain -- --cluster cluster-01
# Or: make explain CLUSTER=cluster-01
```

Observed output (excerpt):

```text
== cluster-01:ABRT/76f90594e445df61 (rep [1/108] | group=prism_flaw | profile=asan_ubsan | 108 bkts, 15474 occ) ==
headline:    INVARIANT[node_location]: type=PM_EMBEDDED_STATEMENTS_NODE kind=length_underflow [detail: parent=PM_INTERPOLATED_STRING_NODE start=5 length=4294967295 parsed_size=12]
loupe:       https://stevenjohnstone.github.io/prism-loupe/?code=PDxDPAoje3k9Pnsg&ruby_ver=4.1
siblings:    108 bucket(s) in cluster; pass --member N / --bucket PAT / --all-buckets / --list-members
header:      00000301 (bytes: 0x00 0x00 0x03 0x01)
options:     version=4.1 stream_mode=false start_line=1
source:      <<C<\n#{y=>{ 
mode:        buffer (pm_parse)
parsed:      parsed_size=12 encoding=UTF-8 start_line=1 frozen_lit=0 continuable=true data_loc=(0,0) checksum=0xed69dd112edfb60e
counts:      errors=8 warnings=1 comments=0 magic_comments=0 constants=1 line_offsets=2
offsets:     [0, 5]
errors:
  [0] type=heredoc_term level=syntax loc=(2,1) lc=(1:2) msg="unterminated heredoc; can't find string "C" anywhere before EOF"
  ...
anomalies:   2 issue(s)
  [0] node_location: kind=length_underflow PM_EMBEDDED_STATEMENTS_NODE [parent=PM_INTERPOLATED_STRING_NODE] start=5 len=4294967295 (signed=-1) wrapped_end=4 parsed_size=12 lc=(2,0)-(1,4)
  [1] sub_location: kind=closing_before_opening PM_EMBEDDED_STATEMENTS_NODE.closing_loc (4,0) starts before opening_loc (5,2) lc=(2,0)-(1,4)
ast:
@ ProgramNode (location: (1,0)-(1,3))
+-- statements:
    @ StatementsNode (location: (1,0)-(1,3))
    +-- body: (length: 1)
        +-- @ InterpolatedStringNode (location: (1,0)-(1,3))
            +-- opening_loc: (1,0)-(1,3) = "<<C"
            +-- parts: (length: 1)
            |   +-- @ EmbeddedStatementsNode (location: (2,0)-(1,4))  <-- [! length_underflow: PM_EMBEDDED_STATEMENTS_NODE [parent=PM_INTERPOLATED_STRING_NODE] start=5 len=4294967295 (signed=-1) wrapped_end=4 parsed_size=12]
            |       +-- opening_loc: (2,0)-(2,2) = "\#{"
            ...
            |       +-- closing_loc: (1,4)-(1,4) = ""  <-- [! closing_before_opening: PM_EMBEDDED_STATEMENTS_NODE.closing_loc (4,0) starts before opening_loc (5,2)]
```

Inspecting another cluster member (e.g. `[2/108]`):

```bash
./campaigns/default.rb explain -- cluster-01 --member 2 --no-errors-format
```

```text
== cluster-01:ABRT/a4aedd62c964f56a ([2/108] | group=prism_flaw | profile=asan_ubsan | 108 bkts, 15474 occ) ==
headline:    INVARIANT[node_location]: type=PM_CALL_NODE kind=length_underflow [detail: parent=PM_ARRAY_NODE start=7 length=4294967293 parsed_size=22]
source:      <<B\n#{[b{<<k=>{\n#{{3}\n
...
anomalies:   7 issue(s)
  [0] node_location: kind=length_underflow PM_CALL_NODE [parent=PM_ARRAY_NODE] start=7 len=4294967293 (signed=-3) wrapped_end=4 parsed_size=22 lc=(2,3)-(2,0)
  [1] node_location: kind=length_underflow PM_BLOCK_NODE [parent=PM_CALL_NODE] start=8 len=4294967292 (signed=-4) wrapped_end=4 parsed_size=22 lc=(2,4)-(2,0)
  [2] sub_location: kind=closing_before_opening PM_BLOCK_NODE.closing_loc (4,0) starts before opening_loc (8,1) lc=(2,4)-(2,0)
  ...
```

**Ruby-terms takeaway:**
- On an **unterminated heredoc** whose body contains an **incomplete pattern-match hash inside string interpolation** (`<<C<\n#{y=>{ `), `EmbeddedStatementsNode` starts on line 2 at `#{` (`(2,0)`, byte `5`) while its `closing_loc` lands backwards on line 1 (`(1,4)`, byte `4`), causing unsigned `length = 4294967295` (`-1`).
- Upstream search terms (`ruby/prism` issues): `EmbeddedStatementsNode` `heredoc` `location` / backwards location on `unterminated heredoc`.

---

### Example B — `recursion_depth`: Parser error-recovery depth & CLI flags (`cluster-03`)

`cluster-03` has `options: cmd=-n` (`hdr=00080301`). Pass `--no-ast --no-errors-format` when there are hundreds of syntax errors:

```bash
./campaigns/default.rb explain -- cluster-03 --no-ast --no-errors-format
```

Observed output (excerpt):

```text
header:      00080301 (bytes: 0x00 0x08 0x03 0x01)
options:     version=4.1 stream_mode=false start_line=1 cmd=-n
source:      (((((((((H (((((((((((((((((((((((((((((((((((((|((((((((((((((((((((((((((((((((((((((((((E (((((((((((((((((== == == == ...
parsed:      parsed_size=421 encoding=UTF-8 start_line=1 frozen_lit=0 continuable=false data_loc=(0,0) checksum=0xb803d908a782d7bc
counts:      errors=525 warnings=102 comments=0 magic_comments=0 constants=6 line_offsets=1
...
anomalies:   1 issue(s)
  [0] recursion_depth: kind=depth_exceeded PM_STATEMENTS_NODE non_iter_depth=321 > limit=320 (max=128) without depth/stack error lc=(1,109)-(1,110)
```

**Ruby-terms takeaway:**
- Under `-n`, repeated unclosed `(` groups followed by invalid non-associative `== == == ...` chains emit 525 syntax errors and allow `PM_STATEMENTS_NODE` recursion depth (`321`) to exceed the fuzz threshold (`limit=320`, `max=128`) without bailing out with `nesting_too_deep`.

---

### Example C — `stream_diff`: Buffer vs. `pm_parse_stream` divergence (`cluster-02`)

`cluster-02` has `INVARIANT[stream_diff]`, so `explain` enables `--compare-stream` automatically:

```bash
./campaigns/default.rb explain -- cluster-02 --no-ast --no-errors-format
```

Observed output (excerpt):

```text
== cluster-02:ABRT/8bea44e4dc1b51e3 (rep [1/3] | group=prism_flaw | profile=msan_slow | 3 bkts, 5435 occ | options: stream_mode) ==
headline:    INVARIANT[stream_diff]: kind=ast_mismatch [detail: parsed_size=21 size=22 stream_pp=1406 full_pp=1404]
...
stream_compare:
  parsed_size: buffer=22 stream=21
  data_loc:    buffer=(13,9) stream=(13,8)
  errors:      buffer=5 stream=5
  warnings:    buffer=0 stream=0
  anomalies:   buffer=1 stream=1
  encoding:    buffer=UTF-8 stream=UTF-8
  prettyprint: DIFF (buffer=1404 stream=1406 first_diff=579)
  -- buffer prettyprint --
  ...
        +-- @ ClassNode (location: (1,0)-(1,12))
            +-- body:
            |   @ BeginNode (location: (1,0)-(3,1))  <-- [! child_after_parent: PM_BEGIN_NODE [0..22) extends past parent PM_CLASS_NODE [0..12)]
            |   +-- ensure_clause:
            |   |   @ EnsureNode (location: (1,6)-(3,1))
            |   |   +-- end_keyword_loc: (3,1)-(3,1) = ""
  -- stream prettyprint --
  ...
            |   @ BeginNode (location: (1,0)-(3,0))  <-- [! child_after_parent: PM_BEGIN_NODE [0..21) extends past parent PM_CLASS_NODE [0..12)]
            |   +-- ensure_clause:
            |   |   @ EnsureNode (location: (1,6)-(3,0))
            |   |   +-- end_keyword_loc: (2,7)-(3,0) = "\n"
  serialize:   DIFF (buffer=490 stream=490 first_diff=33 buf=0x09 stream=0x08)
  prefix_ser:  EQUAL (490 bytes on source[0..21))
```

**Ruby-terms takeaway:**
- On invalid `class ensure` followed by `__END__\nx` (22 bytes), buffer parsing (`pm_parse`) lets `EnsureNode.end_keyword_loc` extend to byte 22 (`(3,1)-(3,1)` after `x`) and sets `data_loc=(13,9)`, whereas stream parsing (`pm_parse_stream`) stops at byte 21 after `__END__\n` (`data_loc=(13,8)`, `end_keyword_loc=(2,7)-(3,0)`). Notice `prefix_ser: EQUAL` confirms buffer parsing on `source[0..21)` matches stream parsing byte-for-byte, and inline `[! child_after_parent]` highlights `BeginNode [0..21/22)` escaping `ClassNode [0..12)`.
- Upstream search terms: `pm_parse_stream` `__END__` `data_loc` / `end_keyword_loc` past `__END__`.

---

### Example D — `oracle_arm32`: 32-bit ARM vs. 64-bit AST divergence (`cluster-04`)

`cluster-04` has `profile=arm32_oracle`, so `explain` automatically enables `--serialize` and runs both the 64-bit host `<ws>/build/fuzz.explain` and 32-bit `arm32` (`qemu-arm` inside `prism-fuzzer` Docker; also available manually via `--arch arm32|ppc` or disabled via `--no-cross-arch`):

```bash
./campaigns/default.rb explain -- --cluster cluster-04
```

Observed output (excerpt):

```text
== cluster-04:ABRT/c867e29c8d2abea1 (rep [1/3] | group=prism_flaw | profile=arm32_oracle | 3 bkts, 319 occ) ==
headline:    INVARIANT[oracle_arm32]: kind=ast_size_mismatch stream=0 [detail: arm32_len=81 oracle64_len=315 first_diff=30 byte32=0x00 byte64=0x02]
...
source:      _END_^   

--- 64-bit host (build/fuzz.explain) ---
counts:      errors=2 warnings=1 comments=0 magic_comments=0 constants=2 line_offsets=1
...
@ ProgramNode (location: (1,0)-(1,6))
+-- statements:
    @ StatementsNode (location: (1,0)-(1,6))
    +-- body: (length: 1)
        +-- @ CallNode (location: (1,0)-(1,6))
            +-- receiver: CallNode(name: :_END_, message_loc: (1,0)-(1,5) = "_END_")
            +-- name: :^
            +-- arguments: ArgumentsNode -> [ErrorRecoveryNode]
serialize:   315 bytes

--- arm32 (qemu-arm) ---
counts:      errors=0 warnings=0 comments=0 magic_comments=0 constants=1 line_offsets=1
...
@ ProgramNode (location: (1,0)-(1,6))
+-- statements:
    @ StatementsNode (location: (1,0)-(1,6))
    +-- body: (length: 1)
        +-- @ CallNode (location: (1,0)-(1,6))
            +-- name: :_END_^
            +-- message_loc: (1,0)-(1,6) = "_END_^"
serialize:   81 bytes
```

**Ruby-terms takeaway:**
- On 64-bit, `_END_^   ` splits cleanly at `^` (`CallNode(:_END_ ^ ErrorRecoveryNode)` with `2` syntax errors, `315` serialized bytes, `byte64=0x02` at offset `30`). On 32-bit ARM (`qemu-arm`), Prism mis-lexes `_END_^` as a single identifier `CallNode(name: :_END_^)` with `0` errors (`81` serialized bytes, `byte32=0x00` at offset `30`). Testing `ruby --parser=...` is unnecessary here—both ASTs come from Prism's own C parser compiled for 64-bit vs. 32-bit ARM.

---

### Example E — `diff_parse_y` (`syntax_mismatch`): Prism accepts invalid label syntax (`cluster-13`)

Because `cluster-13` is a `diff_parse_y` cluster, `explain` automatically prints both Prism's local C `ast:` and Docker CRuby `--parser=parse.y` vs `--parser=prism` parity:

```bash
./campaigns/default.rb explain -- cluster-13 --disasm
./campaigns/default.rb match -- -e 'x"#{}\":<2'
```

Observed output (excerpt):

```text
CRuby: ruby 4.1.0dev (2026-11-21T06:46:31Z HEAD 72d4cf2e9a) +PRISM [aarch64-linux]
Checked 1 input(s): match=0, mismatch=1

== cluster-13:ABRT/6ba0e914352b20ba (rep [1/2] | group=diff_parse_y | profile=diff_parse_y | 2 bkts, 95 occ) ==
headline:    INVARIANT[diff_parse_y]: kind=syntax_mismatch sub=prism_ok_cruby_err nul=0 utf8=1 prism=ok cruby=SyntaxError:unexpected_punct [detail: prism_errs=0 cruby=SyntaxError: syntax error, unexpected '<']
...
ast:
@ ProgramNode (location: (1,0)-(1,9))
+-- statements:
    @ StatementsNode (location: (1,0)-(1,9))
    +-- body: (length: 1)
        +-- @ CallNode (location: (1,0)-(1,9))
            +-- name: :x
            +-- arguments:
            |   @ ArgumentsNode (location: (1,1)-(1,9))
            |   +-- arguments: (length: 1)
            |       +-- @ CallNode (location: (1,1)-(1,9))
            |           +-- receiver:
            |           |   @ InterpolatedSymbolNode (location: (1,1)-(1,7))
            |           |   +-- opening_loc: (1,1)-(1,2) = "\""
            |           |   +-- closing_loc: (1,5)-(1,7) = "\":"
            |           +-- name: :<
            |           +-- arguments: [IntegerNode(2)]
...
cruby_compare (ruby 4.1.0dev (2026-11-21T06:46:31Z HEAD 72d4cf2e9a) +PRISM [aarch64-linux]): parity=mismatch
  syntax:    prism_ok_parse_y_err
    parse.y: ok=false ... syntax error, unexpected '<' (SyntaxError)
    prism:   ok=true
  iseq:      prism_ok_parse_y_compile_err
    parse.y compile err: SyntaxError: (compare):1: syntax error, unexpected '<'
x"#{}":<2
       ^

  prism disasm:
    == disasm: #<ISeq:<compiled>@(compare):1 (1,0)-(1,9)>
    0000 putself                                                          (   1)[Li]
    ...
    0008 concatstrings                          2
    0010 intern
    0011 putobject                              2
    0013 opt_lt                                 <calldata!mid:<, argc:1, ARGS_SIMPLE>[CcCr]
    0015 opt_send_without_block                 <calldata!mid:x, argc:1, FCALL|ARGS_SIMPLE>
    0017 leave
```

And `match` confirms a snippet stays in the exact cluster when minimizing a plain-Ruby reproducer for an issue report:

```text
MATCHED: cluster-13 (avg=0.911 >= 0.250, rep=1.000, max=1.000, buckets=2, occ=95, rep=ABRT/6ba0e914352b20ba)
```

**Ruby-terms takeaway:**
- A quoted dynamic hash label `"#{}":` is only valid as a hash key or keyword argument label, not as a general expression. Prism parsed `x"#{}":<2` as `x(:"..." < 2)` (`InterpolatedSymbolNode` -> `intern`), while CRuby `parse.y` rejects it with `SyntaxError: syntax error, unexpected '<'`.

---

### Example F — `diff_parse_y` (`ast_tree_mismatch`): Harmless/design difference vs. real semantics bug (`cluster-25` vs. `cluster-27`)

#### 1. Concrete syntax vs. parser folding (`cluster-25`: `{a=>d,**{"":b}}\n`)

```bash
./campaigns/default.rb explain -- cluster-25 --disasm --no-ast
```

```text
== cluster-25:ABRT/c7bc325cdad1e4ed (rep [1/4] | group=diff_parse_y | profile=diff_parse_y | 4 bkts, 29 occ) ==
  source: {a=>d,**{"":b}}\n
cruby_compare (ruby 4.1.0dev (2026-11-21T06:46:31Z HEAD 72d4cf2e9a) +PRISM [aarch64-linux]): parity=mismatch
  syntax:    both_ok
  iseq:      disasm_diff
  disasm diff:
    --- parse.y
    +++ prism
    @@ ops 4..19 @@
     0003 putself
     0004 opt_send_without_block                 <calldata!mid:d, argc:0, FCALL|VCALL|ARGS_SIMPLE>
    -0006 putobject                              :""
    -0008 putself
    -0009 opt_send_without_block                 <calldata!mid:b, argc:0, FCALL|VCALL|ARGS_SIMPLE>
    -0011 newhash                                4
    -0013 leave
    +0006 newhash                                2
    +0008 putspecialobject                       1
    +0010 swap
    +0011 putobject                              :""
    +0013 putself
    +0014 opt_send_without_block                 <calldata!mid:b, argc:0, FCALL|VCALL|ARGS_SIMPLE>
    +0016 newhash                                2
    +0018 opt_send_without_block                 <calldata!mid:core#hash_merge_bang_kwd, argc:2, ARGS_SIMPLE>
    +0020 leave
```

**Ruby-terms takeaway:**
- Both parsers accept it and produce the same Ruby hash, but Prism preserves `**{"" => b}` as an `AssocSplatNode` wrapping `HashNode` (emitting two hashes + `core#hash_merge_bang_kwd`), whereas `parse.y` folds literal `**{...}` pairs directly into one `newhash 4`. Search Redmine (`prism_compile` + `hash_merge_bang_kwd`) and `ruby/prism` (`AssocSplatNode` hash literal) to check if flattening belongs in `prism_compile.c` or is intentional.

#### 2. Opposite runtime behavior (`cluster-27`: `not (o\nn and..r) ` and `not (;n..) `)

```bash
./campaigns/default.rb explain -- cluster-27 --all-buckets --no-ast
./campaigns/default.rb explain -- -e "n = true; r = false; p(begin; not (1; n and ..r); end)" -e "n = false; p(begin; not (;n..); end)" --eval --no-ast
```

Observed `--eval` output (`ruby 4.1.0dev`, `72d4cf2e9a`):
- `not (1; n and ..r)` (with `n = true; r = false`):
  - `--parser=parse.y` compiles a flip-flop (`getspecial 2, 0` / `setspecial 2`) and prints **`true`**
  - `--parser=prism` parses `RangeNode` (`newrange 0`, `nil..false`) and prints **`false`**
- `not (;n..)` (with `n = false`):
  - `--parser=parse.y` compiles `Range` (`newrange 0`, `false..nil`) and prints **`false`**
  - `--parser=prism` compiles `FlipFlopNode` (`getspecial 2, 0` / `setspecial 2`) and prints **`true`**

**Ruby-terms takeaway:**
- Genuine behavioral discrepancy in `not (...)` flip-flop vs. range inference, testable in one line of plain Ruby.

---

## 3. Verifying & Bisecting Fixes

Because triage keeps raw minimized inputs (`input.min`) and archived raw inputs (`inputs.tar.gz`) alongside `verify.sh` instead of synthesizing standalone `testcase.c` reproducers, verify candidate fixes and track down introducing commits directly against the workspace triage buckets:

```bash
# Verify a cluster across input.min and all archived raw crashes against a patched Prism checkout:
PRISM_DIR=/path/to/fixed-prism ./campaigns/default.rb verify -- --cluster cluster-01

# Re-run a single bucket's verifier inside Docker (e.g. for an isolated bucket profile):
./campaigns/default.rb shell -- -c ./tmp/fuzz/report/triage/ABRT/76f90594e445df61/verify.sh

# Bisect when a bug was introduced (--good / --bad) or fixed (--broken / --fixed):
./campaigns/default.rb bisect -- --good <sha> --bad HEAD --cluster cluster-01
```

- For `diff_prism` clusters (from `PRISM_REF` vs `PRISM_B_REF` campaigns), check `target.sources` in `<bucket>/meta.json` and pass `--no-diff-prism` / `--diff-prism` to `explain` to inspect `prism_a` (`<ws>/build/fuzz.explain`) and `prism_b` (`<ws>/build/fuzz.explain.b`) side by side.

---

## 4. Routing Findings Upstream

- **File on `github.com/ruby/prism/issues`**:
  - Any `prism_flaw` invariant (`node_location`, `node_relation`, `error_recovery`, `recursion_depth`, `stream_diff`, `oracle_arm32`, `oracle_ppc`, parser assertions/sanitizers).
  - Any `diff_parse_y` `syntax_mismatch` where `Prism.parse` and `parse.y` disagree on Ruby syntax validity, or AST semantics mismatches like `cluster-27` (`FlipFlopNode` vs `RangeNode`).
  - Regressions or parser divergences surfaced by `diff_prism` once narrowed with `explain` (`--diff-prism`) and `bisect`.
- **File on Ruby Redmine (`bugs.ruby-lang.org`)**:
  - Any `cruby_crash` inside `--parser=parse.y`.
  - Cases where `explain` shows `Prism.parse` succeeds with the expected AST (`syntax: both_ok`), yet `InstructionSequence.compile` or `--eval` fails or diverges under `--parser=prism` (e.g. CRuby's `prism_compile.c` bytecode generation or missing compile-time optimization/parity like `cluster-25`).
