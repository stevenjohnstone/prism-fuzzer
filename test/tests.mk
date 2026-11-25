# Dependency-tracked test build & verification stages (included by Makefile).

TEST_BUILD_DIR := build/test
TEST_STAMPS_DIR := $(TEST_BUILD_DIR)/stamps
TEST_CC := $(if $(filter default,$(origin CC)),clang,$(CC))
TEST_CXX := $(if $(filter default,$(origin CXX)),clang++,$(CXX))

RUNTIME_TOPOLOGY_DEPS := runtime/topology.rb $(sort $(wildcard runtime/lib/topology/*.rb))
RUNTIME_CAMPAIGN_DEPS := runtime/campaign.rb $(sort $(wildcard runtime/lib/campaign/*.rb))
REPORT_LIB_DEPS := report/report.rb report/sankey.rb $(sort $(wildcard report/lib/*.rb report/lib/*/*.rb report/lib/assets/*))
TEST_RUNNER_DEPS := test/run.rb test/lib/autorun.rb test/lib/test_helpers.rb test/lib/fixtures.rb
PRISM_A_STATE_DEP := $(wildcard $(PRISM_A_DIR)/.fuzz-target-state.json)
PRISM_A_CONFIG_DEP := $(PRISM_A_DIR)/config.yml
FUZZ_DIFF_DEPS := harnesses/prism/diff.c harnesses/prism/diff/summary.h harnesses/prism/diff/summary.c harnesses/prism/diff/cruby_vm.h harnesses/prism/diff/cruby_vm.c harnesses/prism/diff/prism_walker.h harnesses/prism/diff/prism_walker.c harnesses/prism/diff/cruby_walker.c harnesses/prism/build_diff.sh harnesses/prism/cruby_compile.c harnesses/prism/build_cruby_compile.sh harnesses/prism/gen_diff_ids.rb runtime/provenance.rb
FUZZ_PRISM_DIFF_DEPS := harnesses/prism/prism_diff.c harnesses/prism/prism_diff_side.c harnesses/prism/prism_diff_side.h harnesses/prism/build_prism_diff.sh harnesses/prism/gen_diff_ids.rb runtime/provenance.rb
TRIAGE_COMMON_DEPS := triage/triage.rb triage/verify.rb triage/verify_bucket.sh triage/retriage.rb triage/cluster.rb triage/match.rb triage/inspect.rb triage/explain.rb triage/signature.sh triage/halfempty.sh triage/halfempty_compare.sh triage/bisect.rb $(sort $(wildcard triage/lib/*.rb)) runtime/common.rb runtime/fuzz_header.rb runtime/provenance.rb $(RUNTIME_TOPOLOGY_DEPS)

$(PRISM_A_GEN_DIR)/node_locations.inc: harnesses/prism/gen_node_locations.rb $(PRISM_A_DIR)/config.yml
	$(Q) $(MAKEDIRS) $(@D)
	$(ECHO) "generating $@"
	$(Q) ruby ./harnesses/prism/gen_node_locations.rb $(PRISM_A_DIR)/config.yml $@

$(PRISM_A_GEN_DIR)/prism_fuzz_compat.h: harnesses/prism/gen_api_compat.rb $(PRISM_A_GEN_DIR)/node_locations.inc $(PRISM_A_HEADERS) $(PRISM_A_STATE_DEP)
	$(Q) $(MAKEDIRS) $(@D)
	$(ECHO) "generating $@"
	$(Q) ruby ./harnesses/prism/gen_api_compat.rb --include-dir $(PRISM_A_DIR)/include --subloc-inc $(PRISM_A_GEN_DIR)/node_locations.inc --output $@

# ------------------------------------------------------------------------------
# Incremental test binary builds (cached under build/test/)
# ------------------------------------------------------------------------------

TEST_ACCEL_DIR := $(TEST_BUILD_DIR)/accel
TEST_ACCEL_BIN := $(TEST_ACCEL_DIR)/fuzz.accel
TEST_ACCEL_NATIVE_SO := $(TEST_ACCEL_DIR)/libprism_native.so
TEST_ACCEL_SWAR_SO := $(TEST_ACCEL_DIR)/libprism_swar.so
TEST_ACCEL_PRISM_SRCS := $(filter-out %/prism.c,$(sort $(wildcard $(PRISM_A_DIR)/src/*.c)))
TEST_ACCEL_NATIVE_OBJS := $(patsubst $(PRISM_A_DIR)/src/%.c,$(TEST_ACCEL_DIR)/obj/native/%.o,$(TEST_ACCEL_PRISM_SRCS)) $(TEST_ACCEL_DIR)/obj/native/accel_backend.o
TEST_ACCEL_SWAR_OBJS := $(patsubst $(PRISM_A_DIR)/src/%.c,$(TEST_ACCEL_DIR)/obj/swar/%.o,$(TEST_ACCEL_PRISM_SRCS)) $(TEST_ACCEL_DIR)/obj/swar/accel_backend.o
TEST_ACCEL_MAP := $(TEST_ACCEL_DIR)/accel.map
TEST_ACCEL_CFLAGS := -std=c99 -O1 -g -fPIC -Wall -Wextra -Werror -Wundef -Wconversion -Wno-missing-braces -Wimplicit-fallthrough -Wno-unused-function -I$(PRISM_A_DIR)/include -I$(PRISM_A_DIR)/src -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=all

$(TEST_ACCEL_DIR)/obj/native/%.o: $(PRISM_A_DIR)/src/%.c $(PRISM_A_HEADERS) $(PRISM_A_STATE_DEP)
	$(Q) $(MAKEDIRS) $(@D)
	$(Q) $(TEST_CC) $(TEST_ACCEL_CFLAGS) -c $< -o $@

$(TEST_ACCEL_DIR)/obj/swar/%.o: $(PRISM_A_DIR)/src/%.c $(PRISM_A_HEADERS) $(PRISM_A_STATE_DEP)
	$(Q) $(MAKEDIRS) $(@D)
	$(Q) $(TEST_CC) $(TEST_ACCEL_CFLAGS) -DPRISM_ACCEL_SWAR -c $< -o $@

$(TEST_ACCEL_DIR)/obj/native/accel_backend.o: harnesses/prism/accel_backend.c $(PRISM_A_DIR)/src/prism.c $(PRISM_A_HEADERS) $(PRISM_A_STATE_DEP)
	$(Q) $(MAKEDIRS) $(@D)
	$(Q) $(TEST_CC) $(TEST_ACCEL_CFLAGS) -DACCEL_BACKEND=native -c $< -o $@

$(TEST_ACCEL_DIR)/obj/swar/accel_backend.o: harnesses/prism/accel_backend.c $(PRISM_A_DIR)/src/prism.c $(PRISM_A_HEADERS) $(PRISM_A_STATE_DEP)
	$(Q) $(MAKEDIRS) $(@D)
	$(Q) $(TEST_CC) $(TEST_ACCEL_CFLAGS) -DPRISM_ACCEL_SWAR -DACCEL_BACKEND=swar -c $< -o $@

$(TEST_ACCEL_DIR)/native.map:
	$(Q) $(MAKEDIRS) $(@D)
	$(Q) printf '{\n    global:\n        accel_native_*;\n    local:\n        *;\n};\n' > $@

$(TEST_ACCEL_DIR)/swar.map:
	$(Q) $(MAKEDIRS) $(@D)
	$(Q) printf '{\n    global:\n        accel_swar_*;\n    local:\n        *;\n};\n' > $@

$(TEST_ACCEL_NATIVE_SO): $(TEST_ACCEL_NATIVE_OBJS) $(TEST_ACCEL_DIR)/native.map
	$(Q) $(MAKEDIRS) $(@D)
	$(Q) $(TEST_CC) -shared -fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=all -Wl,--version-script=$(TEST_ACCEL_DIR)/native.map -Wl,-Bsymbolic $(TEST_ACCEL_NATIVE_OBJS) -o $@

$(TEST_ACCEL_SWAR_SO): $(TEST_ACCEL_SWAR_OBJS) $(TEST_ACCEL_DIR)/swar.map
	$(Q) $(MAKEDIRS) $(@D)
	$(Q) $(TEST_CC) -shared -fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=all -Wl,--version-script=$(TEST_ACCEL_DIR)/swar.map -Wl,-Bsymbolic $(TEST_ACCEL_SWAR_OBJS) -o $@

$(TEST_ACCEL_BIN): harnesses/prism/accel.c $(TEST_ACCEL_NATIVE_SO) $(TEST_ACCEL_SWAR_SO)
	$(ECHO) "linking incremental test binary $@"
	$(Q) $(MAKEDIRS) $(@D)
	$(Q) $(TEST_CC) -std=c99 -O1 -g -Wall -Wextra -Werror -Wundef -Wconversion -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all $< $(TEST_ACCEL_NATIVE_SO) $(TEST_ACCEL_SWAR_SO) -Wl,-rpath,'$$ORIGIN' -o $@

# Incremental explain test binaries (O1 for explain suite, ASAN+UBSAN+strict warnings for standalone checks)
TEST_EXPLAIN_BIN := $(TEST_BUILD_DIR)/bin/fuzz.explain
TEST_EXPLAIN_ASAN_BIN := $(TEST_BUILD_DIR)/bin/fuzz.explain.asan
TEST_EXPLAIN_OBJS := $(patsubst $(PRISM_A_DIR)/src/%.c,$(TEST_BUILD_DIR)/obj/explain/%.o,$(PRISM_A_SOURCES))
TEST_EXPLAIN_ASAN_OBJS := $(patsubst $(PRISM_A_DIR)/src/%.c,$(TEST_BUILD_DIR)/obj/explain-asan/%.o,$(PRISM_A_SOURCES))
TEST_EXPLAIN_HARNESS_SRCS := harnesses/prism/explain.c harnesses/prism/explain/analysis.c harnesses/prism/explain/prettyprint.c harnesses/prism/explain/json_digest.c
TEST_EXPLAIN_HARNESS_DEPS := harnesses/prism/explain/explain.h harnesses/prism/include/fuzz_invariants.h harnesses/prism/include/fuzz_options.h harnesses/prism/include/fuzz_json.h $(PRISM_A_GEN_DIR)/node_locations.inc $(PRISM_A_GEN_DIR)/prism_fuzz_compat.h $(PRISM_A_HEADERS) $(PRISM_A_STATE_DEP)
TEST_EXPLAIN_HARNESS_OBJS := $(addprefix $(TEST_BUILD_DIR)/obj/explain/,harness_explain.o harness_explain_analysis.o harness_explain_prettyprint.o harness_explain_json_digest.o)
TEST_EXPLAIN_ASAN_HARNESS_OBJS := $(addprefix $(TEST_BUILD_DIR)/obj/explain-asan/,harness_explain.o harness_explain_analysis.o harness_explain_prettyprint.o harness_explain_json_digest.o)
TEST_EXPLAIN_CFLAGS := -O1 -std=c99 -I$(PRISM_A_DIR)/include -I$(PRISM_A_GEN_DIR) -Iharnesses/prism -DPRISM_DEPTH_MAXIMUM=128 -DPM_INTEGER_DIVIDE_THRESHOLD=8
TEST_EXPLAIN_ASAN_CFLAGS := -O1 -std=c99 -Wall -Werror -Wextra -Wpedantic -Wundef -Wconversion -Wno-missing-braces -fsanitize=address,undefined -I$(PRISM_A_DIR)/include -I$(PRISM_A_GEN_DIR) -Iharnesses/prism -DPRISM_DEPTH_MAXIMUM=128 -DPM_INTEGER_DIVIDE_THRESHOLD=8

$(TEST_BUILD_DIR)/obj/explain/%.o: $(PRISM_A_DIR)/src/%.c $(PRISM_A_HEADERS) $(PRISM_A_STATE_DEP)
	$(Q) $(MAKEDIRS) $(@D)
	$(Q) $(TEST_CC) $(TEST_EXPLAIN_CFLAGS) -c $< -o $@

$(TEST_BUILD_DIR)/obj/explain/harness_explain.o: harnesses/prism/explain.c $(TEST_EXPLAIN_HARNESS_DEPS)
	$(Q) $(MAKEDIRS) $(@D)
	$(Q) $(TEST_CC) $(TEST_EXPLAIN_CFLAGS) -c $< -o $@

$(TEST_BUILD_DIR)/obj/explain/harness_explain_%.o: harnesses/prism/explain/%.c $(TEST_EXPLAIN_HARNESS_DEPS)
	$(Q) $(MAKEDIRS) $(@D)
	$(Q) $(TEST_CC) $(TEST_EXPLAIN_CFLAGS) -c $< -o $@

$(TEST_EXPLAIN_BIN): $(TEST_EXPLAIN_OBJS) $(TEST_EXPLAIN_HARNESS_OBJS)
	$(ECHO) "linking incremental test binary $@"
	$(Q) $(MAKEDIRS) $(@D)
	$(Q) $(TEST_CC) $^ -lm -o $@

$(TEST_BUILD_DIR)/obj/explain-asan/%.o: $(PRISM_A_DIR)/src/%.c $(PRISM_A_HEADERS) $(PRISM_A_STATE_DEP)
	$(Q) $(MAKEDIRS) $(@D)
	$(Q) $(TEST_CC) $(TEST_EXPLAIN_ASAN_CFLAGS) -c $< -o $@

$(TEST_BUILD_DIR)/obj/explain-asan/harness_explain.o: harnesses/prism/explain.c $(TEST_EXPLAIN_HARNESS_DEPS)
	$(Q) $(MAKEDIRS) $(@D)
	$(Q) $(TEST_CC) $(TEST_EXPLAIN_ASAN_CFLAGS) -c $< -o $@

$(TEST_BUILD_DIR)/obj/explain-asan/harness_explain_%.o: harnesses/prism/explain/%.c $(TEST_EXPLAIN_HARNESS_DEPS)
	$(Q) $(MAKEDIRS) $(@D)
	$(Q) $(TEST_CC) $(TEST_EXPLAIN_ASAN_CFLAGS) -c $< -o $@

$(TEST_EXPLAIN_ASAN_BIN): $(TEST_EXPLAIN_ASAN_OBJS) $(TEST_EXPLAIN_ASAN_HARNESS_OBJS)
	$(ECHO) "linking incremental test binary $@"
	$(Q) $(MAKEDIRS) $(@D)
	$(Q) $(TEST_CC) -fsanitize=address,undefined $^ -lm -o $@

TEST_EXPLAIN_ARM32_BIN := $(TEST_BUILD_DIR)/bin/fuzz.explain.arm32
$(TEST_EXPLAIN_ARM32_BIN): $(PRISM_A_SOURCES) $(TEST_EXPLAIN_HARNESS_SRCS) $(TEST_EXPLAIN_HARNESS_DEPS)
	$(ECHO) "linking incremental test binary $@"
	$(Q) rm -rf $(TEST_BUILD_DIR)/obj/explain-arm32 && $(MAKEDIRS) $(TEST_BUILD_DIR)/obj/explain-arm32 $(@D) && \
		objs="" && \
		for src in $(PRISM_A_SOURCES) $(TEST_EXPLAIN_HARNESS_SRCS); do \
			obj="$(TEST_BUILD_DIR)/obj/explain-arm32/$$(printf '%s' "$$src" | tr '/.' '__').o"; \
			clang --target=arm-linux-gnueabihf -isystem /usr/arm-linux-gnueabihf/include \
				-std=c99 -Wall -Werror -Wextra -Wpedantic -Wundef -Wconversion \
				-Wno-missing-braces -fvisibility=hidden -Wimplicit-fallthrough \
				$(TEST_EXPLAIN_CFLAGS) -Iharnesses/prism/include \
				-c "$$src" -o "$$obj" || exit $$?; \
			objs="$$objs $$obj"; \
		done && \
		arm-linux-gnueabihf-gcc -no-pie $$objs -lm -o $@ && \
		rm -rf $(TEST_BUILD_DIR)/obj/explain-arm32

# Dependency-tracked OSS-Fuzz build cache (ASan+UBSan and CmpLog targets)
TEST_OSS_FUZZ_DIR := $(TEST_BUILD_DIR)/oss-fuzz
TEST_OSS_FUZZ_SRC := $(TEST_OSS_FUZZ_DIR)/src-tmp
TEST_OSS_FUZZ_STAMP := $(TEST_OSS_FUZZ_DIR)/built.stamp
TEST_OSS_FUZZ_DEPS := $(PRISM_A_SOURCES) $(PRISM_A_HEADERS) $(PRISM_A_CONFIG_DEP) $(PRISM_A_STATE_DEP) harnesses/prism/parse.c harnesses/prism/fuzz.c harnesses/prism/include/fuzz_arena_unslab.h harnesses/prism/include/fuzz_options.h harnesses/prism/gen_node_locations.rb harnesses/prism/gen_api_compat.rb runtime/corpus.rb $(RUNTIME_TOPOLOGY_DEPS) dict/prism.dict oss-fuzz/build.sh oss-fuzz/project.yaml oss-fuzz/prism_parse_fuzzer.options oss-fuzz/prism_full_fuzzer.options

$(TEST_OSS_FUZZ_STAMP): $(TEST_OSS_FUZZ_DEPS)
	$(ECHO) "building OSS-Fuzz test binaries (ASan+UBSan and CmpLog)"
	$(Q) rm -rf $(TEST_OSS_FUZZ_DIR)/out $(TEST_OSS_FUZZ_DIR)/cmplog $(TEST_OSS_FUZZ_SRC) && \
		$(MAKEDIRS) $(TEST_OSS_FUZZ_DIR)/out $(TEST_OSS_FUZZ_DIR)/work $(TEST_OSS_FUZZ_DIR)/cmplog $(TEST_OSS_FUZZ_DIR)/cmplog-work $(TEST_OSS_FUZZ_SRC) && \
		cp -R $(PRISM_A_DIR) $(TEST_OSS_FUZZ_SRC)/prism && \
		cp -f oss-fuzz/build.sh oss-fuzz/*.options $(TEST_OSS_FUZZ_SRC)/ && \
		ln -s $(CURDIR) $(TEST_OSS_FUZZ_SRC)/prism-fuzzer && \
		src_abs="$(CURDIR)/$(TEST_OSS_FUZZ_SRC)" && \
		cflags="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address,undefined -fno-sanitize-recover=all -fsanitize=fuzzer-no-link" && \
		OUT="$(CURDIR)/$(TEST_OSS_FUZZ_DIR)/out" WORK="$(CURDIR)/$(TEST_OSS_FUZZ_DIR)/work" SRC="$$src_abs" CC="$(TEST_CC)" CXX="$(TEST_CXX)" CFLAGS="$$cflags" CXXFLAGS="$$cflags" LIB_FUZZING_ENGINE="-fsanitize=fuzzer" "$$src_abs/build.sh" >/dev/null && \
		OUT="$(CURDIR)/$(TEST_OSS_FUZZ_DIR)/cmplog" WORK="$(CURDIR)/$(TEST_OSS_FUZZ_DIR)/cmplog-work" SRC="$$src_abs" CC="$(TEST_CC)" CXX="$(TEST_CXX)" CFLAGS="$$cflags" CXXFLAGS="$$cflags" LIB_FUZZING_ENGINE="-fsanitize=fuzzer" AFL_LLVM_CMPLOG=1 "$$src_abs/build.sh" >/dev/null && \
		rm -rf $(TEST_OSS_FUZZ_SRC) $(TEST_OSS_FUZZ_DIR)/work $(TEST_OSS_FUZZ_DIR)/cmplog-work
	$(Q) touch $@

# ------------------------------------------------------------------------------
# Dependency-tracked test stage stamps
# ------------------------------------------------------------------------------

TEST_STAGE_ENV := env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL
TEST_TARGET_ENV := PRISM_A_DIR="$(PRISM_A_DIR)" PRISM_A_GEN_DIR="$(PRISM_A_GEN_DIR)"
define RUN_TEST_STAGE
	$(Q) $(MAKEDIRS) $(@D)
	$(Q) rm -f $@ && $(TEST_STAGE_ENV) $(1) && touch $@
endef

TARGETS_COMMON_DEPS := $(TEST_RUNNER_DEPS) bin/topology.rb bin/campaign.rb bin/publish.rb lib/prism_fuzzer.rb lib/ruby_fuzz.rb $(RUNTIME_TOPOLOGY_DEPS) $(RUNTIME_CAMPAIGN_DEPS) runtime/common.rb runtime/fuzz_header.rb runtime/campaign_dsl.rb runtime/progress.rb runtime/json_schema.rb runtime/provenance.rb runtime/run.sh runtime/kill.sh runtime/status.rb topology.schema.json campaigns/default.rb $(wildcard patches/prism/*.patch) $(REPORT_LIB_DEPS) report/coverage.sh triage/triage.rb triage/cluster.rb triage/inspect.rb triage/explain.rb triage/target_worktree.sh harnesses/prism/coverage.c harnesses/prism/build_diff.sh harnesses/prism/gen_node_locations.rb harnesses/prism/gen_api_compat.rb harnesses/prism/gen_serialize_walk.rb

$(TEST_STAMPS_DIR)/targets_sync_and_patches.stamp: test/targets/sync_and_patches_test.rb $(TARGETS_COMMON_DEPS)
	$(call RUN_TEST_STAGE,$(TEST_TARGET_ENV) ruby test/run.rb test/targets/sync_and_patches_test.rb)

$(TEST_STAMPS_DIR)/targets_consumers_and_dsl.stamp: test/targets/consumers_and_dsl_test.rb $(TARGETS_COMMON_DEPS)
	$(call RUN_TEST_STAGE,$(TEST_TARGET_ENV) ruby test/run.rb test/targets/consumers_and_dsl_test.rb)

$(TEST_STAMPS_DIR)/targets_workspace_and_coverage.stamp: test/targets/workspace_and_coverage_test.rb $(TARGETS_COMMON_DEPS)
	$(call RUN_TEST_STAGE,$(TEST_TARGET_ENV) ruby test/run.rb test/targets/workspace_and_coverage_test.rb)

$(TEST_STAMPS_DIR)/targets_runtime_tmux.stamp: test/targets/runtime_tmux_test.rb $(TARGETS_COMMON_DEPS)
	$(call RUN_TEST_STAGE,$(TEST_TARGET_ENV) ruby test/run.rb test/targets/runtime_tmux_test.rb)

$(TEST_STAMPS_DIR)/targets_launch_and_status.stamp: test/targets/launch_and_status_test.rb $(TARGETS_COMMON_DEPS) $(FUZZ_DIFF_DEPS)
	$(call RUN_TEST_STAGE,$(TEST_TARGET_ENV) ruby test/run.rb test/targets/launch_and_status_test.rb)

$(TEST_STAMPS_DIR)/targets_build_and_cross.stamp: test/targets/build_and_cross_test.rb $(TARGETS_COMMON_DEPS) Makefile test/tests.mk
	$(call RUN_TEST_STAGE,$(TEST_TARGET_ENV) ruby test/run.rb test/targets/build_and_cross_test.rb)

$(TEST_STAMPS_DIR)/prism_diff.stamp: test/prism_diff_test.rb $(TEST_RUNNER_DEPS) $(TEST_EXPLAIN_BIN) $(FUZZ_AFL_STAMP) $(PRISM_A_SOURCES) $(PRISM_A_HEADERS) $(PRISM_A_STATE_DEP) $(FUZZ_PRISM_DIFF_DEPS) harnesses/prism/explain.c harnesses/prism/gen_node_locations.rb harnesses/prism/gen_api_compat.rb $(TRIAGE_COMMON_DEPS) bin/publish.rb
	$(call RUN_TEST_STAGE,$(TEST_TARGET_ENV) PRISM_DIFF_EXPLAIN_A_BIN="$(CURDIR)/$(TEST_EXPLAIN_BIN)" ruby test/run.rb test/prism_diff_test.rb)

$(TEST_STAMPS_DIR)/afl_patch.stamp: test/test_afl_patch.sh $(FUZZ_AFL_STAMP) $(FUZZ_DOCKER_STAMP)
	$(call RUN_TEST_STAGE,./test/test_afl_patch.sh)

$(TEST_STAMPS_DIR)/sanitizers.stamp: test/sanitizers_test.rb $(TEST_RUNNER_DEPS) $(FUZZ_AFL_STAMP) $(PRISM_A_SOURCES) $(PRISM_A_HEADERS) $(PRISM_A_STATE_DEP) harnesses/prism/fuzz.c harnesses/prism/parse.c harnesses/prism/include/fuzz_arena_unslab.h harnesses/prism/include/prism_xallocator.h harnesses/prism/gen_node_locations.rb harnesses/prism/gen_api_compat.rb $(TRIAGE_COMMON_DEPS)
	$(call RUN_TEST_STAGE,$(TEST_TARGET_ENV) ruby test/run.rb test/sanitizers_test.rb)

$(TEST_STAMPS_DIR)/grammar.stamp: test/grammar_test.rb $(TEST_RUNNER_DEPS) runtime/grammar.rb runtime/grammar_bench.rb $(RUNTIME_TOPOLOGY_DEPS) $(shell find lib/lrama -type f 2>/dev/null) $(PRISM_A_STATE_DEP)
	$(call RUN_TEST_STAGE,$(TEST_TARGET_ENV) ruby test/run.rb test/grammar_test.rb)

$(TEST_STAMPS_DIR)/sankey.stamp: test/sankey_test.rb $(TEST_RUNNER_DEPS) $(REPORT_LIB_DEPS) triage/cluster.rb $(RUNTIME_TOPOLOGY_DEPS)
	$(call RUN_TEST_STAGE,ruby test/run.rb test/sankey_test.rb)

$(TEST_STAMPS_DIR)/accel_smoke.stamp: test/test_accel.sh $(TEST_ACCEL_BIN)
	$(call RUN_TEST_STAGE,$(TEST_TARGET_ENV) ACCEL_BIN="$(CURDIR)/$(TEST_ACCEL_BIN)" ACCEL_SKIP_BUILD=1 ./test/test_accel.sh --smoke)

$(TEST_STAMPS_DIR)/oss_fuzz.stamp: test/oss_fuzz_test.rb $(TEST_RUNNER_DEPS) $(TEST_OSS_FUZZ_STAMP) $(PRISM_A_SOURCES) $(PRISM_A_HEADERS) $(PRISM_A_CONFIG_DEP) $(PRISM_A_STATE_DEP) harnesses/prism/fuzz.c harnesses/prism/parse.c harnesses/prism/gen_node_locations.rb harnesses/prism/gen_api_compat.rb runtime/corpus.rb oss-fuzz/build.sh oss-fuzz/project.yaml oss-fuzz/prism_parse_fuzzer.options oss-fuzz/prism_full_fuzzer.options
	$(call RUN_TEST_STAGE,$(TEST_TARGET_ENV) OSS_FUZZ_SKIP_BUILD=1 OSS_FUZZ_OUT_DIR="$(CURDIR)/$(TEST_OSS_FUZZ_DIR)/out" OSS_FUZZ_CMPLOG_OUT_DIR="$(CURDIR)/$(TEST_OSS_FUZZ_DIR)/cmplog" ruby test/run.rb test/oss_fuzz_test.rb)

# Modular triage suites
$(TEST_STAMPS_DIR)/triage_signature.stamp: test/triage/signature_test.rb $(TEST_RUNNER_DEPS) triage/signature.sh triage/lib/signature.rb triage/halfempty.sh triage/halfempty_compare.sh
	$(call RUN_TEST_STAGE,$(TEST_TARGET_ENV) ruby test/run.rb test/triage/signature_test.rb)

$(TEST_STAMPS_DIR)/triage_repro.stamp: test/triage/repro_test.rb $(TEST_RUNNER_DEPS) triage/triage.rb triage/verify_bucket.sh triage/signature.sh bin/topology.rb lib/prism_fuzzer.rb $(RUNTIME_TOPOLOGY_DEPS) $(RUNTIME_CAMPAIGN_DEPS) runtime/campaign_dsl.rb runtime/progress.rb campaigns/default.rb harnesses/prism/include/fuzz_invariants.h harnesses/prism/include/fuzz_options.h harnesses/prism/parse.c harnesses/prism/gen_node_locations.rb harnesses/prism/gen_api_compat.rb harnesses/prism/gen_serialize_walk.rb runtime/corpus.rb $(PRISM_A_SOURCES) $(PRISM_A_HEADERS) $(PRISM_A_STATE_DEP)
	$(call RUN_TEST_STAGE,$(TEST_TARGET_ENV) ruby test/run.rb test/triage/repro_test.rb)

$(TEST_STAMPS_DIR)/triage_pipeline.stamp: test/triage/pipeline_test.rb $(TEST_RUNNER_DEPS) $(FUZZ_AFL_STAMP) $(TRIAGE_COMMON_DEPS) harnesses/prism/include/fuzz_options.h
	$(call RUN_TEST_STAGE,$(TEST_TARGET_ENV) ruby test/run.rb test/triage/pipeline_test.rb)

$(TEST_STAMPS_DIR)/triage_verify.stamp: test/triage/verify_test.rb $(TEST_RUNNER_DEPS) triage/verify_runner.c harnesses/prism/include/fuzz_invariants.h harnesses/prism/include/fuzz_options.h harnesses/prism/include/fuzz_json.h harnesses/prism/gen_node_locations.rb harnesses/prism/gen_api_compat.rb $(PRISM_A_SOURCES) $(PRISM_A_HEADERS) $(PRISM_A_STATE_DEP) $(TRIAGE_COMMON_DEPS)
	$(call RUN_TEST_STAGE,$(TEST_TARGET_ENV) REAL_VERIFY_BUILD_DIR="$(CURDIR)/$(TEST_BUILD_DIR)/verify/main" ruby test/run.rb test/triage/verify_test.rb)

$(TEST_STAMPS_DIR)/triage_cluster.stamp: test/triage/cluster_test.rb $(TEST_RUNNER_DEPS) triage/verify_runner.c $(TRIAGE_COMMON_DEPS)
	$(call RUN_TEST_STAGE,$(TEST_TARGET_ENV) ruby test/run.rb test/triage/cluster_test.rb)

$(TEST_STAMPS_DIR)/triage_retriage_match.stamp: test/triage/retriage_match_test.rb $(TEST_RUNNER_DEPS) $(FUZZ_AFL_STAMP) $(TRIAGE_COMMON_DEPS)
	$(call RUN_TEST_STAGE,$(TEST_TARGET_ENV) ruby test/run.rb test/triage/retriage_match_test.rb)

$(TEST_STAMPS_DIR)/triage_explain.stamp: test/triage/explain_test.rb $(TEST_RUNNER_DEPS) $(TEST_EXPLAIN_BIN) $(TEST_EXPLAIN_ARM32_BIN) $(TRIAGE_COMMON_DEPS) $(REPORT_LIB_DEPS) harnesses/prism/explain.c harnesses/prism/include/fuzz_invariants.h $(FUZZ_DOCKER_STAMP)
	$(call RUN_TEST_STAGE,$(TEST_TARGET_ENV) EXPLAIN_SUITE_BIN="$(CURDIR)/$(TEST_EXPLAIN_BIN)" EXPLAIN_ARM32_BIN="$(CURDIR)/$(TEST_EXPLAIN_ARM32_BIN)" ruby test/run.rb test/triage/explain_test.rb)

$(TEST_STAMPS_DIR)/triage_bisect.stamp: test/triage/bisect_test.rb $(TEST_RUNNER_DEPS) $(TRIAGE_COMMON_DEPS) triage/target_worktree.sh triage/verify_runner.c harnesses/prism/parse.c harnesses/prism/include/fuzz_invariants.h harnesses/prism/include/fuzz_options.h $(PRISM_A_SOURCES) $(PRISM_A_HEADERS) $(PRISM_A_STATE_DEP)
	$(call RUN_TEST_STAGE,$(TEST_TARGET_ENV) ruby test/run.rb test/triage/bisect_test.rb)

$(TEST_STAMPS_DIR)/triage_diff_parse_y.stamp: test/triage/diff_parse_y_test.rb $(TEST_RUNNER_DEPS) $(FUZZ_DIFF_DEPS) triage/verify_runner.c harnesses/prism/include/fuzz_options.h $(TRIAGE_COMMON_DEPS) $(PRISM_A_SOURCES) $(PRISM_A_HEADERS) $(PRISM_A_STATE_DEP) $(FUZZ_DOCKER_STAMP)
	$(call RUN_TEST_STAGE,$(TEST_TARGET_ENV) DIFF_VERIFY_BUILD_DIR="$(CURDIR)/$(TEST_BUILD_DIR)/verify/diff" DIFF_TC_ORACLE_DIR="$(CURDIR)/$(TEST_BUILD_DIR)/diff-oracle" COMPILE_VERIFY_BUILD_DIR="$(CURDIR)/$(TEST_BUILD_DIR)/verify/compile" COMPILE_TC_ORACLE_DIR="$(CURDIR)/$(TEST_BUILD_DIR)/compile-oracle" ruby test/run.rb test/triage/diff_parse_y_test.rb)

$(TEST_STAMPS_DIR)/triage_provenance.stamp: test/triage/provenance_test.rb $(TEST_RUNNER_DEPS) $(FUZZ_AFL_STAMP) $(TRIAGE_COMMON_DEPS) $(REPORT_LIB_DEPS) $(RUNTIME_CAMPAIGN_DEPS) lib/prism_fuzzer.rb runtime/campaign_dsl.rb runtime/progress.rb campaigns/default.rb Makefile test/tests.mk
	$(call RUN_TEST_STAGE,$(TEST_TARGET_ENV) ruby test/run.rb test/triage/provenance_test.rb)

$(TEST_STAMPS_DIR)/triage_oracle_explain.stamp: test/triage/oracle_explain_test.rb $(TEST_RUNNER_DEPS) $(TEST_EXPLAIN_ASAN_BIN) $(TRIAGE_COMMON_DEPS) triage/verify_runner.c harnesses/prism/mutator_oracle64.c harnesses/prism/explain.c harnesses/prism/include/fuzz_invariants.h harnesses/prism/include/fuzz_options.h harnesses/prism/include/fuzz_json.h $(PRISM_A_SOURCES) $(PRISM_A_HEADERS) $(PRISM_A_STATE_DEP)
	$(call RUN_TEST_STAGE,$(TEST_TARGET_ENV) CROSS_VERIFY_BUILD_BASE="$(CURDIR)/$(TEST_BUILD_DIR)/verify" TEST_EXPLAIN_ASAN_BIN="$(CURDIR)/$(TEST_EXPLAIN_ASAN_BIN)" ruby test/run.rb test/triage/oracle_explain_test.rb)

TEST_TARGETS_STAMPS := \
	$(TEST_STAMPS_DIR)/targets_sync_and_patches.stamp \
	$(TEST_STAMPS_DIR)/targets_consumers_and_dsl.stamp \
	$(TEST_STAMPS_DIR)/targets_workspace_and_coverage.stamp \
	$(TEST_STAMPS_DIR)/targets_runtime_tmux.stamp \
	$(TEST_STAMPS_DIR)/targets_launch_and_status.stamp \
	$(TEST_STAMPS_DIR)/targets_build_and_cross.stamp

TEST_TRIAGE_STAMPS := \
	$(TEST_STAMPS_DIR)/triage_signature.stamp \
	$(TEST_STAMPS_DIR)/triage_repro.stamp \
	$(TEST_STAMPS_DIR)/triage_pipeline.stamp \
	$(TEST_STAMPS_DIR)/triage_verify.stamp \
	$(TEST_STAMPS_DIR)/triage_cluster.stamp \
	$(TEST_STAMPS_DIR)/triage_retriage_match.stamp \
	$(TEST_STAMPS_DIR)/triage_explain.stamp \
	$(TEST_STAMPS_DIR)/triage_bisect.stamp \
	$(TEST_STAMPS_DIR)/triage_diff_parse_y.stamp \
	$(TEST_STAMPS_DIR)/triage_provenance.stamp \
	$(TEST_STAMPS_DIR)/triage_oracle_explain.stamp

TEST_ALL_STAMPS := \
	$(TEST_TARGETS_STAMPS) \
	$(TEST_STAMPS_DIR)/prism_diff.stamp \
	$(TEST_STAMPS_DIR)/afl_patch.stamp \
	$(TEST_STAMPS_DIR)/sanitizers.stamp \
	$(TEST_STAMPS_DIR)/grammar.stamp \
	$(TEST_STAMPS_DIR)/sankey.stamp \
	$(TEST_STAMPS_DIR)/accel_smoke.stamp \
	$(TEST_STAMPS_DIR)/oss_fuzz.stamp \
	$(TEST_TRIAGE_STAMPS)

_test-all: $(TEST_ALL_STAMPS)
	$(ECHO) "ALL DEPENDENCY-TRACKED TEST STAGES PASSED"

test-targets: $(TEST_TARGETS_STAMPS)
test-targets-%: $(TEST_STAMPS_DIR)/targets_%.stamp ;
test-prism-diff: $(TEST_STAMPS_DIR)/prism_diff.stamp
test-afl-patch: $(TEST_STAMPS_DIR)/afl_patch.stamp
test-sanitizers: $(TEST_STAMPS_DIR)/sanitizers.stamp
test-grammar: $(TEST_STAMPS_DIR)/grammar.stamp
test-sankey: $(TEST_STAMPS_DIR)/sankey.stamp
test-accel: $(TEST_STAMPS_DIR)/accel_smoke.stamp
test-oss-fuzz: $(TEST_STAMPS_DIR)/oss_fuzz.stamp
test-triage: $(TEST_TRIAGE_STAMPS)
test-triage-%: $(TEST_STAMPS_DIR)/triage_%.stamp ;

.PHONY: _test-all test-targets test-prism-diff test-afl-patch test-sanitizers test-grammar test-sankey test-accel test-oss-fuzz test-triage
