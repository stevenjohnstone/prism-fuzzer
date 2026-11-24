# prism-fuzzer Makefile — decoupled fuzzing harness for Prism & CRuby

CAMPAIGN ?= campaigns/default.rb
TOPOLOGY ?= $(CAMPAIGN)
PRISM_REF ?=
PRISM_REPO ?=
PRISM_DIR ?=
PRISM_PATCHES ?=
PRISM_TEMPLATES ?=
PRISM_B_REF ?=
PRISM_B_REPO ?=
PRISM_B_DIR ?=
PRISM_B_PATCHES ?=
PRISM_B_TEMPLATES ?=
RUBY_REF ?=
RUBY_REPO ?=
RUBY_DIR ?=
TARGETS_OFFLINE ?=

define _TARGETS_ENV_LIST
$(strip \
  $(if $(strip $(CAMPAIGN)),CAMPAIGN=$(strip $(CAMPAIGN)),) \
  $(if $(strip $(TOPOLOGY)),TOPOLOGY=$(strip $(TOPOLOGY)),) \
  $(if $(strip $(PRISM_REF)),PRISM_REF=$(strip $(PRISM_REF)),) \
  $(if $(strip $(PRISM_REPO)),PRISM_REPO=$(strip $(PRISM_REPO)),) \
  $(if $(strip $(PRISM_DIR)),PRISM_DIR=$(strip $(PRISM_DIR)),) \
  $(if $(strip $(PRISM_PATCHES)),PRISM_PATCHES=$(strip $(PRISM_PATCHES)),) \
  $(if $(strip $(PRISM_TEMPLATES)),PRISM_TEMPLATES=$(strip $(PRISM_TEMPLATES)),) \
  $(if $(strip $(PRISM_B_REF)),PRISM_B_REF=$(strip $(PRISM_B_REF)),) \
  $(if $(strip $(PRISM_B_REPO)),PRISM_B_REPO=$(strip $(PRISM_B_REPO)),) \
  $(if $(strip $(PRISM_B_DIR)),PRISM_B_DIR=$(strip $(PRISM_B_DIR)),) \
  $(if $(strip $(PRISM_B_PATCHES)),PRISM_B_PATCHES=$(strip $(PRISM_B_PATCHES)),) \
  $(if $(strip $(PRISM_B_TEMPLATES)),PRISM_B_TEMPLATES=$(strip $(PRISM_B_TEMPLATES)),) \
  $(if $(strip $(RUBY_REF)),RUBY_REF=$(strip $(RUBY_REF)),) \
  $(if $(strip $(RUBY_REPO)),RUBY_REPO=$(strip $(RUBY_REPO)),) \
  $(if $(strip $(RUBY_DIR)),RUBY_DIR=$(strip $(RUBY_DIR)),) \
  $(if $(strip $(TARGETS_OFFLINE)),TARGETS_OFFLINE=$(strip $(TARGETS_OFFLINE)),))
endef

TARGETS_ENV := $(_TARGETS_ENV_LIST)
TARGETS_DOCKER_ENV := $(foreach kv,$(_TARGETS_ENV_LIST),-e $(kv))

_WS_PATHS := $(shell $(TARGETS_ENV) ruby ./bin/topology.rb paths --topology "$(TOPOLOGY)" --relative 2>/dev/null)
_ws_val = $(or $(patsubst $(1)=%,%,$(filter $(1)=%,$(_WS_PATHS))),$(2))
_abs_or_curdir = $(if $(filter /%,$(1)),$(1),$(CURDIR)/$(1))

_WS_DIR_REL := $(call _ws_val,WORKSPACE_DIR,tmp/fuzz)
_WS_BUILD_REL := $(call _ws_val,WORKSPACE_BUILD_DIR,tmp/fuzz/build)
_WS_AFL_SUB := $(call _ws_val,WORKSPACE_AFL_SUBDIR,afl)
_WS_CORPUS_REL := $(call _ws_val,WORKSPACE_CORPUS_DIR,$(_WS_DIR_REL)/corpus)
_WS_REPORT_REL := $(call _ws_val,WORKSPACE_REPORT_DIR,$(_WS_DIR_REL)/report)
_WS_TRIAGE_REL := $(call _ws_val,WORKSPACE_TRIAGE_DIR,$(_WS_REPORT_REL)/triage)
_WS_COVERAGE_REL := $(call _ws_val,WORKSPACE_COVERAGE_DIR,$(_WS_REPORT_REL)/coverage)
_WS_REPORTS_REL := $(call _ws_val,WORKSPACE_REPORTS_DIR,reports)

FUZZ_DIR = $(call _abs_or_curdir,$(_WS_DIR_REL))
_FUZZ_DIR_OVR := $(filter-out file,$(origin FUZZ_DIR))
FUZZ_BUILD_DIR = $(if $(_FUZZ_DIR_OVR),$(FUZZ_DIR)/build,$(call _abs_or_curdir,$(_WS_BUILD_REL)))
FUZZ_AFL_DIR = $(FUZZ_DIR)/$(_WS_AFL_SUB)
FUZZ_BIN_DIR = $(FUZZ_DIR)/bin
FUZZ_CORPUS_DIR = $(if $(_FUZZ_DIR_OVR),$(FUZZ_DIR)/corpus,$(call _abs_or_curdir,$(_WS_CORPUS_REL)))
FUZZ_SEEDS_DIR = $(FUZZ_DIR)/seeds
FUZZ_REPORT_DIR = $(if $(_FUZZ_DIR_OVR),$(FUZZ_DIR)/report,$(call _abs_or_curdir,$(_WS_REPORT_REL)))
FUZZ_COVERAGE_DIR = $(if $(_FUZZ_DIR_OVR),$(FUZZ_REPORT_DIR)/coverage,$(call _abs_or_curdir,$(_WS_COVERAGE_REL)))
FUZZ_TRIAGE_DIR = $(if $(_FUZZ_DIR_OVR),$(FUZZ_REPORT_DIR)/triage,$(call _abs_or_curdir,$(_WS_TRIAGE_REL)))
REPORTS_DIR ?= $(call _abs_or_curdir,$(_WS_REPORTS_REL))

FUZZ_DOCKER_IMAGE ?= prism-fuzzer
FUZZ_CONTAINER_NAME ?= prism-fuzzer
FUZZ_TMPFS_FLAGS ?= --tmpfs /tmp:rw,exec,mode=1777
FUZZ_CCACHE_VOLUME ?= prism-fuzzer-ccache
FUZZ_CCACHE_FLAGS ?= $(if $(filter 0,$(FUZZ_CCACHE)),,-v $(FUZZ_CCACHE_VOLUME):/ccache)
JOBS ?=
_JOBS_DOCKER_ENV := $(if $(strip $(JOBS)),-e JOBS=$(strip $(JOBS)),)
RUBY_GIT_REF ?=

FUZZ_MAX_INPUT_SIZE ?= 1024
FUZZ_MAX_ALLOCATED ?= 128
FUZZ_FLAGS ?=
FUZZ_NO_POST ?=

_LIMITS_ENV := $(strip \
  $(if $(filter-out file,$(origin FUZZ_MAX_INPUT_SIZE)),FUZZ_MAX_INPUT_SIZE=$(FUZZ_MAX_INPUT_SIZE),) \
  $(if $(filter-out file,$(origin FUZZ_MAX_ALLOCATED)),FUZZ_MAX_ALLOCATED=$(FUZZ_MAX_ALLOCATED),))
_LIMITS_DOCKER_ENV := $(foreach kv,$(_LIMITS_ENV),-e $(kv))

_USER_PRISM_DIR := $(strip $(PRISM_DIR))
PRISM_A_DIR := $(or $(strip $(PRISM_A_DIR)),$(_USER_PRISM_DIR),$(FUZZ_BUILD_DIR)/targets/prism_a)
PRISM_A_GEN_DIR := $(or $(strip $(PRISM_A_GEN_DIR)),$(FUZZ_BUILD_DIR)/targets/gen/prism_a)

# Support external local checkouts and external topology files inside Docker.
_DOCKER_EXTRA_MOUNTS := $(shell $(TARGETS_ENV) ruby ./bin/topology.rb docker-args --topology "$(TOPOLOGY)" 2>/dev/null)

PRISM_A_SOURCES := $(sort $(wildcard $(PRISM_A_DIR)/src/*.c $(PRISM_A_DIR)/src/*/*.c))
PRISM_A_HEADERS := $(sort $(wildcard $(PRISM_A_DIR)/include/*.h $(PRISM_A_DIR)/include/prism/*.h $(PRISM_A_DIR)/include/prism/*/*.h))

FUZZ_DOCKER_STAMP := ./build/.fuzz.docker.stamp
FUZZ_AFL_STAMP := ./build/.fuzz.afl.stamp
IN_DOCKER := $(or $(wildcard /.dockerenv),$(wildcard /run/.containerenv))

ifneq ($(FUZZ_DAEMON),)
FUZZ_RUN_DOCKER_FLAGS := -d --name $(FUZZ_CONTAINER_NAME) -e FUZZ_DAEMON=1
else
FUZZ_RUN_DOCKER_FLAGS := -it --name $(FUZZ_CONTAINER_NAME)
endif

Q ?= @
ECHO ?= @echo
MAKEDIRS ?= mkdir -p

all: build

docker-force: ;

docker-build: $(FUZZ_DOCKER_STAMP)
	$(ECHO) "Docker image '$(FUZZ_DOCKER_IMAGE)' is up to date"

$(FUZZ_DOCKER_STAMP): docker/Dockerfile $(if $(strip $(RUBY_GIT_REF)),docker-force,)
	$(Q) FUZZ_DOCKER_IMAGE="$(FUZZ_DOCKER_IMAGE)" RUBY_GIT_REF="$(RUBY_GIT_REF)" \
		ruby ./bin/campaign.rb docker-build --build-dir "$(FUZZ_BUILD_DIR)" $(if $(strip $(RUBY_GIT_REF)),--force,) && \
		$(MAKEDIRS) $(@D) && touch $@

docker-update:
	$(ECHO) "resolving mainline Prism and CRuby HEAD from ruby/prism and ruby/ruby"
	$(Q) prism_rev="$$(git ls-remote https://github.com/ruby/prism.git refs/heads/main | awk 'NR==1 { print $$1 }')"; \
		ruby_rev="$$(git ls-remote https://github.com/ruby/ruby.git refs/heads/master | awk 'NR==1 { print $$1 }')"; \
		test -n "$$prism_rev" || { echo "Failed to resolve ruby/prism main SHA" >&2; exit 1; }; \
		test -n "$$ruby_rev" || { echo "Failed to resolve ruby/ruby master SHA" >&2; exit 1; }; \
		ruby -e 'df, prism_rev, ruby_rev, *tfs = ARGV; \
			s = File.read(df); cur = s[/^ARG RUBY_GIT_REF=(.*)/, 1] or abort("ARG RUBY_GIT_REF not found in #{df}"); \
			if cur.strip != ruby_rev then s.sub!(/^ARG RUBY_GIT_REF=.*/, "ARG RUBY_GIT_REF=#{ruby_rev}"); File.write(df, s); puts("Updated #{df} RUBY_GIT_REF: #{cur} -> #{ruby_rev}") else puts("#{df} already pinned to #{ruby_rev}") end; \
			tfs.each do |tf| \
				ts = File.read(tf); tcur = ts[/^DEFAULT_PRISM_REF = "([^"]+)"/, 1] or next; \
				if tcur != prism_rev then ts.sub!(/^DEFAULT_PRISM_REF = "[^"]+"/, "DEFAULT_PRISM_REF = \"#{prism_rev}\""); File.write(tf, ts); puts("Updated #{tf} DEFAULT_PRISM_REF -> #{prism_rev}") else puts("#{tf} already pinned to #{prism_rev}") end; \
				ts = File.read(tf); tcur = ts[/^DEFAULT_RUBY_REF = "([^"]+)"/, 1] or next; \
				if tcur != ruby_rev then ts.sub!(/^DEFAULT_RUBY_REF = "[^"]+"/, "DEFAULT_RUBY_REF = \"#{ruby_rev}\""); File.write(tf, ts); puts("Updated #{tf} DEFAULT_RUBY_REF -> #{ruby_rev}") else puts("#{tf} already pinned to #{ruby_rev}") end; \
			end' docker/Dockerfile "$$prism_rev" "$$ruby_rev" campaigns/*.rb && \
		$(MAKE) docker-build RUBY_GIT_REF="$$ruby_rev"

targets-sync topology-sync:
	$(Q) $(TARGETS_ENV) ruby ./bin/topology.rb sync --topology "$(TOPOLOGY)" $(TARGETS_ARGS)

ruby-sync:
ifeq ($(IN_DOCKER),)
	$(Q) $(MAKE) docker-build
	$(Q) docker run --rm $(FUZZ_TMPFS_FLAGS) $(TARGETS_DOCKER_ENV) $(_DOCKER_EXTRA_MOUNTS) -v $(CURDIR):/prism-fuzzer $(FUZZ_DOCKER_IMAGE) ruby ./bin/topology.rb sync-ruby --topology "$(TOPOLOGY)" $(TARGETS_ARGS)
else
	$(Q) $(TARGETS_ENV) ruby ./bin/topology.rb sync-ruby --topology "$(TOPOLOGY)" $(TARGETS_ARGS)
endif

targets-status topology-status:
	$(Q) $(TARGETS_ENV) ruby ./bin/topology.rb status --topology "$(TOPOLOGY)"

topology-plan:
	$(Q) $(TARGETS_ENV) ruby ./bin/topology.rb plan --topology "$(TOPOLOGY)"

topology-validate:
	$(Q) $(TARGETS_ENV) ruby ./bin/topology.rb validate --topology "$(TOPOLOGY)"

$(FUZZ_AFL_STAMP): patches/afl/aflplusplus.patch patches/afl/aflplusplus_ppc.patch
	$(Q) ruby ./bin/campaign.rb ensure-afl-passes
	$(Q) $(MAKEDIRS) $(@D) && touch $@

$(_WS_BUILD_REL)/fuzz.explain:
	$(Q) $(TARGETS_ENV) ruby ./bin/topology.rb build-explain --topology "$(TOPOLOGY)" --build-dir "$(FUZZ_BUILD_DIR)" --arch host --output $@

$(_WS_BUILD_REL)/fuzz.explain.b:
	$(Q) $(TARGETS_ENV) ruby ./bin/topology.rb build-explain --topology "$(TOPOLOGY)" --build-dir "$(FUZZ_BUILD_DIR)" --arch host --source prism_b --output $@

$(_WS_BUILD_REL)/fuzz.explain.arm32:
	$(Q) $(TARGETS_ENV) ruby ./bin/topology.rb build-explain --topology "$(TOPOLOGY)" --build-dir "$(FUZZ_BUILD_DIR)" --arch arm32 --output $@

$(_WS_BUILD_REL)/fuzz.explain.ppc:
	$(Q) $(TARGETS_ENV) ruby ./bin/topology.rb build-explain --topology "$(TOPOLOGY)" --build-dir "$(FUZZ_BUILD_DIR)" --arch ppc --output $@

_build-all: $(FUZZ_AFL_STAMP)
	$(Q) $(TARGETS_ENV) $(_LIMITS_ENV) FUZZ_FLAGS="$(FUZZ_FLAGS)" \
		ruby ./bin/topology.rb build --topology "$(TOPOLOGY)"

build:
ifeq ($(IN_DOCKER),)
	$(Q) $(MAKE) docker-build targets-sync
	$(Q) docker run --rm $(FUZZ_TMPFS_FLAGS) $(FUZZ_CCACHE_FLAGS) $(TARGETS_DOCKER_ENV) $(_DOCKER_EXTRA_MOUNTS) $(_LIMITS_DOCKER_ENV) $(_JOBS_DOCKER_ENV) -e FUZZ_FLAGS="$(FUZZ_FLAGS)" -e FUZZ_IMAGE_ID="$$(docker image inspect -f '{{.Id}}' $(FUZZ_DOCKER_IMAGE) 2>/dev/null || true)" -v $(CURDIR):/prism-fuzzer $(FUZZ_DOCKER_IMAGE) make _build-all
else
	$(Q) $(MAKE) targets-sync
	$(Q) $(MAKE) _build-all
endif

run:
ifeq ($(IN_DOCKER),)
	$(Q) $(MAKE) build
	$(ECHO) "starting AFL++ run"
	$(Q) $(MAKEDIRS) $(FUZZ_AFL_DIR) $(FUZZ_BIN_DIR)
	$(Q) docker run $(FUZZ_RUN_DOCKER_FLAGS) --init --rm $(FUZZ_TMPFS_FLAGS) $(TARGETS_DOCKER_ENV) $(_DOCKER_EXTRA_MOUNTS) $(_LIMITS_DOCKER_ENV) -e FUZZ_DIFF_BACKTRACE -e FUZZ_IMAGE_ID="$$(docker image inspect -f '{{.Id}}' $(FUZZ_DOCKER_IMAGE) 2>/dev/null || true)" -v $(CURDIR):/prism-fuzzer $(FUZZ_DOCKER_IMAGE) /bin/bash -c "exec ./runtime/run.sh"
ifneq ($(FUZZ_DAEMON),)
	$(ECHO) "Fuzzer daemon started in container '$(FUZZ_CONTAINER_NAME)'."
	$(ECHO) "Attach to tmux with: make attach"
	$(ECHO) "Stop the daemon with: make stop"
else ifeq ($(strip $(FUZZ_NO_POST)),)
	$(Q) $(MAKE) _report
endif
else
	$(Q) $(MAKE) build
	$(Q) $(MAKEDIRS) $(FUZZ_AFL_DIR) $(FUZZ_BIN_DIR)
	$(Q) exec ./runtime/run.sh
endif

daemon:
	$(Q) $(MAKE) run FUZZ_DAEMON=1

attach:
	$(Q) docker exec -it $(FUZZ_CONTAINER_NAME) tmux -2 attach-session -t fuzzer

stop:
	$(Q) docker stop $(FUZZ_CONTAINER_NAME)

debug: docker-build
	$(ECHO) "entering debug shell"
	$(Q) $(MAKEDIRS) $(FUZZ_DIR)
	$(Q) docker run -it --rm $(FUZZ_TMPFS_FLAGS) $(TARGETS_DOCKER_ENV) $(_DOCKER_EXTRA_MOUNTS) -e HISTFILE=$(if $(filter /%,$(_WS_DIR_REL)),/external/ws_dir,/prism-fuzzer/$(_WS_DIR_REL))/.bash_history -v $(CURDIR):/prism-fuzzer $(FUZZ_DOCKER_IMAGE)

define FUZZ_RUN_TRIAGE
( \
	if [ -t 1 ]; then DOCKER_ARGS="-it"; fi; \
	docker run $${DOCKER_ARGS} --init --rm $(FUZZ_TMPFS_FLAGS) $(TARGETS_DOCKER_ENV) $(_DOCKER_EXTRA_MOUNTS) -e TRIAGE_MINIMIZE -e TRIAGE_RECOUNT -e TRIAGE_THREADS -e TRIAGE_COVERAGE_BIN -e TRIAGE_COVERAGE_IDS -e TRIAGE_DIFF_COVERAGE_BIN -e TRIAGE_DIFF_COVERAGE_IDS -e TRIAGE_CORPUS_DIR -e TRIAGE_LIVE_SCRIPTS -e FUZZ_HARNESS_DIR $(_LIMITS_DOCKER_ENV) -e FUZZ_IMAGE_ID="$$(docker image inspect -f '{{.Id}}' $(FUZZ_DOCKER_IMAGE) 2>/dev/null || true)" -e HISTFILE=/prism-fuzzer/$(_WS_DIR_REL)/.bash_history -v $(CURDIR):/prism-fuzzer $(FUZZ_DOCKER_IMAGE) /bin/bash -c 'if [ "$${TRIAGE_LIVE_SCRIPTS:-0}" != "1" ] && [ -f "./$(_WS_DIR_REL)/snapshot/triage/triage.rb" ]; then exec ruby ./$(_WS_DIR_REL)/snapshot/triage/triage.rb; else exec ruby ./triage/triage.rb; fi' \
)
endef

retriage: docker-build targets-sync
	@if [ -t 1 ]; then DOCKER_ARGS="-it"; fi; \
	docker run $${DOCKER_ARGS} --init --rm $(FUZZ_TMPFS_FLAGS) $(TARGETS_DOCKER_ENV) $(_DOCKER_EXTRA_MOUNTS) -e TRIAGE_DIR -e CLUSTER -e CLUSTERS_FILE -e BUCKET -e REASON -e VERIFY_TIMEOUT -e VERIFY_UNREPRODUCIBLE -e VERIFY_REBUILD -e VERIFY_VERBOSE -e VERIFY_QUIET -e TRIAGE_MINIMIZE -e TRIAGE_THREADS -e TRIAGE_COVERAGE_BIN -e TRIAGE_COVERAGE_IDS -e TRIAGE_DIFF_COVERAGE_BIN -e TRIAGE_DIFF_COVERAGE_IDS -e TRIAGE_CORPUS_DIR -e RETRIAGE_BUILD -e RETRIAGE_DRY_RUN -e FUZZ_FLAGS="$(FUZZ_FLAGS)" $(_LIMITS_DOCKER_ENV) -e FUZZ_IMAGE_ID="$$(docker image inspect -f '{{.Id}}' $(FUZZ_DOCKER_IMAGE) 2>/dev/null || true)" -e HISTFILE=/prism-fuzzer/$(_WS_DIR_REL)/.bash_history -v $(CURDIR):/prism-fuzzer $(FUZZ_DOCKER_IMAGE) ruby ./triage/retriage.rb $(RETRIAGE_ARGS)

FUZZ_VERIFY_ENV_FLAGS := -e TRIAGE_DIR -e CLUSTER -e CLUSTERS_FILE -e BY_CLUSTER -e BUCKET -e REASON -e VERIFY_TIMEOUT -e VERIFY_MAX_FAILURES -e VERIFY_EXTRACT_SURVIVORS -e VERIFY_INPUT_MIN_ONLY -e VERIFY_SKIP_MIN -e VERIFY_UNREPRODUCIBLE -e VERIFY_REBUILD -e VERIFY_SYMBOLIZE -e VERIFY_FAIL_FAST -e VERIFY_INVERT -e VERIFY_BISECT -e VERIFY_VERBOSE -e VERIFY_QUIET $(_LIMITS_DOCKER_ENV)

verify: docker-build targets-sync
	@if [ -t 1 ]; then DOCKER_ARGS="-it"; fi; \
	docker run $${DOCKER_ARGS} --init --rm $(FUZZ_TMPFS_FLAGS) $(FUZZ_VERIFY_ENV_FLAGS) $(TARGETS_DOCKER_ENV) $(_DOCKER_EXTRA_MOUNTS) -v $(CURDIR):/prism-fuzzer $(FUZZ_DOCKER_IMAGE) ruby ./triage/verify.rb $(VERIFY_ARGS)

bisect: docker-build
	$(Q) FUZZ_DOCKER_IMAGE="$(FUZZ_DOCKER_IMAGE)" FUZZ_TMPFS_FLAGS="$(FUZZ_TMPFS_FLAGS)" $(_LIMITS_ENV) $(TARGETS_ENV) ruby ./triage/bisect.rb $(BISECT_ARGS)

match: docker-build
	@if [ -t 0 ] && [ -t 1 ]; then DOCKER_ARGS="-it"; else DOCKER_ARGS="-i"; fi; \
	docker run $${DOCKER_ARGS} --init --rm $(FUZZ_TMPFS_FLAGS) $(TARGETS_DOCKER_ENV) $(_DOCKER_EXTRA_MOUNTS) -e TRIAGE_DIR -e CLUSTER -e CLUSTERS_FILE -e TRIAGE_COVERAGE_BIN -e TRIAGE_COVERAGE_IDS -e TRIAGE_DIFF_COVERAGE_BIN -e TRIAGE_DIFF_COVERAGE_IDS $(_LIMITS_DOCKER_ENV) -v $(CURDIR):/prism-fuzzer $(FUZZ_DOCKER_IMAGE) ruby ./triage/match.rb $(MATCH_ARGS)

explain: build
	$(Q) FUZZ_DOCKER_IMAGE="$(FUZZ_DOCKER_IMAGE)" TRIAGE_DIR="$(or $(TRIAGE_DIR),$(_WS_TRIAGE_REL))" CLUSTER="$(CLUSTER)" BUCKET="$(BUCKET)" CLUSTERS_FILE="$(CLUSTERS_FILE)" EXPLAIN_BIN="$(FUZZ_BUILD_DIR)/fuzz.explain" EXPLAIN_B_BIN="$(FUZZ_BUILD_DIR)/fuzz.explain.b" FUZZ_TMPFS_FLAGS="$(FUZZ_TMPFS_FLAGS)" $(TARGETS_ENV) ruby ./triage/explain.rb $(EXPLAIN_ARGS)

inspect:
	$(Q) ruby ./triage/inspect.rb --triage-dir $(FUZZ_TRIAGE_DIR) $(INSPECT_ARGS)

define FUZZ_RUN_COVERAGE
( \
	LIVE_SEEDS_TAR=""; \
	GUEST_LIVE_SEEDS_TAR=""; \
	COV_LIVE="$${FUZZ_COVERAGE_LIVE:-}"; \
	COV_FINAL="$${FUZZ_COVERAGE_FINAL:-}"; \
	trap 'rc=$$?; rm -f "$$LIVE_SEEDS_TAR"; exit $$rc' EXIT; \
	trap 'exit 130' INT; \
	trap 'exit 143' TERM; \
	if [ -n "$$(docker ps -q -f name="^/$(FUZZ_CONTAINER_NAME)$$" 2>/dev/null)" ]; then \
		mkdir -p $(FUZZ_DIR); \
		[ -n "$$COV_LIVE" ] || COV_LIVE=1; \
		eval "$$($(TARGETS_ENV) FUZZ_DIR="$(if $(_FUZZ_DIR_OVR),$(FUZZ_DIR),)" FUZZ_CONTAINER_NAME="$(FUZZ_CONTAINER_NAME)" ruby -r./runtime/campaign -e 'puts PrismFuzzer::Campaign.capture_live_seeds_shell_env' 2>/dev/null || true)"; \
	else \
		[ -n "$$COV_FINAL" ] || COV_FINAL=1; \
	fi; \
	docker run --rm $(FUZZ_TMPFS_FLAGS) $(FUZZ_CCACHE_FLAGS) $(TARGETS_DOCKER_ENV) $(_DOCKER_EXTRA_MOUNTS) $(_JOBS_DOCKER_ENV) -e FUZZ_CCACHE="$(FUZZ_CCACHE)" -e FUZZ_FLAGS="$(FUZZ_FLAGS)" -e FUZZ_COVERAGE_NO_CACHE -e FUZZ_COVERAGE_CACHE_DIR -e FUZZ_COVERAGE_LIVE="$$COV_LIVE" -e FUZZ_COVERAGE_FINAL="$$COV_FINAL" -e FUZZ_IMAGE_ID="$$(docker image inspect -f '{{.Id}}' $(FUZZ_DOCKER_IMAGE) 2>/dev/null || true)" -e FUZZ_LIVE_SEEDS_TAR="$$GUEST_LIVE_SEEDS_TAR" -v $(CURDIR):/prism-fuzzer $(FUZZ_DOCKER_IMAGE) ./report/coverage.sh \
)
endef

_report:
	$(ECHO) "triaging findings"
	@$(FUZZ_RUN_TRIAGE)
	$(ECHO) "generating campaign report"
	@will_cov=""; \
	if [ -z "$(FUZZ_SKIP_COVERAGE)" ] && [ -d "$(FUZZ_AFL_DIR)" ]; then \
		if [ -d "$(FUZZ_DIR)/.coverage-cache" ] || [ ! -f "$(FUZZ_COVERAGE_DIR)/coverage.json" ] || [ -n "$$(find $(FUZZ_DIR) -maxdepth 4 \( -name 'queue' -o -name 'crashes' -o -name 'hangs' \) -newer $(FUZZ_COVERAGE_DIR)/coverage.json -print -quit 2>/dev/null)" ] || [ -n "$$(find $(FUZZ_SEEDS_DIR) -newer $(FUZZ_COVERAGE_DIR)/coverage.json -print -quit 2>/dev/null)" ]; then \
			will_cov="--coverage-pending"; \
		fi; \
	fi; \
	ruby ./report/report.rb $(FUZZ_AFL_DIR) $(FUZZ_REPORT_DIR)/index.html $(FUZZ_COVERAGE_DIR)/coverage.json --triage-dir $(FUZZ_TRIAGE_DIR) $$will_cov $(REPORT_ARGS); \
	if [ -n "$$will_cov" ]; then \
		echo "collecting coverage (set FUZZ_SKIP_COVERAGE=1 to skip)"; \
		$(FUZZ_RUN_COVERAGE); \
		ruby ./report/report.rb $(FUZZ_AFL_DIR) $(FUZZ_REPORT_DIR)/index.html $(FUZZ_COVERAGE_DIR)/coverage.json --triage-dir $(FUZZ_TRIAGE_DIR) $(REPORT_ARGS); \
	fi

report: docker-build targets-sync _report

coverage: docker-build targets-sync
	$(ECHO) "collecting coverage"
	@$(FUZZ_RUN_COVERAGE)
	@if [ -f "$(FUZZ_REPORT_DIR)/index.html" ]; then \
		ruby ./report/report.rb $(FUZZ_AFL_DIR) $(FUZZ_REPORT_DIR)/index.html $(FUZZ_COVERAGE_DIR)/coverage.json --triage-dir $(FUZZ_TRIAGE_DIR) $(REPORT_ARGS); \
	fi

pages-worktree:
	$(ECHO) "ensuring gh-pages worktree at $(REPORTS_DIR)"
	$(Q) ruby ./bin/publish.rb --init --gh-pages --out-dir $(REPORTS_DIR)

publish:
	$(ECHO) "publishing reports to $(REPORTS_DIR)"
	$(Q) ruby ./bin/publish.rb --report-dir $(FUZZ_REPORT_DIR) --triage-dir $(FUZZ_TRIAGE_DIR) --coverage-dir $(FUZZ_COVERAGE_DIR) --bin-dir $(FUZZ_BIN_DIR) --out-dir $(REPORTS_DIR) $(PUBLISH_ARGS)

bench: docker-build targets-sync
	$(ECHO) "benchmarking grammar seed generator"
	$(Q) $(MAKEDIRS) $(FUZZ_DIR)
	$(Q) docker run --rm $(FUZZ_TMPFS_FLAGS) $(TARGETS_DOCKER_ENV) $(_DOCKER_EXTRA_MOUNTS) -v $(CURDIR):/prism-fuzzer $(FUZZ_DOCKER_IMAGE) ruby ./runtime/grammar_bench.rb --json $(_WS_DIR_REL)/grammar-bench.json $(GRAMMAR_BENCH_ARGS)

accel: docker-build targets-sync
	$(ECHO) "running SIMD vs SWAR differential accel fuzzer"
	$(Q) $(MAKEDIRS) $(FUZZ_DIR)
	$(Q) docker run --rm $(FUZZ_TMPFS_FLAGS) $(TARGETS_DOCKER_ENV) $(_DOCKER_EXTRA_MOUNTS) -e ACCEL_TIME -e ACCEL_FUZZ_ARGS -e ACCEL_BIN -e ACCEL_ARTIFACT_DIR -v $(CURDIR):/prism-fuzzer $(FUZZ_DOCKER_IMAGE) ./test/test_accel.sh

TEST_JOBS ?=
TEST_FORCE ?= 0

test-clean:
	$(ECHO) "Removing cached test build artifacts and stage stamps under build/test/"
	$(Q) rm -rf build/test build/oss-fuzz-gen

ifeq ($(IN_DOCKER),)
test:
	$(Q) $(MAKE) docker-build targets-sync
	$(Q) if [ "$(TEST_FORCE)" = "1" ]; then rm -f build/test/stamps/*.stamp; fi
	$(ECHO) "running dependency-tracked prism-fuzzer test suite inside container"
	$(Q) docker run --rm $(FUZZ_TMPFS_FLAGS) $(TARGETS_DOCKER_ENV) $(_DOCKER_EXTRA_MOUNTS) -v $(CURDIR):/prism-fuzzer $(FUZZ_DOCKER_IMAGE) /bin/bash -c "jobs='$(TEST_JOBS)'; [ -n \"\$$jobs\" ] || jobs=\"\$$(nproc 2>/dev/null || echo 4)\"; make $(FUZZ_AFL_STAMP) && make -j\"\$$jobs\" _test-all"

test-targets test-prism-diff test-afl-patch test-grammar test-sankey test-accel test-oss-fuzz test-triage:
	$(Q) $(MAKE) docker-build targets-sync
	$(Q) if [ "$(TEST_FORCE)" = "1" ]; then rm -f build/test/stamps/*.stamp; fi
	$(Q) docker run --rm $(FUZZ_TMPFS_FLAGS) $(TARGETS_DOCKER_ENV) $(_DOCKER_EXTRA_MOUNTS) -v $(CURDIR):/prism-fuzzer $(FUZZ_DOCKER_IMAGE) /bin/bash -c "jobs='$(TEST_JOBS)'; [ -n \"\$$jobs\" ] || jobs=\"\$$(nproc 2>/dev/null || echo 4)\"; make $(FUZZ_AFL_STAMP) && make -j\"\$$jobs\" $@"

test-targets-% test-triage-%:
	$(Q) $(MAKE) docker-build targets-sync
	$(Q) if [ "$(TEST_FORCE)" = "1" ]; then rm -f build/test/stamps/*.stamp; fi
	$(Q) docker run --rm $(FUZZ_TMPFS_FLAGS) $(TARGETS_DOCKER_ENV) $(_DOCKER_EXTRA_MOUNTS) -v $(CURDIR):/prism-fuzzer $(FUZZ_DOCKER_IMAGE) /bin/bash -c "jobs='$(TEST_JOBS)'; [ -n \"\$$jobs\" ] || jobs=\"\$$(nproc 2>/dev/null || echo 4)\"; make $(FUZZ_AFL_STAMP) && make -j\"\$$jobs\" $@"
else
include test/tests.mk

test:
	$(Q) if [ "$(TEST_FORCE)" = "1" ]; then rm -f build/test/stamps/*.stamp; fi
	$(Q) $(MAKE) $(FUZZ_AFL_STAMP)
	$(Q) $(MAKE) -j$(or $(strip $(TEST_JOBS)),$(shell nproc 2>/dev/null || echo 4)) _test-all
endif

test-oss-fuzz-docker:
	$(Q) TEST_OSS_FUZZ_DOCKER=1 ruby test/run.rb --docker-only --suite oss_fuzz

clean:
	$(ECHO) "Removing runtime files under $(_WS_DIR_REL)/ (preserving report/triage/, build/)"
	$(Q) ruby -r./runtime/campaign -e 'PrismFuzzer::Campaign.clean_preserving_paths(ARGV[0], ARGV[1..])' "$(FUZZ_DIR)" "$(FUZZ_BUILD_DIR)" "$(FUZZ_TRIAGE_DIR)"
	$(ECHO) "done"

.PHONY: all docker-force docker-build docker-update targets-sync topology-sync ruby-sync targets-status topology-status topology-plan topology-validate _build-all build run daemon attach stop debug retriage verify bisect match explain inspect _report report coverage pages-worktree publish bench accel test test-clean test-targets test-prism-diff test-afl-patch test-grammar test-sankey test-accel test-oss-fuzz test-oss-fuzz-docker test-triage clean
