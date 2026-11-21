# OSS-Fuzz builder image for ruby/prism (mirrors test/fuzz/oss-fuzz/).
FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y --no-install-recommends ruby zip && rm -rf /var/lib/apt/lists/*
ARG PRISM_FUZZER_REPO=""
ARG PRISM_FUZZER_REF="main"
ARG RUBY_FUZZ_REPO=""
ARG RUBY_FUZZ_REF="main"
RUN git clone --depth 1 https://github.com/ruby/prism.git prism \
    && _fuzz_repo="${PRISM_FUZZER_REPO:-$RUBY_FUZZ_REPO}" \
    && _fuzz_ref="${PRISM_FUZZER_REF:-$RUBY_FUZZ_REF}" \
    && if [ ! -f prism/test/fuzz/harness/parse.c ] && [ -n "$_fuzz_repo" ]; then \
         git clone --depth 1 --branch "$_fuzz_ref" "$_fuzz_repo" prism-fuzzer; \
       fi
WORKDIR prism
COPY build.sh *.options $SRC/

