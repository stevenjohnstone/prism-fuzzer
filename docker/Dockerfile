FROM aflplusplus/aflplusplus:v5.03c

ARG USERNAME=ubuntu
ARG USER_UID=1000
ARG USER_GID=$USER_UID
ENV MAKEFLAGS=-j8
ENV LC_CTYPE=C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
        sudo \
        libglib2.0-dev \
        libyaml-dev \
        libz-dev \
        libssl-dev \
        python3 \
        unzip \
        tmux \
        xxhash \
        autoconf \
        bison \
        gperf \
        bsdextrautils \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME \
    && rm -rf /var/lib/apt/lists/*

# Guard g_close(task->fd, NULL) against task->fd == -1 so GLib >= 2.76 does not
# raise G_CRITICAL / SIGTRAP when halfempty cleans up already-closed task fds.
ARG HALFEMPTY_COMMIT=ad15964d0fcaba12e5aca65c8935ebe3f37d7ea3
RUN git clone https://github.com/googleprojectzero/halfempty \
    && cd halfempty \
    && git checkout "${HALFEMPTY_COMMIT}" \
    && grep -qF 'g_close(task->fd, NULL);' tree.c \
    && sed -i 's/g_close(task->fd, NULL);/if (task->fd != -1) g_close(task->fd, NULL);/' tree.c \
    && grep -qF 'if (task->fd != -1) g_close(task->fd, NULL);' tree.c \
    && make \
    && cp halfempty /usr/bin/ \
    && cd / \
    && rm -rf halfempty

ENV PATH="/usr/lib/llvm-${LLVM_VERSION}/bin:${PATH}"

# Install 32-bit cross-toolchains and QEMU user emulators before building CRuby
# so bumping RUBY_GIT_REF preserves cached apt/toolchain Docker layers.
RUN apt-get update && apt-get install -y --no-install-recommends \
        qemu-user \
        gcc-arm-linux-gnueabihf \
        libc6-dev-armhf-cross \
        libubsan1-armhf-cross \
        libasan8-armhf-cross \
        gcc-powerpc-linux-gnu \
        libc6-dev-powerpc-cross \
        libubsan1-powerpc-cross \
        libasan8-powerpc-cross \
    && rm -rf /var/lib/apt/lists/*

# Pin explicit ruby/ruby and ruby/prism commit SHAs (or override with
# RUBY_GIT_REF=... / PRISM_GIT_REF=...). Syncing mainline Prism into CRuby
# ensures `ruby --parser=prism` and `ruby -rprism` in the container match the
# upstream Prism target under test.
# Targets at other refs can also be built incrementally into build/targets/ruby/.
ARG RUBY_GIT_REF=0d399335b733776187e43a783e5f950c18ad881c
ARG PRISM_GIT_REF=a5e01d818fa45f2cea9232754251a6855f82ab98
ENV RUBY_ORACLE_DIR=/opt/ruby
COPY docker/sync_prism_into_ruby.rb /tmp/sync_prism_into_ruby.rb
RUN apt-get update && apt-get install -y --no-install-recommends ruby \
    && git init /opt/ruby \
    && git -C /opt/ruby fetch --depth=1 https://github.com/ruby/ruby.git "${RUBY_GIT_REF}" \
    && git -C /opt/ruby checkout FETCH_HEAD \
    && git init /tmp/prism \
    && git -C /tmp/prism fetch --depth=1 https://github.com/ruby/prism.git "${PRISM_GIT_REF}" \
    && git -C /tmp/prism checkout FETCH_HEAD \
    && ruby /tmp/sync_prism_into_ruby.rb /tmp/prism /opt/ruby \
    && cd /opt/ruby && ./autogen.sh && ./configure --disable-install-doc && make && make install \
    && apt-get purge -y ruby && apt-get autoremove -y && rm -rf /var/lib/apt/lists/* && hash -r \
    && sed -i 's|^BASERUBY = .*|BASERUBY = /usr/local/bin/ruby --disable=gems|' /opt/ruby/Makefile \
    && git config --system --add safe.directory /opt/ruby \
    && cd /tmp/prism && ruby templates/template.rb \
    && gem build prism.gemspec \
    && gem install --no-document --force prism-*.gem \
    && cd / && rm -rf /tmp/prism /tmp/sync_prism_into_ruby.rb

RUN gem install --no-document concurrent-ruby:1.3.8

RUN apt-get update && apt-get install -y --no-install-recommends ccache \
    && mkdir -p /ccache && chown $USERNAME:$USERNAME /ccache \
    && rm -rf /var/lib/apt/lists/*
ENV CCACHE_DIR=/ccache
ENV CCACHE_MAXSIZE=5G
ENV CCACHE_NOHASHDIR=1

# Shrink AFL++'s IJON map (default 64 KiB + 512 u64 slots = 68 KiB) so
# trace_bits stays L1d-friendly on Prism's 15-26 KiB CFG maps.
ARG IJON_MAP_SIZE=8192
ARG IJON_MAX_ENTRIES=128
RUN grep -qF '#define MAP_SIZE_IJON_MAP 65536' /AFLplusplus/include/config.h \
    && grep -qF '#define MAP_SIZE_IJON_ENTRIES 512' /AFLplusplus/include/config.h \
    && sed -i "s/^#define MAP_SIZE_IJON_MAP 65536/#define MAP_SIZE_IJON_MAP ${IJON_MAP_SIZE}/" /AFLplusplus/include/config.h \
    && sed -i "s/^#define MAP_SIZE_IJON_ENTRIES 512/#define MAP_SIZE_IJON_ENTRIES ${IJON_MAX_ENTRIES}/" /AFLplusplus/include/config.h \
    && make -C /AFLplusplus clean && make -C /AFLplusplus source-only && make -C /AFLplusplus install

WORKDIR /prism-fuzzer
USER $USERNAME
