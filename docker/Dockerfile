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

# Pin an explicit ruby/ruby commit SHA (or override with RUBY_GIT_REF=...).
# Targets at other refs can also be built incrementally into build/targets/ruby/.
ARG RUBY_GIT_REF=dec1bb786f718840e7ea828fafdcc3cd29c64448
ENV RUBY_ORACLE_DIR=/opt/ruby
RUN apt-get update && apt-get install -y --no-install-recommends ruby \
    && git init /opt/ruby \
    && git -C /opt/ruby fetch --depth=1 https://github.com/ruby/ruby.git "${RUBY_GIT_REF}" \
    && git -C /opt/ruby checkout FETCH_HEAD \
    && cd /opt/ruby && ./autogen.sh && ./configure --disable-install-doc && make && make install \
    && apt-get purge -y ruby && apt-get autoremove -y && rm -rf /var/lib/apt/lists/* && hash -r \
    && sed -i 's|^BASERUBY = .*|BASERUBY = /usr/local/bin/ruby --disable=gems|' /opt/ruby/Makefile \
    && git config --system --add safe.directory /opt/ruby

RUN gem install --no-document concurrent-ruby:1.3.8 lrama:0.8.0 lrama-fuzz:0.1.0

RUN apt-get update && apt-get install -y --no-install-recommends ccache \
    && mkdir -p /ccache && chown $USERNAME:$USERNAME /ccache \
    && rm -rf /var/lib/apt/lists/*
ENV CCACHE_DIR=/ccache
ENV CCACHE_MAXSIZE=5G
ENV CCACHE_NOHASHDIR=1

WORKDIR /prism-fuzzer
USER $USERNAME
