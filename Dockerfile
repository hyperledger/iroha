#base stage
FROM archlinux:base-devel AS builder

# Force-sync packages, install archlinux-keyring, repopulate keys
RUN pacman -Syy
RUN pacman -S archlinux-keyring --noconfirm --disable-download-timeout
RUN rm -rf /etc/pacman.d/gnupg/* && pacman-key --init && pacman-key --populate archlinux

# Install updates
RUN pacman -Syu --noconfirm --disable-download-timeout

# Set up Rust toolchain
RUN pacman -S rustup mold musl rust-musl wget --noconfirm --disable-download-timeout
RUN rustup toolchain install nightly-2023-06-25
RUN rustup default nightly-2023-06-25
RUN rustup target add x86_64-unknown-linux-musl wasm32-unknown-unknown
RUN rustup component add rust-src

# Install musl C++ toolchain to build wasm-opt
RUN wget -c http://musl.cc/x86_64-linux-musl-native.tgz -O - | tar -xz
RUN ln -s /x86_64-linux-musl-native/bin/x86_64-linux-musl-g++ /x86_64-linux-musl-native/bin/musl-g++
ENV PATH="$PATH:/x86_64-linux-musl-native/bin"
ENV RUSTFLAGS="-C link-arg=-static"
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=/x86_64-linux-musl-native/bin/x86_64-linux-musl-gcc

# builder stage
WORKDIR /iroha
COPY . .
RUN cargo build --target x86_64-unknown-linux-musl --features vendored --profile deploy


# final image
FROM alpine:3.18

ARG  STORAGE=/storage
ARG  TARGET_DIR=/iroha/target/x86_64-unknown-linux-musl/deploy
ENV  BIN_PATH=/usr/local/bin/
ENV  CONFIG_DIR=/config
ENV  IROHA2_CONFIG_PATH=$CONFIG_DIR/config.json
ENV  IROHA2_GENESIS_PATH=$CONFIG_DIR/genesis.json
ENV  KURA_BLOCK_STORE_PATH=$STORAGE

RUN  set -ex && \
     apk --update add curl ca-certificates && \
     adduser --disabled-password iroha --shell /bin/bash --home /app && \
     mkdir -p $CONFIG_DIR && \
     mkdir $STORAGE && \
     chown iroha:iroha $STORAGE

COPY --from=builder $TARGET_DIR/iroha $BIN_PATH
COPY --from=builder $TARGET_DIR/iroha_client_cli $BIN_PATH
COPY --from=builder $TARGET_DIR/kagami $BIN_PATH
USER iroha
CMD  iroha
