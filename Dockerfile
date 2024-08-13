FROM --platform=linux/amd64 archlinux:base-devel AS builder

ARG NIGHTLY_VERSION=2024-09-09

RUN <<EOT
  set -eux
  # Force-sync packages, install archlinux-keyring, repopulate keys
  pacman -Syy
  pacman -S archlinux-keyring --noconfirm --disable-download-timeout
  rm -rf /etc/pacman.d/gnupg/* && pacman-key --init && pacman-key --populate archlinux
  # Install updates
  pacman -Syu --noconfirm --disable-download-timeout
  # Set up Rust toolchain
  pacman -S rustup wget --noconfirm --disable-download-timeout
  # Install musl C++ toolchain to build wasm-opt
  wget -c https://musl.cc/x86_64-linux-musl-native.tgz -O - | tar -xz
  ln -s /x86_64-linux-musl-native/bin/x86_64-linux-musl-g++ /x86_64-linux-musl-native/bin/musl-g++
  ln -s /x86_64-linux-musl-native/bin/x86_64-linux-musl-gcc-ar /x86_64-linux-musl-native/bin/musl-ar
  ln -s /x86_64-linux-musl-native/bin/x86_64-linux-musl-gcc-ar /x86_64-linux-musl-native/bin/x86_64-linux-musl-ar
  ln -s /x86_64-linux-musl-native/bin/x86_64-linux-musl-gcc-ranlib /x86_64-linux-musl-native/bin/musl-ranlib
EOT

RUN <<EOT
  set -eux
  rustup toolchain install nightly-$NIGHTLY_VERSION \
    --profile minimal \
    --component rust-src
  rustup default nightly-$NIGHTLY_VERSION
  rustup target add x86_64-unknown-linux-musl wasm32-unknown-unknown
EOT

ENV PATH="$PATH:/x86_64-linux-musl-native/bin"
ENV RUSTFLAGS="-C link-arg=-static"
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=/x86_64-linux-musl-native/bin/x86_64-linux-musl-gcc

WORKDIR /iroha
COPY . .
RUN cargo build \
    --bin irohad \
    --bin iroha \
    --bin kagami \
    --target x86_64-unknown-linux-musl \
    --profile deploy

FROM alpine:3.20

ARG STORAGE=/storage
ARG TARGET_DIR=/iroha/target/x86_64-unknown-linux-musl/deploy
ENV BIN_PATH=/usr/local/bin/
ENV CONFIG_DIR=/config

ENV KURA_STORE_DIR=$STORAGE
ENV SNAPSHOT_STORE_DIR=$STORAGE/snapshot

ENV WASM_DIRECTORY=/app/.cache/wasmtime
ENV USER=iroha
ENV UID=1001
ENV GID=1001

RUN <<EOT
  set -eux
  apk add --no-cache curl ca-certificates jq
  addgroup -g $GID $USER
  adduser \
    --disabled-password \
    --gecos "" \
    --home /app \
    --ingroup "$USER" \
    --no-create-home \
    --uid "$UID" \
    "$USER"
  mkdir -p $CONFIG_DIR
  mkdir -p $STORAGE
  mkdir -p $WASM_DIRECTORY
  chown $USER:$USER $STORAGE
  chown $USER:$USER $WASM_DIRECTORY
  chown $USER:$USER $CONFIG_DIR
EOT

COPY --from=builder $TARGET_DIR/irohad $BIN_PATH
COPY --from=builder $TARGET_DIR/iroha $BIN_PATH
COPY --from=builder $TARGET_DIR/kagami $BIN_PATH
COPY defaults/genesis.json $CONFIG_DIR
COPY defaults/executor.wasm $CONFIG_DIR
COPY defaults/client.toml $CONFIG_DIR
USER $USER
CMD ["irohad"]
