#base stage
FROM archlinux:base-devel AS builder

RUN pacman -Syu rustup mold musl rust-musl --noconfirm
RUN rustup toolchain install nightly-2022-12-22-x86_64-unknown-linux-musl
RUN rustup default nightly-2022-12-22-x86_64-unknown-linux-musl
RUN rustup target add x86_64-unknown-linux-musl
RUN rustup component add rust-src
RUN rustup target add x86_64-unknown-linux-musl wasm32-unknown-unknown
RUN rustup component add rust-src llvm-tools-preview

# builder stage
WORKDIR /iroha
COPY . .
RUN  mold --run cargo build --profile deploy --target x86_64-unknown-linux-musl --features vendored

# final image
FROM alpine:3.16

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
