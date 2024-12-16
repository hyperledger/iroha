# builder stage
FROM rust:slim-bookworm AS builder

WORKDIR /app

# install required packages
RUN apt-get update -y && \
    apt-get install -y build-essential mold

RUN rustup toolchain install nightly-2024-09-09
RUN rustup target add wasm32-unknown-unknown
RUN rustup default nightly-2024-09-09

COPY . .
ARG PROFILE="deploy"
ARG RUSTFLAGS=""
ARG FEATURES=""
ARG CARGOFLAGS=""
RUN RUSTFLAGS="${RUSTFLAGS}" mold --run cargo ${CARGOFLAGS} build --profile "${PROFILE}" --features "${FEATURES}"

# final image
FROM debian:bookworm-slim

ARG PROFILE="deploy"
ARG  STORAGE=/storage
ARG  TARGET_DIR=/app/target/${PROFILE}
ENV  BIN_PATH=/usr/local/bin/
ENV  CONFIG_DIR=/config
ENV  KURA_STORE_DIR=$STORAGE
ENV  SNAPSHOT_STORE_DIR=$STORAGE/snapshot
ENV  WASM_DIRECTORY=/app/.cache/wasmtime
ENV  USER=iroha
ENV  UID=1001
ENV  GID=1001

RUN <<EOT
  set -ex
  apt-get update -y && \
    apt-get install -y curl ca-certificates jq
  addgroup --gid $GID $USER &&
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
