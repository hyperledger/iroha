ARG  TAG=dev
FROM alpine:3.17

ARG  STORAGE=/storage
ARG  TARGET_DIR=/iroha/target/x86_64-unknown-linux-musl/deploy
ENV  BIN_PATH=/usr/local/bin/
ENV  CONFIG_DIR=/configs
ENV  IROHA2_CONFIG_PATH=$CONFIG_DIR/config.json
ENV  IROHA2_GENESIS_PATH=$CONFIG_DIR/genesis.json
ENV  KURA_BLOCK_STORE_PATH=$STORAGE

RUN  set -ex && \
     apk --update add curl ca-certificates && \
     adduser --disabled-password iroha --shell /bin/bash --home /app && \
     mkdir -p $CONFIG_DIR && \
     mkdir $STORAGE && \
     chown iroha:iroha $STORAGE

COPY  $TARGET_DIR/iroha $BIN_PATH
COPY  $TARGET_DIR/iroha_client_cli $BIN_PATH
COPY  $TARGET_DIR/kagami $BIN_PATH
USER  iroha
CMD   iroha
