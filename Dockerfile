FROM iroha2:build AS builder

FROM alpine:3.16

ENV  GLIBC_REPO=https://github.com/sgerrand/alpine-pkg-glibc
ENV  GLIBC_VERSION=2.30-r0
ENV  BIN_PATH=/usr/local/bin/
ENV  CONFIG_DIR=config
ENV  IROHA2_CONFIG_PATH=$CONFIG_DIR/config.json
ENV  IROHA2_GENESIS_PATH=$CONFIG_DIR/genesis.json
ARG  TARGET_DIR=/iroha/target/release

RUN  set -ex && \
     apk --update add libstdc++ curl ca-certificates && \
     for pkg in glibc-${GLIBC_VERSION} glibc-bin-${GLIBC_VERSION}; \
         do curl -sSL ${GLIBC_REPO}/releases/download/${GLIBC_VERSION}/${pkg}.apk -o /tmp/${pkg}.apk; done && \
     apk add --allow-untrusted /tmp/*.apk && \
     rm -v /tmp/*.apk && \
     /usr/glibc-compat/sbin/ldconfig /lib /usr/glibc-compat/lib && \
     adduser --disabled-password iroha --shell /bin/bash --home /app && \
     mkdir -p $CONFIG_DIR && \
     mkdir /chain && \
     chown iroha:iroha /chain
COPY --from=builder $TARGET_DIR/iroha $BIN_PATH
COPY --from=builder $TARGET_DIR/iroha_client_cli $BIN_PATH
COPY --from=builder $TARGET_DIR/kagami $BIN_PATH
USER iroha
CMD  iroha
