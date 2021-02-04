FROM rust:slim AS builder
RUN apt-get update && apt-get -y upgrade && apt-get install -y apt-utils
RUN apt-get install -y libssl-dev pkg-config
COPY . iroha/
WORKDIR iroha
RUN cargo build --release

FROM debian:buster-slim
RUN apt-get update && apt-get -y upgrade && apt-get install -y apt-utils
RUN apt-get install -y libssl-dev pkg-config
COPY iroha/config.json .
COPY iroha/trusted_peers.json .
COPY --from=builder /iroha/target/release/iroha .
CMD ["./iroha"]