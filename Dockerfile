FROM debian:stable-slim
COPY target/release/iroha .
COPY iroha/config.json .
RUN apt-get update && apt-get -y upgrade && apt-get install -y libssl-dev
CMD ["./iroha"]
