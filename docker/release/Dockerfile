FROM ubuntu:18.04

RUN apt-get update; \
    apt install -y software-properties-common; \
    add-apt-repository ppa:ubuntu-toolchain-r/test

#Install iroha
COPY iroha.deb /tmp/iroha.deb
RUN set -e; apt-get update; \
    apt-get install -y /tmp/iroha.deb; \
    rm -f /tmp/iroha.deb; \
    apt-get -y clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/iroha_data

COPY entrypoint.sh wait-for-it.sh /
RUN chmod +x /entrypoint.sh /wait-for-it.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["irohad"]
