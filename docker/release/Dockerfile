FROM ubuntu:18.04

RUN apt-get update

#Install iroha
COPY iroha.deb /tmp/iroha.deb
RUN apt-get install -y /tmp/iroha.deb; \
    rm -f /tmp/iroha.deb

WORKDIR /opt/iroha_data

COPY entrypoint.sh wait-for-it.sh /
RUN chmod +x /entrypoint.sh /wait-for-it.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/sbin/init"]
