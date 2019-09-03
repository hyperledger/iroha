FROM python:3.6.6-alpine3.8

RUN apk --no-cache add g++ zeromq-dev \
      && pip install locustio pyzmq

EXPOSE 8089 5557 5558

ENTRYPOINT ["/usr/local/bin/locust"]

RUN pip install grpcio==1.19.0 grpcio-tools==1.19.0 iroha influxdb
