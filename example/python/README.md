# Python client library example

## Prerequisites

In order to execute script demonstrating execution of python client library you need to have python 2.7 installed. After that please follow next steps:

1. To compile grpc proto files it is needed to have grpc-io installed:
```sh
pip2 install grpcio-tools
```

2. Run prepare.sh script to build iroha python library and compile proto files:
```sh
./prepare.sh
```

3. Make sure you have running iroha on your machine. You can follow [this](https://hyperledger.github.io/iroha-api/#run-the-daemon-irohad) guide to launch iroha daemon. Please run iroha from iroha/example folder, since python script uses keys from there.

## Launch example

Script `tx-example.py` does the following:
1. Assemble transaction from several commands using tx builder
2. Sign it using keys from iroha/example folder
3. Send it to iroha
4. Wait 5 secs and check transaction's status using its hash
5. Assemble query using query builder
6. Send query to iroha
7. Read query response

Launch it:
```sh
python2 tx-example
```
