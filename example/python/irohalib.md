# Python Iroha Lib Description

irohalib.py is a possible implementation of a platform-independent way of interaction with Iroha network via Python 3.

The only dependency is an implementation of ed25519 crypto in python.
ed25519.py is also provided.

# Preparation Steps

All you have to do before the first usage is:

```sh
pip3 install grpcio-tools
pip3 install pysha3
protoc --proto_path=../../shared_model/schema --python_out=. ../../shared_model/schema/*.proto
python -m grpc_tools.protoc --proto_path=../../shared_model/schema --python_out=. --grpc_python_out=. ../../shared_model/schema/endpoint.proto

```

# Usage Examples

Please see the example of irohalib.py usage in the batch-example.py file. The scripts (batch-example.py) is designed
to work with genesis.block from example directory.

!!!
MST should be enabled in config.sample

```sh
python3 batch-example.py
```
