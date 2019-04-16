#!/usr/bin/env bash

cd $(dirname $0)

# generate proto files in current dir
protoc --proto_path=../shared_model/schema --python_out=. ../shared_model/schema/*.proto
python -m grpc_tools.protoc --proto_path=../shared_model/schema --python_out=. --grpc_python_out=. ../shared_model/schema/endpoint.proto
