#!/bin/sh

echo "Getting proto compiler..."
go get github.com/golang/protobuf/protoc-gen-go
echo "go get github.com/golang/protobuf/protoc-gen-go - done"
echo "vmCall build is started"

# build vmCall.so and vmCall.h
mkdir -p /opt/iroha/goSrc/src/vmCaller/iroha_protocol
/opt/dependencies/installed/x64-linux/tools/protobuf/protoc -I/opt/dependencies/installed/x64-linux/include --proto_path=/opt/iroha/shared_model/schema --go_out /opt/iroha/goSrc/src/vmCaller/iroha_protocol /opt/iroha/shared_model/schema/*.proto
cd /opt/iroha/goSrc/src/vmCaller
go build -o vmCall.a -buildmode=c-archive main.go iroha_event_sink.go
cp /opt/iroha/goSrc/src/vmCaller/vmCall.a /opt/iroha/irohad/ametsuchi/
cp /opt/iroha/goSrc/src/vmCaller/vmCall.h /opt/iroha/irohad/ametsuchi/
