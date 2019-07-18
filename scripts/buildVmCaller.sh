#!/bin/sh

echo "Getting Burrow source code..."
go get github.com/hyperledger/burrow/execution/evm
echo "go get github.com/hyperledger/burrow/execution/evm — done"
go get github.com/hyperledger/burrow/acm
echo "go get github.com/hyperledger/burrow/acm — done"
go get github.com/hyperledger/burrow/binary
echo "go get github.com/hyperledger/burrow/binary — done"
go get github.com/hyperledger/burrow/crypto
echo "go get github.com/hyperledger/burrow/crypto — done"
go get github.com/hyperledger/burrow/logging
echo "go get github.com/hyperledger/burrow/logging — done"
go get github.com/tmthrgd/go-hex
echo "go get github.com/tmthrgd/go-hex — done"
go get golang.org/x/crypto/ripemd160
echo "go get golang.org/x/crypto/ripemd160 — done"
go get github.com/golang/protobuf/protoc-gen-go
echo "go get github.com/golang/protobuf/protoc-gen-go — done"
echo "All sources downloaded, vmCall build is started"

# build vmCall.so and vmCall.h
mkdir -p $GOPATH/src/iroha_protocol
protoc --proto_path=/opt/iroha/shared_model/schema --go_out $GOPATH/src/iroha_protocol /opt/iroha/shared_model/schema/*.proto
cd $GOPATH/src/vmCaller
go build -o vmCall.a -buildmode=c-archive main.go iroha_app_state.go iroha_event_sink.go
cp $GOPATH/src/vmCaller/vmCall.a /opt/iroha/irohad/ametsuchi/
cp $GOPATH/src/vmCaller/vmCall.h /opt/iroha/irohad/ametsuchi/
