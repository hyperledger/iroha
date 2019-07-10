#!/usr/bin/env make

# TODO igor-egorov 21.01.2019 reimplement using cmake IR-239

# sources
PROTO_PATH = ../../shared_model/schema
PROTO_FILES = $(wildcard $(PROTO_PATH)/*.proto)

# targets
PYTHON_GRPC_LIBS_PATH = .
PYTHON_GRPC_LIBS_FILES = $(PYTHON_GRPC_LIBS_PATH)/endpoint_pb2_grpc.py
PYTHON_PROTO_LIBS_PATH = .
PYTHON_PROTO_LIBS_FILES = $(patsubst $(PROTO_PATH)/%.proto,$(PYTHON_PROTO_LIBS_PATH)/%_pb2.py,$(PROTO_FILES))

# binaries
PROTOC_EXECUTABLE ?= protoc
PYTHON_INTERPRETER ?= python

.PHONY: default
default: all

.PHONY: all
all: $(PYTHON_PROTO_LIBS_FILES) $(PYTHON_GRPC_LIBS_FILES)

$(PYTHON_PROTO_LIBS_PATH)/%_pb2.py: $(PROTO_PATH)/%.proto
	$(PROTOC_EXECUTABLE) --proto_path=$(PROTO_PATH) --python_out=$(PYTHON_PROTO_LIBS_PATH) $<

$(PYTHON_GRPC_LIBS_PATH)/%_pb2_grpc.py: $(PROTO_PATH)/%.proto
	$(PYTHON_INTERPRETER) -m grpc_tools.protoc --proto_path=$(PROTO_PATH)  --grpc_python_out=$(PYTHON_PROTO_LIBS_PATH) $<
