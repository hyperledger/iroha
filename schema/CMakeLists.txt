# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set(SM_SCHEMA_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../shared_model/schema/)
set(SCHEMA_PATH ${SM_SCHEMA_PATH})
compile_proto_only_grpc_to_cpp(endpoint.proto "-I${SM_SCHEMA_PATH}")
set(SCHEMA_PATH ${CMAKE_CURRENT_SOURCE_DIR})
compile_proto_to_grpc_cpp(yac.proto)
compile_proto_to_grpc_cpp(ordering.proto "-I${SM_SCHEMA_PATH}")
compile_proto_to_grpc_cpp(loader.proto "-I${SM_SCHEMA_PATH}")
compile_proto_to_grpc_cpp(utility_endpoint.proto)

add_library(endpoint
    endpoint.grpc.pb.cc
    )
target_link_libraries(endpoint
    gRPC::grpc++
    schema
    )

add_library(utility_endpoint
    utility_endpoint.pb.cc
    utility_endpoint.grpc.pb.cc
    )
target_link_libraries(utility_endpoint
    protobuf::libprotobuf
    gRPC::grpc++
    )
target_include_directories(utility_endpoint PUBLIC
    ${SCHEMA_OUT_DIR}
    )

add_library(yac_grpc
    yac.pb.cc
    yac.grpc.pb.cc
    )
target_link_libraries(yac_grpc
    protobuf::libprotobuf
    gRPC::grpc++
    )

add_library(ordering_grpc
    ordering.pb.cc
    ordering.grpc.pb.cc
    )
target_link_libraries(ordering_grpc
    schema
    gRPC::grpc++
    )

add_library(loader_grpc
    loader.pb.cc
    loader.grpc.pb.cc
    )
target_link_libraries(loader_grpc
    schema
    gRPC::grpc++
    )
