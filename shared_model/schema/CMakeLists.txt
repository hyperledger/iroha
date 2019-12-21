# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set(SCHEMA_PATH ${CMAKE_CURRENT_SOURCE_DIR})
compile_proto_to_cpp(block.proto)
compile_proto_to_cpp(transaction.proto)
compile_proto_to_cpp(commands.proto)
compile_proto_to_cpp(primitive.proto)
compile_proto_to_cpp(proposal.proto)
compile_proto_to_cpp(qry_responses.proto)
compile_proto_to_cpp(queries.proto)
compile_proto_to_cpp(endpoint.proto)

add_library(schema
    ${SCHEMA_OUT_DIR}/block.pb.cc
    ${SCHEMA_OUT_DIR}/transaction.pb.cc
    ${SCHEMA_OUT_DIR}/commands.pb.cc
    ${SCHEMA_OUT_DIR}/primitive.pb.cc
    ${SCHEMA_OUT_DIR}/proposal.pb.cc
    ${SCHEMA_OUT_DIR}/qry_responses.pb.cc
    ${SCHEMA_OUT_DIR}/queries.pb.cc
    ${SCHEMA_OUT_DIR}/endpoint.pb.cc)

target_link_libraries(schema
    protobuf::libprotobuf
    )
target_include_directories(schema PUBLIC
    ${SCHEMA_OUT_DIR}
    )
