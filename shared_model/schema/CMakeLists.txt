# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set(SCHEMA_PATH ${CMAKE_CURRENT_SOURCE_DIR})
FILE(GLOB SCHEMA_FILES "${SCHEMA_PATH}/*\.proto")

add_custom_target(schema_go)
add_library(schema)

foreach(SCHEMA_FILE IN LISTS SCHEMA_FILES)
  compile_proto_to_go("${SCHEMA_FILE}" schema_go)

  get_filename_component(FILE_NAME_WO_PATH "${SCHEMA_FILE}" NAME)
  compile_proto_to_cpp("${FILE_NAME_WO_PATH}")
  get_filename_component(FILE_NAME_WO_EXT "${FILE_NAME_WO_PATH}" NAME_WE)
  target_sources(schema PRIVATE "${SCHEMA_OUT_DIR}/${FILE_NAME_WO_EXT}.pb.cc")
endforeach()

target_link_libraries(schema
    protobuf::libprotobuf
    )
target_include_directories(schema PUBLIC
    ${SCHEMA_OUT_DIR}
    )
