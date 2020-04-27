#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

find_library(golang REQUIRED)

set(GOPATH_GENERATED "${CMAKE_BINARY_DIR}/gopath")

if(NOT IS_DIRECTORY("${GOPATH_GENERATED}"))
  file(MAKE_DIRECTORY "${GOPATH_GENERATED}")
endif()

# GOPATH_PERSISTENT can be outside the build tree
set(GOPATH_PERSISTENT "$ENV{GOPATH}")
if(DEFINED GOPATH_PERSISTENT)
  # generated dir goes first as it is used to install local packages
  set(GOPATH "${GOPATH_GENERATED}:${GOPATH_PERSISTENT}")
else()
  set(GOPATH "${GOPATH_GENERATED}")
endif()

set(VM_CALLER_LIB ${CMAKE_CURRENT_BINARY_DIR}/vmCall.a)
set(VM_CALLER_HDR ${CMAKE_CURRENT_BINARY_DIR}/vmCall.h)

file(GLOB_RECURSE VM_CALLER_GO_SRCS LIST_DIRECTORIES false *.go)

set(GO_MOD_FILE_PATH "${CMAKE_CURRENT_BINARY_DIR}/go.mod")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/go.mod.in"
    "${GO_MOD_FILE_PATH}"
    @ONLY
  )

get_go_env_path(ENV_PATH)

add_custom_command(
  OUTPUT
    "${VM_CALLER_LIB}"
    "${VM_CALLER_HDR}"
  DEPENDS
    "${VM_CALLER_GO_SRCS}"
    schema_go
  WORKING_DIRECTORY
    "${CMAKE_CURRENT_SOURCE_DIR}"
  COMMAND
  env "PATH=${ENV_PATH}" "GOPATH=${GOPATH}" go build
      --modfile "${GO_MOD_FILE_PATH}"
      -buildmode=c-archive
      -o "${VM_CALLER_LIB}"
      "${CMAKE_CURRENT_SOURCE_DIR}/main.go"
      "${CMAKE_CURRENT_SOURCE_DIR}/iroha_event_sink.go"
  )

add_custom_target(generate_burrow_vm_caller_lib_and_header
  DEPENDS
    "${VM_CALLER_LIB}"
    "${VM_CALLER_HDR}"
)

add_library(burrow_vm_caller STATIC IMPORTED GLOBAL)
add_dependencies(burrow_vm_caller generate_burrow_vm_caller_lib_and_header)
set_property(TARGET burrow_vm_caller PROPERTY IMPORTED_LOCATION "${VM_CALLER_LIB}")
target_link_libraries(burrow_vm_caller
  INTERFACE
    proto_command_executor
    proto_specific_query_executor
    burrow_storage
  )
target_include_directories(burrow_vm_caller INTERFACE "${CMAKE_CURRENT_BINARY_DIR}")
target_compile_definitions(burrow_vm_caller
  INTERFACE
    USE_EVM
    DEFAULT_VM_CALL_INCLUDE_IMPL="${VM_CALLER_HDR}"
  )
