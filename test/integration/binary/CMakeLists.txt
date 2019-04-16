#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

find_package(PythonInterp 3.5 REQUIRED)

set(PYLIB_PATH "${PROJECT_SOURCE_DIR}/example/python")
set(PYTHON_PROTO_INCLUDES
    "${PYLIB_PATH}/block_pb2.py"
    "${PYLIB_PATH}/commands_pb2.py"
    "${PYLIB_PATH}/endpoint_pb2.py"
    "${PYLIB_PATH}/endpoint_pb2_grpc.py"
    "${PYLIB_PATH}/primitive_pb2.py"
    "${PYLIB_PATH}/proposal_pb2.py"
    "${PYLIB_PATH}/qry_responses_pb2.py"
    "${PYLIB_PATH}/queries_pb2.py"
    "${PYLIB_PATH}/transaction_pb2.py"
    )

add_custom_command(
    COMMAND make
    WORKING_DIRECTORY ${PYLIB_PATH}
    OUTPUT ${PYTHON_PROTO_INCLUDES}
    COMMENT "Generating python protobuf includes"
    VERBATIM
)
add_custom_target(python_proto_includes DEPENDS ${PYTHON_PROTO_INCLUDES})

add_executable(binary_test
    launchers.cpp
    binaries_test.cpp
    )
target_link_libraries(binary_test
    gtest::main
    integration_framework
    shared_model_cryptography
    )
add_dependencies(binary_test python_proto_includes)
target_include_directories(binary_test PUBLIC ${PROJECT_SOURCE_DIR}/test)

add_test(
    NAME python_binary_test
    COMMAND ${CMAKE_COMMAND} -E env
    "PYTHON_INTERPRETER=${PYTHON_EXECUTABLE}"
    "PYTHONPATH=${PYLIB_PATH}"
    "ROOT_DIR=${PROJECT_SOURCE_DIR}"
    $<TARGET_FILE:binary_test> --gtest_filter=*/0*
)
