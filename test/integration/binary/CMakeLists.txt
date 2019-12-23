#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

find_package(Python3 REQUIRED COMPONENTS Interpreter)

add_executable(binary_test
    launchers.cpp
    binaries_test.cpp
    )
target_link_libraries(binary_test
    GTest::gtest_main
    integration_framework
    shared_model_cryptography
    )
target_include_directories(binary_test PUBLIC ${PROJECT_SOURCE_DIR}/test)
target_compile_definitions(binary_test PRIVATE
    PYTHON_INTERPRETER="${Python3_EXECUTABLE}"
    ROOT_DIR="${PROJECT_SOURCE_DIR}"
    )

add_test(
    NAME python_binary_test
    COMMAND $<TARGET_FILE:binary_test> --gtest_filter=*/0*
)
