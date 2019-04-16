#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/test_bin)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../test
)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../test/module/shared_model shared_model_test)
