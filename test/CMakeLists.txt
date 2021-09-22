# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/test_bin)

set(GENERATED_TEST_DATA_DIR ${PROJECT_BINARY_DIR}/test_data)
file(MAKE_DIRECTORY ${GENERATED_TEST_DATA_DIR})

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(module)
add_subdirectory(framework)
add_subdirectory(integration)
add_subdirectory(regression)
add_subdirectory(system)
add_subdirectory(tool)

if(BENCHMARKING)
  add_subdirectory(benchmark)
endif()

if (FUZZING)
  add_subdirectory(fuzzing)
endif()
