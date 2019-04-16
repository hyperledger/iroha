# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/test_bin)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(module)
add_subdirectory(framework)
add_subdirectory(integration)
add_subdirectory(regression)
add_subdirectory(system)

if(BENCHMARKING)
  add_subdirectory(benchmark)
endif()

if (FUZZING)
  add_subdirectory(fuzzing)
endif()
