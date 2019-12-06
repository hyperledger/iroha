# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/test_bin)

set(STATIC_TEST_DATA_DIR ${PROJECT_SOURCE_DIR}/test/data)

set(GENERATED_TEST_DATA_DIR ${PROJECT_BINARY_DIR}/test_data)
file(MAKE_DIRECTORY ${GENERATED_TEST_DATA_DIR})
set(TEST_P2P_TLS_DATA_DIR ${GENERATED_TEST_DATA_DIR}/p2p_tls)
file(MAKE_DIRECTORY ${TEST_P2P_TLS_DATA_DIR})
set(TEST_TORII_TLS_DATA_DIR ${STATIC_TEST_DATA_DIR}/torii_tls)
file(MAKE_DIRECTORY ${TEST_TORII_TLS_DATA_DIR})

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(test_data_providers)
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
