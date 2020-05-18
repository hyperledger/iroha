#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

# directory contains benchmarks

# default benchmark path is build/benchmark_bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/benchmark_bin)


add_executable(benchmark_example
    benchmark_example.cpp
    )
target_link_libraries(benchmark_example
    benchmark::benchmark
    shared_model_stateless_validation
    )

add_executable(bm_proto_creation
    bm_proto_creation.cpp
    )

target_include_directories(bm_proto_creation PUBLIC
    ${PROJECT_SOURCE_DIR}/test
    )

target_link_libraries(bm_proto_creation
    benchmark::benchmark
    GTest::gtest
    GTest::gmock
    shared_model_proto_backend
    shared_model_stateless_validation
    )

add_executable(bm_query
    bm_query.cpp
    )

target_link_libraries(bm_query
    benchmark::benchmark
    GTest::gtest
    GTest::gmock
    integration_framework
    )

add_executable(bm_pipeline
    bm_pipeline.cpp)

target_link_libraries(bm_pipeline
    benchmark::benchmark
    GTest::gtest
    GTest::gmock
    application
    raw_block_loader
    integration_framework
    shared_model_stateless_validation
    )

add_executable(bm_iroha_ed25519 bm_iroha_ed25519.cpp)
target_link_libraries(bm_iroha_ed25519
    benchmark::benchmark
    iroha::ed25519
    )

if(USE_LIBURSA)
    find_package(ursa REQUIRED)
    add_executable(bm_ursa_ed25519 bm_ursa_ed25519.cpp)
    target_link_libraries(bm_ursa_ed25519
        benchmark::benchmark
        ursa
        )
endif()
