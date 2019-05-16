# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fsanitize=fuzzer,address")

find_package(protobuf-mutator REQUIRED)

add_library(fuzzing_engine standalone_fuzz_target_runner.cpp)

add_executable(torii_fuzzing torii_fuzz.cpp)
target_link_libraries(torii_fuzzing
  rxcpp
  gtest::gtest
  gmock::gmock
  ametsuchi
  torii_service
  protobuf-mutator
  fuzzing_engine
  )

add_executable(status_fuzzing status_fuzz.cpp)
target_link_libraries(status_fuzzing
  rxcpp
  gtest::gtest
  gmock::gmock
  ametsuchi
  torii_service
  protobuf-mutator
  fuzzing_engine
  )

add_executable(find_fuzzing find_fuzz.cpp)
target_link_libraries(find_fuzzing
  rxcpp
  gtest::gtest
  gmock::gmock
  ametsuchi
  torii_service
  protobuf-mutator
  fuzzing_engine
  )

add_executable(send_batches_fuzz send_batches_fuzz.cpp)
target_link_libraries(send_batches_fuzz
  gtest::gtest
  gmock::gmock
  ametsuchi
  on_demand_ordering_service
  on_demand_ordering_service_transport_grpc
  protobuf-mutator
  fuzzing_engine
  )

add_executable(request_proposal_fuzz request_proposal_fuzz.cpp)
target_link_libraries(request_proposal_fuzz
  ametsuchi
  rxcpp
  gtest::gtest
  gmock::gmock
  on_demand_ordering_service
  on_demand_ordering_service_transport_grpc
  protobuf-mutator
  fuzzing_engine
  )

add_executable(retrieve_block_fuzz retrieve_block_fuzz.cpp)
target_link_libraries(retrieve_block_fuzz
  gtest::gtest
  gmock::gmock
  block_loader_service
  shared_model_default_builders
  protobuf-mutator
  fuzzing_engine
  )

add_executable(retrieve_blocks_fuzz retrieve_blocks_fuzz.cpp)
target_link_libraries(retrieve_blocks_fuzz
  gtest::gtest
  gmock::gmock
  block_loader_service
  shared_model_default_builders
  protobuf-mutator
  fuzzing_engine
  )

add_executable(consensus_fuzz consensus_fuzz.cpp)
target_link_libraries(consensus_fuzz
  gtest::gtest
  gmock::gmock
  yac_transport
  yac
  protobuf-mutator
  test_logger
  fuzzing_engine
  )

add_executable(mst_fuzz mst_fuzz.cpp)
target_link_libraries(mst_fuzz
  gtest::gtest
  gmock::gmock
  mst_transport
  ametsuchi
  protobuf-mutator
  fuzzing_engine
  )
