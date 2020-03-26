# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

find_package(protobuf-mutator REQUIRED)

if(DEFINED ENV{LIB_FUZZING_ENGINE})
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} $ENV{LIB_FUZZING_ENGINE}")
  set(fuzzing_engine "")
else()
  add_library(fuzzing_engine standalone_fuzz_target_runner.cpp)
  set(fuzzing_engine fuzzing_engine)
endif()

add_executable(torii_fuzz torii_fuzz.cpp)
target_link_libraries(torii_fuzz
  endpoint
  protobuf-mutator
  rxcpp
  GTest::gtest
  GTest::gmock
  shared_model_proto_backend
  torii_service
  ${fuzzing_engine}
  )

add_executable(status_fuzz status_fuzz.cpp)
target_link_libraries(status_fuzz
  endpoint
  protobuf-mutator
  rxcpp
  GTest::gtest
  GTest::gmock
  shared_model_proto_backend
  torii_service
  ${fuzzing_engine}
  )

add_executable(find_fuzz find_fuzz.cpp)
target_link_libraries(find_fuzz
  endpoint
  protobuf-mutator
  rxcpp
  GTest::gtest
  GTest::gmock
  shared_model_proto_backend
  torii_service
  ${fuzzing_engine}
  )

add_executable(send_batches_fuzz send_batches_fuzz.cpp)
target_link_libraries(send_batches_fuzz
  protobuf-mutator
  GTest::gtest
  GTest::gmock
  on_demand_ordering_service
  on_demand_ordering_service_transport_grpc
  ordering_grpc
  shared_model_proto_backend
  tx_presence_cache
  ${fuzzing_engine}
  )

add_executable(request_proposal_fuzz request_proposal_fuzz.cpp)
target_link_libraries(request_proposal_fuzz
  protobuf-mutator
  rxcpp
  GTest::gtest
  GTest::gmock
  on_demand_ordering_service
  on_demand_ordering_service_transport_grpc
  ordering_grpc
  shared_model_proto_backend
  tx_presence_cache
  ${fuzzing_engine}
  )

add_executable(retrieve_block_fuzz retrieve_block_fuzz.cpp)
target_link_libraries(retrieve_block_fuzz
  protobuf-mutator
  GTest::gtest
  GTest::gmock
  block_loader_service
  loader_grpc
  shared_model_default_builders
  shared_model_proto_backend
  ${fuzzing_engine}
  )

add_executable(retrieve_blocks_fuzz retrieve_blocks_fuzz.cpp)
target_link_libraries(retrieve_blocks_fuzz
  protobuf-mutator
  GTest::gtest
  GTest::gmock
  block_loader_service
  loader_grpc
  shared_model_default_builders
  shared_model_proto_backend
  ${fuzzing_engine}
  )

add_executable(consensus_fuzz consensus_fuzz.cpp)
target_link_libraries(consensus_fuzz
  protobuf-mutator
  GTest::gtest
  GTest::gmock
  yac
  yac_grpc
  yac_transport
  shared_model_proto_backend
  test_logger
  ${fuzzing_engine}
  )

add_executable(mst_fuzz mst_fuzz.cpp)
target_link_libraries(mst_fuzz
  protobuf-mutator
  GTest::gtest
  GTest::gmock
  mst_grpc
  mst_transport
  shared_model_proto_backend
  tx_presence_cache
  ${fuzzing_engine}
  )

add_custom_target(fuzzing DEPENDS
  torii_fuzz
  status_fuzz
  find_fuzz
  send_batches_fuzz
  request_proposal_fuzz
  retrieve_block_fuzz
  retrieve_blocks_fuzz
  consensus_fuzz
  mst_fuzz
  )
