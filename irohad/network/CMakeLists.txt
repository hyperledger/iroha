# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_library(networking
    impl/peer_communication_service_impl.cpp
    )

target_link_libraries(networking
    rxcpp
    shared_model_interfaces
    synchronizer
    logger
    )

add_library(block_loader
    impl/block_loader_impl.cpp
    )

target_link_libraries(block_loader
    loader_grpc
    rxcpp
    shared_model_interfaces
    shared_model_proto_backend
    schema
    logger
    common
    )

add_library(block_loader_service
    impl/block_loader_service.cpp
    )
target_link_libraries(block_loader_service
    loader_grpc
    ametsuchi
    )

add_library(ordering_gate_common
    ordering_gate_common.cpp
    )
target_link_libraries(ordering_gate_common
    boost
    )

add_library(async_grpc_client INTERFACE
    # impl/async_grpc_client.hpp
    )

target_link_libraries(async_grpc_client INTERFACE
    rxcpp
    )
