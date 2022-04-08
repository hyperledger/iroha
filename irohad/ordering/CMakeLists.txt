# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_library(on_demand_common
    impl/on_demand_common.cpp
    )

target_link_libraries(on_demand_common
    consensus_round
    )

add_library(batches_cache
    impl/batches_cache.cpp
    )
target_link_libraries(batches_cache
    Boost::boost
    )

add_library(on_demand_ordering_service
    impl/on_demand_ordering_service_impl.cpp
    )
target_link_libraries(on_demand_ordering_service
    batches_cache
    on_demand_common
    shared_model_interfaces
    consensus_round
    logger
    )

add_library(on_demand_ordering_service_transport_grpc
    impl/on_demand_os_server_grpc.cpp
    impl/on_demand_os_client_grpc.cpp
    )

target_link_libraries(on_demand_ordering_service_transport_grpc
    grpc_generic_client_factory
    shared_model_interfaces
    shared_model_interfaces_factories
    shared_model_proto_backend
    consensus_round
    logger
    ordering_grpc
    common
    )

add_library(on_demand_connection_manager
    impl/on_demand_connection_manager.cpp
    )
target_link_libraries(on_demand_connection_manager
    on_demand_common
    shared_model_interfaces
    consensus_round
    Boost::boost
    logger
    )

add_library(on_demand_ordering_gate
    impl/on_demand_ordering_gate.cpp
    )
target_link_libraries(on_demand_ordering_gate
    on_demand_common
    consensus_round
    Boost::boost
    logger
    common
    )
