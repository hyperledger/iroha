# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_library(on_demand_common
    impl/on_demand_common.cpp
    )

target_link_libraries(on_demand_common
    consensus_round
    )

add_library(on_demand_ordering_service
    impl/on_demand_ordering_service_impl.cpp
    impl/kick_out_proposal_creation_strategy.cpp
    )

target_link_libraries(on_demand_ordering_service
    on_demand_common
    TBB::tbb
    mst_hash
    mst_state
    shared_model_interfaces
    consensus_round
    logger
    )

add_library(on_demand_ordering_service_transport_grpc
    impl/on_demand_os_server_grpc.cpp
    impl/on_demand_os_client_grpc.cpp
    )

target_link_libraries(on_demand_ordering_service_transport_grpc
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
    rxcpp
    Boost::boost
    logger
    )

add_library(on_demand_ordering_gate
    impl/on_demand_ordering_gate.cpp
    impl/ordering_gate_cache/ordering_gate_cache.cpp
    impl/ordering_gate_cache/on_demand_cache.cpp
    )
target_link_libraries(on_demand_ordering_gate
    on_demand_common
    consensus_round
    rxcpp
    Boost::boost
    logger
    common
    )
