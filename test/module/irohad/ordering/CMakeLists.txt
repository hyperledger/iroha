# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

addtest(on_demand_os_test on_demand_os_test.cpp)
target_link_libraries(on_demand_os_test
    on_demand_ordering_service
    shared_model_default_builders
    ametsuchi
    test_logger
    )

addtest(on_demand_os_client_grpc_test on_demand_os_client_grpc_test.cpp)
target_link_libraries(on_demand_os_client_grpc_test
    on_demand_ordering_service_transport_grpc
    test_logger
    )

addtest(on_demand_os_server_grpc_test on_demand_os_server_grpc_test.cpp)
target_link_libraries(on_demand_os_server_grpc_test
    on_demand_ordering_service_transport_grpc
    test_logger
    )

addtest(on_demand_connection_manager_test on_demand_connection_manager_test.cpp)
target_link_libraries(on_demand_connection_manager_test
    on_demand_connection_manager
    test_logger
    )

addtest(on_demand_ordering_gate_test on_demand_ordering_gate_test.cpp)
target_link_libraries(on_demand_ordering_gate_test
    on_demand_ordering_gate
    ordering_gate_common
    shared_model_interfaces_factories
    test_logger
    )

addtest(on_demand_cache_test on_demand_cache_test.cpp)
target_link_libraries(on_demand_cache_test
    on_demand_ordering_gate
    shared_model_interfaces_factories
    )

addtest(kick_out_proposal_creation_strategy_test
    kick_out_proposal_creation_strategy_test.cpp
    )
target_link_libraries(kick_out_proposal_creation_strategy_test
    on_demand_ordering_service
    )
