# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

AddTest(state_test state_test.cpp)
target_link_libraries(state_test
    mst_state
    test_logger
    shared_model_default_builders
    shared_model_stateless_validation
    shared_model_interfaces_factories
    )

AddTest(storage_test storage_test.cpp)
target_link_libraries(storage_test
    mst_storage
    test_logger
    shared_model_default_builders
    shared_model_stateless_validation
    shared_model_interfaces_factories
    )

AddTest(completer_test completer_test.cpp)
target_link_libraries(completer_test
    mst_state
    )

AddTest(transport_test transport_test.cpp)
target_link_libraries(transport_test
    mst_transport
    mst_processor
    test_logger
    shared_model_cryptography
    shared_model_stateless_validation
    shared_model_proto_backend
    )

AddTest(mst_processor_test mst_processor_test.cpp)
target_link_libraries(mst_processor_test
    mst_processor
    test_logger
    shared_model_default_builders
    shared_model_stateless_validation
    )

AddTest(gossip_propagation_strategy_test
    gossip_propagation_strategy_test.cpp
    )
target_link_libraries(gossip_propagation_strategy_test
    mst_processor
    logger
    shared_model_cryptography
    shared_model_stateless_validation
    shared_model_proto_backend
    )

AddTest(mst_net_input_test mst_net_input_test.cpp)
target_link_libraries(mst_net_input_test
    integration_framework
    )
