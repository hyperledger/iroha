#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

addtest(ametsuchi_test ametsuchi_test.cpp)
target_link_libraries(ametsuchi_test
    ametsuchi
    ametsuchi_fixture
    shared_model_stateless_validation
    test_logger
    )

addtest(wsv_query_command_test wsv_query_command_test.cpp)
target_link_libraries(wsv_query_command_test
    ametsuchi
    ametsuchi_fixture
    test_logger
    )

addtest(flat_file_test flat_file_test.cpp)
target_link_libraries(flat_file_test
    ametsuchi
    test_logger
    )

addtest(block_query_test block_query_test.cpp)
target_link_libraries(block_query_test
    ametsuchi
    ametsuchi_fixture
    shared_model_stateless_validation
    )

addtest(storage_init_test storage_init_test.cpp)
target_link_libraries(storage_init_test
    ametsuchi
    integration_framework_config_helper
    shared_model_proto_backend
    test_logger
    )

addtest(postgres_options_test postgres_options_test.cpp)
target_link_libraries(postgres_options_test
    ametsuchi
    test_logger
    )

addtest(postgres_executor_test postgres_executor_test.cpp)
target_link_libraries(postgres_executor_test
    integration_framework_config_helper
    shared_model_proto_backend
    ametsuchi
    commands_mocks_factory
    framework_sql_query
    test_logger
    )

addtest(postgres_query_executor_test postgres_query_executor_test.cpp)
target_link_libraries(postgres_query_executor_test
    shared_model_proto_backend
    ametsuchi_fixture
    ametsuchi
    commands_mocks_factory
    test_logger
    )

addtest(tx_presence_cache_test tx_presence_cache_test.cpp)
target_link_libraries(tx_presence_cache_test
    ametsuchi
    shared_model_interfaces_factories
    )

addtest(in_memory_block_storage_test in_memory_block_storage_test.cpp)
target_link_libraries(in_memory_block_storage_test
    ametsuchi
    )

addtest(flat_file_block_storage_test flat_file_block_storage_test.cpp)
target_link_libraries(flat_file_block_storage_test
    ametsuchi
    test_logger
    )

add_library(ametsuchi_fixture INTERFACE)
target_link_libraries(ametsuchi_fixture INTERFACE
    integration_framework_config_helper
    shared_model_proto_backend
    framework_sql_query
    SOCI::postgresql
    SOCI::core
    test_logger
    )

addtest(k_times_reconnection_strategy_test k_times_reconnection_strategy_test.cpp)
target_link_libraries(k_times_reconnection_strategy_test
    ametsuchi
    )
