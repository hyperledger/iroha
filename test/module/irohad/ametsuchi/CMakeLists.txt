#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

addtest(ametsuchi_test ametsuchi_test.cpp)
target_link_libraries(ametsuchi_test
    ametsuchi
    ametsuchi_fixture
    common_test_constants
    flat_file_storage
    rocksdb_block_storage
    shared_model_stateless_validation
    test_logger
    sync_subscription
    )

addtest(wsv_query_command_test wsv_query_command_test.cpp)
target_link_libraries(wsv_query_command_test
    ametsuchi
    ametsuchi_fixture
    sync_subscription
    test_logger
    )

addtest(rdb_wsv_query_command_test rdb_wsv_query_command_test.cpp)
target_link_libraries(rdb_wsv_query_command_test
    test_logger
    ametsuchi
    ametsuchi_fixture
    ametsuchi_rocksdb
    sync_subscription
    )

addtest(rdb_wsv_query_test rdb_wsv_query_test.cpp)
target_link_libraries(rdb_wsv_query_test
    test_logger
    ametsuchi
    ametsuchi_fixture
    ametsuchi_rocksdb
    sync_subscription
    )

addtest(rocksdb_indexer_test rocksdb_indexer_test.cpp)
target_link_libraries(rocksdb_indexer_test
    Boost::filesystem
    rocksdb_indexer
    )

addtest(wsv_query_test wsv_query_test.cpp)
target_link_libraries(wsv_query_test
    ametsuchi
    ametsuchi_fixture
    sync_subscription
    test_logger
    )

addtest(rocksdb_common_test rocksdb_common_test.cpp)
target_link_libraries(rocksdb_common_test
    Boost::filesystem
    shared_model_interfaces
    common
    RocksDB::rocksdb
    )

addtest(flat_file_test flat_file_test.cpp)
target_link_libraries(flat_file_test
    ametsuchi
    test_logger
    sync_subscription
    )

addtest(block_query_test block_query_test.cpp)
target_link_libraries(block_query_test
    ametsuchi
    ametsuchi_fixture
    shared_model_stateless_validation
    sync_subscription
    )

addtest(storage_init_test storage_init_test.cpp)
target_link_libraries(storage_init_test
    ametsuchi
    integration_framework_config_helper
    shared_model_proto_backend
    pg_connection_init
    rdb_connection_init
    test_logger
    sync_subscription
    )

addtest(postgres_options_test postgres_options_test.cpp)
target_link_libraries(postgres_options_test
    ametsuchi
    test_logger
    sync_subscription
    )

addtest(postgres_executor_test postgres_executor_test.cpp)
target_link_libraries(postgres_executor_test
    integration_framework_config_helper
    shared_model_proto_backend
    ametsuchi
    commands_mocks_factory
    framework_sql_query
    pg_connection_init
    test_logger
    common_test_constants
    sync_subscription
    )

addtest(rocksdb_executor_test rocksdb_executor_test.cpp)
target_link_libraries(rocksdb_executor_test
    integration_framework_config_helper
    shared_model_proto_backend
    ametsuchi
    ametsuchi_rocksdb
    framework_sql_query
    commands_mocks_factory
    test_logger
    common_test_constants
    sync_subscription
    )

addtest(postgres_query_executor_test postgres_query_executor_test.cpp)
target_link_libraries(postgres_query_executor_test
    shared_model_plain_backend
    shared_model_proto_backend
    ametsuchi_fixture
    ametsuchi
    commands_mocks_factory
    test_logger
    RapidJSON::rapidjson
    sync_subscription
    )

addtest(tx_presence_cache_test tx_presence_cache_test.cpp)
target_link_libraries(tx_presence_cache_test
    ametsuchi
    shared_model_interfaces_factories
    sync_subscription
    )

addtest(settings_test settings_test.cpp)
target_link_libraries(settings_test
    ametsuchi
    ametsuchi_fixture
    test_logger
    commands_mocks_factory
    sync_subscription
    )

addtest(in_memory_block_storage_test in_memory_block_storage_test.cpp)
target_link_libraries(in_memory_block_storage_test
    ametsuchi
    sync_subscription
    )

addtest(flat_file_block_storage_test flat_file_block_storage_test.cpp)
target_link_libraries(flat_file_block_storage_test
    ametsuchi
    test_logger
    sync_subscription
    )

addtest(rocksdb_block_storage_test rocksdb_block_storage_test.cpp)
target_link_libraries(rocksdb_block_storage_test
    ametsuchi
    test_logger
    sync_subscription
    )

addtest(postgres_block_storage_test postgres_block_storage_test.cpp)
target_link_libraries(postgres_block_storage_test
    ametsuchi
    generator
    test_logger
    integration_framework_config_helper
    pg_connection_init
    sync_subscription
    )

add_library(ametsuchi_fixture INTERFACE)
target_link_libraries(ametsuchi_fixture INTERFACE
    integration_framework_config_helper
    shared_model_proto_backend
    framework_sql_query
    SOCI::postgresql
    SOCI::core
    pg_connection_init
    rdb_connection_init
    test_logger
    )

addtest(k_times_reconnection_strategy_test k_times_reconnection_strategy_test.cpp)
target_link_libraries(k_times_reconnection_strategy_test
    ametsuchi
    sync_subscription
    )

addtest(peer_query_wsv_test peer_query_wsv_test.cpp)
target_link_libraries(peer_query_wsv_test
    ametsuchi
    sync_subscription
    )

if(USE_BURROW)
  addtest(postgres_burrow_storage_test postgres_burrow_storage_test.cpp)
  target_link_libraries(postgres_burrow_storage_test
      postgres_burrow_storage
      shared_model_utils
      test_db_manager
      test_logger
      )
endif()
