#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

addtest(test_subscriber_testing test_subscriber_testing.cpp)
target_link_libraries(test_subscriber_testing
    rxcpp
    )

add_library(test_client_factory test_client_factory.cpp)
target_link_libraries(test_client_factory
    grpc_channel_pool
    grpc_channel_factory
    grpc_generic_client_factory
    test_logger
    )

add_library(test_logger test_logger.cpp)
target_link_libraries(test_logger
    logger
    logger_manager
    )

add_library(integration_framework
    integration_framework/integration_test_framework.cpp
    integration_framework/iroha_instance.cpp
    integration_framework/fake_peer/fake_peer.cpp
    integration_framework/fake_peer/block_storage.cpp
    integration_framework/fake_peer/proposal_storage.cpp
    integration_framework/fake_peer/behaviour/behaviour.cpp
    integration_framework/fake_peer/behaviour/empty.cpp
    integration_framework/fake_peer/behaviour/honest.cpp
    integration_framework/fake_peer/network/loader_grpc.cpp
    integration_framework/fake_peer/network/on_demand_os_network_notifier.cpp
    integration_framework/fake_peer/network/ordering_service_network_notifier.cpp
    integration_framework/fake_peer/network/ordering_gate_network_notifier.cpp
    integration_framework/fake_peer/network/yac_network_notifier.cpp
    integration_framework/port_guard.cpp
    )
target_link_libraries(integration_framework
    PRIVATE
    test_client_factory
    yac_transport
    PUBLIC
    application
    integration_framework_config_helper
    command_client
    common_test_constants
    grpc_generic_client_factory
    query_client
    ordering_gate_common
    shared_model_cryptography_model
    server_runner
    test_logger
    pg_connection_init
    rdb_connection_init
    )
find_path(BOOST_ASIO_INCLUDE_DIRS "boost/asio.hpp")
target_include_directories(integration_framework PRIVATE ${BOOST_ASIO_INCLUDE_DIRS})

add_library(common_test_constants common_constants.cpp)
target_link_libraries(common_test_constants
    shared_model_interfaces
    )

target_include_directories(integration_framework PUBLIC ${PROJECT_SOURCE_DIR}/test)

add_library(integration_framework_config_helper
    config_helper.cpp
    )
target_include_directories(integration_framework_config_helper PUBLIC ${PROJECT_SOURCE_DIR}/test)
target_link_libraries(integration_framework_config_helper
    Boost::boost
    )

add_library(framework_sql_query
    sql_query.cpp
    )
target_link_libraries(framework_sql_query
    SOCI::postgresql
    SOCI::core
    logger
    shared_model_proto_backend
    )
target_compile_definitions(framework_sql_query
    PRIVATE SOCI_USE_BOOST HAVE_BOOST
    )

add_library(test_db_manager test_db_manager.cpp)
target_link_libraries(test_db_manager
    GTest::gtest
    integration_framework_config_helper
    k_times_reconnection_strategy
    logger_manager
    pg_connection_init
    rdb_connection_init
    postgres_options
    SOCI::postgresql
    SOCI::core
    )

add_subdirectory(executor_itf)
