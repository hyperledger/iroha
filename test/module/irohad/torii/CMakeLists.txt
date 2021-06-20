#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_subdirectory(processor)

# command service test
addtest(torii_transport_command_test torii_transport_command_test.cpp)
target_link_libraries(torii_transport_command_test
    torii_service
    command_client
    test_logger
    )

addtest(torii_queries_test torii_queries_test.cpp)
target_link_libraries(torii_queries_test
    torii_service
    command_client
    query_client
    server_runner
    processors
    test_client_factory
    test_logger
    async_subscription
    )

addtest(query_service_test query_service_test.cpp)
target_link_libraries(query_service_test
    torii_service
    query_client
    test_logger
    sync_subscription
    )

addtest(torii_service_query_test torii_service_query_test.cpp)
target_link_libraries(torii_service_query_test
    torii_service
    server_runner
    query_client
    test_client_factory
    test_logger
    )

addtest(command_sync_client_test
    command_sync_client_test.cpp
    )
target_link_libraries(command_sync_client_test
    command_client
    server_runner
    endpoint
    test_logger
    )

addtest(command_service_replay_test
    command_service_replay_test.cpp
    )
target_link_libraries(command_service_replay_test
    torii_service
    test_logger
    )

addtest(command_service_test
    command_service_test.cpp
    )
target_link_libraries(command_service_test
    torii_service
    test_logger
    )
