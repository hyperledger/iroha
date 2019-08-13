# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_library(executor_fixture executor_fixture.cpp)
target_link_libraries(executor_fixture
    executor_itf
    )

add_library(executor_fixture_param executor_fixture_param.cpp)
target_link_libraries(executor_fixture_param
    gtest::main
    )

add_library(executor_fixture_param_postgres executor_fixture_param_postgres.cpp)
target_link_libraries(executor_fixture_param_postgres
    ametsuchi
    executor_fixture_param
    gmock::main
    shared_model_proto_backend
    test_db_manager
    test_logger
    )

add_library(executor_fixture_param_provider executor_fixture_param_provider.cpp)
target_link_libraries(executor_fixture_param_provider
    executor_fixture_param_postgres
    )

addtest(add_signatory_test add_signatory_test.cpp)
target_link_libraries(add_signatory_test
    executor_fixture
    executor_fixture_param_provider
    query_permission_test
    )
