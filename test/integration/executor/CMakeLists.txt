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

add_library(account_detail_checker account_detail_checker.cpp)
target_link_libraries(account_detail_checker
    gtest::main
    rapidjson
    )

add_library(command_permission_test command_permission_test.cpp)
target_link_libraries(command_permission_test
    executor_fixture
    executor_fixture_param_provider
    common_test_constants
    )

addtest(add_asset_qty_test add_asset_qty_test.cpp)
target_link_libraries(add_asset_qty_test
    command_permission_test
    common_test_constants
    executor_fixture
    executor_fixture_param_provider
    )

addtest(add_signatory_test add_signatory_test.cpp)
target_link_libraries(add_signatory_test
    command_permission_test
    common_test_constants
    executor_fixture
    executor_fixture_param_provider
    )

addtest(create_account_test create_account_test.cpp)
target_link_libraries(create_account_test
    command_permission_test
    executor_fixture
    executor_fixture_param_provider
    )

addtest(get_account_assets_test get_account_assets_test.cpp)
target_link_libraries(get_account_assets_test
    executor_fixture
    executor_fixture_param_provider
    common_test_constants
    query_permission_test
    )

addtest(get_account_detail_test get_account_detail_test.cpp)
target_link_libraries(get_account_detail_test
    account_detail_checker
    executor_fixture
    executor_fixture_param_provider
    common_test_constants
    query_permission_test
    )

addtest(get_asset_info_test get_asset_info_test.cpp)
target_link_libraries(get_asset_info_test
    executor_fixture
    executor_fixture_param_provider
    common_test_constants
    query_permission_test
    )

addtest(get_account_test get_account_test.cpp)
target_link_libraries(get_account_test
    account_detail_checker
    executor_fixture
    executor_fixture_param_provider
    common_test_constants
    query_permission_test
    )

add_library(query_permission_test query_permission_test.cpp)
target_link_libraries(query_permission_test
    executor_fixture
    executor_fixture_param_provider
    common_test_constants
    )

addtest(set_account_detail_test set_account_detail_test.cpp)
target_link_libraries(set_account_detail_test
    account_detail_checker
    command_permission_test
    common_test_constants
    executor_fixture
    executor_fixture_param_provider
    )

addtest(get_signatories_test get_signatories_test.cpp)
target_link_libraries(get_signatories_test
    executor_fixture
    executor_fixture_param_provider
    common_test_constants
    query_permission_test
    )

addtest(remove_signatory_test remove_signatory_test.cpp)
target_link_libraries(remove_signatory_test
    command_permission_test
    common_test_constants
    executor_fixture
    executor_fixture_param_provider
    )
