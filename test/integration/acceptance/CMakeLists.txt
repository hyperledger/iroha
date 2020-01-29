#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

add_library(acceptance_fixture acceptance_fixture.cpp)
target_link_libraries(acceptance_fixture
    GTest::gtest
    GTest::gmock
    common_test_constants
    shared_model_default_builders
    )

add_library(grantable_permissions_fixture
    grantable_permissions_fixture.cpp
    )
target_link_libraries(grantable_permissions_fixture
    acceptance_fixture
    integration_framework
    )

addtest(add_peer_test add_peer_test.cpp)
target_link_libraries(add_peer_test
    acceptance_fixture
    integration_framework
    )

addtest(remove_peer_test remove_peer_test.cpp)
target_link_libraries(remove_peer_test
    acceptance_fixture
    integration_framework
    )

addtest(create_domain_test create_domain_test.cpp)
target_link_libraries(create_domain_test
    acceptance_fixture
    integration_framework
    )

addtest(get_transactions_test get_transactions_test.cpp)
target_link_libraries(get_transactions_test
    acceptance_fixture
    integration_framework
    )

addtest(grant_permission_test grant_permission_test.cpp)
target_link_libraries(grant_permission_test
    grantable_permissions_fixture
    )

addtest(revoke_permission_test revoke_permission_test.cpp)
target_link_libraries(revoke_permission_test
    grantable_permissions_fixture
    )

addtest(invalid_fields_test invalid_fields_test.cpp)
target_link_libraries(invalid_fields_test
    acceptance_fixture
    integration_framework
    )

addtest(query_test query_test.cpp)
target_link_libraries(query_test
    acceptance_fixture
    integration_framework
    )

addtest(subtract_asset_qty_test subtract_asset_qty_test.cpp)
target_link_libraries(subtract_asset_qty_test
    acceptance_fixture
    integration_framework
    )

addtest(transfer_asset_test transfer_asset_test.cpp)
target_link_libraries(transfer_asset_test
    acceptance_fixture
    integration_framework
    )

addtest(tx_acceptance_test tx_acceptance_test.cpp)
target_link_libraries(tx_acceptance_test
    acceptance_fixture
    integration_framework
    )

addtest(tx_heavy_data tx_heavy_data.cpp)
target_link_libraries(tx_heavy_data
    acceptance_fixture
    integration_framework
    )

addtest(get_roles_test get_roles_test.cpp)
target_link_libraries(get_roles_test
    acceptance_fixture
    integration_framework
    )

addtest(queries_acceptance_test queries_acceptance_test.cpp)
target_link_libraries(queries_acceptance_test
    acceptance_fixture
    integration_framework
    )

addtest(create_asset_test create_asset_test.cpp)
target_link_libraries(create_asset_test
    acceptance_fixture
    integration_framework
    )

addtest(get_account_asset_txs_test
    "get_account_asset_txs_test.cpp;\
query_permission_test_ast_txs.cpp;\
query_permission_test_base.cpp"
    )
target_link_libraries(get_account_asset_txs_test
    acceptance_fixture
    integration_framework
    )

addtest(query_permissions_common_test
    "query_permission_common_tests.cpp;\
query_permission_test_ast_txs.cpp;\
query_permission_test_base.cpp;\
query_permission_test_txs.cpp"
    )
target_link_libraries(query_permissions_common_test
    acceptance_fixture
    integration_framework
    )

if(USE_BURROW)
    addtest(engine_call_test
        engine_call_test.cpp
        )
    target_link_libraries(engine_call_test
        acceptance_fixture
        integration_framework
        )
endif()

addtest(get_role_permissions_test
    get_role_permissions_test.cpp
    )
target_link_libraries(get_role_permissions_test
    acceptance_fixture
    integration_framework
    )

addtest(replay_test
    replay_test.cpp
    )
target_link_libraries(replay_test
    acceptance_fixture
    integration_framework
    )

addtest(fake_peer_example_test
    fake_peer_example_test.cpp
    )
target_link_libraries(fake_peer_example_test
    acceptance_fixture
    integration_framework
    ametsuchi
    )

addtest(set_account_quorum_test
    set_account_quorum_test.cpp
    )
target_link_libraries(set_account_quorum_test
    acceptance_fixture
    integration_framework
    )

addtest(hex_keys_test
   hex_keys_test.cpp
   )
target_link_libraries(hex_keys_test
   acceptance_fixture
   integration_framework
   )
