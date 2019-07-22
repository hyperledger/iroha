/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/binary/binaries_test_fixture.hpp"

using namespace shared_model::interface;

using BinaryTestTypes = ::testing::Types<
    binary_test::PythonLauncher>;  //, binary_test::JavaLauncher>;

TYPED_TEST_CASE(BinaryTestFixture, BinaryTestTypes, );

// -------------------------- Transactions --------------------------

TYPED_TEST(BinaryTestFixture, can_create_account) {
  this->doTest(2);
}

TYPED_TEST(BinaryTestFixture, can_set_detail) {
  this->doTest(2);
}

TYPED_TEST(BinaryTestFixture, can_grant_can_set_my_account_detail) {
  this->doTest(3);
}

TYPED_TEST(BinaryTestFixture, can_set_my_account_detail) {
  this->doTest(3);
}

TYPED_TEST(BinaryTestFixture, can_create_asset) {
  this->doTest(2);
}

TYPED_TEST(BinaryTestFixture, can_receive) {
  this->doTest(2);
}

TYPED_TEST(BinaryTestFixture, can_transfer) {
  this->doTest(2);
}

TYPED_TEST(BinaryTestFixture, can_grant_can_transfer_my_assets) {
  this->doTest(3);
}

TYPED_TEST(BinaryTestFixture, can_transfer_my_assets) {
  this->doTest(3);
}

TYPED_TEST(BinaryTestFixture, can_add_asset_qty) {
  this->doTest(2);
}

TYPED_TEST(BinaryTestFixture, can_subtract_asset_qty) {
  this->doTest(2);
}

TYPED_TEST(BinaryTestFixture, can_create_domain) {
  this->doTest(2);
}

TYPED_TEST(BinaryTestFixture, can_add_peer) {
  this->doTest(2);
}

// TODO lebdron 2019-07-22: IR-587 Enable can_remove_peer test
TYPED_TEST(BinaryTestFixture, DISABLED_can_remove_peer) {
  this->doTest(2);
}

TYPED_TEST(BinaryTestFixture, can_create_role) {
  this->doTest(2);
}

TYPED_TEST(BinaryTestFixture, can_append_role) {
  this->doTest(2);
}

TYPED_TEST(BinaryTestFixture, can_detach_role) {
  this->doTest(2);
}

TYPED_TEST(BinaryTestFixture, can_add_signatory) {
  this->doTest(2);
}

TYPED_TEST(BinaryTestFixture, can_grant_can_add_my_signatory) {
  this->doTest(3);
}

TYPED_TEST(BinaryTestFixture, can_grant_can_remove_my_signatory) {
  this->doTest(3);
}

TYPED_TEST(BinaryTestFixture, can_grant_can_set_my_quorum) {
  this->doTest(3);
}

TYPED_TEST(BinaryTestFixture, can_add_my_signatory) {
  this->doTest(3);
}

TYPED_TEST(BinaryTestFixture, can_remove_signatory) {
  this->doTest(2);
}

TYPED_TEST(BinaryTestFixture, can_set_my_quorum) {
  this->doTest(3);
}

TYPED_TEST(BinaryTestFixture, can_remove_my_signatory) {
  this->doTest(3);
}

TYPED_TEST(BinaryTestFixture, can_set_quorum) {
  this->doTest(2);
}

// -------------------------- Queries --------------------------

TYPED_TEST(BinaryTestFixture, can_get_all_acc_detail) {
  this->template doTest<AccountDetailResponse>(1, 1);
}

TYPED_TEST(BinaryTestFixture, can_get_all_accounts) {
  this->template doTest<AccountResponse>(1, 1);
}

TYPED_TEST(BinaryTestFixture, can_get_domain_acc_detail) {
  this->template doTest<AccountDetailResponse>(1, 1);
}

TYPED_TEST(BinaryTestFixture, can_get_domain_accounts) {
  this->template doTest<AccountResponse>(1, 1);
}

TYPED_TEST(BinaryTestFixture, can_get_my_acc_detail) {
  this->template doTest<AccountDetailResponse>(1, 1);
}

TYPED_TEST(BinaryTestFixture, can_get_my_account) {
  this->template doTest<AccountResponse>(1, 1);
}

TYPED_TEST(BinaryTestFixture, can_get_all_acc_ast) {
  this->template doTest<AccountAssetResponse>(1, 1);
}

TYPED_TEST(BinaryTestFixture, can_get_domain_acc_ast) {
  this->template doTest<AccountAssetResponse>(1, 1);
}

TYPED_TEST(BinaryTestFixture, can_get_my_acc_ast) {
  this->template doTest<AccountAssetResponse>(1, 1);
}

TYPED_TEST(BinaryTestFixture, can_get_all_acc_ast_txs) {
  this->template doTest<TransactionsPageResponse>(1, 1);
}

TYPED_TEST(BinaryTestFixture, can_get_domain_acc_ast_txs) {
  this->template doTest<TransactionsPageResponse>(1, 1);
}

TYPED_TEST(BinaryTestFixture, can_get_my_acc_ast_txs) {
  this->template doTest<TransactionsPageResponse>(1, 1);
}

TYPED_TEST(BinaryTestFixture, can_get_all_acc_txs) {
  this->template doTest<TransactionsPageResponse>(1, 1);
}

TYPED_TEST(BinaryTestFixture, can_get_domain_acc_txs) {
  this->template doTest<TransactionsPageResponse>(1, 1);
}

TYPED_TEST(BinaryTestFixture, can_get_my_acc_txs) {
  this->template doTest<TransactionsPageResponse>(1, 1);
}

TYPED_TEST(BinaryTestFixture, can_read_assets) {
  this->template doTest<AssetResponse>(1, 1);
}

TYPED_TEST(BinaryTestFixture, can_get_roles) {
  this->template doTest<RolesResponse, RolePermissionsResponse>(1, 2);
}

TYPED_TEST(BinaryTestFixture, can_get_all_signatories) {
  this->template doTest<SignatoriesResponse>(1, 1);
}

TYPED_TEST(BinaryTestFixture, can_get_domain_signatories) {
  this->template doTest<SignatoriesResponse>(1, 1);
}

TYPED_TEST(BinaryTestFixture, can_get_my_signatories) {
  this->template doTest<SignatoriesResponse>(1, 1);
}

TYPED_TEST(BinaryTestFixture, can_get_all_txs) {
  this->template doTest<TransactionsResponse>(3, 1);
}

TYPED_TEST(BinaryTestFixture, can_get_my_txs) {
  this->template doTest<TransactionsResponse>(3, 1);
}

TYPED_TEST(BinaryTestFixture, can_get_peers) {
  this->template doTest<PeersResponse>(1, 1);
}
