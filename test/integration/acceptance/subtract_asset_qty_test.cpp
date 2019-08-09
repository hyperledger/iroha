/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "backend/protobuf/transaction.hpp"
#include "cryptography/crypto_provider/crypto_defaults.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"

using namespace integration_framework;
using namespace shared_model;
using namespace common_constants;

class SubtractAssetQuantity : public AcceptanceFixture {
 public:
  /**
   * Creates the transaction with the user creation commands
   * @param perms are the permissions of the user
   * @return built tx and a hash of its payload
   */
  auto makeUserWithPerms(const interface::RolePermissionSet &perms = {
                             interface::permissions::Role::kSubtractAssetQty,
                             interface::permissions::Role::kAddAssetQty}) {
    return AcceptanceFixture::makeUserWithPerms(perms);
  }

  /**
   * @return built tx that adds kAmount assets to the users
   */
  auto replenish() {
    return complete(baseTx().addAssetQuantity(kAssetId, kAmount));
  }

  const std::string kAmount = "1.0";
};

/**
 * TODO mboldyrev 18.01.2019 IR-228 "Basic" tests should be replaced with a
 * common acceptance test
 * also covered by postgres_executor_test SubtractAccountAssetTest.Valid
 *
 * @given some user with all required permissions
 * @when execute tx with SubtractAssetQuantity command with max available amount
 * @then there is the tx in proposal
 */
TEST_F(SubtractAssetQuantity, Everything) {
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms())
      .skipProposal()
      .skipBlock()
      .sendTx(replenish())
      .skipProposal()
      .skipVerifiedProposal()
      .skipBlock()
      .sendTxAwait(
          complete(baseTx().subtractAssetQuantity(kAssetId, kAmount)),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); });
}

/**
 * TODO mboldyrev 18.01.2019 IR-225 remove, covered by
 * postgres_executor_test SubtractAccountAssetTest.NotEnoughAsset
 *
 * @given some user with all required permissions
 * @when execute tx with SubtractAssetQuantity command with amount more than
 * user has
 * @then there is an empty verified proposal
 */
TEST_F(SubtractAssetQuantity, Overdraft) {
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms())
      .skipProposal()
      .skipVerifiedProposal()
      .skipBlock()
      .sendTx(replenish())
      .skipProposal()
      .skipVerifiedProposal()
      .skipBlock()
      .sendTx(complete(baseTx().subtractAssetQuantity(kAssetId, "2.0")))
      .skipProposal()
      .checkVerifiedProposal(
          [](auto &proposal) { ASSERT_EQ(proposal->transactions().size(), 0); })
      .checkBlock(
          [](auto block) { ASSERT_EQ(block->transactions().size(), 0); });
}

/**
 * TODO mboldyrev 18.01.2019 IR-225 remove, covered by
 * postgres_executor_test SubtractAccountAssetTest.NoPerms
 *
 * @given some user without can_subtract_asset_qty permission
 * @when execute tx with SubtractAssetQuantity command there is an empty
 * verified proposal
 */
TEST_F(SubtractAssetQuantity, NoPermissions) {
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms({interface::permissions::Role::kAddAssetQty}))
      .skipProposal()
      .skipVerifiedProposal()
      .skipBlock()
      .sendTx(replenish())
      .skipProposal()
      .skipVerifiedProposal()
      .skipBlock()
      .sendTx(complete(baseTx().subtractAssetQuantity(kAssetId, kAmount)))
      .skipProposal()
      .checkVerifiedProposal(
          [](auto &proposal) { ASSERT_EQ(proposal->transactions().size(), 0); })
      .checkBlock(
          [](auto block) { ASSERT_EQ(block->transactions().size(), 0); });
}

/**
 * TODO mboldyrev 18.01.2019 IR-225 remove, covered by field validator test
 *
 * @given pair of users with all required permissions
 * @when execute tx with SubtractAssetQuantity command with zero amount
 * @then the tx hasn't passed stateless validation
 *       (aka skipProposal throws)
 */
TEST_F(SubtractAssetQuantity, ZeroAmount) {
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms())
      .skipProposal()
      .skipBlock()
      .sendTxAwait(replenish(), [](auto &) {})
      .sendTx(complete(baseTx().subtractAssetQuantity(kAssetId, "0.0")),
              CHECK_STATELESS_INVALID);
}

/**
 * TODO mboldyrev 18.01.2019 IR-225 remove, covered by
 * postgres_executor_test SubtractAccountAssetTest.NoAsset
 *
 * @given some user with all required permissions
 * @when execute tx with SubtractAssetQuantity command with nonexistent asset
 * @then there is an empty verified proposal
 */
TEST_F(SubtractAssetQuantity, NonexistentAsset) {
  std::string nonexistent = "inexist#test";
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms())
      .skipProposal()
      .skipVerifiedProposal()
      .skipBlock()
      .sendTxAwait(replenish(), [](auto &) {})
      .sendTx(complete(baseTx().subtractAssetQuantity(nonexistent, kAmount)))
      .skipProposal()
      .checkVerifiedProposal(
          [](auto &proposal) { ASSERT_EQ(proposal->transactions().size(), 0); })
      .checkBlock(
          [](auto block) { ASSERT_EQ(block->transactions().size(), 0); });
}
