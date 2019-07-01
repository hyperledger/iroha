/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "framework/integration_framework/integration_test_framework.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"

using namespace integration_framework;
using namespace shared_model;
using namespace common_constants;

class AddAssetQuantity : public AcceptanceFixture {
 public:
  auto makeUserWithPerms(const interface::RolePermissionSet &perms = {
                             interface::permissions::Role::kAddAssetQty}) {
    return AcceptanceFixture::makeUserWithPerms(perms);
  }

  const std::string kAmount = "1.0";
};

/**
 * TODO mboldyrev 17.01.2019 IR-228 "Basic" tests should be replaced with a
 * common acceptance test
 *
 * @given some user with can_add_asset_qty permission
 * @when execute tx with AddAssetQuantity command
 * @then there is the tx in proposal
 */
TEST_F(AddAssetQuantity, Basic) {
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms())
      .skipProposal()
      .skipBlock()
      .sendTxAwait(
          complete(baseTx().addAssetQuantity(kAssetId, kAmount)),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); });
}

/**
 * TODO mboldyrev 17.01.2019 IR-203 convert to an integration test
 *
 * @given some user without can_add_asset_qty permission
 * @when execute tx with AddAssetQuantity command
 * @then verified proposal is empty
 */
TEST_F(AddAssetQuantity, NoPermissions) {
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms({interface::permissions::Role::kGetMyTxs}))
      .skipProposal()
      .skipVerifiedProposal()
      .skipBlock()
      .sendTx(complete(baseTx().addAssetQuantity(kAssetId, kAmount)))
      .skipProposal()
      .checkVerifiedProposal(
          [](auto &proposal) { ASSERT_EQ(proposal->transactions().size(), 0); })
      .checkBlock(
          [](auto block) { ASSERT_EQ(block->transactions().size(), 0); });
}

/**
 * TODO mboldyrev 17.01.2019 IR-203 seems can be removed (covered by field
 * validator test and the above test)
 *
 * @given pair of users with all required permissions
 * @when execute tx with AddAssetQuantity command with zero amount
 * @then the tx hasn't passed stateless validation
 *       (aka skipProposal throws)
 */
TEST_F(AddAssetQuantity, ZeroAmount) {
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms())
      .skipProposal()
      .skipVerifiedProposal()
      .skipBlock()
      .sendTx(complete(baseTx().addAssetQuantity(kAssetId, "0.0")),
              CHECK_STATELESS_INVALID);
}

/**
 * TODO mboldyrev 17.01.2019 IR-203 remove, covered by
 * postgres_executor_test AddAccountAssetTest.Uint256Overflow
 *
 * @given pair of users with all required permissions
 * @when execute two txes with AddAssetQuantity command with amount more than a
 * uint256 max half
 * @then first transaction is committed @and verified proposal is empty for the
 * second
 */
TEST_F(AddAssetQuantity, Uint256DestOverflow) {
  std::string uint256_halfmax =
      "578960446186580977117854925043439539266349923328202820197287920039565648"
      "19966.0";  // 2**255 - 2
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms())
      .skipProposal()
      .skipVerifiedProposal()
      .skipBlock()
      // Add first half of the maximum
      .sendTxAwait(
          complete(baseTx().addAssetQuantity(kAssetId, uint256_halfmax)),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      // Add second half of the maximum
      .sendTx(complete(baseTx().addAssetQuantity(kAssetId, uint256_halfmax)))
      .skipProposal()
      .checkVerifiedProposal(
          [](auto &proposal) { ASSERT_EQ(proposal->transactions().size(), 0); })
      .checkBlock(
          [](auto block) { ASSERT_EQ(block->transactions().size(), 0); });
}

/**
 * TODO mboldyrev 17.01.2019 IR-203 remove, covered by
 * postgres_executor_test AddAccountAssetTest.InvalidAsset
 *
 * @given some user with all required permissions
 * @when execute tx with AddAssetQuantity command with nonexistent asset
 * @then verified proposal is empty
 */
TEST_F(AddAssetQuantity, NonexistentAsset) {
  std::string nonexistent = "inexist#test";
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms())
      .skipProposal()
      .skipVerifiedProposal()
      .skipBlock()
      .sendTx(complete(baseTx().addAssetQuantity(nonexistent, kAmount)))
      .skipProposal()
      .checkVerifiedProposal(
          [](auto &proposal) { ASSERT_EQ(proposal->transactions().size(), 0); })
      .checkBlock(
          [](auto block) { ASSERT_EQ(block->transactions().size(), 0); });
}
