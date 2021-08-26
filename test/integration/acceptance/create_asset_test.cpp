/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <limits>

#include <gtest/gtest.h>
#include "framework/integration_framework/integration_test_framework.hpp"
#include "instantiate_test_suite.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"

using namespace integration_framework;
using namespace shared_model;
using namespace common_constants;

using iroha::StorageType;

struct CreateAssetFixture : AcceptanceFixture,
                            testing::WithParamInterface<iroha::StorageType> {
  auto makeUserWithPerms(const interface::RolePermissionSet &perms = {
                             interface::permissions::Role::kCreateAsset}) {
    return AcceptanceFixture::makeUserWithPerms(perms);
  }

  const interface::types::AssetNameType kAnotherAssetName = "newcoin";
  const interface::types::PrecisionType kPrecision = 1;
  const interface::types::PrecisionType kNonDefaultPrecision = kPrecision + 17;
  const interface::types::DomainIdType kNonExistingDomain = "nonexisting";
};

INSTANTIATE_TEST_SUITE_P_DifferentStorageTypes(CreateAssetFixture);

/*
 * With the current implementation of crateAsset method of TransactionBuilder
 * that is not possible to create tests for the following cases:
 * C238 Create asset with overflow of precision data type
 *   because the current implementation of TransactionBuilder does not
 *   allow to pass oversized value on a type level.
 */

/**
 * TODO mboldyrev 18.01.2019 IR-228 "Basic" tests should be replaced with a
 * common acceptance test
 *
 * @given some user with can_create_asset permission
 * @when the user tries to create an asset
 * @then asset is successfully created
 */
TEST_P(CreateAssetFixture, Basic) {
  const auto asset_id = kAnotherAssetName + "#" + kDomain;
  const auto asset_amount = "100.0";

  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms({interface::permissions::Role::kCreateAsset,
                                 interface::permissions::Role::kAddAssetQty}))
      .skipProposal()
      .checkBlock(
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      // testing the target command
      .sendTx(complete(
          baseTx().createAsset(kAnotherAssetName, kDomain, kPrecision)))
      .skipProposal()
      .checkBlock(
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      // testing that target command actually changed the state of the ledger
      .sendTx(complete(baseTx().addAssetQuantity(asset_id, asset_amount)))
      .skipProposal()
      .checkBlock(
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); });
}

/**
 * TODO mboldyrev 18.01.2019 IR-206 remove, covered by
 * postgres_executor_test CreateAccount.NameNotUnique
 *
 * C234 Create asset with an existing id (name)
 * @given a user with can_create_asset permission
 * @when the user tries to create asset that already exists
 * @then stateful validation failed
 */
TEST_P(CreateAssetFixture, ExistingName) {
  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTxAwait(
          makeUserWithPerms(),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendTx(complete(baseTx().createAsset(kAssetName, kDomain, kPrecision)))
      .checkProposal(
          [](auto &proposal) { ASSERT_EQ(proposal->transactions().size(), 1); })
      .checkVerifiedProposal(
          // todo igor-egorov, 2018-08-15, IR-1625, add precise check of
          // failure reason
          [](auto &vproposal) {
            ASSERT_EQ(vproposal->transactions().size(), 0);
          })
      .checkBlock(
          [](auto block) { ASSERT_EQ(block->transactions().size(), 0); });
}

/**
 * TODO mboldyrev 18.01.2019 IR-206 convert to a SFV integration test
 *
 * C234a Create asset with an existing id (name) but different precision
 * @given a user with can_create_asset permission
 * @when the user tries to create asset that already exists but with different
 * precision
 * @then stateful validation failed
 */
TEST_P(CreateAssetFixture, ExistingNameDifferentPrecision) {
  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTxAwait(
          makeUserWithPerms(),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendTx(complete(
          baseTx().createAsset(kAssetName, kDomain, kNonDefaultPrecision)))
      .checkProposal(
          [](auto &proposal) { ASSERT_EQ(proposal->transactions().size(), 1); })
      .checkVerifiedProposal(
          // todo igor-egorov, 2018-08-15, IR-1625, add precise check of
          // failure reason
          [](auto &vproposal) {
            ASSERT_EQ(vproposal->transactions().size(), 0);
          })
      .checkBlock(
          [](auto block) { ASSERT_EQ(block->transactions().size(), 0); });
}

/**
 * TODO mboldyrev 18.01.2019 IR-206 remove, covered by
 * postgres_executor_test CreateAccount.NoPerms
 *
 * C239 CreateAsset without such permissions
 * @given a user without can_create_asset permission
 * @when the user tries to create asset
 * @then stateful validation is failed
 */
TEST_P(CreateAssetFixture, WithoutPermission) {
  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTxAwait(
          makeUserWithPerms({}),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendTx(complete(baseTx().createAsset(kAssetName, kDomain, kPrecision)))
      .checkProposal(
          [](auto &proposal) { ASSERT_EQ(proposal->transactions().size(), 1); })
      .checkVerifiedProposal(
          // todo igor-egorov, 2018-08-15, IR-1625, add precise check of
          // failure reason
          [](auto &vproposal) {
            ASSERT_EQ(vproposal->transactions().size(), 0);
          })
      .checkBlock(
          [](auto block) { ASSERT_EQ(block->transactions().size(), 0); });
}

/**
 * TODO mboldyrev 18.01.2019 IR-206 remove, covered by
 * postgres_executor_test CreateAccount.NoDomain
 *
 * @given a user with can_create_asset permission
 * @when the user tries to create asset in valid but non existing domain
 * @then stateful validation will be failed
 */
TEST_P(CreateAssetFixture, ValidNonExistingDomain) {
  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTxAwait(
          makeUserWithPerms(),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendTx(complete(
          baseTx().createAsset(kAssetName, kNonExistingDomain, kPrecision)))
      .checkProposal(
          [](auto &proposal) { ASSERT_EQ(proposal->transactions().size(), 1); })
      .checkVerifiedProposal(
          // todo igor-egorov, 2018-08-15, IR-1625, add precise check of
          // failure reason
          [](auto &vproposal) {
            ASSERT_EQ(vproposal->transactions().size(), 0);
          })
      .checkBlock(
          [](auto block) { ASSERT_EQ(block->transactions().size(), 0); });
}
