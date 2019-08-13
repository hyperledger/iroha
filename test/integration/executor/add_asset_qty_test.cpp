/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/executor/executor_fixture.hpp"

#include <gtest/gtest.h>
#include "cryptography/crypto_provider/crypto_defaults.hpp"
#include "framework/common_constants.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "integration/executor/executor_fixture_param_provider.hpp"
#include "interfaces/common_objects/amount.hpp"
#include "module/shared_model/mock_objects_factories/mock_command_factory.hpp"
#include "module/shared_model/mock_objects_factories/mock_query_factory.hpp"

using namespace common_constants;
using namespace framework::expected;

using shared_model::interface::permissions::Grantable;
using shared_model::interface::permissions::Role;

using shared_model::interface::Amount;

static const Amount kAmount{std::string{"12.3"}};

using AddAssetQuantityBasicTest =
    executor_testing::BasicExecutorTest<executor_testing::ExecutorTestBase>;

/**
 * @given an asset in another domain and a user with kAddAssetQty permission
 * @when execute AddAssetQuantity command from that user for that asset
 * @then the command succeeds
 * @and the asset quantity gets increased
 */
TEST_P(AddAssetQuantityBasicTest, Basic) {
  getItf().createDomain(kSecondDomain);
  createAsset(kAssetName, kSecondDomain, 1);
  assertResultValue(getItf().createUserWithPerms(
      kUser, kDomain, kUserKeypair.publicKey(), {Role::kAddAssetQty}));

  expectResultValue(getItf().executeCommandAsAccount(
      *getItf().getMockCommandFactory()->constructAddAssetQuantity(
          kAnotherDomainAssetId, kAmount),
      kUserId,
      true));

  checkAssetQuantities(kUserId,
                       {AssetQuantity{kAnotherDomainAssetId, kAmount}});
}

/**
 * @given a user with kAddDomainAssetQty permission and an asset in the same
 * domain
 * @when execute AddAssetQuantity command from that user for that asset
 * @then the command succeeds
 * @and the asset quantity gets increased
 */
TEST_P(AddAssetQuantityBasicTest, DomainPermValid) {
  createAsset(kAssetName, kDomain, 1);
  assertResultValue(getItf().createUserWithPerms(
      kUser, kDomain, kUserKeypair.publicKey(), {Role::kAddDomainAssetQty}));

  expectResultValue(getItf().executeCommandAsAccount(
      *getItf().getMockCommandFactory()->constructAddAssetQuantity(kAssetId,
                                                                   kAmount),
      kUserId,
      true));

  checkAssetQuantities(kUserId, {AssetQuantity{kAssetId, kAmount}});
}

/**
 * @given a user with kAddDomainAssetQty permission and an asset in another
 * domain
 * @when execute AddAssetQuantity command from that user for that asset
 * @then the command fails
 * @and the asset is not added to the user
 */
TEST_P(AddAssetQuantityBasicTest, DomainPermInvalidValid) {
  getItf().createDomain(kSecondDomain);
  createAsset(kAssetName, kSecondDomain, 1);
  assertResultValue(getItf().createUserWithPerms(
      kUser, kDomain, kUserKeypair.publicKey(), {Role::kAddDomainAssetQty}));

  expectResultError(getItf().executeCommandAsAccount(
      *getItf().getMockCommandFactory()->constructAddAssetQuantity(
          kAnotherDomainAssetId, kAmount),
      kUserId,
      true));

  checkAssetQuantities(kUserId, {});
}

/**
 * @given a user without any permissions and an asset in the same domain
 * @when execute AddAssetQuantity command from that user for that asset
 * @then the command fails
 * @and the asset is not added to the user
 */
TEST_P(AddAssetQuantityBasicTest, NoPermissions) {
  createAsset(kAssetName, kDomain, 1);
  assertResultValue(getItf().createUserWithPerms(
      kUser, kDomain, kUserKeypair.publicKey(), {}));

  expectResultError(getItf().executeCommandAsAccount(
      *getItf().getMockCommandFactory()->constructAddAssetQuantity(kAssetId,
                                                                   kAmount),
      kUserId,
      true));

  checkAssetQuantities(kUserId, {});
}

/**
 * @given a user with all related permissions
 * @when execute AddAssetQuantity command from that user for nonexistent asset
 * @then the command fails
 * @and the asset is not added to the user
 */
TEST_P(AddAssetQuantityBasicTest, InvalidAsset) {
  expectResultError(getItf().executeMaintenanceCommand(
      *getItf().getMockCommandFactory()->constructAddAssetQuantity(kAssetId,
                                                                   kAmount)));

  checkAssetQuantities(kAdminId, {});
}

/**
 * @given a user with all related permissions having the maximum amount of an
 * asset with precision 1
 * @when execute AddAssetQuantity command from that user for that asset that
 * would overflow the asset quantity by:
 * 1) minimum amount quantity of that asset precision
 * 2) minimum amount quantity of less precision
 * @then both commands fail
 * @and the asset amount is not increased
 */
TEST_P(AddAssetQuantityBasicTest, DestOverflowPrecision1) {
  createAsset(kAssetName, kDomain, 1);
  assertResultValue(getItf().executeMaintenanceCommand(
      *getItf().getMockCommandFactory()->constructAddAssetQuantity(
          kAssetId, kAmountPrec1Max)));
  checkAssetQuantities(kAdminId, {AssetQuantity{kAssetId, kAmountPrec1Max}});

  expectResultError(getItf().executeMaintenanceCommand(
      *getItf().getMockCommandFactory()->constructAddAssetQuantity(
          kAssetId, Amount{"0.1"})));
  expectResultError(getItf().executeMaintenanceCommand(
      *getItf().getMockCommandFactory()->constructAddAssetQuantity(
          kAssetId, Amount{"1"})));
  checkAssetQuantities(kAdminId, {AssetQuantity{kAssetId, kAmountPrec1Max}});
}

/**
 * @given a user with all related permissions having the maximum amount of an
 * asset with precision 2
 * @when execute AddAssetQuantity command from that user for that asset that
 * would overflow the asset quantity by:
 * 1) minimum amount quantity of that asset precision
 * 2) minimum amount quantity of less precision
 * @then both commands fail
 * @and the asset amount is not increased
 */
TEST_P(AddAssetQuantityBasicTest, DestOverflowPrecision2) {
  createAsset(kAssetName, kDomain, 2);
  assertResultValue(getItf().executeMaintenanceCommand(
      *getItf().getMockCommandFactory()->constructAddAssetQuantity(
          kAssetId, kAmountPrec2Max)));
  checkAssetQuantities(kAdminId, {AssetQuantity{kAssetId, kAmountPrec2Max}});

  expectResultError(getItf().executeMaintenanceCommand(
      *getItf().getMockCommandFactory()->constructAddAssetQuantity(
          kAssetId, Amount{"0.01"})));
  expectResultError(getItf().executeMaintenanceCommand(
      *getItf().getMockCommandFactory()->constructAddAssetQuantity(
          kAssetId, Amount{"0.1"})));
  checkAssetQuantities(kAdminId, {AssetQuantity{kAssetId, kAmountPrec2Max}});
}

INSTANTIATE_TEST_CASE_P(Base,
                        AddAssetQuantityBasicTest,
                        executor_testing::getExecutorTestParams(),
                        executor_testing::paramToString);
