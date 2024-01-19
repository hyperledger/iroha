/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/executor/executor_fixture.hpp"

#include <gtest/gtest.h>
#include "framework/common_constants.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "integration/executor/command_permission_test.hpp"
#include "integration/executor/executor_fixture_param_provider.hpp"
#include "interfaces/common_objects/amount.hpp"
#include "module/shared_model/mock_objects_factories/mock_command_factory.hpp"
#include "module/shared_model/mock_objects_factories/mock_query_factory.hpp"

using namespace common_constants;
using namespace executor_testing;
using namespace framework::expected;
using namespace shared_model::interface::types;

using shared_model::interface::permissions::Role;

using shared_model::interface::Amount;

static const Amount kAmount{std::string{"12.3"}};

class AddAssetQuantityTest : public ExecutorTestBase {
 public:
  iroha::ametsuchi::CommandResult addAsset(const AccountIdType &issuer,
                                           const AssetIdType &asset = kAssetId,
                                           const Amount &amount = kAmount,
                                           bool validation_enabled = true) {
    return getItf().executeCommandAsAccount(
        *getItf().getMockCommandFactory()->constructAddAssetQuantity(asset,
                                                                     amount),
        issuer,
        validation_enabled);
  }
  iroha::ametsuchi::CommandResult addAssetWithDescription(const AccountIdType &issuer,
                                           const AssetIdType &asset = kAssetId,
                                           const Amount &amount = kAmount,
                                           const DescriptionType &description = "",
                                           bool validation_enabled = true) {
    return getItf().executeCommandAsAccount(
        *getItf().getMockCommandFactory()->constructAddAssetQuantityWithDescription(asset,
                                                                     amount, description),
        issuer,
        validation_enabled);
  }
};

using AddAssetQuantityBasicTest = BasicExecutorTest<AddAssetQuantityTest>;

/**
 * @given a user with all related permissions
 * @when execute AddAssetQuantity command from that user for nonexistent asset
 * @then the command fails
 * @and the asset is not added to the user
 */
TEST_P(AddAssetQuantityBasicTest, InvalidAsset) {
  checkCommandError(addAssetWithDescription(kAdminId, kSecondDomainAssetId), 3);
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
  ASSERT_NO_FATAL_FAILURE(createAsset(kAssetName, kDomain, 1));
  IROHA_ASSERT_RESULT_VALUE(addAsset(kAdminId, kAssetId, kAmountPrec1Max));
  ASSERT_NO_FATAL_FAILURE(checkAssetQuantities(
      kAdminId, {AssetQuantity{kAssetId, kAmountPrec1Max}}));

  checkCommandError(addAssetWithDescription(kAdminId, kAssetId, Amount{"0.1"}), 4);
  checkCommandError(addAssetWithDescription(kAdminId, kAssetId, Amount{"1"}), 4);

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
  ASSERT_NO_FATAL_FAILURE(createAsset(kAssetName, kDomain, 2));
  IROHA_ASSERT_RESULT_VALUE(addAsset(kAdminId, kAssetId, kAmountPrec2Max));
  ASSERT_NO_FATAL_FAILURE(checkAssetQuantities(
      kAdminId, {AssetQuantity{kAssetId, kAmountPrec2Max}}));

  checkCommandError(addAssetWithDescription(kAdminId, kAssetId, Amount{"0.01"}), 4);
  checkCommandError(addAssetWithDescription(kAdminId, kAssetId, Amount{"0.1"}), 4);

  checkAssetQuantities(kAdminId, {AssetQuantity{kAssetId, kAmountPrec2Max}});
}

INSTANTIATE_TEST_SUITE_P(Base,
                         AddAssetQuantityBasicTest,
                         executor_testing::getExecutorTestParams(),
                         executor_testing::paramToString);

using AddAssetQuantityPermissionTest =
    command_permission_test::CommandPermissionTest<AddAssetQuantityTest>;

TEST_P(AddAssetQuantityPermissionTest, CommandPermissionTest) {
  ASSERT_NO_FATAL_FAILURE(getItf().createDomain(kSecondDomain));
  ASSERT_NO_FATAL_FAILURE(createAsset(kAssetName, kDomain, 1));
  ASSERT_NO_FATAL_FAILURE(prepareState({}));

  if (checkResponse(
          addAssetWithDescription(getActor(), kAssetId, kAmount, "", getValidationEnabled()))) {
    checkAssetQuantities(getActor(), {AssetQuantity{kAssetId, kAmount}});
  } else {
    checkAssetQuantities(getActor(), {});
  }
}

INSTANTIATE_TEST_SUITE_P(
    Common,
    AddAssetQuantityPermissionTest,
    command_permission_test::getParams(
        boost::none, Role::kAddDomainAssetQty, Role::kAddAssetQty, boost::none),
    command_permission_test::paramToString);
