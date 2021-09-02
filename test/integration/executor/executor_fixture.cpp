/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/executor/executor_fixture.hpp"

#include <gtest/gtest.h>
#include <boost/range/adaptor/transformed.hpp>
#include "framework/common_constants.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "interfaces/query_responses/query_response.hpp"
#include "interfaces/query_responses/signatories_response.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"
#include "module/shared_model/mock_objects_factories/mock_command_factory.hpp"
#include "module/shared_model/mock_objects_factories/mock_query_factory.hpp"

using namespace common_constants;
using namespace executor_testing;
using namespace framework::expected;
using namespace iroha::ametsuchi;
using namespace iroha::expected;
using namespace iroha::integration_framework;
using namespace shared_model::interface::types;

namespace executor_testing {

  void checkCommandError(const CommandResult &command_result,
                         CommandError::ErrorCodeType error_code) {
    if (auto err = resultToOptionalError(command_result)) {
      // EXPECT_EQ(err->error_code, error_code);
    } else {
      ADD_FAILURE() << "Did not get the expected command error!";
    }
  }

  std::pair<std::string, std::string> splitNameAndDomain(const std::string &id,
                                                         char delimeter) {
    auto it = id.find(delimeter);
    if (it == std::string::npos) {
      throw std::runtime_error(std::string{"Failed to split '"} + id + "' by '"
                               + delimeter + "' because delimeter not found.");
    }
    if (id.find(delimeter, it + 1) != std::string::npos) {
      throw std::runtime_error(std::string{"Failed to split '"} + id + "' by '"
                               + delimeter
                               + "' because delimeter found more than once.");
    }
    return std::make_pair(id.substr(0, it), id.substr(it + 1));
  }

  std::pair<std::string, std::string> splitAssetId(const std::string &id) {
    return splitNameAndDomain(id, '#');
  }

  std::pair<std::string, std::string> splitAccountId(const std::string &id) {
    return splitNameAndDomain(id, '@');
  }

}  // namespace executor_testing

void ExecutorTestBase::SetUp() {
  getBackendParam().clearBackendState();
  auto &test_param = getBackendParam();
  type_ = test_param.getType();

  auto executor_itf_result =
      ExecutorItf::create(test_param.getExecutorItfParam());
  IROHA_ASSERT_RESULT_VALUE(executor_itf_result);
  executor_itf_ = std::move(executor_itf_result).assumeValue();
}

ExecutorItf &ExecutorTestBase::getItf() const {
  return *executor_itf_;
}

void ExecutorTestBase::createAsset(const std::string &name,
                                   const std::string &domain,
                                   PrecisionType precision) const {
  SCOPED_TRACE("createAsset");
  IROHA_ASSERT_RESULT_VALUE(getItf().executeMaintenanceCommand(
      *getItf().getMockCommandFactory()->constructCreateAsset(
          name, domain, precision)));
}

void ExecutorTestBase::addAsset(
    const AccountIdType &dest_account_id,
    const AssetIdType &asset_id,
    const shared_model::interface::Amount &quantity) {
  SCOPED_TRACE("addAsset");
  IROHA_ASSERT_RESULT_VALUE(getItf().executeMaintenanceCommand(
      *getItf().getMockCommandFactory()->constructAddAssetQuantity(asset_id,
                                                                   quantity)));
  IROHA_ASSERT_RESULT_VALUE(getItf().executeMaintenanceCommand(
      *getItf().getMockCommandFactory()->constructTransferAsset(
          kAdminId, dest_account_id, asset_id, "adding asset", quantity)));
}

void ExecutorTestBase::checkAssetQuantities(
    const AccountAssetCollectionType &test_quantities,
    const std::vector<AssetQuantity> &reference_quantities) {
  static const auto make_asset_matcher = [](AssetQuantity reference) {
    return ::testing::Truly(
        [reference](const shared_model::interface::AccountAsset &tested) {
          if (tested.assetId() == reference.asset_id) {
            EXPECT_EQ(tested.balance(), reference.balance)
                << "Wrong balance of asset " << reference.asset_id;
            return true;
          }
          return false;
        });
  };

  auto asset_matchers = boost::copy_range<
      std::vector<decltype(make_asset_matcher(reference_quantities.front()))>>(
      reference_quantities | boost::adaptors::transformed(make_asset_matcher));

  EXPECT_THAT(test_quantities,
              ::testing::UnorderedElementsAreArray(asset_matchers));
}

void ExecutorTestBase::checkAssetQuantities(
    const std::string &account_id,
    const std::vector<AssetQuantity> &quantities) {
  auto pagination_meta =
      getItf().getMockQueryFactory()->constructAssetPaginationMeta(
          quantities.size(), std::nullopt);
  getItf()
      .executeQueryAndConvertResult(
          *getItf().getMockQueryFactory()->constructGetAccountAssets(
              account_id, *pagination_meta))
      .specific_response.match(
          [&](const auto &get_account_assets_response) {
            checkAssetQuantities(
                get_account_assets_response.value.accountAssets(), quantities);
          },
          [](const auto &other_response) {
            ADD_FAILURE() << "Unexpected query response: "
                          << other_response.error->toString();
          });
}

void ExecutorTestBase::checkSignatories(
    const std::string &account_id,
    const std::vector<PublicKeyHexStringView> &keys) {
  getItf()
      .executeQueryAndConvertResult(
          *getItf().getMockQueryFactory()->constructGetSignatories(account_id))
      .specific_response.match(
          [&](const auto &get_signatories_response) {
            EXPECT_THAT(get_signatories_response.value.keys(),
                        ::testing::UnorderedElementsAreArray(keys));
          },
          [](const auto &other_response) {
            ADD_FAILURE() << "Unexpected query response: "
                          << other_response.error->toString();
          });
}
