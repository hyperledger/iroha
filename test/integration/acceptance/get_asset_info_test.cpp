/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include <boost/variant.hpp>
#include "backend/protobuf/transaction.hpp"
#include "builders/protobuf/queries.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"
#include "interfaces/query_responses/asset_response.hpp"
#include "utils/query_error_response_visitor.hpp"

using namespace integration_framework;
using namespace shared_model;
using namespace common_constants;

class GetAssetInfo : public AcceptanceFixture {
 public:
  GetAssetInfo() : itf(1) {}
  /**
   * Creates the transaction with the user creation commands
   * @param perms are the permissions of the user
   * @return built tx
   */
  auto makeUserWithPerms(const interface::RolePermissionSet &perms = {
                             interface::permissions::Role::kReadAssets}) {
    auto new_perms = perms;
    new_perms.set(interface::permissions::Role::kCreateAsset);
    return AcceptanceFixture::makeUserWithPerms(kNewRole, new_perms);
  }

  /**
   * Prepares base state that contains a default user
   * @param perms are the permissions of the user
   * @return itf with the base state
   */
  IntegrationTestFramework &prepareState(
      const interface::RolePermissionSet &perms = {
          interface::permissions::Role::kReadAssets}) {
    itf.setInitialState(kAdminKeypair)
        .sendTxAwait(makeUserWithPerms(perms), [=](auto &block) {
          ASSERT_EQ(block->transactions().size(), 1);
        });
    return itf;
  }

  /**
   * Creates valid GetAssetInfo query of the selected asset
   * @param asset is asset to query
   * @return built query
   */
  auto makeQuery(const std::string &asset) {
    return complete(baseQry().getAssetInfo(asset));
  }

  /**
   * Creates valid GetAssetInfo query of the current asset
   * @return built query
   */
  auto makeQuery() {
    return makeQuery(kAssetId);
  }

  /**
   * @param asset is asset name for checking
   * @param domain is domain for checking
   * @param role is role for checking
   * @return a lambda that verifies that query response contains specified asset
   */
  auto checkValidAsset(const std::string &asset,
                       const std::string &domain,
                       uint8_t precision) {
    return [&](const proto::QueryResponse &response) {
      ASSERT_NO_THROW({
        const auto &resp =
            boost::get<const shared_model::interface::AssetResponse &>(
                response.get());
        ASSERT_EQ(resp.asset().assetId(), asset);
        ASSERT_EQ(resp.asset().domainId(), domain);
        ASSERT_EQ(resp.asset().precision(), precision);
      }) << "Actual response: "
         << response.toString();
    };
  }

  /**
   * @return a lambda that verifies that query response contains specified asset
   */
  auto checkValidAsset() {
    return checkValidAsset(kAssetId, kDomain, 1);
  }

  const std::string kNewRole = "rl";
  IntegrationTestFramework itf;
};

/**
 * TODO mboldyrev 18.01.2019 IR-228 "Basic" tests should be replaced with a
 * common acceptance test
 *
 * C363 Get asset info with CanReadAssets permission
 * @given a user with GetMyAccount permission
 * @when GetAssetInfo is queried on the user
 * @then there is a valid AccountResponse
 * TODO(@l4l) 3/9/18: enable after IR-1668
 */
TEST_F(GetAssetInfo, DISABLED_Basic) {
  prepareState().sendQuery(makeQuery(), checkValidAsset());
}

/**
 * TODO mboldyrev 18.01.2019 IR-212 seems can be removed (covered by field
 * validator test)
 *
 * C365 Pass an empty asset id
 * @given a user with all required permissions
 * @when GetAssetInfo is queried on the empty asset name
 * @then query has stateless invalid response
 */
TEST_F(GetAssetInfo, EmptyAsset) {
  prepareState().sendQuery(
      makeQuery(""),
      checkQueryErrorResponse<
          shared_model::interface::StatelessFailedErrorResponse>());
}

/**
 * TODO mboldyrev 18.01.2019 IR-212 remove, covered by
 * postgres_query_executor_test GetAssetInfoExecutorTest.InvalidNoAsset
 *
 * C366 Pass a non-existing asset id
 * @given a user with all required permissions
 * @when GetAssetInfo is queried on the user
 * @then query has stateful invalid response
 */
TEST_F(GetAssetInfo, NonexistentAsset) {
  prepareState().sendQuery(
      makeQuery("inexistent#" + kDomain),
      checkQueryErrorResponse<shared_model::interface::NoAssetErrorResponse>());
}

/**
 * TODO mboldyrev 18.01.2019 IR-212 remove, covered by
 * postgres_query_executor_test GetAssetInfoExecutorTest.Invalid
 * seems we should move the common_query_permissions_test to SFV integration
 *
 * C364 Get asset info without CanReadAssets permission
 * @given a user without any query-related permission
 * @when GetAssetInfo is queried on the user
 * @then query has stateful invalid response
 */
TEST_F(GetAssetInfo, NoPermission) {
  prepareState({}).sendQuery(
      makeQuery(),
      checkQueryErrorResponse<
          shared_model::interface::StatefulFailedErrorResponse>());
}
