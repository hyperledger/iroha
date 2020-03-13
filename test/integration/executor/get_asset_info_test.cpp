/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/executor/executor_fixture.hpp"

#include <gtest/gtest.h>
#include "framework/common_constants.hpp"
#include "integration/executor/query_permission_test.hpp"
#include "module/shared_model/mock_objects_factories/mock_command_factory.hpp"
#include "module/shared_model/mock_objects_factories/mock_query_factory.hpp"

using namespace common_constants;
using namespace executor_testing;
using namespace framework::expected;
using namespace shared_model::interface::types;

using iroha::ametsuchi::QueryExecutorResult;
using shared_model::interface::AssetResponse;
using shared_model::interface::permissions::Role;

constexpr PrecisionType kAssetPrecision(1);

struct GetAssetInfoTest : public ExecutorTestBase {
  void prepareAsset() {
    SCOPED_TRACE("GetAssetInfoTest::prepareAsset");
    createAsset(kAssetName, kDomain, kAssetPrecision);
  }

  /// Check the response.
  void validateResponse(const AssetResponse &response) {
    EXPECT_EQ(response.asset().assetId(), kAssetId);
    EXPECT_EQ(response.asset().domainId(), kDomain);
    EXPECT_EQ(response.asset().precision(), kAssetPrecision);
  }

  /// Query asset info.
  QueryExecutorResult query(AccountIdType command_issuer = kAdminId) {
    return getItf().executeQuery(
        *getItf().getMockQueryFactory()->constructGetAssetInfo(kAssetId),
        command_issuer);
  }
};

using GetAssetInfoBasicTest = BasicExecutorTest<GetAssetInfoTest>;

/**
 * @given a user with all related permissions
 * @when GetAssetInfo is queried on a nonexistent asset
 * @then there is an error
 */
TEST_P(GetAssetInfoBasicTest, InvalidNoAsset) {
  checkQueryError<shared_model::interface::NoAssetErrorResponse>(
      query(), error_codes::kNoStatefulError);
}

INSTANTIATE_TEST_SUITE_P(Base,
                         GetAssetInfoBasicTest,
                         executor_testing::getExecutorTestParams(),
                         executor_testing::paramToString);

using GetAssetInfoPermissionTest =
    query_permission_test::QueryPermissionTest<GetAssetInfoTest>;

TEST_P(GetAssetInfoPermissionTest, QueryPermissionTest) {
  ASSERT_NO_FATAL_FAILURE(prepareState({}));
  prepareAsset();
  checkResponse<AssetResponse>(query(getSpectator()),
                               [this](const AssetResponse &response) {
                                 this->validateResponse(response);
                               });
}

INSTANTIATE_TEST_SUITE_P(Common,
                         GetAssetInfoPermissionTest,
                         query_permission_test::getParams({boost::none},
                                                          {boost::none},
                                                          {Role::kReadAssets}),
                         query_permission_test::paramToString);
