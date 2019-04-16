/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/acceptance/query_permission_fixture.hpp"
#include "integration/acceptance/query_permission_test_ast.hpp"
#include "interfaces/query_responses/account_asset_response.hpp"

using namespace common_constants;
using AccountAssetsFixture = QueryPermissionFixture<QueryPermissionAssets>;

/**
 * Creates a functor for checking the quantity of assets in a query response
 * @param the expected quantity
 * @return the checker functor
 */
auto getAccountAssetsQuantityChecker(int quantity) {
  return [quantity](const shared_model::proto::QueryResponse &query_response) {
    ASSERT_NO_THROW({
      const auto &resp = boost::get<const interface::AccountAssetResponse &>(
          query_response.get());

      ASSERT_EQ(resp.accountAssets().size(), quantity);
    });
  };
}

/**
 * TODO mboldyrev 18.01.2019 IR-210 convert to a SFV integration test
 * (no such test in postgres_query_executor_test)
 *
 * @given a user with all required permissions
 * @when GetAccountAssets is queried on the user with no assets
 * @then there is an AccountAssetResponse reporting no asset presence
 */
TEST_F(AccountAssetsFixture, NonAddedAssets) {
  auto check_zero_assets = getAccountAssetsQuantityChecker(0);

  static_cast<QueryPermissionTestBase *>(&this->impl_)
      ->prepareState(*this, {}, {this->impl_.kPermissionToQueryEveryone})
      .sendQuery(this->impl_.makeQuery(*this, kUserId, kUserId, kUserKeypair),
                 check_zero_assets);
}
