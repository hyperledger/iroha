/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/acceptance/query_permission_test_ast.hpp"

#include "framework/common_constants.hpp"
#include "interfaces/query_responses/account_asset_response.hpp"

using shared_model::interface::Amount;
using namespace common_constants;

QueryPermissionAssets::QueryPermissionAssets()
    : QueryPermissionTestBase({Role::kGetMyAccAst},
                              {Role::kGetDomainAccAst},
                              {Role::kGetAllAccAst}),
      account_assets_(
          {std::make_pair(std::string("asset1#") + kDomain, Amount("100.0")),
           std::make_pair(std::string("asset2#") + kDomain, Amount("200.0"))}) {
}

IntegrationTestFramework &QueryPermissionAssets::prepareState(
    AcceptanceFixture &fixture,
    const interface::RolePermissionSet &spectator_permissions) {
  auto target_permissions = spectator_permissions;
  target_permissions.set(Role::kCreateAsset);
  target_permissions.set(Role::kAddAssetQty);
  target_permissions.set(Role::kSubtractAssetQty);

  // initial state setup
  auto &itf = QueryPermissionTestBase::prepareState(
      fixture, spectator_permissions, target_permissions);

  // Add assets to target user
  for (const auto &asset : account_assets_) {
    const std::string asset_id = asset.first;
    const auto domain_sep = std::find(asset_id.cbegin(), asset_id.cend(), '#');
    const std::string asset_name(asset_id.cbegin(), domain_sep);
    const std::string asset_domain(domain_sep + 1, asset_id.cend());
    itf.sendTxAwait(
        fixture.complete(
            fixture.baseTx(kUserId)
                .createAsset(asset_name, asset_domain, asset.second.precision())
                .addAssetQuantity(asset.first, asset.second.toStringRepr()),
            kUserKeypair),
        getBlockTransactionsAmountChecker(1));
  }

  return itf;
}

std::function<void(const proto::QueryResponse &response)>
QueryPermissionAssets::getGeneralResponseChecker() {
  return [this](const proto::QueryResponse &response) {
    ASSERT_NO_THROW({
      const auto &resp =
          boost::get<const interface::AccountAssetResponse &>(response.get());

      const auto &resp_assets = resp.accountAssets();
      ASSERT_EQ(boost::size(resp_assets), account_assets_.size());
      // check that every initially created asset is present in the result
      for (const auto &asset : account_assets_) {
        ASSERT_NE(std::find_if(resp_assets.begin(),
                               resp_assets.end(),
                               [&asset](const auto &a) {
                                 return asset.first == a.assetId()
                                     and asset.second == a.balance()
                                     and kUserId == a.accountId();
                               }),
                  resp_assets.end());
      }
    }) << "Actual response: "
       << response.toString();
  };
}

shared_model::proto::Query QueryPermissionAssets::makeQuery(
    AcceptanceFixture &fixture,
    const interface::types::AccountIdType &target,
    const interface::types::AccountIdType &spectator,
    const crypto::Keypair &spectator_keypair) {
  return fixture.complete(fixture.baseQry(spectator).getAccountAssets(
                              target, kMaxPageSize, boost::none),
                          spectator_keypair);
}
