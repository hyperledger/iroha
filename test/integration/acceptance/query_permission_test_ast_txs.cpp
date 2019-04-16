/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/acceptance/query_permission_test_ast_txs.hpp"

#include "interfaces/query_responses/transactions_page_response.hpp"

using namespace common_constants;

static constexpr shared_model::interface::types::TransactionsNumberType
    kTxPageSize(10);

QueryPermissionAssetTxs::QueryPermissionAssetTxs()
    : QueryPermissionTestBase({Role::kGetMyAccAstTxs},
                              {Role::kGetDomainAccAstTxs},
                              {Role::kGetAllAccAstTxs}) {}

IntegrationTestFramework &QueryPermissionAssetTxs::prepareState(
    AcceptanceFixture &fixture,
    const interface::RolePermissionSet &spectator_permissions) {
  auto target_permissions = spectator_permissions;
  target_permissions.set(Role::kReceive);
  target_permissions.set(Role::kTransfer);
  target_permissions.set(Role::kAddAssetQty);
  target_permissions.set(Role::kSubtractAssetQty);

  // Add asset to admin and transfer to target account
  auto prepare_tx_1 = fixture.complete(
      fixture.baseTx(kAdminId)
          .addAssetQuantity(kAssetId, "20000.0")
          .transferAsset(kAdminId, kUserId, kAssetId, "incoming", "500.0"),
      kAdminKeypair);

  // Transfer assets back to admin
  auto prepare_tx_2 = fixture.complete(fixture.baseTx().transferAsset(
      kUserId, kAdminId, kAssetId, "outgoing", "500.0"));

  tx_hashes_.push_back(prepare_tx_1.hash());
  tx_hashes_.push_back(prepare_tx_2.hash());

  return QueryPermissionTestBase::prepareState(
             fixture, spectator_permissions, target_permissions)
      .sendTxAwait(prepare_tx_1, getBlockTransactionsAmountChecker(1))
      .sendTxAwait(prepare_tx_2, getBlockTransactionsAmountChecker(1));
}

std::function<void(const proto::QueryResponse &response)>
QueryPermissionAssetTxs::getGeneralResponseChecker() {
  return [this](const proto::QueryResponse &response) {
    ASSERT_NO_THROW({
      const auto &resp =
          boost::get<const interface::TransactionsPageResponse &>(
              response.get());

      const auto &transactions = resp.transactions();
      ASSERT_EQ(boost::size(transactions), tx_hashes_.size());
      std::vector<shared_model::interface::types::HashType> resp_tx_hashes;
      resp_tx_hashes.reserve(tx_hashes_.size());
      std::transform(resp.transactions().begin(),
                     resp.transactions().end(),
                     std::back_inserter(resp_tx_hashes),
                     [](const shared_model::interface::Transaction &tx) {
                       return tx.hash();
                     });
      for (const auto &tx_hash : tx_hashes_) {
        ASSERT_NE(
            std::find(resp_tx_hashes.cbegin(), resp_tx_hashes.cend(), tx_hash),
            resp_tx_hashes.cend());
      }
    }) << "Actual response: "
       << response.toString();
  };
}

shared_model::proto::Query QueryPermissionAssetTxs::makeQuery(
    AcceptanceFixture &fixture,
    const interface::types::AccountIdType &target,
    const interface::types::AccountIdType &spectator,
    const crypto::Keypair &spectator_keypair) {
  return fixture.complete(
      fixture.baseQry(spectator).getAccountAssetTransactions(
          target, kAssetId, kTxPageSize),
      spectator_keypair);
}
