/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/acceptance/query_permission_test_txs.hpp"

#include "interfaces/query_responses/transactions_page_response.hpp"

using namespace common_constants;

static constexpr shared_model::interface::types::TransactionsNumberType
    kTxPageSize(10);

QueryPermissionTxs::QueryPermissionTxs()
    : QueryPermissionTestBase({Role::kGetMyAccTxs},
                              {Role::kGetDomainAccTxs},
                              {Role::kGetAllAccTxs}) {}

IntegrationTestFramework &QueryPermissionTxs::prepareState(
    AcceptanceFixture &fixture,
    const interface::RolePermissionSet &spectator_permissions) {
  auto target_permissions = spectator_permissions;
  target_permissions.set(Role::kReceive);
  target_permissions.set(Role::kTransfer);
  target_permissions.set(Role::kAddAssetQty);
  target_permissions.set(Role::kSubtractAssetQty);
  target_permissions.set(Role::kSetDetail);

  // Make some transactions of different kinds:
  std::vector<shared_model::proto::Transaction> user_transactions{
      // Add asset to user
      fixture.complete(fixture.baseTx().addAssetQuantity(kAssetId, "20000.0")),
      // Transfer assets to admin
      fixture.complete(fixture.baseTx().transferAsset(
          kUserId, kAdminId, kAssetId, "outgoing", "500.0")),
      // Set account details
      fixture.complete(
          fixture.baseTx(kUserId).setAccountDetail(kUserId, "key1", "val1"))};

  std::transform(user_transactions.cbegin(),
                 user_transactions.cend(),
                 std::back_inserter(tx_hashes_),
                 [](const auto &tx) { return tx.hash(); });

  // initial state setup
  auto &itf = QueryPermissionTestBase::prepareState(
      fixture, spectator_permissions, target_permissions);

  for (const auto &tx : user_transactions) {
    itf.sendTxAwait(tx, getBlockTransactionsAmountChecker(1));
  }

  return itf;
}

std::function<void(const proto::QueryResponse &response)>
QueryPermissionTxs::getGeneralResponseChecker() {
  return [this](const proto::QueryResponse &response) {
    ASSERT_NO_THROW({
      const auto &resp =
          boost::get<const interface::TransactionsPageResponse &>(
              response.get());
      const auto &transactions = resp.transactions();
      ASSERT_EQ(boost::size(transactions), tx_hashes_.size());
      std::vector<shared_model::interface::types::HashType> resp_tx_hashes;
      resp_tx_hashes.reserve(tx_hashes_.size());
      for(auto const& tx : resp.transactions())
        resp_tx_hashes.emplace_back(tx.hash());
      for (const auto &tx_hash : tx_hashes_) {
        ASSERT_NE(
            std::find(resp_tx_hashes.cbegin(), resp_tx_hashes.cend(), tx_hash),
            resp_tx_hashes.cend())
            << "Did not get transaction with hash '" << tx_hash.toString()
            << "'.";
      }
    }) << "Actual response: "
       << response.toString();
  };
}

shared_model::proto::Query QueryPermissionTxs::makeQuery(
    AcceptanceFixture &fixture,
    const interface::types::AccountIdType &target,
    const interface::types::AccountIdType &spectator,
    const crypto::Keypair &spectator_keypair) {
  return fixture.complete(
      fixture.baseQry(spectator).getAccountTransactions(target, kTxPageSize),
      spectator_keypair);
}
