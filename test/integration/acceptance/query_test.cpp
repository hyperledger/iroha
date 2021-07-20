/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/acceptance/acceptance_fixture.hpp"

#include <thread>

#include <boost/variant.hpp>
#include "backend/protobuf/query_responses/proto_query_response.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "interfaces/query_responses/transactions_response.hpp"

using namespace integration_framework;
using namespace shared_model;
using namespace common_constants;

class QueryAcceptanceTest : public AcceptanceFixture {
 public:
  /**
   * Creates the transaction with the user creation commands
   * @param perms are the permissions of the user
   * @return built tx and a hash of its payload
   */
  auto makeUserWithPerms(const interface::RolePermissionSet &perms = {
                             interface::permissions::Role::kGetMyTxs}) {
    auto new_perms = perms;
    new_perms.set(interface::permissions::Role::kSetQuorum);
    return AcceptanceFixture::makeUserWithPerms(kNewRole, new_perms);
  }

  /**
   * Valid transaction that user can execute.
   * @return built tx and a hash of its payload
   * Note: It should affect the ledger minimally
   */
  auto dummyTx() {
    return complete(AcceptanceFixture::baseTx().setAccountQuorum(kUserId, 1));
  }

  /**
   * Creates valid GetTransactions query of current user
   * @param hash of the tx for querying
   * @return built query
   */
  auto makeQuery(const crypto::Hash &hash) {
    return complete(baseQry().queryCounter(1).getTransactions(
        std::vector<crypto::Hash>{hash}));
  }

  const std::string kNewRole = "rl";
};

/**
 * TODO mboldyrev 18.01.2019 IR-220 remove, covered by
 * postgres_query_executor_test GetTransactionsHashExecutorTest.ValidMyAccount
 * seems we should move common query permissions tests to SFV integration
 *
 * @given some user with only can_get_my_txs permission
 * @when query GetTransactions of existing transaction of the user in parallel
 * @then receive TransactionsResponse with the transaction hash
 */
TEST_F(QueryAcceptanceTest, ParallelBlockQuery) {
  auto dummy_tx = dummyTx();
  auto check = [dummy_tx = dummy_tx](auto &status) {
    ASSERT_NO_THROW({
      const auto &resp =
          boost::get<const shared_model::interface::TransactionsResponse &>(
              status.get());
      ASSERT_EQ(resp.transactions().size(), 1);
      ASSERT_EQ(resp.transactions().front(), dummy_tx);
    });
  };

  for (auto const type :
       {iroha::StorageType::kPostgres, iroha::StorageType::kRocksDb}) {
    IntegrationTestFramework itf(1, type);
    itf.setInitialState(kAdminKeypair)
        .sendTxAwait(
            makeUserWithPerms(),
            [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
        .sendTxAwait(dummy_tx, [](auto &block) {
          ASSERT_EQ(block->transactions().size(), 1);
        });

    const auto num_queries = 5;
    const auto hash = dummy_tx.hash();

    auto send_query = [&] {
      for (int i = 0; i < num_queries; ++i) {
        itf.sendQuery(makeQuery(hash), check);
      }
    };

    const auto num_threads = 5;

    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i) {
      threads.emplace_back(send_query);
    }

    for (auto &thread : threads) {
      thread.join();
    }

    itf.done();
  }
}
