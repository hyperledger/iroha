/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include <boost/variant.hpp>

#include "backend/protobuf/query_responses/proto_query_response.hpp"
#include "backend/protobuf/transaction.hpp"
#include "builders/protobuf/queries.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"
#include "interfaces/query_responses/transactions_response.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"
#include "utils/query_error_response_visitor.hpp"

using namespace integration_framework;
using namespace shared_model;
using namespace common_constants;

using iroha::StorageType;

class GetTransactions : public AcceptanceFixture,
                        public testing::WithParamInterface<iroha::StorageType> {
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
  auto makeQuery(std::vector<crypto::Hash> const &hashes) {
    return complete(baseQry().queryCounter(1).getTransactions(hashes));
  }

  auto makeQuery(const crypto::Hash &hash) {
    return makeQuery(std::vector<crypto::Hash>{hash});
  }

  const std::string kNewRole = "rl";
};

/**
 * TODO mboldyrev 18.01.2019 IR-215 convert to a SFV integration test
 * (not covered by postgres_query_executor_test)
 * convert to a common SFV permissions integration test
 *
 * @given some user without can_get_{my,all}_txs permissions
 * @when query GetTransactions of existing transaction of the user
 * @then stateful validation fail returned
 */
TEST_P(GetTransactions, HaveNoGetPerms) {
  auto check = [](auto &status) {
    ASSERT_TRUE(
        boost::apply_visitor(interface::QueryErrorResponseChecker<
                                 interface::StatefulFailedErrorResponse>(),
                             status.get()));
  };

  auto dummy_tx = dummyTx();
  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms({interface::permissions::Role::kReadAssets}))
      .skipProposal()
      .skipBlock()
      .sendTxAwait(
          dummy_tx,
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendQuery(makeQuery(dummy_tx.hash()), check);
}

/**
 * TODO mboldyrev 18.01.2019 IR-215 remove, covered by
 * postgres_query_executor_test GetTransactionsHashExecutorTest.ValidAllAccounts
 * convert to a common SFV permissions integration test
 *
 * @given some user with only can_get_all_txs permission
 * @when query GetTransactions of existing transaction of the user
 * @then receive TransactionsResponse with the transaction hash
 */
TEST_P(GetTransactions, HaveGetAllTx) {
  auto dummy_tx = dummyTx();
  auto check = [&dummy_tx](auto &status) {
    ASSERT_NO_THROW({
      const auto &resp =
          boost::get<const shared_model::interface::TransactionsResponse &>(
              status.get());
      ASSERT_EQ(resp.transactions().size(), 1);
      ASSERT_EQ(resp.transactions().front(), dummy_tx);
    });
  };

  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms({interface::permissions::Role::kGetAllTxs}))
      .skipProposal()
      .skipBlock()
      .sendTxAwait(
          dummy_tx,
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendQuery(makeQuery(dummy_tx.hash()), check);
}

TEST_P(GetTransactions, MultipleHaveGetAllTx) {
  decltype(dummyTx()) txs[] = {dummyTx(), dummyTx(), dummyTx()};
  auto check = [&txs](auto &status) {
    ASSERT_NO_THROW({
      const auto &resp =
          boost::get<const shared_model::interface::TransactionsResponse &>(
              status.get());
      ASSERT_EQ(resp.transactions().size(), sizeof(txs) / sizeof(txs[0]));
      for (size_t ix = 0; ix < resp.transactions().size(); ++ix) {
        ASSERT_EQ(resp.transactions()[ix], txs[ix]);
      }
    });
  };

  IntegrationTestFramework itf(1, GetParam());

  itf.setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms({interface::permissions::Role::kGetAllTxs}))
      .skipProposal()
      .skipBlock();

  std::vector<crypto::Hash> hashes;
  for (auto const &tx : txs) {
    hashes.emplace_back(tx.hash());
    itf.sendTxAwait(
        tx, [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); });
  }

  itf.sendQuery(makeQuery(hashes), check);
}

/**
 * TODO mboldyrev 18.01.2019 IR-215 remove, covered by
 * postgres_query_executor_test GetTransactionsHashExecutorTest.ValidMyAccount
 * convert to a common SFV permissions integration test
 *
 * @given some user with only can_get_my_txs permission
 * @when query GetTransactions of existing transaction of the user
 * @then receive TransactionsResponse with the transaction hash
 */
TEST_P(GetTransactions, HaveGetMyTx) {
  auto dummy_tx = dummyTx();
  auto check = [&dummy_tx](auto &status) {
    ASSERT_NO_THROW({
      const auto &resp =
          boost::get<const shared_model::interface::TransactionsResponse &>(
              status.get());
      ASSERT_EQ(resp.transactions().size(), 1);
      ASSERT_EQ(resp.transactions().front(), dummy_tx);
    });
  };

  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms())
      .skipProposal()
      .skipBlock()
      .sendTxAwait(
          dummy_tx,
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendQuery(makeQuery(dummy_tx.hash()), check);
}

/**
 * TODO mboldyrev 18.01.2019 IR-215 remove, covered by
 * query_processor_test QueryProcessorTest.QueryProcessorWithWrongKey
 *
 * @given some user with only can_get_my_txs permission
 * @when query GetTransactions of existing transaction of the user, but with
 * invalid signatures
 * @then receive StatefullErrorResponse
 */
TEST_P(GetTransactions, InvalidSignatures) {
  auto dummy_tx = dummyTx();
  auto check = [](auto &status) {
    ASSERT_NO_THROW({
      const auto &error_rsp =
          boost::get<const shared_model::interface::ErrorQueryResponse &>(
              status.get());
      boost::get<const shared_model::interface::StatefulFailedErrorResponse &>(
          error_rsp.get());
    });
  };

  auto query = baseQry()
                   .queryCounter(1)
                   .getTransactions(std::vector<crypto::Hash>{dummy_tx.hash()})
                   .build()
                   .signAndAddSignature(
                       crypto::DefaultCryptoAlgorithmType::generateKeypair())
                   .finish();

  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms())
      .skipProposal()
      .skipVerifiedProposal()
      .skipBlock()
      .sendQuery(query, check);
}

/**
 * TODO mboldyrev 18.01.2019 IR-215 convert to a SFV integration test
 * (not covered by postgres_query_executor_test)
 *
 * @given some user with only can_get_my_txs permission
 * @when query GetTransactions with nonexistent hash
 * @then Stateful invalid query response
 */
TEST_P(GetTransactions, NonexistentHash) {
  auto check = [](auto &status) {
    ASSERT_NO_THROW({
      const auto &resp =
          boost::get<const shared_model::interface::ErrorQueryResponse &>(
              status.get());
      // TODO [IR-1816] Akvinikym 03.12.18: replace magic number 4
      // with a named constant
      ASSERT_EQ(resp.errorCode(), 4);
      boost::get<const shared_model::interface::StatefulFailedErrorResponse &>(
          resp.get());
    });
  };

  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTxAwait(
          makeUserWithPerms(),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendQuery(makeQuery(crypto::Hash(std::string(
                     crypto::DefaultCryptoAlgorithmType::kHashLength, '0'))),
                 check);
}

/**
 * TODO mboldyrev 18.01.2019 IR-215 convert to a SFV integration test
 * (not covered by postgres_query_executor_test)
 * seems we should move the common_query_permissions_test to SFV integration
 *
 * @given some user with can_get_my_txs
 * @when query GetTransactions of existing transaction of the other user
 * @then TransactionsResponse with no transactions
 */
TEST_P(GetTransactions, OtherUserTx) {
  auto check = [](auto &status) {
    ASSERT_NO_THROW({
      const auto &resp =
          boost::get<const shared_model::interface::TransactionsResponse &>(
              status.get());
      ASSERT_EQ(resp.transactions().size(), 0);
    });
  };

  iroha::StorageType type = GetParam();
  auto tx = makeUserWithPerms();
  IntegrationTestFramework(1, type)
      .setInitialState(kAdminKeypair)
      .sendTxAwait(
          tx, [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
      .sendQuery(makeQuery(tx.hash()), check);
}

INSTANTIATE_TEST_SUITE_P(DifferentStorageType,
                         GetTransactions,
                         testing::Values(StorageType::kPostgres,
                                         StorageType::kRocksDb),
                         [](const testing::TestParamInfo<StorageType> &info) {
                           return info.param == StorageType::kPostgres
                               ? "kPostgres"
                               : info.param == StorageType::kRocksDb
                                   ? "kRocksDb"
                                   : "UNKNOWN";
                         });
