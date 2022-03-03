/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include <chrono>
#include <iostream>
#include <thread>
#include <utility>

#include "backend/protobuf/query_responses/proto_query_response.hpp"
#include "builders/protobuf/queries.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"
#include "interfaces/query_responses/pending_transactions_page_response.hpp"
#include "interfaces/query_responses/transactions_response.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"

using namespace std::string_literals;
using namespace integration_framework;
using namespace shared_model;
using namespace common_constants;

using shared_model::interface::types::PublicKeyHexStringView;

class MstPipelineTest : public AcceptanceFixture {
 public:
  MstPipelineTest() = default;

  /**
   * Creates a mst user
   * @param itf, in which the user will be created
   * @param sigs - number of signatories of that mst user
   * @return itf with created user
   */
  IntegrationTestFramework &makeMstUser(IntegrationTestFramework &itf,
                                        size_t sigs = kSignatories) {
    auto create_user_tx =
        createUserWithPerms(kUser,
                            PublicKeyHexStringView{kUserKeypair.publicKey()},
                            kNewRole,
                            {interface::permissions::Role::kSetQuorum,
                             interface::permissions::Role::kAddSignatory,
                             interface::permissions::Role::kSetDetail})
            .build()
            .signAndAddSignature(kAdminKeypair)
            .finish();
    auto add_signatories_tx = baseTx().quorum(1);
    for (size_t i = 0; i < sigs; ++i) {
      signatories.push_back(
          crypto::DefaultCryptoAlgorithmType::generateKeypair());
      add_signatories_tx = add_signatories_tx.addSignatory(
          kUserId, PublicKeyHexStringView{signatories[i].publicKey()});
    }
    add_signatories_tx.setAccountQuorum(kUserId, sigs + 1);
    itf.sendTxAwait(
           create_user_tx,
           [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); })
        .sendTxAwait(
            add_signatories_tx.build()
                .signAndAddSignature(kUserKeypair)
                .finish(),
            [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); });
    return itf;
  }

  /**
   * TODO 2019-06-13 igor-egorov IR-516 remove
   *
   * Makes a ready-to-send query to get pending transactions
   * @param creator - account, which asks for pending transactions
   * @param key - that account's keypair
   * @return built and signed query
   */
  auto makeGetPendingTxsQuery(const std::string &creator,
                              const crypto::Keypair &key) {
    return shared_model::proto::QueryBuilder()
        .createdTime(getUniqueTime())
        .creatorAccountId(creator)
        .queryCounter(1)
        .getPendingTransactions()
        .build()
        .signAndAddSignature(key)
        .finish();
  }

  /**
   * Makes a ready-to-send query to get pending transactions
   * @param creator - account, which asks for pending transactions
   * @param key - that account's keypair
   * @param page_size - maximum number of transactions to be returned
   * @param first_tx_hash - the hash of the first transaction of the batch that
   * should begin the resulting set
   * @return built and signed query
   */
  auto makeGetPendingTxsQuery(
      const std::string &creator,
      const crypto::Keypair &key,
      const interface::types::TransactionsNumberType &page_size,
      const std::optional<interface::types::HashType> &first_tx_hash =
          std::nullopt) {
    return shared_model::proto::QueryBuilder()
        .createdTime(getUniqueTime())
        .creatorAccountId(creator)
        .queryCounter(1)
        .getPendingTransactions(page_size, first_tx_hash)
        .build()
        .signAndAddSignature(key)
        .finish();
  }

  /**
   * TODO 2019-06-13 igor-egorov IR-516 remove
   *
   * Query validation lambda - check that empty transactions response returned
   * @param response - query response
   */
  static void oldNoTxsCheck(const proto::QueryResponse &response) {
    ASSERT_NO_THROW({
      const auto &pending_txs_resp =
          boost::get<const interface::TransactionsResponse &>(response.get());

      ASSERT_TRUE(pending_txs_resp.transactions().empty());
    });
  }

  /**
   * Query validation lambda - check that empty transactions response returned
   * @param response - query response
   */
  static void noTxsCheck(const proto::QueryResponse &response) {
    ASSERT_NO_THROW({
      const auto &pending_txs_resp =
          boost::get<const interface::PendingTransactionsPageResponse &>(
              response.get());

      ASSERT_TRUE(pending_txs_resp.transactions().empty());
    });
  }

  /**
   * TODO 2019-06-13 igor-egorov IR-516 remove
   *
   * Returns lambda that checks the number of signatures of the first pending
   * transaction
   * @param expected_signatures_number
   * @return query validation lambda
   */
  static auto oldSignatoryCheck(size_t expected_signatures_number) {
    return [expected_signatures_number](const auto &response) {
      ASSERT_NO_THROW({
        const auto &pending_txs_resp =
            boost::get<const interface::TransactionsResponse &>(response.get());

        ASSERT_EQ(
            boost::size(pending_txs_resp.transactions().front().signatures()),
            expected_signatures_number);
      });
    };
  }

  /**
   * Returns lambda that checks the number of signatures of the first pending
   * transaction
   * @param expected_signatures_number
   * @return query validation lambda
   */
  static auto signatoryCheck(size_t expected_signatures_number) {
    return [expected_signatures_number](const auto &response) {
      ASSERT_NO_THROW({
        const auto &pending_txs_resp =
            boost::get<const interface::PendingTransactionsPageResponse &>(
                response.get());

        ASSERT_EQ(
            boost::size(pending_txs_resp.transactions().front().signatures()),
            expected_signatures_number);
      });
    };
  }

  /**
   * Prepares an instance of ITF with MST turned on
   * @and different DB types
   * @return reference to the MST ITF
   */
  template <typename F>
  void executeForItf(F &&f) {
    for (auto const type :
         {iroha::StorageType::kPostgres, iroha::StorageType::kRocksDb}) {
      IntegrationTestFramework mst_itf(
          1, type, {}, iroha::StartupWsvDataPolicy::kDrop, true, true);
      mst_itf.setInitialState(kAdminKeypair);
      std::forward<F>(f)(makeMstUser(mst_itf));
    }
  }

  const std::string kNewRole = "rl"s;
  static const size_t kSignatories = 2;
  std::vector<crypto::Keypair> signatories;
};

/**
 * @given mst account, pair of signers and tx with a SetAccountDetail command
 * @when sending that tx with author signature @and then with signers' ones
 * @then commit appears only after tx is signed by all required signatories
 */
TEST_F(MstPipelineTest, OnePeerSendsTest) {
  auto tx = baseTx()
                .setAccountDetail(kUserId, "fav_meme", "doge")
                .quorum(kSignatories + 1);
  auto hash = tx.build().hash();

  executeForItf([&](auto &mst_itf) {
    mst_itf.sendTx(complete(tx, kUserKeypair))
        .sendTx(complete(tx, signatories[0]))
        .sendTxAwait(complete(tx, signatories[1]), [](auto &block) {
          ASSERT_EQ(block->transactions().size(), 1);
        });
  });
}

/**
 * TODO 2019-06-13 igor-egorov IR-516 remove
 *
 * @given a user that has sent a semi-signed transaction to a ledger
 * @when the user requests pending transactions
 * @then user's semi-signed transaction is returned
 */
TEST_F(MstPipelineTest, OldGetPendingTxsAwaitingForThisPeer) {
  auto pending_tx = baseTx()
                        .setAccountDetail(kUserId, "fav_meme", "doge")
                        .quorum(kSignatories + 1);

  executeForItf([&](auto &mst_itf) {
    auto signed_tx = complete(pending_tx, kUserKeypair);

    auto pending_tx_check = [pending_hash = signed_tx.hash()](auto &response) {
      ASSERT_NO_THROW({
        const auto &pending_tx_resp =
            boost::get<const interface::TransactionsResponse &>(response.get());
        ASSERT_EQ(pending_tx_resp.transactions().front().hash(), pending_hash);
      });
    };

    // send pending transaction, signing it only with one signatory
    mst_itf.sendTx(signed_tx);
    std::this_thread::sleep_for(std::chrono::seconds(3));
    mst_itf.sendQuery(makeGetPendingTxsQuery(kUserId, kUserKeypair),
                      pending_tx_check);
  });
}

/**
 * TODO 2019-06-13 igor-egorov IR-516 remove
 *
 * @given an empty ledger
 * @when creating pending transactions, which lack two or more signatures,
 * @and signing those transactions with one signature @and executing get
 * pending transactions
 * @then they are returned with initial number of signatures plus one
 */
TEST_F(MstPipelineTest, OldGetPendingTxsLatestSignatures) {
  auto pending_tx = baseTx()
                        .setAccountDetail(kUserId, "fav_meme", "doge")
                        .quorum(kSignatories + 1);

  // make the same queries have different hashes with help of timestamps
  const auto q1 = makeGetPendingTxsQuery(kUserId, kUserKeypair);
  const auto q2 = makeGetPendingTxsQuery(kUserId, kUserKeypair);

  executeForItf([&](auto &mst_itf) {
    mst_itf.sendTx(complete(pending_tx, signatories[0]));
    std::this_thread::sleep_for(std::chrono::seconds(3));
    mst_itf.sendQuery(q1, oldSignatoryCheck(1))
        .sendTx(complete(pending_tx, signatories[1]));
    std::this_thread::sleep_for(std::chrono::seconds(3));
    mst_itf.sendQuery(q2, oldSignatoryCheck(2));
  });
}

/**
 * TODO 2019-06-13 igor-egorov IR-516 remove
 *
 * @given an empty ledger
 * @when creating pending transactions @and signing them with number of
 * signatures to get over quorum @and executing get pending transactions
 * @then those transactions are not returned
 */
TEST_F(MstPipelineTest, OldGetPendingTxsNoSignedTxs) {
  auto pending_tx = baseTx()
                        .setAccountDetail(kUserId, "fav_meme", "doge")
                        .quorum(kSignatories + 1);
  auto user_tx = complete(pending_tx, kUserKeypair);

  executeForItf([&](auto &mst_itf) {
    mst_itf.sendTx(complete(pending_tx, signatories[0]))
        .sendTx(complete(pending_tx, signatories[1]))
        .sendTx(user_tx)
        .checkProposal([&user_tx](auto &proposal) {
          ASSERT_EQ(proposal->transactions().size(), 1);
          ASSERT_EQ(proposal->transactions()[0].hash(), user_tx.hash());
        })
        .skipVerifiedProposal()
        .skipBlock()
        .sendQuery(makeGetPendingTxsQuery(kUserId, kUserKeypair),
                   oldNoTxsCheck);
  });
}

/**
 * TODO 2019-06-13 igor-egorov IR-516 remove
 *
 * @given a ledger with mst user (quorum=3) created
 * @when the user sends a transaction with only one signature, then sends the
 * transaction with all three signatures
 * @then there should be no pending transactions
 */
TEST_F(MstPipelineTest, OldReplayViaFullySignedTransaction) {
  executeForItf([&](auto &mst_itf) {
    auto pending_tx = baseTx()
                          .setAccountDetail(kUserId, "age", "10")
                          .quorum(kSignatories + 1);

    auto fully_signed_tx = pending_tx.build()
                               .signAndAddSignature(signatories[0])
                               .signAndAddSignature(signatories[1])
                               .signAndAddSignature(kUserKeypair)
                               .finish();

    mst_itf.sendTx(complete(pending_tx, signatories[0]))
        .sendTx(fully_signed_tx)
        .checkProposal([&fully_signed_tx](auto &proposal) {
          ASSERT_EQ(proposal->transactions().size(), 1);
          ASSERT_EQ(proposal->transactions()[0].hash(), fully_signed_tx.hash());
        })
        .skipVerifiedProposal()
        .skipBlock()
        .sendQuery(makeGetPendingTxsQuery(kUserId, kUserKeypair),
                   oldNoTxsCheck);
  });
}

/**
 * @given a user that has sent a semi-signed transaction to a ledger
 * @when the user requests pending transactions
 * @then user's semi-signed transaction is returned
 */
TEST_F(MstPipelineTest, GetPendingTxsAwaitingForThisPeer) {
  const auto kPageSize = 100u;
  auto pending_tx = baseTx()
                        .setAccountDetail(kUserId, "fav_meme", "doge")
                        .quorum(kSignatories + 1);

  executeForItf([&](auto &mst_itf) {
    auto signed_tx = complete(pending_tx, kUserKeypair);

    auto pending_tx_check = [pending_hash = signed_tx.hash()](auto &response) {
      ASSERT_NO_THROW({
        const auto &pending_tx_resp =
            boost::get<const interface::PendingTransactionsPageResponse &>(
                response.get());
        ASSERT_EQ(pending_tx_resp.transactions().front().hash(), pending_hash);
      });
    };

    // send pending transaction, signing it only with one signatory
    mst_itf.sendTx(signed_tx);
    std::this_thread::sleep_for(std::chrono::seconds(3));
    mst_itf.sendQuery(makeGetPendingTxsQuery(kUserId, kUserKeypair, kPageSize),
                      pending_tx_check);
  });
}

/**
 * @given an empty ledger
 * @when creating pending transactions, which lack two or more signatures,
 * @and signing those transactions with one signature @and executing get
 * pending transactions
 * @then they are returned with initial number of signatures plus one
 */
TEST_F(MstPipelineTest, GetPendingTxsLatestSignatures) {
  const auto kPageSize = 100u;
  auto pending_tx = baseTx()
                        .setAccountDetail(kUserId, "fav_meme", "doge")
                        .quorum(kSignatories + 1);

  // make the same queries have different hashes with the help of timestamps
  const auto q1 = makeGetPendingTxsQuery(kUserId, kUserKeypair, kPageSize);
  const auto q2 = makeGetPendingTxsQuery(kUserId, kUserKeypair, kPageSize);

  executeForItf([&](auto &mst_itf) {
    mst_itf.sendTx(complete(pending_tx, signatories[0]));
    std::this_thread::sleep_for(std::chrono::seconds(1));
    mst_itf.sendQuery(q1, signatoryCheck(1))
        .sendTx(complete(pending_tx, signatories[1]));
    std::this_thread::sleep_for(std::chrono::seconds(1));
    mst_itf.sendQuery(q2, signatoryCheck(2));
  });
}

/**
 * @given an empty ledger
 * @when creating pending transactions @and signing them with number of
 * signatures to get over quorum @and executing get pending transactions
 * @then those transactions are not returned
 */
TEST_F(MstPipelineTest, GetPendingTxsNoSignedTxs) {
  const auto kPageSize = 100u;
  auto pending_tx = baseTx()
                        .setAccountDetail(kUserId, "fav_meme", "doge")
                        .quorum(kSignatories + 1);
  auto user_tx = complete(pending_tx, kUserKeypair);

  executeForItf([&](auto &mst_itf) {
    mst_itf.sendTx(complete(pending_tx, signatories[0]))
        .sendTx(complete(pending_tx, signatories[1]))
        .sendTx(user_tx)
        .checkProposal([&user_tx](auto &proposal) {
          ASSERT_EQ(proposal->transactions().size(), 1);
          ASSERT_EQ(proposal->transactions()[0].hash(), user_tx.hash());
        })
        .skipVerifiedProposal()
        .skipBlock();
    std::this_thread::sleep_for(std::chrono::seconds(1));
    mst_itf.sendQuery(makeGetPendingTxsQuery(kUserId, kUserKeypair, kPageSize),
                      noTxsCheck);
  });
}

/**
 * @given a ledger with mst user (quorum=3) created
 * @when the user sends a transaction with only one signature, then sends the
 * transaction with all three signatures
 * @then there should be no pending transactions
 */
TEST_F(MstPipelineTest, ReplayViaFullySignedTransaction) {
  const auto kPageSize = 100u;
  executeForItf([&](auto &mst_itf) {
    auto pending_tx = baseTx()
                          .setAccountDetail(kUserId, "age", "10")
                          .quorum(kSignatories + 1);

    auto fully_signed_tx = pending_tx.build()
                               .signAndAddSignature(signatories[0])
                               .signAndAddSignature(signatories[1])
                               .signAndAddSignature(kUserKeypair)
                               .finish();

    mst_itf.sendTx(complete(pending_tx, signatories[0]))
        .sendTx(fully_signed_tx)
        .checkProposal([&fully_signed_tx](auto &proposal) {
          ASSERT_EQ(proposal->transactions().size(), 1);
          ASSERT_EQ(proposal->transactions()[0].hash(), fully_signed_tx.hash());
        })
        .skipVerifiedProposal()
        .skipBlock();
    std::this_thread::sleep_for(std::chrono::seconds(1));
    mst_itf.sendQuery(makeGetPendingTxsQuery(kUserId, kUserKeypair, kPageSize),
                      noTxsCheck);
  });
}
