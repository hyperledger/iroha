/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include "builders/protobuf/queries.hpp"
#include "cryptography/crypto_provider/crypto_defaults.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"
#include "interfaces/query_responses/transactions_response.hpp"

using namespace std::string_literals;
using namespace integration_framework;
using namespace shared_model;
using namespace common_constants;

class MstPipelineTest : public AcceptanceFixture {
 public:
  MstPipelineTest() : mst_itf_{1, {}, true, true} {}

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
                            kUserKeypair.publicKey(),
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
      add_signatories_tx =
          add_signatories_tx.addSignatory(kUserId, signatories[i].publicKey());
    }
    add_signatories_tx.setAccountQuorum(kUserId, sigs + 1);
    itf.sendTx(create_user_tx)
        .checkProposal([](auto &proposal) {
          ASSERT_EQ(proposal->transactions().size(), 1);
        })
        .checkVerifiedProposal([](auto &proposal) {
          ASSERT_EQ(proposal->transactions().size(), 1);
        })
        .checkBlock([](auto &proposal) {
          ASSERT_EQ(proposal->transactions().size(), 1);
        })
        .sendTx(add_signatories_tx.build()
                    .signAndAddSignature(kUserKeypair)
                    .finish())
        .checkProposal([](auto &proposal) {
          ASSERT_EQ(proposal->transactions().size(), 1);
        })
        .checkVerifiedProposal([](auto &proposal) {
          ASSERT_EQ(proposal->transactions().size(), 1);
        })
        .checkBlock([](auto &proposal) {
          ASSERT_EQ(proposal->transactions().size(), 1);
        });
    return itf;
  }

  /**
   * Makes a ready-to-send query to get pending transactions
   * @param creator - account, which asks for pending transactions
   * @param key - that account's keypair
   * @return built and signed transaction
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
   * Query validation lambda - check that empty transactions response returned
   * @param response - query response
   */
  static void noTxsCheck(const proto::QueryResponse &response) {
    ASSERT_NO_THROW({
      const auto &pending_txs_resp =
          boost::get<const interface::TransactionsResponse &>(response.get());

      ASSERT_TRUE(pending_txs_resp.transactions().empty());
    });
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
            boost::get<const interface::TransactionsResponse &>(response.get());

        ASSERT_EQ(
            boost::size(pending_txs_resp.transactions().front().signatures()),
            expected_signatures_number);
      });
    };
  }

  /**
   * Prepares an instance of ITF with MST turned on
   * @return reference to the MST ITF
   */
  IntegrationTestFramework &prepareMstItf() {
    mst_itf_.setInitialState(kAdminKeypair);
    return makeMstUser(mst_itf_);
  }

  IntegrationTestFramework mst_itf_;

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

  auto &mst_itf = prepareMstItf();
  mst_itf.sendTx(complete(tx, kUserKeypair))
      .sendTx(complete(tx, signatories[0]))
      .sendTxAwait(complete(tx, signatories[1]), [](auto &block) {
        ASSERT_EQ(block->transactions().size(), 1);
      });
}

/**
 * @given a user that has sent a semi-signed transaction to a ledger
 * @when the user requests pending transactions
 * @then user's semi-signed transaction is returned
 */
TEST_F(MstPipelineTest, GetPendingTxsAwaitingForThisPeer) {
  auto pending_tx = baseTx()
                        .setAccountDetail(kUserId, "fav_meme", "doge")
                        .quorum(kSignatories + 1);

  auto &mst_itf = prepareMstItf();
  auto signed_tx = complete(pending_tx, kUserKeypair);

  auto pending_tx_check = [pending_hash = signed_tx.hash()](auto &response) {
    ASSERT_NO_THROW({
      const auto &pending_tx_resp =
          boost::get<const interface::TransactionsResponse &>(response.get());
      ASSERT_EQ(pending_tx_resp.transactions().front().hash(), pending_hash);
    });
  };

  // send pending transaction, signing it only with one signatory
  mst_itf.sendTx(signed_tx).sendQuery(
      makeGetPendingTxsQuery(kUserId, kUserKeypair), pending_tx_check);
}

/**
 * @given an empty ledger
 * @when creating pending transactions, which lack two or more signatures,
 * @and signing those transactions with one signature @and executing get
 * pending transactions
 * @then they are returned with initial number of signatures plus one
 */
TEST_F(MstPipelineTest, GetPendingTxsLatestSignatures) {
  auto pending_tx = baseTx()
                        .setAccountDetail(kUserId, "fav_meme", "doge")
                        .quorum(kSignatories + 1);

  // make the same queries have different hashes with help of timestamps
  const auto q1 = makeGetPendingTxsQuery(kUserId, kUserKeypair);
  const auto q2 = makeGetPendingTxsQuery(kUserId, kUserKeypair);
  auto &mst_itf = prepareMstItf();
  mst_itf.sendTx(complete(pending_tx, signatories[0]))
      .sendQuery(q1, signatoryCheck(1))
      .sendTx(complete(pending_tx, signatories[1]))
      .sendQuery(q2, signatoryCheck(2));
}

/**
 * @given an empty ledger
 * @when creating pending transactions @and signing them with number of
 * signatures to get over quorum @and executing get pending transactions
 * @then those transactions are not returned
 */
TEST_F(MstPipelineTest, GetPendingTxsNoSignedTxs) {
  auto pending_tx = baseTx()
                        .setAccountDetail(kUserId, "fav_meme", "doge")
                        .quorum(kSignatories + 1);

  auto &mst_itf = prepareMstItf();
  mst_itf.sendTx(complete(pending_tx, signatories[0]))
      .sendTx(complete(pending_tx, signatories[1]))
      .sendTx(complete(pending_tx, kUserKeypair))
      .sendQuery(makeGetPendingTxsQuery(kUserId, kUserKeypair), noTxsCheck);
}

/**
 * @given a ledger with mst user (quorum=3) created
 * @when the user sends a transaction with only one signature, then sends the
 * transaction with all three signatures
 * @then there should be no pending transactions
 */
TEST_F(MstPipelineTest, ReplayViaFullySignedTransaction) {
  auto &mst_itf = prepareMstItf();
  auto pending_tx =
      baseTx().setAccountDetail(kUserId, "age", "10").quorum(kSignatories + 1);

  auto fully_signed_tx = pending_tx.build()
                             .signAndAddSignature(signatories[0])
                             .signAndAddSignature(signatories[1])
                             .signAndAddSignature(kUserKeypair)
                             .finish();

  mst_itf.sendTx(complete(pending_tx, signatories[0]))
      .sendQuery(makeGetPendingTxsQuery(kUserId, kUserKeypair),
                 signatoryCheck(1))
      .sendTx(fully_signed_tx)
      .sendQuery(makeGetPendingTxsQuery(kUserId, kUserKeypair), noTxsCheck);
}
