/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "datetime/time.hpp"
#include "framework/crypto_literals.hpp"
#include "framework/test_logger.hpp"
#include "module/irohad/multi_sig_transactions/mst_test_helpers.hpp"
#include "multi_sig_transactions/state/mst_state.hpp"
#include "pending_txs_storage/impl/pending_txs_storage_impl.hpp"

class OldPendingTxsStorageFixture : public ::testing::Test {
 public:
  using Batch = shared_model::interface::TransactionBatch;

  /**
   * Get the closest to now timestamp from the future but never return the same
   * value twice.
   * @return iroha timestamp
   */
  iroha::time::time_t getUniqueTime() {
    static iroha::time::time_t latest_timestamp = 0;
    auto now = iroha::time::now();
    if (now > latest_timestamp) {
      latest_timestamp = now;
      return now;
    } else {
      return ++latest_timestamp;
    }
  }

  std::shared_ptr<iroha::PendingTransactionStorageImpl> storage_ =
      std::make_shared<iroha::PendingTransactionStorageImpl>();
  std::shared_ptr<iroha::DefaultCompleter> completer_ =
      std::make_shared<iroha::DefaultCompleter>(std::chrono::minutes(0));

  logger::LoggerPtr mst_state_log_{getTestLogger("MstState")};
  logger::LoggerPtr log_{getTestLogger("OldPendingTxsStorageFixture")};
};

/**
 * Test that checks that fixture common preparation procedures can be done
 * successfully.
 * @given empty MST state
 * @when two mst transactions generated as batch
 * @then the transactions can be added to MST state successfully
 */
TEST_F(OldPendingTxsStorageFixture, FixtureSelfCheck) {
  auto state = std::make_shared<iroha::MstState>(
      iroha::MstState::empty(mst_state_log_, completer_));

  auto transactions =
      addSignatures(makeTestBatch(txBuilder(1, getUniqueTime()),
                                  txBuilder(1, getUniqueTime())),
                    0,
                    makeSignature("1"_hex_sig, "pub_key_1"_hex_pubkey));

  *state += transactions;
  ASSERT_EQ(state->getBatches().size(), 1) << "Failed to prepare MST state";
  ASSERT_EQ((*state->getBatches().begin())->transactions().size(), 2)
      << "Test batch contains wrong amount of transactions";
}

/**
 * Transactions insertion works in PendingTxsStorage
 * @given Batch of two transactions and storage
 * @when storage receives updated mst state with the batch
 * @then list of pending transactions can be received for all batch creators
 */
TEST_F(OldPendingTxsStorageFixture, InsertionTest) {
  auto state = std::make_shared<iroha::MstState>(
      iroha::MstState::empty(mst_state_log_, completer_));
  auto transactions = addSignatures(
      makeTestBatch(txBuilder(2, getUniqueTime(), 2, "alice@iroha"),
                    txBuilder(2, getUniqueTime(), 2, "bob@iroha")),
      0,
      makeSignature("1"_hex_sig, "pub_key_1"_hex_pubkey));
  *state += transactions;

  storage_->updatedBatchesHandler(state);
  for (const auto &creator : {"alice@iroha", "bob@iroha"}) {
    auto pending = storage_->getPendingTransactions(creator);
    ASSERT_EQ(pending.size(), 2)
        << "Wrong amount of pending transactions was retrieved for " << creator
        << " account";

    // generally it's illegal way to verify the correctness.
    // here we can do it because the order is preserved by batch meta and there
    // are no transactions non-related to requested account
    for (auto i = 0u; i < pending.size(); ++i) {
      ASSERT_EQ(*pending[i], *(transactions->transactions()[i]));
    }
  }
}

/**
 * Updated batch replaces previously existed
 * @given Batch with one transaction with one signature and storage
 * @when transaction inside batch receives additional signature
 * @then pending transactions response is also updated
 */
TEST_F(OldPendingTxsStorageFixture, SignaturesUpdate) {
  auto state1 = std::make_shared<iroha::MstState>(
      iroha::MstState::empty(mst_state_log_, completer_));
  auto state2 = std::make_shared<iroha::MstState>(
      iroha::MstState::empty(mst_state_log_, completer_));
  auto transactions = addSignatures(
      makeTestBatch(txBuilder(3, getUniqueTime(), 3, "alice@iroha")),
      0,
      makeSignature("1"_hex_sig, "pub_key_1"_hex_pubkey));
  *state1 += transactions;
  transactions = addSignatures(
      transactions, 0, makeSignature("2"_hex_sig, "pub_key_2"_hex_pubkey));
  *state2 += transactions;

  storage_->updatedBatchesHandler(state1);
  storage_->updatedBatchesHandler(state2);
  auto pending = storage_->getPendingTransactions("alice@iroha");
  ASSERT_EQ(pending.size(), 1);
  ASSERT_EQ(boost::size(pending.front()->signatures()), 2);
}

/**
 * Storage correctly handles storing of several batches
 * @given MST state update with three batches inside
 * @when different users asks pending transactions
 * @then users receives correct responses
 */
TEST_F(OldPendingTxsStorageFixture, SeveralBatches) {
  auto state = std::make_shared<iroha::MstState>(
      iroha::MstState::empty(mst_state_log_, completer_));
  auto batch1 = addSignatures(
      makeTestBatch(txBuilder(2, getUniqueTime(), 2, "alice@iroha"),
                    txBuilder(2, getUniqueTime(), 2, "bob@iroha")),
      0,
      makeSignature("1"_hex_sig, "pub_key_1"_hex_pubkey));
  auto batch2 = addSignatures(
      makeTestBatch(txBuilder(2, getUniqueTime(), 2, "alice@iroha"),
                    txBuilder(3, getUniqueTime(), 3, "alice@iroha")),
      0,
      makeSignature("1"_hex_sig, "pub_key_1"_hex_pubkey));
  auto batch3 = addSignatures(
      makeTestBatch(txBuilder(2, getUniqueTime(), 2, "bob@iroha")),
      0,
      makeSignature("2"_hex_sig, "pub_key_2"_hex_pubkey));
  *state += batch1;
  *state += batch2;
  *state += batch3;

  storage_->updatedBatchesHandler(state);
  auto alice_pending = storage_->getPendingTransactions("alice@iroha");
  ASSERT_EQ(alice_pending.size(), 4);

  auto bob_pending = storage_->getPendingTransactions("bob@iroha");
  ASSERT_EQ(bob_pending.size(), 3);
}

/**
 * New updates do not overwrite the whole state
 * @given two MST updates with different batches
 * @when updates arrives to storage sequentially
 * @then updates don't overwrite the whole storage state
 */
TEST_F(OldPendingTxsStorageFixture, SeparateBatchesDoNotOverwriteStorage) {
  auto state1 = std::make_shared<iroha::MstState>(
      iroha::MstState::empty(mst_state_log_, completer_));
  auto batch1 = addSignatures(
      makeTestBatch(txBuilder(2, getUniqueTime(), 2, "alice@iroha"),
                    txBuilder(2, getUniqueTime(), 2, "bob@iroha")),
      0,
      makeSignature("1"_hex_sig, "pub_key_1"_hex_pubkey));
  *state1 += batch1;
  auto state2 = std::make_shared<iroha::MstState>(
      iroha::MstState::empty(mst_state_log_, completer_));
  auto batch2 = addSignatures(
      makeTestBatch(txBuilder(2, getUniqueTime(), 2, "alice@iroha"),
                    txBuilder(3, getUniqueTime(), 3, "alice@iroha")),
      0,
      makeSignature("1"_hex_sig, "pub_key_1"_hex_pubkey));
  *state2 += batch2;

  storage_->updatedBatchesHandler(state1);
  storage_->updatedBatchesHandler(state2);
  auto alice_pending = storage_->getPendingTransactions("alice@iroha");
  ASSERT_EQ(alice_pending.size(), 4);

  auto bob_pending = storage_->getPendingTransactions("bob@iroha");
  ASSERT_EQ(bob_pending.size(), 2);
}

/**
 * Batches with fully signed transactions (prepared transactions) should be
 * removed from storage
 * @given a batch with semi-signed transaction as MST update
 * @when the batch collects all the signatures
 * @then storage removes the batch
 */
TEST_F(OldPendingTxsStorageFixture, PreparedBatch) {
  auto state = std::make_shared<iroha::MstState>(
      iroha::MstState::empty(mst_state_log_, completer_));
  std::shared_ptr<shared_model::interface::TransactionBatch> batch =
      addSignatures(
          makeTestBatch(txBuilder(3, getUniqueTime(), 3, "alice@iroha")),
          0,
          makeSignature("1"_hex_sig, "pub_key_1"_hex_pubkey));
  *state += batch;

  storage_->updatedBatchesHandler(state);
  batch = addSignatures(batch,
                        0,
                        makeSignature("2"_hex_sig, "pub_key_2"_hex_pubkey),
                        makeSignature("3"_hex_sig, "pub_key_3"_hex_pubkey));
  storage_->removeBatch(batch);
  auto pending = storage_->getPendingTransactions("alice@iroha");
  ASSERT_EQ(pending.size(), 0);
}

/**
 * Batches with expired transactions should be removed from storage.
 * @given a batch with semi-signed transaction as MST update
 * @when the batch expires
 * @then storage removes the batch
 */
TEST_F(OldPendingTxsStorageFixture, ExpiredBatch) {
  auto state = std::make_shared<iroha::MstState>(
      iroha::MstState::empty(mst_state_log_, completer_));
  std::shared_ptr<shared_model::interface::TransactionBatch> batch =
      addSignatures(
          makeTestBatch(txBuilder(3, getUniqueTime(), 3, "alice@iroha")),
          0,
          makeSignature("1"_hex_sig, "pub_key_1"_hex_pubkey));
  *state += batch;

  storage_->updatedBatchesHandler(state);
  storage_->removeBatch(batch);
  auto pending = storage_->getPendingTransactions("alice@iroha");
  ASSERT_EQ(pending.size(), 0);
}
