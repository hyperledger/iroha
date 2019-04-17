/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include <rxcpp/rx.hpp>
#include "datetime/time.hpp"
#include "framework/test_logger.hpp"
#include "module/irohad/multi_sig_transactions/mst_test_helpers.hpp"
#include "multi_sig_transactions/state/mst_state.hpp"
#include "pending_txs_storage/impl/pending_txs_storage_impl.hpp"

class PendingTxsStorageFixture : public ::testing::Test {
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

  std::shared_ptr<iroha::DefaultCompleter> completer_ =
      std::make_shared<iroha::DefaultCompleter>(std::chrono::minutes(0));
  size_t mst_state_txs_limit_{10};

  logger::LoggerPtr mst_state_log_{getTestLogger("MstState")};
  logger::LoggerPtr log_{getTestLogger("PendingTxsStorageFixture")};
};

/**
 * Test that check that fixture common preparation procedures can be done
 * successfully.
 * @given empty MST state
 * @when two mst transactions generated as batch
 * @then the transactions can be added to MST state successfully
 */
TEST_F(PendingTxsStorageFixture, FixutureSelfCheck) {
  auto state = std::make_shared<iroha::MstState>(
      iroha::MstState::empty(completer_, mst_state_txs_limit_, mst_state_log_));
  auto transactions =
      addSignatures(makeTestBatch(txBuilder(1, getUniqueTime()),
                                  txBuilder(1, getUniqueTime())),
                    0,
                    makeSignature("1", "pub_key_1"));

  *state += transactions;
  ASSERT_EQ(state->batchesQuantity(), 1) << "Failed to prepare MST state";
  ASSERT_EQ(state->transactionsQuantity(), 2)
      << "Test batch contains wrong quantity of transactions";
}

/**
 * Transactions insertion works in PendingTxsStorage
 * @given Batch of two transactions and storage
 * @when storage receives updated mst state with the batch
 * @then list of pending transactions can be received for all batch creators
 */
TEST_F(PendingTxsStorageFixture, InsertionTest) {
  auto state = std::make_shared<iroha::MstState>(
      iroha::MstState::empty(completer_, mst_state_txs_limit_, mst_state_log_));
  auto transactions = addSignatures(
      makeTestBatch(txBuilder(2, getUniqueTime(), 2, "alice@iroha"),
                    txBuilder(2, getUniqueTime(), 2, "bob@iroha")),
      0,
      makeSignature("1", "pub_key_1"));
  *state += transactions;

  auto updates = rxcpp::observable<>::create<decltype(state)>([&state](auto s) {
    s.on_next(state);
    s.on_completed();
  });
  auto dummy = rxcpp::observable<>::create<std::shared_ptr<Batch>>(
      [](auto s) { s.on_completed(); });

  iroha::PendingTransactionStorageImpl storage(updates, dummy, dummy);
  for (const auto &creator : {"alice@iroha", "bob@iroha"}) {
    auto pending = storage.getPendingTransactions(creator);
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
TEST_F(PendingTxsStorageFixture, SignaturesUpdate) {
  auto state1 = std::make_shared<iroha::MstState>(
      iroha::MstState::empty(completer_, mst_state_txs_limit_, mst_state_log_));
  auto state2 = std::make_shared<iroha::MstState>(
      iroha::MstState::empty(completer_, mst_state_txs_limit_, mst_state_log_));
  auto transactions = addSignatures(
      makeTestBatch(txBuilder(3, getUniqueTime(), 3, "alice@iroha")),
      0,
      makeSignature("1", "pub_key_1"));
  *state1 += transactions;
  transactions =
      addSignatures(transactions, 0, makeSignature("2", "pub_key_2"));
  *state2 += transactions;

  auto updates =
      rxcpp::observable<>::create<decltype(state1)>([&state1, &state2](auto s) {
        s.on_next(state1);
        s.on_next(state2);
        s.on_completed();
      });
  auto dummy = rxcpp::observable<>::create<std::shared_ptr<Batch>>(
      [](auto s) { s.on_completed(); });

  iroha::PendingTransactionStorageImpl storage(updates, dummy, dummy);
  auto pending = storage.getPendingTransactions("alice@iroha");
  ASSERT_EQ(pending.size(), 1);
  ASSERT_EQ(boost::size(pending.front()->signatures()), 2);
}

/**
 * Storage correctly handles storing of several batches
 * @given MST state update with three batches inside
 * @when different users asks pending transactions
 * @then users receives correct responses
 */
TEST_F(PendingTxsStorageFixture, SeveralBatches) {
  auto state = std::make_shared<iroha::MstState>(
      iroha::MstState::empty(completer_, mst_state_txs_limit_, mst_state_log_));
  auto batch1 = addSignatures(
      makeTestBatch(txBuilder(2, getUniqueTime(), 2, "alice@iroha"),
                    txBuilder(2, getUniqueTime(), 2, "bob@iroha")),
      0,
      makeSignature("1", "pub_key_1"));
  auto batch2 = addSignatures(
      makeTestBatch(txBuilder(2, getUniqueTime(), 2, "alice@iroha"),
                    txBuilder(3, getUniqueTime(), 3, "alice@iroha")),
      0,
      makeSignature("1", "pub_key_1"));
  auto batch3 = addSignatures(
      makeTestBatch(txBuilder(2, getUniqueTime(), 2, "bob@iroha")),
      0,
      makeSignature("2", "pub_key_2"));
  *state += batch1;
  *state += batch2;
  *state += batch3;

  auto updates = rxcpp::observable<>::create<decltype(state)>([&state](auto s) {
    s.on_next(state);
    s.on_completed();
  });
  auto dummy = rxcpp::observable<>::create<std::shared_ptr<Batch>>(
      [](auto s) { s.on_completed(); });

  iroha::PendingTransactionStorageImpl storage(updates, dummy, dummy);
  auto alice_pending = storage.getPendingTransactions("alice@iroha");
  ASSERT_EQ(alice_pending.size(), 4);

  auto bob_pending = storage.getPendingTransactions("bob@iroha");
  ASSERT_EQ(bob_pending.size(), 3);
}

/**
 * New updates do not overwrite the whole state
 * @given two MST updates with different batches
 * @when updates arrives to storage sequentially
 * @then updates don't overwrite the whole storage state
 */
TEST_F(PendingTxsStorageFixture, SeparateBatchesDoNotOverwriteStorage) {
  auto state1 = std::make_shared<iroha::MstState>(
      iroha::MstState::empty(completer_, mst_state_txs_limit_, mst_state_log_));
  auto batch1 = addSignatures(
      makeTestBatch(txBuilder(2, getUniqueTime(), 2, "alice@iroha"),
                    txBuilder(2, getUniqueTime(), 2, "bob@iroha")),
      0,
      makeSignature("1", "pub_key_1"));
  *state1 += batch1;
  auto state2 = std::make_shared<iroha::MstState>(
      iroha::MstState::empty(completer_, mst_state_txs_limit_, mst_state_log_));
  auto batch2 = addSignatures(
      makeTestBatch(txBuilder(2, getUniqueTime(), 2, "alice@iroha"),
                    txBuilder(3, getUniqueTime(), 3, "alice@iroha")),
      0,
      makeSignature("1", "pub_key_1"));
  *state2 += batch2;

  auto updates =
      rxcpp::observable<>::create<decltype(state1)>([&state1, &state2](auto s) {
        s.on_next(state1);
        s.on_next(state2);
        s.on_completed();
      });
  auto dummy = rxcpp::observable<>::create<std::shared_ptr<Batch>>(
      [](auto s) { s.on_completed(); });

  iroha::PendingTransactionStorageImpl storage(updates, dummy, dummy);
  auto alice_pending = storage.getPendingTransactions("alice@iroha");
  ASSERT_EQ(alice_pending.size(), 4);

  auto bob_pending = storage.getPendingTransactions("bob@iroha");
  ASSERT_EQ(bob_pending.size(), 2);
}

/**
 * Batches with fully signed transactions (prepared transactions) should be
 * removed from storage
 * @given a batch with semi-signed transaction as MST update
 * @when the batch collects all the signatures
 * @then storage removes the batch
 */
TEST_F(PendingTxsStorageFixture, PreparedBatch) {
  auto state = std::make_shared<iroha::MstState>(
      iroha::MstState::empty(completer_, mst_state_txs_limit_, mst_state_log_));
  std::shared_ptr<shared_model::interface::TransactionBatch> batch =
      addSignatures(
          makeTestBatch(txBuilder(3, getUniqueTime(), 3, "alice@iroha")),
          0,
          makeSignature("1", "pub_key_1"));
  *state += batch;

  rxcpp::subjects::subject<decltype(batch)> prepared_batches_subject;
  auto updates = rxcpp::observable<>::create<decltype(state)>([&state](auto s) {
    s.on_next(state);
    s.on_completed();
  });
  auto dummy = rxcpp::observable<>::create<std::shared_ptr<Batch>>(
      [](auto s) { s.on_completed(); });
  iroha::PendingTransactionStorageImpl storage(
      updates, prepared_batches_subject.get_observable(), dummy);

  batch = addSignatures(batch,
                        0,
                        makeSignature("2", "pub_key_2"),
                        makeSignature("3", "pub_key_3"));
  prepared_batches_subject.get_subscriber().on_next(batch);
  prepared_batches_subject.get_subscriber().on_completed();
  auto pending = storage.getPendingTransactions("alice@iroha");
  ASSERT_EQ(pending.size(), 0);
}

/**
 * Batches with expired transactions should be removed from storage.
 * @given a batch with semi-signed transaction as MST update
 * @when the batch expires
 * @then storage removes the batch
 */
TEST_F(PendingTxsStorageFixture, ExpiredBatch) {
  auto state = std::make_shared<iroha::MstState>(
      iroha::MstState::empty(completer_, mst_state_txs_limit_, mst_state_log_));
  std::shared_ptr<shared_model::interface::TransactionBatch> batch =
      addSignatures(
          makeTestBatch(txBuilder(3, getUniqueTime(), 3, "alice@iroha")),
          0,
          makeSignature("1", "pub_key_1"));
  *state += batch;

  rxcpp::subjects::subject<decltype(batch)> expired_batches_subject;
  auto updates = rxcpp::observable<>::create<decltype(state)>([&state](auto s) {
    s.on_next(state);
    s.on_completed();
  });
  auto dummy = rxcpp::observable<>::create<std::shared_ptr<Batch>>(
      [](auto s) { s.on_completed(); });
  iroha::PendingTransactionStorageImpl storage(
      updates, dummy, expired_batches_subject.get_observable());

  expired_batches_subject.get_subscriber().on_next(batch);
  expired_batches_subject.get_subscriber().on_completed();
  auto pending = storage.getPendingTransactions("alice@iroha");
  ASSERT_EQ(pending.size(), 0);
}
