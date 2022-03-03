/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "datetime/time.hpp"
#include "framework/crypto_literals.hpp"
#include "framework/test_logger.hpp"
#include "pending_txs_storage/impl/pending_txs_storage_impl.hpp"

#include "builders/protobuf/transaction.hpp"
#include "datetime/time.hpp"
#include "framework/batch_helper.hpp"
#include "framework/test_logger.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "interfaces/common_objects/types.hpp"
#include "logger/logger.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"

template <typename... TxBuilders>
auto makeTestBatch(TxBuilders... builders) {
  return framework::batch::makeTestBatch(builders...);
}

inline auto makeSignature(
    shared_model::interface::types::SignedHexStringView sign,
    shared_model::interface::types::PublicKeyHexStringView public_key) {
  return std::make_pair(std::string{std::string_view{sign}},
                        std::string{std::string_view{public_key}});
}

inline auto txBuilder(
    const shared_model::interface::types::CounterType &counter,
    shared_model::interface::types::TimestampType created_time =
        iroha::time::now(),
    shared_model::interface::types::QuorumType quorum = 3,
    shared_model::interface::types::AccountIdType account_id = "user@test") {
  return TestTransactionBuilder()
      .createdTime(created_time)
      .creatorAccountId(account_id)
      .setAccountQuorum(account_id, counter)
      .quorum(quorum);
}

template <typename Batch, typename... Signatures>
auto addSignatures(Batch &&batch, int tx_number, Signatures... signatures) {
  static logger::LoggerPtr log_ = getTestLogger("addSignatures");

  auto insert_signatures = [&](auto &&sig_pair) {
    batch->addSignature(
        tx_number,
        shared_model::interface::types::SignedHexStringView{sig_pair.first},
        shared_model::interface::types::PublicKeyHexStringView{
            sig_pair.second});
  };

  // pack expansion trick:
  // an ellipsis operator applies insert_signatures to each signature, operator
  // comma returns the rightmost argument, which is 0
  int temp[] = {
      (insert_signatures(std::forward<Signatures>(signatures)), 0)...};
  // use unused variable
  (void)temp;

  log_->info("Number of signatures was inserted {}",
             boost::size(batch->transactions().at(tx_number)->signatures()));
  return std::forward<Batch>(batch);
}

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

  logger::LoggerPtr mst_state_log_{getTestLogger("MstState")};
  logger::LoggerPtr log_{getTestLogger("OldPendingTxsStorageFixture")};
};

/**
 * Transactions insertion works in PendingTxsStorage
 * @given Batch of two transactions and storage
 * @when storage receives updated mst state with the batch
 * @then list of pending transactions can be received for all batch creators
 */
TEST_F(OldPendingTxsStorageFixture, InsertionTest) {
  auto transactions = addSignatures(
      makeTestBatch(txBuilder(2, getUniqueTime(), 2, "alice@iroha"),
                    txBuilder(2, getUniqueTime(), 2, "bob@iroha")),
      0,
      makeSignature("1"_hex_sig, "pub_key_1"_hex_pubkey));

  storage_->updatedBatchesHandler(transactions);
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
  auto transactions = addSignatures(
      makeTestBatch(txBuilder(3, getUniqueTime(), 3, "alice@iroha")),
      0,
      makeSignature("1"_hex_sig, "pub_key_1"_hex_pubkey));
  storage_->updatedBatchesHandler(transactions);
  transactions = addSignatures(
      transactions, 0, makeSignature("2"_hex_sig, "pub_key_2"_hex_pubkey));
  storage_->updatedBatchesHandler(transactions);
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

  storage_->updatedBatchesHandler(batch1);
  storage_->updatedBatchesHandler(batch2);
  storage_->updatedBatchesHandler(batch3);
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

  storage_->updatedBatchesHandler(batch1);
  storage_->updatedBatchesHandler(batch2);
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
  std::shared_ptr<shared_model::interface::TransactionBatch> batch =
      addSignatures(
          makeTestBatch(txBuilder(3, getUniqueTime(), 3, "alice@iroha")),
          0,
          makeSignature("1"_hex_sig, "pub_key_1"_hex_pubkey));

  storage_->updatedBatchesHandler(batch);
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
  std::shared_ptr<shared_model::interface::TransactionBatch> batch =
      addSignatures(
          makeTestBatch(txBuilder(3, getUniqueTime(), 3, "alice@iroha")),
          0,
          makeSignature("1"_hex_sig, "pub_key_1"_hex_pubkey));

  storage_->updatedBatchesHandler(batch);
  storage_->removeBatch(batch);
  auto pending = storage_->getPendingTransactions("alice@iroha");
  ASSERT_EQ(pending.size(), 0);
}
