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

// TODO igor-egorov 2019-06-24 IR-573 Refactor pending txs storage tests
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

  auto dummyObservable() {
    return rxcpp::observable<>::empty<std::shared_ptr<Batch>>();
  }

  auto dummyPreparedTxsObservable() {
    return rxcpp::observable<>::empty<
        std::pair<shared_model::interface::types::AccountIdType,
                  shared_model::interface::types::HashType>>();
  }

  auto updatesObservable(std::vector<std::shared_ptr<iroha::MstState>> states) {
    return rxcpp::observable<>::iterate(states);
  }

  auto emptyState() {
    return std::make_shared<iroha::MstState>(
        iroha::MstState::empty(mst_state_log_, completer_));
  }

  auto twoTransactionsBatch() {
    return addSignatures(
        makeTestBatch(txBuilder(2, getUniqueTime(), 2, "alice@iroha"),
                      txBuilder(2, getUniqueTime(), 2, "bob@iroha")),
        0,
        makeSignature("1", "pub_key_1"));
  }

  std::shared_ptr<iroha::DefaultCompleter> completer_ =
      std::make_shared<iroha::DefaultCompleter>(std::chrono::minutes(0));

  logger::LoggerPtr mst_state_log_{getTestLogger("MstState")};
  logger::LoggerPtr log_{getTestLogger("PendingTxsStorageFixture")};
};

/**
 * Test that checks that fixture common preparation procedures can be done
 * successfully.
 * @given empty MST state
 * @when two mst transactions generated as batch
 * @then the transactions can be added to MST state successfully
 */
TEST_F(PendingTxsStorageFixture, FixtureSelfCheck) {
  auto state = emptyState();
  auto transactions = twoTransactionsBatch();
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
TEST_F(PendingTxsStorageFixture, InsertionTest) {
  auto state = emptyState();
  auto transactions = twoTransactionsBatch();
  *state += transactions;

  const auto kPageSize = 100u;

  iroha::PendingTransactionStorageImpl storage(updatesObservable({state}),
                                               dummyObservable(),
                                               dummyObservable(),
                                               dummyPreparedTxsObservable());
  for (const auto &creator : {"alice@iroha", "bob@iroha"}) {
    auto pending =
        storage.getPendingTransactions(creator, kPageSize, boost::none);
    pending.match(
        [&txs = transactions](const auto &response) {
          auto &pending_txs = response.value.transactions;
          EXPECT_EQ(response.value.all_transactions_size,
                    txs->transactions().size());
          EXPECT_EQ(pending_txs.size(), txs->transactions().size());
          EXPECT_FALSE(response.value.next_batch_info);
          // generally it's illegal way to verify the correctness.
          // here we can do it because the order is preserved by batch meta and
          // there are no transactions non-related to requested account
          for (auto i = 0u; i < pending_txs.size(); ++i) {
            ASSERT_EQ(*pending_txs[i], *(txs->transactions()[i]));
          }
        },
        [](const auto &error) {
          FAIL() << "An error was not expected, the error code is "
                 << error.error;
        });
  }
}

/**
 * All the transactions can be received when exact page size is specified
 * @given a storage with a batch with two transactions
 * @when pending transactions are queired with page size equal to the batch size
 * @then all the transactions are correctly returned
 */
TEST_F(PendingTxsStorageFixture, ExactSize) {
  auto state = emptyState();
  auto transactions = twoTransactionsBatch();
  *state += transactions;

  const auto kPageSize = transactions->transactions().size();

  iroha::PendingTransactionStorageImpl storage(updatesObservable({state}),
                                               dummyObservable(),
                                               dummyObservable(),
                                               dummyPreparedTxsObservable());
  for (const auto &creator : {"alice@iroha", "bob@iroha"}) {
    auto pending =
        storage.getPendingTransactions(creator, kPageSize, boost::none);
    pending.match(
        [&txs = transactions](const auto &response) {
          auto &pending_txs = response.value.transactions;
          EXPECT_EQ(response.value.all_transactions_size,
                    txs->transactions().size());
          EXPECT_EQ(pending_txs.size(), txs->transactions().size());
          EXPECT_FALSE(response.value.next_batch_info);
          // generally it's illegal way to verify the correctness.
          // here we can do it because the order is preserved by batch meta and
          // there are no transactions non-related to requested account
          for (auto i = 0u; i < pending_txs.size(); ++i) {
            ASSERT_EQ(*pending_txs[i], *(txs->transactions()[i]));
          }
        },
        [](const auto &error) {
          FAIL() << "An error was not expected, the error code is "
                 << error.error;
        });
  }
}

/**
 * Correctly formed response is returned when queried page size smaller than the
 * size of the smallest batch
 * @given a storage with a batch with two transactions
 * @when pending transactions are queired with page size equal to 1
 * @then no transactions are returned, but all the meta is correctly set
 */
TEST_F(PendingTxsStorageFixture, InsufficientSize) {
  auto state = emptyState();
  auto transactions = twoTransactionsBatch();
  *state += transactions;

  const auto kPageSize = 1;
  ASSERT_NE(kPageSize, transactions->transactions().size());

  iroha::PendingTransactionStorageImpl storage(updatesObservable({state}),
                                               dummyObservable(),
                                               dummyObservable(),
                                               dummyPreparedTxsObservable());
  for (const auto &creator : {"alice@iroha", "bob@iroha"}) {
    auto pending =
        storage.getPendingTransactions(creator, kPageSize, boost::none);
    pending.match(
        [&txs = transactions](const auto &response) {
          auto &pending_txs = response.value.transactions;
          EXPECT_EQ(response.value.all_transactions_size,
                    txs->transactions().size());
          EXPECT_EQ(pending_txs.size(), 0);
          EXPECT_TRUE(response.value.next_batch_info);
          EXPECT_EQ(response.value.next_batch_info->first_tx_hash,
                    txs->transactions().front()->hash());
          EXPECT_EQ(response.value.next_batch_info->batch_size,
                    txs->transactions().size());
        },
        [](const auto &error) {
          FAIL() << "An error was not expected, the error code is "
                 << error.error;
        });
  }
}

/**
 * Correctly formed response is returned when there are two batches are in the
 * storage and the page size is bigger than the size of the first batch and
 * smaller than the sum of the first and the second batches sizes.
 */
TEST_F(PendingTxsStorageFixture, BatchAndAHalfPageSize) {
  auto state1 = emptyState();
  auto state2 = emptyState();
  auto batch1 = twoTransactionsBatch();
  auto batch2 = twoTransactionsBatch();
  *state1 += batch1;
  *state2 += batch2;

  const auto kPageSize =
      batch1->transactions().size() + batch2->transactions().size() - 1;
  auto updates = updatesObservable({state1, state2});

  iroha::PendingTransactionStorageImpl storage(updates,
                                               dummyObservable(),
                                               dummyObservable(),
                                               dummyPreparedTxsObservable());
  for (const auto &creator : {"alice@iroha", "bob@iroha"}) {
    auto pending =
        storage.getPendingTransactions(creator, kPageSize, boost::none);
    pending.match(
        [&](const auto &response) {
          auto &pending_txs = response.value.transactions;
          EXPECT_EQ(
              response.value.all_transactions_size,
              batch1->transactions().size() + batch2->transactions().size());
          EXPECT_EQ(pending_txs.size(), batch1->transactions().size());
          EXPECT_TRUE(response.value.next_batch_info);
          EXPECT_EQ(response.value.next_batch_info->first_tx_hash,
                    batch2->transactions().front()->hash());
          EXPECT_EQ(response.value.next_batch_info->batch_size,
                    batch2->transactions().size());
          for (auto i = 0u; i < pending_txs.size(); ++i) {
            ASSERT_EQ(*pending_txs[i], *(batch1->transactions()[i]));
          }
        },
        [](const auto &error) {
          FAIL() << "An error was not expected, the error code is "
                 << error.error;
        });
  }
}

/**
 * Correctly formed response is returned when there are two batches are in the
 * storage and first tx hash in request is equal to the hash of the first
 * transaction in the second stored batch.
 */
TEST_F(PendingTxsStorageFixture, StartFromTheSecondBatch) {
  auto state1 = emptyState();
  auto state2 = emptyState();
  auto batch1 = twoTransactionsBatch();
  auto batch2 = twoTransactionsBatch();
  *state1 += batch1;
  *state2 += batch2;

  const auto kPageSize = batch2->transactions().size();
  auto updates = updatesObservable({state1, state2});

  iroha::PendingTransactionStorageImpl storage(updates,
                                               dummyObservable(),
                                               dummyObservable(),
                                               dummyPreparedTxsObservable());
  for (const auto &creator : {"alice@iroha", "bob@iroha"}) {
    auto pending = storage.getPendingTransactions(
        creator, kPageSize, batch2->transactions().front()->hash());
    pending.match(
        [&](const auto &response) {
          auto &pending_txs = response.value.transactions;
          EXPECT_EQ(
              response.value.all_transactions_size,
              batch1->transactions().size() + batch2->transactions().size());
          EXPECT_EQ(pending_txs.size(), batch2->transactions().size());
          EXPECT_FALSE(response.value.next_batch_info);
          for (auto i = 0u; i < pending_txs.size(); ++i) {
            ASSERT_EQ(*pending_txs[i], *(batch2->transactions()[i]));
          }
        },
        [](const auto &error) {
          FAIL() << "An error was not expected, the error code is "
                 << error.error;
        });
  }
}

/**
 * @given non empty pending transactions storage
 * @when a user requests pending transactions (and the storage has nothing for
 * the user)
 * @then an empty response is produced for the user
 */
TEST_F(PendingTxsStorageFixture, NoPendingBatches) {
  auto state = emptyState();
  auto transactions = twoTransactionsBatch();
  *state += transactions;

  const auto kThirdAccount = "clark@iroha";
  const auto kPageSize = 100u;

  iroha::PendingTransactionStorageImpl storage(updatesObservable({state}),
                                               dummyObservable(),
                                               dummyObservable(),
                                               dummyPreparedTxsObservable());

  auto response =
      storage.getPendingTransactions(kThirdAccount, kPageSize, boost::none);
  response.match(
      [](const auto &response) {
        auto &pending_txs = response.value.transactions;
        EXPECT_EQ(pending_txs.size(), 0);
        EXPECT_EQ(response.value.all_transactions_size, 0);
        auto &next_batch_info = response.value.next_batch_info;
        ASSERT_FALSE(next_batch_info);
      },
      [](const auto &error) { FAIL() << error.error; });
}

/**
 * Updated batch replaces previously existed
 * @given Batch with one transaction with one signature and storage
 * @when transaction inside batch receives additional signature
 * @then pending transactions response is also updated
 */
TEST_F(PendingTxsStorageFixture, SignaturesUpdate) {
  auto state1 = emptyState();
  auto state2 = emptyState();
  auto transactions = addSignatures(
      makeTestBatch(txBuilder(3, getUniqueTime(), 3, "alice@iroha")),
      0,
      makeSignature("1", "pub_key_1"));
  *state1 += transactions;
  transactions =
      addSignatures(transactions, 0, makeSignature("2", "pub_key_2"));
  *state2 += transactions;

  auto updates = updatesObservable({state1, state2});
  const auto kPageSize = 100u;

  iroha::PendingTransactionStorageImpl storage(updates,
                                               dummyObservable(),
                                               dummyObservable(),
                                               dummyPreparedTxsObservable());
  auto pending =
      storage.getPendingTransactions("alice@iroha", kPageSize, boost::none);
  pending.match(
      [&txs = transactions](const auto &response) {
        const auto &resp = response.value;
        EXPECT_EQ(resp.transactions.size(), txs->transactions().size());
        EXPECT_EQ(boost::size(resp.transactions.front()->signatures()), 2);
      },
      [](const auto &error) {
        FAIL() << "An error was not expected, the error code is "
               << error.error;
      });
}

/**
 * Storage correctly handles storing of several batches
 * @given MST state update with three batches inside
 * @when different users asks pending transactions
 * @then users receives correct responses
 */
TEST_F(PendingTxsStorageFixture, SeveralBatches) {
  auto state = emptyState();
  auto batch1 = twoTransactionsBatch();
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

  auto updates = updatesObservable({state});
  const auto kPageSize = 100u;

  iroha::PendingTransactionStorageImpl storage(updates,
                                               dummyObservable(),
                                               dummyObservable(),
                                               dummyPreparedTxsObservable());
  auto alice_pending =
      storage.getPendingTransactions("alice@iroha", kPageSize, boost::none);
  alice_pending.match(
      [](const auto &response) {
        ASSERT_EQ(response.value.transactions.size(), 4);
      },
      [](const auto &error) {
        FAIL() << "An error was not expected, the error code is "
               << error.error;
      });

  auto bob_pending =
      storage.getPendingTransactions("bob@iroha", kPageSize, boost::none);
  bob_pending.match(
      [](const auto &response) {
        ASSERT_EQ(response.value.transactions.size(), 3);
      },
      [](const auto &error) {
        FAIL() << "An error was not expected, the error code is "
               << error.error;
      });
}

/**
 * New updates do not overwrite the whole state
 * @given two MST updates with different batches
 * @when updates arrives to storage sequentially
 * @then updates don't overwrite the whole storage state
 */
TEST_F(PendingTxsStorageFixture, SeparateBatchesDoNotOverwriteStorage) {
  auto state1 = emptyState();
  auto batch1 = twoTransactionsBatch();
  *state1 += batch1;
  auto state2 = std::make_shared<iroha::MstState>(
      iroha::MstState::empty(mst_state_log_, completer_));
  auto batch2 = addSignatures(
      makeTestBatch(txBuilder(2, getUniqueTime(), 2, "alice@iroha"),
                    txBuilder(3, getUniqueTime(), 3, "alice@iroha")),
      0,
      makeSignature("1", "pub_key_1"));
  *state2 += batch2;

  auto updates = updatesObservable({state1, state2});
  const auto kPageSize = 100u;

  iroha::PendingTransactionStorageImpl storage(updates,
                                               dummyObservable(),
                                               dummyObservable(),
                                               dummyPreparedTxsObservable());

  auto alice_pending =
      storage.getPendingTransactions("alice@iroha", kPageSize, boost::none);
  alice_pending.match(
      [](const auto &response) {
        ASSERT_EQ(response.value.transactions.size(), 4);
      },
      [](const auto &error) {
        FAIL() << "An error was not expected, the error code is "
               << error.error;
      });

  auto bob_pending =
      storage.getPendingTransactions("bob@iroha", kPageSize, boost::none);
  bob_pending.match(
      [](const auto &response) {
        ASSERT_EQ(response.value.transactions.size(), 2);
      },
      [](const auto &error) {
        FAIL() << "An error was not expected, the error code is "
               << error.error;
      });
}

/**
 * Batches with fully signed transactions (prepared transactions) should be
 * removed from storage
 * @given a batch with semi-signed transaction as MST update
 * @when the batch collects all the signatures
 * @then storage removes the batch
 */
TEST_F(PendingTxsStorageFixture, PreparedBatch) {
  auto state = emptyState();
  std::shared_ptr<shared_model::interface::TransactionBatch> batch =
      addSignatures(
          makeTestBatch(txBuilder(3, getUniqueTime(), 3, "alice@iroha")),
          0,
          makeSignature("1", "pub_key_1"));
  *state += batch;

  rxcpp::subjects::subject<decltype(batch)> prepared_batches_subject;
  auto updates = updatesObservable({state});

  iroha::PendingTransactionStorageImpl storage(
      updates,
      prepared_batches_subject.get_observable(),
      dummyObservable(),
      dummyPreparedTxsObservable());

  batch = addSignatures(batch,
                        0,
                        makeSignature("2", "pub_key_2"),
                        makeSignature("3", "pub_key_3"));
  prepared_batches_subject.get_subscriber().on_next(batch);
  prepared_batches_subject.get_subscriber().on_completed();
  const auto kPageSize = 100u;
  auto pending =
      storage.getPendingTransactions("alice@iroha", kPageSize, boost::none);
  pending.match(
      [](const auto &response) {
        ASSERT_EQ(response.value.transactions.size(), 0);
      },
      [](const auto &error) {
        FAIL() << "An error was not expected, the error code is "
               << error.error;
      });
}

/**
 * Batches with expired transactions should be removed from storage.
 * @given a batch with semi-signed transaction as MST update
 * @when the batch expires
 * @then storage removes the batch
 */
TEST_F(PendingTxsStorageFixture, ExpiredBatch) {
  auto state = emptyState();
  std::shared_ptr<shared_model::interface::TransactionBatch> batch =
      addSignatures(
          makeTestBatch(txBuilder(3, getUniqueTime(), 3, "alice@iroha")),
          0,
          makeSignature("1", "pub_key_1"));
  *state += batch;

  rxcpp::subjects::subject<decltype(batch)> expired_batches_subject;
  auto updates = updatesObservable({state});

  iroha::PendingTransactionStorageImpl storage(
      updates,
      dummyObservable(),
      expired_batches_subject.get_observable(),
      dummyPreparedTxsObservable());

  expired_batches_subject.get_subscriber().on_next(batch);
  expired_batches_subject.get_subscriber().on_completed();
  const auto kPageSize = 100u;
  auto pending =
      storage.getPendingTransactions("alice@iroha", kPageSize, boost::none);
  pending.match(
      [](const auto &response) {
        ASSERT_EQ(response.value.transactions.size(), 0);
      },
      [](const auto &error) {
        FAIL() << "An error was not expected, the error code is "
               << error.error;
      });
}

/**
 * @given a storage
 * @when the non-existing batch is queried via first tx hash
 * @then not found error is returned by the storage
 */
TEST_F(PendingTxsStorageFixture, QueryingWrongBatch) {
  auto state = emptyState();
  auto transactions = twoTransactionsBatch();
  *state += transactions;

  const auto kThirdAccount = "clark@iroha";
  const auto kPageSize = 100u;

  iroha::PendingTransactionStorageImpl storage(updatesObservable({state}),
                                               dummyObservable(),
                                               dummyObservable(),
                                               dummyPreparedTxsObservable());

  auto response = storage.getPendingTransactions(
      kThirdAccount, kPageSize, transactions->transactions().front()->hash());
  response.match(
      [](const auto &response) {
        FAIL() << "NOT_FOUND error was expected instead of a response";
      },
      [](const auto &error) {
        ASSERT_EQ(error.error,
                  iroha::PendingTransactionStorage::ErrorCode::kNotFound);
      });
}

/**
 * @given a storage with two batches
 * @when a user requests the first batch only
 * @then the second using starting tx hash returned by the first response
 */
TEST_F(PendingTxsStorageFixture, QueryAllTheBatches) {
  auto state1 = emptyState();
  auto state2 = emptyState();
  auto batch1 = twoTransactionsBatch();
  auto batch2 = twoTransactionsBatch();
  *state1 += batch1;
  *state2 += batch2;

  auto batchSize = [](const auto &batch) {
    return batch->transactions().size();
  };
  auto firstHash = [](const auto &batch) {
    return batch->transactions().front()->hash();
  };
  auto errorResponseHandler = [](const auto &error) {
    FAIL() << "An error was not expected, the error code is " << error.error;
  };

  auto updates = updatesObservable({state1, state2});

  iroha::PendingTransactionStorageImpl storage(updates,
                                               dummyObservable(),
                                               dummyObservable(),
                                               dummyPreparedTxsObservable());
  for (const auto &creator : {"alice@iroha", "bob@iroha"}) {
    auto first_page =
        storage.getPendingTransactions(creator, batchSize(batch1), boost::none);
    first_page.match(
        [&](const auto &first_response) {
          const auto &resp1 = first_response.value;
          EXPECT_EQ(resp1.all_transactions_size,
                    batchSize(batch1) + batchSize(batch2));
          EXPECT_EQ(resp1.transactions.size(), batchSize(batch1));
          EXPECT_TRUE(resp1.next_batch_info);
          EXPECT_EQ(resp1.next_batch_info->batch_size, batchSize(batch2));
          EXPECT_EQ(resp1.next_batch_info->first_tx_hash, firstHash(batch2));
          for (auto i = 0u; i < resp1.transactions.size(); ++i) {
            ASSERT_EQ(*resp1.transactions[i], *(batch1->transactions()[i]));
          }

          auto second_page = storage.getPendingTransactions(
              creator, batchSize(batch2), firstHash(batch2));
          second_page.match(
              [&](const auto &second_response) {
                const auto &resp2 = second_response.value;
                EXPECT_EQ(resp2.all_transactions_size,
                          batchSize(batch1) + batchSize(batch2));
                EXPECT_EQ(resp2.transactions.size(), batchSize(batch2));
                EXPECT_FALSE(resp2.next_batch_info);
                for (auto i = 0u; i < resp2.transactions.size(); ++i) {
                  ASSERT_EQ(*resp2.transactions[i],
                            *(batch2->transactions()[i]));
                }
              },
              errorResponseHandler);
        },
        errorResponseHandler);
  }
}