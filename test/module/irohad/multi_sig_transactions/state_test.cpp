/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "framework/test_logger.hpp"
#include "logger/logger.hpp"
#include "module/irohad/multi_sig_transactions/mst_test_helpers.hpp"
#include "multi_sig_transactions/state/mst_state.hpp"
#include "storage_shared_limit/batch_storage_limit_by_txs.hpp"
#include "storage_shared_limit/storage_limit_none.hpp"

using namespace std;
using namespace iroha;
using namespace iroha::model;

using StorageLimitDummy = StorageLimitNone<BatchPtr>;

auto mst_state_log_ = getTestLogger("MstState");
auto log_ = getTestLogger("MstStateTest");
auto completer_ = std::make_shared<TestCompleter>();

/**
 * @given empty state
 * @when  insert one batch
 * @then  checks that state contains the inserted batch
 */
TEST(StateTest, CreateState) {
  auto state = MstState::empty(
      completer_, std::make_shared<StorageLimitDummy>(), mst_state_log_);
  ASSERT_EQ(0, state.batchesQuantity());
  auto tx = addSignatures(
      makeTestBatch(txBuilder(1)), 0, makeSignature("1", "pub_key_1"));
  state += tx;
  ASSERT_EQ(1, state.batchesQuantity());
  ASSERT_EQ(*tx, **state.getBatches().begin());
}

/**
 * @given empty state
 * @when  insert batches with different signatures
 * @then  checks that signatures are merged into the state
 */
TEST(StateTest, UpdateExistingState) {
  auto state = MstState::empty(
      completer_, std::make_shared<StorageLimitDummy>(), mst_state_log_);
  auto time = iroha::time::now();
  auto first_signature = makeSignature("1", "pub_key_1");
  auto second_signature = makeSignature("2", "pub_key_2");
  auto base_tx = makeTestBatch(txBuilder(1, time));

  auto first_tx = addSignatures(base_tx, 0, first_signature);
  state += first_tx;

  auto second_tx = addSignatures(base_tx, 0, second_signature);
  state += second_tx;
  ASSERT_EQ(1, state.batchesQuantity());

  auto merged_tx = addSignatures(base_tx, 0, first_signature, second_signature);
  ASSERT_EQ(*merged_tx, **state.getBatches().begin());
}

/**
 * @given empty state @and a batch
 * @when inserting the batch
 * @then "contains" method shows presence of the batch
 */
TEST(StateTest, ContainsMethodFindsInsertedBatch) {
  auto state = MstState::empty(
      completer_, std::make_shared<StorageLimitDummy>(), mst_state_log_);
  auto first_signature = makeSignature("1", "pub_key_1");
  auto batch = makeTestBatch(txBuilder(1, iroha::time::now()));
  auto tx = addSignatures(batch, 0, first_signature);
  state += tx;

  EXPECT_TRUE(state.contains(batch));
}

/**
 * @given empty state @and a distinct batch
 * @when checking that batch's presence in the state
 * @then "contains" method shows absence of the batch
 */
TEST(StateTest, ContainsMethodDoesNotFindNonInsertedBatch) {
  auto state = MstState::empty(
      completer_, std::make_shared<StorageLimitDummy>(), mst_state_log_);
  auto batch = makeTestBatch(txBuilder(1, iroha::time::now()));
  EXPECT_FALSE(state.contains(batch));
}

/**
 * @given empty state
 * @when  insert batch with same signatures two times
 * @then  checks that the state contains only one signature
 */
TEST(StateTest, UpdateStateWhenTransactionsSame) {
  log_->info("Create empty state => insert two equal transaction");

  auto state = MstState::empty(
      completer_, std::make_shared<StorageLimitDummy>(), mst_state_log_);
  auto time = iroha::time::now();
  state += addSignatures(
      makeTestBatch(txBuilder(1, time)), 0, makeSignature("1", "1"));
  state += addSignatures(
      makeTestBatch(txBuilder(1, time)), 0, makeSignature("1", "1"));

  ASSERT_EQ(1, state.getBatches().size());
  ASSERT_EQ(1,
            boost::size(state.getBatches()
                            .begin()
                            ->get()
                            ->transactions()
                            .begin()
                            ->get()
                            ->signatures()));
}

/**
 * @given prepared state with 3 batches
 * @when  insert the batches, which are not present in the state
 * @then  checks that all batches are here
 */
TEST(StateTest, DifferentSignaturesUnionTest) {
  log_->info("Create two states => merge them");

  auto state1 = MstState::empty(
      completer_, std::make_shared<StorageLimitDummy>(), mst_state_log_);
  state1 +=
      addSignatures(makeTestBatch(txBuilder(1)), 0, makeSignature("1", "1"));

  state1 +=
      addSignatures(makeTestBatch(txBuilder(2)), 0, makeSignature("2", "2"));
  state1 +=
      addSignatures(makeTestBatch(txBuilder(3)), 0, makeSignature("3", "3"));

  ASSERT_EQ(3, state1.batchesQuantity());

  auto state2 = MstState::empty(
      completer_, std::make_shared<StorageLimitDummy>(), mst_state_log_);
  state2 +=
      addSignatures(makeTestBatch(txBuilder(4)), 0, makeSignature("4", "4"));
  state2 +=
      addSignatures(makeTestBatch(txBuilder(5)), 0, makeSignature("5", "5"));
  ASSERT_EQ(2, state2.batchesQuantity());

  state1 += state2;
  ASSERT_EQ(5, state1.batchesQuantity());
}

/**
 * @given two empty states
 * @when insert transaction with quorum 2 to one state
 * AND insert same transaction with another signature to second state
 * AND merge states
 * @then check that merged state contains both signatures
 */
TEST(StateTest, UnionStateWhenSameTransactionHaveDifferentSignatures) {
  log_->info(
      "Create two transactions with different signatures => move them"
      " into owns states => merge states");

  auto time = iroha::time::now();

  auto state1 = MstState::empty(
      completer_, std::make_shared<StorageLimitDummy>(), mst_state_log_);
  auto state2 = MstState::empty(
      completer_, std::make_shared<StorageLimitDummy>(), mst_state_log_);
  state1 += addSignatures(
      makeTestBatch(txBuilder(1, time)), 0, makeSignature("1", "1"));
  state2 += addSignatures(
      makeTestBatch(txBuilder(1, time)), 0, makeSignature("2", "2"));

  state1 += state2;
  ASSERT_EQ(1, state1.getBatches().size());
  ASSERT_EQ(2,
            boost::size(state1.getBatches()
                            .begin()
                            ->get()
                            ->transactions()
                            .begin()
                            ->get()
                            ->signatures()));
}

/**
 * @given given two states with one common transaction but with different
 * signatures
 * @when  states are merged
 * @then  the common transaction is not appeared in the resulting state
 */
TEST(StateTest, UnionStateWhenTransactionsSame) {
  auto time = iroha::time::now();

  auto state1 = MstState::empty(
      completer_, std::make_shared<StorageLimitDummy>(), mst_state_log_);
  state1 += addSignatures(
      makeTestBatch(txBuilder(1, time)), 0, makeSignature("1", "1"));
  state1 += addSignatures(
      makeTestBatch(txBuilder(2)), 0, makeSignature("other", "other"));

  ASSERT_EQ(2, state1.batchesQuantity());

  auto state2 = MstState::empty(
      completer_, std::make_shared<StorageLimitDummy>(), mst_state_log_);
  state2 += addSignatures(
      makeTestBatch(txBuilder(1, time)), 0, makeSignature("1", "1"));
  state2 += addSignatures(
      makeTestBatch(txBuilder(3)), 0, makeSignature("other_", "other_"));
  ASSERT_EQ(2, state2.batchesQuantity());

  state1 += state2;
  ASSERT_EQ(3, state1.batchesQuantity());
}

/**
 * @given two states with a common element
 * @when  difference of the states is taken
 * @then  the common element is present in the difference set
 */
TEST(StateTest, DifferenceTest) {
  auto time = iroha::time::now();

  auto first_signature = makeSignature("1", "1");
  auto second_signature = makeSignature("2", "2");
  auto third_signature = makeSignature("3", "3");

  auto another_signature = makeSignature("another", "another");

  auto common_batch = makeTestBatch(txBuilder(1, time));
  auto another_batch = makeTestBatch(txBuilder(3));

  auto state1 = MstState::empty(
      completer_, std::make_shared<StorageLimitDummy>(), mst_state_log_);
  state1 += addSignatures(common_batch, 0, first_signature);
  state1 += addSignatures(common_batch, 0, second_signature);

  auto state2 = MstState::empty(
      completer_, std::make_shared<StorageLimitDummy>(), mst_state_log_);
  state2 += addSignatures(common_batch, 0, second_signature);
  state2 += addSignatures(common_batch, 0, third_signature);
  state2 += addSignatures(another_batch, 0, another_signature);

  MstState diff = state1 - state2;
  ASSERT_EQ(1, diff.batchesQuantity());
  auto expected_batch = addSignatures(common_batch, 0, first_signature);
  ASSERT_EQ(*expected_batch, **diff.getBatches().begin());
}

/**
 * @given an empty state
 * @when a partially signed transaction with quorum 3 is inserted 3 times
 * @then each time new signature inserted state gives this batch back @and
 * returned statuses correspond to actual ones @and the resulting state contains
 * one signed transaction
 */
TEST(StateTest, UpdateTxUntillQuorum) {
  auto quorum = 3u;
  auto time = iroha::time::now();

  auto state = MstState::empty(
      completer_, std::make_shared<StorageLimitDummy>(), mst_state_log_);
  auto state_after_one_tx = state += addSignatures(
      makeTestBatch(txBuilder(1, time, quorum)), 0, makeSignature("1", "1"));
  ASSERT_EQ(1, state_after_one_tx.updated_state_->batchesQuantity());
  ASSERT_EQ(0, state_after_one_tx.completed_state_.size());

  auto state_after_two_txes = state += addSignatures(
      makeTestBatch(txBuilder(1, time, quorum)), 0, makeSignature("2", "2"));
  ASSERT_EQ(1, state_after_two_txes.updated_state_->batchesQuantity());
  ASSERT_EQ(0, state_after_two_txes.completed_state_.size());

  auto state_after_three_txes = state += addSignatures(
      makeTestBatch(txBuilder(1, time, quorum)), 0, makeSignature("3", "3"));
  ASSERT_EQ(0, state_after_three_txes.updated_state_->batchesQuantity());
  ASSERT_EQ(1, state_after_three_txes.completed_state_.size());
  ASSERT_TRUE(state_after_three_txes.completed_state_.front()
                  ->get()
                  ->hasAllSignatures());
  ASSERT_EQ(0, state.batchesQuantity());
}

/**
 * @given two states with one common partially signed transaction
 * @when  the states are merged
 * @then  the resulting state contains one signed transaction
 */
TEST(StateTest, UpdateStateWithNewStateUntilQuorum) {
  auto quorum = 3u;
  auto keypair = makeKey();
  auto time = iroha::time::now();

  auto state1 = MstState::empty(
      completer_, std::make_shared<StorageLimitDummy>(), mst_state_log_);
  state1 += addSignatures(makeTestBatch(txBuilder(1, time, quorum)),
                          0,
                          makeSignature("1_1", "1_1"));
  state1 += addSignatures(
      makeTestBatch(txBuilder(2, time)), 0, makeSignature("2", "2"));
  state1 += addSignatures(
      makeTestBatch(txBuilder(2, time)), 0, makeSignature("3", "3"));
  ASSERT_EQ(2, state1.batchesQuantity());

  auto state2 = MstState::empty(
      completer_, std::make_shared<StorageLimitDummy>(), mst_state_log_);
  state2 += addSignatures(makeTestBatch(txBuilder(1, time, quorum)),
                          0,
                          makeSignature("1_2", "1_2"));
  state2 += addSignatures(makeTestBatch(txBuilder(1, time, quorum)),
                          0,
                          makeSignature("1_3", "1_3"));
  ASSERT_EQ(1, state2.batchesQuantity());

  auto final_state = state1 += state2;
  ASSERT_EQ(1, final_state.completed_state_.size());
  ASSERT_EQ(1, state1.batchesQuantity());
}

/**
 * @given a timepoint
 * AND    a state with an expired transaction
 * @when  erase by time is called
 * @then   the resulting state contains the expired transaction
 */
TEST(StateTest, TimeIndexInsertionByTx) {
  auto quorum = 2u;
  auto time = iroha::time::now();

  auto prepared_batch = addSignatures(makeTestBatch(txBuilder(1, time, quorum)),
                                      0,
                                      makeSignature("1_1", "1_1"));

  auto state = MstState::empty(
      completer_, std::make_shared<StorageLimitDummy>(), mst_state_log_);
  state += prepared_batch;

  auto expired_state = state.extractExpired(time + 1);
  ASSERT_EQ(1, expired_state.getBatches().size());
  ASSERT_EQ(*prepared_batch, **expired_state.getBatches().begin());
  ASSERT_EQ(0, state.batchesQuantity());
}

/**
 * @given two states with expired transactions
 * @when  merge them
 * AND    make states expired
 * @then checks that all expired transactions are preserved in expired state
 */
TEST(StateTest, TimeIndexInsertionByAddState) {
  auto quorum = 3u;
  auto time = iroha::time::now();

  auto state1 = MstState::empty(
      completer_, std::make_shared<StorageLimitDummy>(), mst_state_log_);
  state1 += addSignatures(makeTestBatch(txBuilder(1, time, quorum)),
                          0,
                          makeSignature("1_1", "1_1"));
  state1 += addSignatures(makeTestBatch(txBuilder(1, time, quorum)),
                          0,
                          makeSignature("1_2", "1_2"));

  auto state2 = MstState::empty(
      completer_, std::make_shared<StorageLimitDummy>(), mst_state_log_);
  state2 += addSignatures(
      makeTestBatch(txBuilder(2, time)), 0, makeSignature("2", "2"));
  state2 += addSignatures(
      makeTestBatch(txBuilder(3, time)), 0, makeSignature("3", "3"));

  auto final_state = state1 += state2;
  ASSERT_EQ(0, final_state.completed_state_.size());
  ASSERT_EQ(2, final_state.updated_state_->batchesQuantity());
}

/**
 * @given a state with two batches
 * AND    an empty state
 * @when  the second state is removed from the first state
 * AND  erase by time is called
 * @then checks that the resulting state does not contain any transactions
 */
TEST(StateTest, RemovingTestWhenByTimeHasExpired) {
  auto time = iroha::time::now();

  auto state1 = MstState::empty(
      completer_, std::make_shared<StorageLimitDummy>(), mst_state_log_);
  state1 += addSignatures(
      makeTestBatch(txBuilder(1, time)), 0, makeSignature("2", "2"));
  state1 += addSignatures(
      makeTestBatch(txBuilder(2, time)), 0, makeSignature("2", "2"));

  auto state2 = MstState::empty(
      completer_, std::make_shared<StorageLimitDummy>(), mst_state_log_);
  auto diff_state = state1 - state2;

  ASSERT_EQ(2, diff_state.batchesQuantity());
}

/**
 * @given empty state
 * @when  insert the batches until the transaction limit is reached
 * @and  sometimes trying to insert more than allowed
 * @then  the transaction limit is not exceeded
 */
TEST(StateTest, TxsLimit) {
  const size_t kMstStateTxLimit{10};
  auto state = MstState::empty(
      completer_,
      std::make_shared<BatchStorageLimitByTxs>(kMstStateTxLimit),
      mst_state_log_);

  auto gen_additional_state = [](size_t first_tx_num, auto... tx_builders) {
    auto sign_batch = [first_tx_num](auto &&batch) {
      const auto n_txs = boost::size(batch->transactions());
      for (size_t tx_num = 0; tx_num < n_txs; ++tx_num) {
        std::string key_str = std::to_string(first_tx_num + tx_num);
        auto sig = makeSignature(key_str, key_str);
        batch->addSignature(tx_num, sig.first, sig.second);
      }
      return std::move(batch);
    };

    auto additional_state = MstState::empty(
        completer_, std::make_shared<StorageLimitDummy>(), mst_state_log_);
    additional_state += sign_batch(makeTestBatch(tx_builders...));
    EXPECT_EQ(additional_state.transactionsQuantity(), sizeof...(tx_builders));
    return additional_state;
  };

  auto try_insert = [&](auto... tx_builders) {
    const auto current_size = state.transactionsQuantity();
    const auto inserted_size = sizeof...(tx_builders);
    const auto expected_size = current_size + inserted_size <= kMstStateTxLimit
        ? current_size + inserted_size
        : current_size;
    state += gen_additional_state(current_size, tx_builders...);
    ASSERT_EQ(state.transactionsQuantity(), expected_size);
  };

  auto next_tx_builder = [] {
    static size_t counter = 0;
    return txBuilder(counter++);
  };

  try_insert(next_tx_builder(), next_tx_builder());                     // 0 + 2
  try_insert(next_tx_builder(), next_tx_builder(), next_tx_builder());  // 2 + 3
  try_insert(next_tx_builder(), next_tx_builder(), next_tx_builder());  // 5 + 3
  try_insert(next_tx_builder(), next_tx_builder(), next_tx_builder());  // 8 + 3
  try_insert(next_tx_builder());                                        // 8 + 1
  try_insert(next_tx_builder(), next_tx_builder());                     // 9 + 2
  try_insert(next_tx_builder());                                        // 9 + 1
  try_insert(next_tx_builder());  // 10 + 1
}
