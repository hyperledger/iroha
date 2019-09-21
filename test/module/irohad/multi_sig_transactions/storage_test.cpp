/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include <memory>
#include "framework/batch_helper.hpp"
#include "framework/test_logger.hpp"
#include "logger/logger.hpp"
#include "module/irohad/multi_sig_transactions/mst_test_helpers.hpp"
#include "multi_sig_transactions/storage/mst_storage_impl.hpp"

using namespace iroha;
using namespace framework::batch;

auto log_ = getTestLogger("MstStorageTest");

class StorageTest : public testing::Test {
 public:
  StorageTest() : absent_peer_key("absent") {}

  void SetUp() override {
    completer_ = std::make_shared<TestCompleter>();
    storage = std::make_shared<MstStorageStateImpl>(
        completer_, getTestLogger("MstState"), getTestLogger("MstStorage"));
    fillOwnState();
  }

  void fillOwnState() {
    storage->updateOwnState(makeTestBatch(txBuilder(1, creation_time)));
    storage->updateOwnState(makeTestBatch(txBuilder(2, creation_time)));
    storage->updateOwnState(makeTestBatch(txBuilder(3, creation_time)));
  }

  std::shared_ptr<MstStorage> storage;
  const shared_model::crypto::PublicKey absent_peer_key;

  const unsigned quorum = 3u;
  const shared_model::interface::types::TimestampType creation_time =
      iroha::time::now();
  std::shared_ptr<TestCompleter> completer_;
};

TEST_F(StorageTest, StorageWhenApplyOtherState) {
  log_->info(
      "create state with default peers and other state => "
      "apply state");

  auto new_state = MstState::empty(getTestLogger("MstState"), completer_);
  new_state += makeTestBatch(txBuilder(5, creation_time));
  new_state += makeTestBatch(txBuilder(6, creation_time));
  new_state += makeTestBatch(txBuilder(7, creation_time));

  storage->apply(shared_model::crypto::PublicKey("another"), new_state);

  ASSERT_EQ(6,
            storage->getDiffState(absent_peer_key, creation_time)
                .getBatches()
                .size());
}

TEST_F(StorageTest, StorageInsertOtherState) {
  log_->info("init fixture state => get expired state");

  ASSERT_EQ(3,
            storage->extractExpiredTransactions(creation_time + 1)
                .getBatches()
                .size());
  ASSERT_EQ(0,
            storage->getDiffState(absent_peer_key, creation_time + 1)
                .getBatches()
                .size());
}

TEST_F(StorageTest, StorageWhenCreateValidDiff) {
  log_->info("insert transactions => check their presence");

  ASSERT_EQ(3,
            storage->getDiffState(absent_peer_key, creation_time)
                .getBatches()
                .size());
}

TEST_F(StorageTest, StorageWhenCreate) {
  log_->info(
      "insert transactions => wait until expiring => "
      " check their absence");

  auto expiration_time = creation_time + 1;

  ASSERT_EQ(0,
            storage->getDiffState(absent_peer_key, expiration_time)
                .getBatches()
                .size());
}

/**
 * @given storage with three batches
 * @when checking, if those batches belong to the storage
 * @then storage reports, that those batches are in it
 */
TEST_F(StorageTest, StorageFindsExistingBatch) {
  auto batch1 = makeTestBatch(txBuilder(1, creation_time));
  auto batch2 = makeTestBatch(txBuilder(2, creation_time));
  auto batch3 = makeTestBatch(txBuilder(3, creation_time));

  EXPECT_TRUE(storage->batchInStorage(batch1));
  EXPECT_TRUE(storage->batchInStorage(batch2));
  EXPECT_TRUE(storage->batchInStorage(batch3));
}

/**
 * @given storage with three batches @and one another batch not in the storage
 * @when checking, if the last batch belongs to the storage
 * @then storage reports, that this batch is not in it
 */
TEST_F(StorageTest, StorageDoesNotFindNonExistingBatch) {
  auto distinct_batch = makeTestBatch(txBuilder(4, creation_time));
  EXPECT_FALSE(storage->batchInStorage(distinct_batch));
}
