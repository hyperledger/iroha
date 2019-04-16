/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "storage_shared_limit/batch_storage_limit_by_txs.hpp"
#include "storage_shared_limit/limitable_storage.hpp"
#include "storage_shared_limit/limited_storage.hpp"
#include "storage_shared_limit/storage_limit.hpp"

#include <gtest/gtest.h>
#include "module/irohad/multi_sig_transactions/mst_test_helpers.hpp"
#include "module/shared_model/interface_mocks.hpp"

using namespace iroha;
using namespace testing;

class StorageLimitTest : public ::testing::Test {
 protected:
  std::shared_ptr<shared_model::interface::Transaction> makeTx() {
    return clone(txBuilder(tx_counter_++).build());
  }

  std::shared_ptr<shared_model::interface::TransactionBatch> makeBatch(
      size_t num_txs) {
    shared_model::interface::types::SharedTxsCollectionType txs;
    std::generate_n(
        std::back_inserter(txs), num_txs, [this]() { return this->makeTx(); });
    return createMockBatchWithTransactions(txs, {});
  }

 private:
  size_t tx_counter_{0};
};

struct StorageImpl : public LimitableStorage<BatchPtr> {
  bool insert(BatchPtr batch) override {
    batches.emplace_back(std::move(batch));
    return true;
  }

  size_t transactionsQuantity() const {
    return std::accumulate(batches.begin(),
                           batches.end(),
                           0,
                           [](size_t sum, const BatchPtr &batch) {
                             return sum + batch->transactions().size();
                           });
  }

  std::vector<BatchPtr> batches;
};

template <typename Limit>
std::vector<std::shared_ptr<LimitedStorage<StorageImpl>>> generateStorages(
    std::shared_ptr<Limit> limit, size_t num_storages) {
  std::vector<std::shared_ptr<LimitedStorage<StorageImpl>>> storages;
  storages.reserve(num_storages);
  for (size_t i = 0; i < num_storages; ++i) {
    storages.emplace_back(std::make_shared<LimitedStorage<StorageImpl>>(
        limit, std::make_unique<StorageImpl>()));
  }
  return storages;
}

size_t getTransactionsQuantity(
    const std::shared_ptr<LimitedStorage<StorageImpl>> &storage) {
  return storage->access(
      [](const auto &storage) { return storage.transactionsQuantity(); });
}

/**
 * @given 5 storages with shared limit of 10 transactions
 * @when first a batch with 2 transactionsa batch with 2 transactions is
 * inserted to each storage, than a batch with single transactions is tried to
 * be inserted to each storage
 * @then first series of batches is inserted successfully and second is not
 */
TEST_F(StorageLimitTest, SharedLimitByTxs) {
  auto limit = std::make_shared<BatchStorageLimitByTxs>(10);
  auto storages = generateStorages(limit, 5);

  for (auto &storage : storages) {
    EXPECT_EQ(storage->itemsQuantity(), 0);
    EXPECT_EQ(getTransactionsQuantity(storage), 0);
    EXPECT_TRUE(storage->insert(makeBatch(2)));
    EXPECT_EQ(storage->itemsQuantity(), 1);
    EXPECT_EQ(getTransactionsQuantity(storage), 2);
  }

  EXPECT_EQ(limit->transactionsQuantity(), 10);

  for (auto &storage : storages) {
    EXPECT_FALSE(storage->insert(makeBatch(1)));
    EXPECT_EQ(storage->itemsQuantity(), 1);
    EXPECT_EQ(getTransactionsQuantity(storage), 2);
  }
}

/**
 * @given a storage with shared limit of 10 transactions
 * @when another storage is created using its limit and is filled with 10
 * transactions, then transactions are tried to be inserted to the first storage
 * @then batches are not inserted to the first storage because it would violate
 * the shared limit
 */
TEST_F(StorageLimitTest, SharedLimitAddStorage) {
  LimitedStorage<StorageImpl> storage1{
      std::make_shared<BatchStorageLimitByTxs>(10),
      std::make_unique<StorageImpl>()};
  LimitedStorage<StorageImpl> storage2{storage1.sharedLimit(),
                                       std::make_unique<StorageImpl>()};
  EXPECT_TRUE(storage2.insert(makeBatch(10)));
  EXPECT_FALSE(storage1.insert(makeBatch(1)));
}

/**
 * @given 2 storages with shared limit of 10 transactions filled to limit
 * @when a batch with 3 transactions is removed from the first one
 * @then the second can accept batches with up to 3 transactions in total
 */
TEST_F(StorageLimitTest, SharedLimitRemoveAndAdd) {
  auto limit = std::make_shared<BatchStorageLimitByTxs>(10);
  auto storages = generateStorages(limit, 2);
  EXPECT_TRUE(storages[0]->insert(makeBatch(3)));
  EXPECT_TRUE(storages[0]->insert(makeBatch(3)));
  EXPECT_TRUE(storages[1]->insert(makeBatch(4)));
  EXPECT_EQ(limit->transactionsQuantity(), 10);

  storages[0]->extract([](auto &storage) {
    auto extracted_batch = std::move(*storage.batches.begin());
    storage.batches.erase(storage.batches.begin());
    return std::vector<BatchPtr>{extracted_batch};
  });
  EXPECT_EQ(storages[0]->itemsQuantity(), 1);
  EXPECT_EQ(getTransactionsQuantity(storages[0]), 3);
  EXPECT_EQ(limit->transactionsQuantity(), 7);

  EXPECT_TRUE(storages[1]->insert(makeBatch(1)));
  EXPECT_TRUE(storages[1]->insert(makeBatch(2)));
  EXPECT_FALSE(storages[1]->insert(makeBatch(1)));
  EXPECT_EQ(limit->transactionsQuantity(), 10);
}

/**
 * @given 2 storages with shared limit of 10 transactions filled to limit
 * @when a batch with 3 transactions is moved from the first one
 * @then both storages do not accept any new batches
 *      @and the second storage can accept the moved batch
 */
TEST_F(StorageLimitTest, SharedLimitMoveBatch) {
  auto limit = std::make_shared<BatchStorageLimitByTxs>(10);
  auto storages = generateStorages(limit, 2);
  EXPECT_TRUE(storages[0]->insert(makeBatch(3)));
  EXPECT_TRUE(storages[0]->insert(makeBatch(3)));
  EXPECT_TRUE(storages[1]->insert(makeBatch(4)));
  EXPECT_EQ(limit->transactionsQuantity(), 10);

  auto moved_batches = storages[0]->move([](auto &storage) {
    std::vector<BatchPtr> extracted_batches;
    extracted_batches.emplace_back(std::move(*storage.batches.begin()));
    storage.batches.erase(storage.batches.begin());
    return extracted_batches;
  });
  EXPECT_EQ(storages[0]->itemsQuantity(), 1);
  EXPECT_EQ(getTransactionsQuantity(storages[0]), 3);

  EXPECT_EQ(limit->transactionsQuantity(), 10);
  EXPECT_FALSE(storages[0]->insert(makeBatch(1)));
  EXPECT_FALSE(storages[1]->insert(makeBatch(1)));

  ASSERT_EQ(moved_batches.size(), 1);
  EXPECT_TRUE(storages[1]->insert(moved_batches.front()));
  EXPECT_EQ(storages[1]->itemsQuantity(), 2);
  EXPECT_EQ(getTransactionsQuantity(storages[1]), 7);

  EXPECT_FALSE(storages[0]->insert(makeBatch(1)));
  EXPECT_FALSE(storages[1]->insert(makeBatch(1)));
}

/**
 * @given 2 storages with shared limit of 10 transactions filled to limit
 * @when a batch with 3 transactions is moved from the first one and then is
 * destroyed without being inserted to any storage
 * @then both storages can accept new batches with up to 3 transactions in total
 */
TEST_F(StorageLimitTest, SharedLimitMovedBatchDestroyed) {
  auto limit = std::make_shared<BatchStorageLimitByTxs>(10);
  auto storages = generateStorages(limit, 2);
  EXPECT_TRUE(storages[0]->insert(makeBatch(3)));
  EXPECT_TRUE(storages[0]->insert(makeBatch(3)));
  EXPECT_TRUE(storages[1]->insert(makeBatch(4)));

  {
    auto moved_batches = storages[0]->move([](auto &storage) {
      std::vector<BatchPtr> extracted_batches;
      extracted_batches.emplace_back(std::move(*storage.batches.begin()));
      storage.batches.erase(storage.batches.begin());
      return extracted_batches;
    });
    EXPECT_EQ(moved_batches.size(), 1);

    EXPECT_EQ(limit->transactionsQuantity(), 10);
    EXPECT_FALSE(storages[0]->insert(makeBatch(1)));
    EXPECT_FALSE(storages[1]->insert(makeBatch(1)));
  }

  EXPECT_EQ(limit->transactionsQuantity(), 7);
  EXPECT_TRUE(storages[0]->insert(makeBatch(1)));
  EXPECT_TRUE(storages[1]->insert(makeBatch(2)));

  EXPECT_FALSE(storages[0]->insert(makeBatch(1)));
  EXPECT_FALSE(storages[1]->insert(makeBatch(1)));
}
