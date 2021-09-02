/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include <memory>

#include "ametsuchi/impl/tx_presence_cache_impl.hpp"
#include "interfaces/common_objects/transaction_sequence_common.hpp"
#include "interfaces/iroha_internal/transaction_batch_factory_impl.hpp"
#include "interfaces/iroha_internal/transaction_batch_impl.hpp"
#include "module/irohad/ametsuchi/mock_block_query.hpp"
#include "module/irohad/ametsuchi/mock_storage.hpp"
#include "module/shared_model/interface/mock_transaction_batch_factory.hpp"
#include "module/shared_model/interface_mocks.hpp"

using namespace iroha::ametsuchi;
using namespace testing;

/**
 * Fixture for non-typed tests (TEST_F)
 */
class TxPresenceCacheTest : public ::testing::Test {
 protected:
  void SetUp() override {
    mock_storage = std::make_shared<MockStorage>();
    mock_block_query = std::make_shared<MockBlockQuery>();
    EXPECT_CALL(*mock_storage, getBlockQuery())
        .WillRepeatedly(Return(mock_block_query));
  }

 public:
  std::shared_ptr<MockStorage> mock_storage;
  std::shared_ptr<MockBlockQuery> mock_block_query;
};

/**
 * Fixture for typed tests (TYPED_TEST)
 */
template <typename T>
class TxPresenceCacheTemplateTest : public TxPresenceCacheTest {};

using CacheStatusTypes = ::testing::Types<tx_cache_status_responses::Missing,
                                          tx_cache_status_responses::Rejected,
                                          tx_cache_status_responses::Committed>;
TYPED_TEST_SUITE(TxPresenceCacheTemplateTest, CacheStatusTypes, );

/**
 * @given hash which has a {Missing, Rejected, Committed} status in storage
 * @when cache asked for hash status
 * @then cache returns {Missing, Rejected, Committed} status
 */
TYPED_TEST(TxPresenceCacheTemplateTest, StatusHashTest) {
  shared_model::crypto::Hash hash("1");
  EXPECT_CALL(*this->mock_block_query, checkTxPresence(hash))
      .WillOnce(Return(std::make_optional<TxCacheStatusType>(TypeParam(hash))));
  auto cache = std::make_unique<TxPresenceCacheImpl>(this->mock_storage);
  TypeParam check_result;
  ASSERT_NO_THROW(check_result = std::get<TypeParam>(*cache->check(hash)));
  ASSERT_EQ(hash, check_result.hash);
}

/**
 * @given storage which cannot create block query
 * @when cache asked for hash status
 * @then cache returns null
 */
TEST_F(TxPresenceCacheTest, BadStorage) {
  EXPECT_CALL(*mock_storage, getBlockQuery()).WillRepeatedly(Return(nullptr));
  shared_model::crypto::Hash hash("1");
  auto cache = std::make_unique<TxPresenceCacheImpl>(mock_storage);
  ASSERT_FALSE(cache->check(hash));
}

/**
 * @given hash which has a Missing and then Committed status in storage
 * @when cache asked for hash status
 * @then cache returns Missing and then Committed status
 */
TEST_F(TxPresenceCacheTest, MissingThenCommittedHashTest) {
  shared_model::crypto::Hash hash("1");
  EXPECT_CALL(*mock_block_query, checkTxPresence(hash))
      .WillOnce(Return(std::make_optional<TxCacheStatusType>(
          tx_cache_status_responses::Missing(hash))));
  auto cache = std::make_unique<TxPresenceCacheImpl>(mock_storage);
  tx_cache_status_responses::Missing check_missing_result;
  ASSERT_NO_THROW(
      check_missing_result =
          std::get<tx_cache_status_responses::Missing>(*cache->check(hash)));
  ASSERT_EQ(hash, check_missing_result.hash);
  EXPECT_CALL(*mock_block_query, checkTxPresence(hash))
      .WillOnce(Return(std::make_optional<TxCacheStatusType>(
          tx_cache_status_responses::Committed(hash))));
  tx_cache_status_responses::Committed check_committed_result;
  ASSERT_NO_THROW(
      check_committed_result =
          std::get<tx_cache_status_responses::Committed>(*cache->check(hash)));
  ASSERT_EQ(hash, check_committed_result.hash);
}

/**
 * @given batch with 3 transactions: Rejected, Committed and Missing
 * @when cache asked for batch status
 * @then cache returns BatchStatusCollectionType with Rejected, Committed and
 * Missing statuses accordingly
 */
TEST_F(TxPresenceCacheTest, BatchHashTest) {
  shared_model::crypto::Hash hash1("1");
  shared_model::crypto::Hash reduced_hash_1("r1");

  shared_model::crypto::Hash hash2("2");
  shared_model::crypto::Hash reduced_hash_2("r2");

  shared_model::crypto::Hash hash3("3");
  shared_model::crypto::Hash reduced_hash_3("r3");

  EXPECT_CALL(*mock_block_query, checkTxPresence(hash1))
      .WillOnce(Return(std::make_optional<TxCacheStatusType>(
          tx_cache_status_responses::Rejected(hash1))));
  EXPECT_CALL(*mock_block_query, checkTxPresence(hash2))
      .WillOnce(Return(std::make_optional<TxCacheStatusType>(
          tx_cache_status_responses::Committed(hash2))));
  EXPECT_CALL(*mock_block_query, checkTxPresence(hash3))
      .WillOnce(Return(std::make_optional<TxCacheStatusType>(
          tx_cache_status_responses::Missing(hash3))));
  auto tx1 = std::make_shared<MockTransaction>();
  EXPECT_CALL(*tx1, hash()).WillOnce(ReturnRefOfCopy(hash1));
  EXPECT_CALL(*tx1, reducedHash()).WillOnce(ReturnRefOfCopy(reduced_hash_1));
  auto tx2 = std::make_shared<MockTransaction>();
  EXPECT_CALL(*tx2, hash()).WillOnce(ReturnRefOfCopy(hash2));
  EXPECT_CALL(*tx2, reducedHash()).WillOnce(ReturnRefOfCopy(reduced_hash_2));
  auto tx3 = std::make_shared<MockTransaction>();
  EXPECT_CALL(*tx3, hash()).WillOnce(ReturnRefOfCopy(hash3));
  EXPECT_CALL(*tx3, reducedHash()).WillOnce(ReturnRefOfCopy(reduced_hash_3));

  shared_model::interface::types::SharedTxsCollectionType txs{tx1, tx2, tx3};
  auto cache = std::make_unique<TxPresenceCacheImpl>(mock_storage);

  auto batch_factory = std::make_shared<MockTransactionBatchFactory>();
  EXPECT_CALL(*batch_factory, createTransactionBatch(txs))
      .WillOnce(Invoke(
          [&txs](
              const shared_model::interface::types::SharedTxsCollectionType &)
              -> shared_model::interface::TransactionBatchFactory::
                  FactoryResult<std::unique_ptr<
                      shared_model::interface::TransactionBatch>> {
                    return iroha::expected::makeValue<std::unique_ptr<
                        shared_model::interface::TransactionBatch>>(
                        std::make_unique<
                            shared_model::interface::TransactionBatchImpl>(
                            txs));
                  }));

  batch_factory->createTransactionBatch(txs).match(
      [&](const auto &batch) {
        auto batch_statuses = *cache->check(*batch.value);
        ASSERT_EQ(3, batch_statuses.size());
        tx_cache_status_responses::Rejected ts1;
        tx_cache_status_responses::Committed ts2;
        tx_cache_status_responses::Missing ts3;
        ASSERT_NO_THROW(ts1 = std::get<tx_cache_status_responses::Rejected>(
                            batch_statuses.at(0)));
        ASSERT_NO_THROW(ts2 = std::get<tx_cache_status_responses::Committed>(
                            batch_statuses.at(1)));
        ASSERT_NO_THROW(ts3 = std::get<tx_cache_status_responses::Missing>(
                            batch_statuses.at(2)));
        ASSERT_EQ(hash1, ts1.hash);
        ASSERT_EQ(hash2, ts2.hash);
        ASSERT_EQ(hash3, ts3.hash);
      },
      [&](const auto &error) { FAIL() << error.error; });
}
