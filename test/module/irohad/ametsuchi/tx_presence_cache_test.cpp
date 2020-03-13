/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include "ametsuchi/impl/tx_presence_cache_impl.hpp"
#include "cryptography/public_key.hpp"
#include "framework/crypto_dummies.hpp"
#include "interfaces/common_objects/transaction_sequence_common.hpp"
#include "interfaces/iroha_internal/transaction_batch_factory_impl.hpp"
#include "interfaces/iroha_internal/transaction_batch_impl.hpp"
#include "module/irohad/ametsuchi/mock_block_query.hpp"
#include "module/irohad/ametsuchi/mock_storage.hpp"
#include "module/shared_model/interface/mock_transaction_batch_factory.hpp"
#include "module/shared_model/interface_mocks.hpp"

using namespace iroha::ametsuchi;
using namespace testing;

static const shared_model::crypto::Hash kHash_1{iroha::createHash("1")};
static const shared_model::crypto::Hash kHash_2{iroha::createHash("2")};
static const shared_model::crypto::Hash kHash_3{iroha::createHash("3")};
static const shared_model::crypto::Hash kReducedHash_1{iroha::createHash("r1")};
static const shared_model::crypto::Hash kReducedHash_2{iroha::createHash("r2")};
static const shared_model::crypto::Hash kReducedHash_3{iroha::createHash("r3")};

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
TYPED_TEST_CASE(TxPresenceCacheTemplateTest, CacheStatusTypes, );

/**
 * @given hash which has a {Missing, Rejected, Committed} status in storage
 * @when cache asked for hash status
 * @then cache returns {Missing, Rejected, Committed} status
 */
TYPED_TEST(TxPresenceCacheTemplateTest, StatusHashTest) {
  EXPECT_CALL(*this->mock_block_query, checkTxPresence(kHash_1))
      .WillOnce(
          Return(std::make_optional<TxCacheStatusType>(TypeParam(kHash_1))));
  TxPresenceCacheImpl cache(this->mock_storage);
  TypeParam check_result{iroha::createHash()};
  ASSERT_NO_THROW(check_result = std::get<TypeParam>(*cache.check(kHash_1)));
  ASSERT_EQ(kHash_1, check_result.hash);
}

/**
 * @given storage which cannot create block query
 * @when cache asked for hash status
 * @then cache returns null
 */
TEST_F(TxPresenceCacheTest, BadStorage) {
  EXPECT_CALL(*mock_storage, getBlockQuery()).WillRepeatedly(Return(nullptr));
  TxPresenceCacheImpl cache(mock_storage);
  ASSERT_FALSE(cache.check(kHash_1));
}

/**
 * @given hash which has a Missing and then Committed status in storage
 * @when cache asked for hash status
 * @then cache returns Missing and then Committed status
 */
TEST_F(TxPresenceCacheTest, MissingThenCommittedHashTest) {
  EXPECT_CALL(*mock_block_query, checkTxPresence(kHash_1))
      .WillOnce(Return(std::make_optional<TxCacheStatusType>(
          tx_cache_status_responses::Missing(kHash_1))));
  TxPresenceCacheImpl cache(mock_storage);
  tx_cache_status_responses::Missing check_missing_result{iroha::createHash()};
  ASSERT_NO_THROW(
      check_missing_result =
          std::get<tx_cache_status_responses::Missing>(*cache.check(kHash_1)));
  ASSERT_EQ(kHash_1, check_missing_result.hash);
  EXPECT_CALL(*mock_block_query, checkTxPresence(kHash_1))
      .WillOnce(Return(std::make_optional<TxCacheStatusType>(
          tx_cache_status_responses::Committed(kHash_1))));
  tx_cache_status_responses::Committed check_committed_result{
      iroha::createHash()};
  ASSERT_NO_THROW(check_committed_result =
                      std::get<tx_cache_status_responses::Committed>(
                          *cache.check(kHash_1)));
  ASSERT_EQ(kHash_1, check_committed_result.hash);
}

/**
 * @given batch with 3 transactions: Rejected, Committed and Missing
 * @when cache asked for batch status
 * @then cache returns BatchStatusCollectionType with Rejected, Committed and
 * Missing statuses accordingly
 */
TEST_F(TxPresenceCacheTest, BatchHashTest) {
  EXPECT_CALL(*mock_block_query, checkTxPresence(kHash_1))
      .WillOnce(Return(std::make_optional<TxCacheStatusType>(
          tx_cache_status_responses::Rejected(kHash_1))));
  EXPECT_CALL(*mock_block_query, checkTxPresence(kHash_2))
      .WillOnce(Return(std::make_optional<TxCacheStatusType>(
          tx_cache_status_responses::Committed(kHash_2))));
  EXPECT_CALL(*mock_block_query, checkTxPresence(kHash_3))
      .WillOnce(Return(std::make_optional<TxCacheStatusType>(
          tx_cache_status_responses::Missing(kHash_3))));
  auto tx1 = std::make_shared<MockTransaction>();
  EXPECT_CALL(*tx1, hash()).WillOnce(ReturnRefOfCopy(kHash_1));
  EXPECT_CALL(*tx1, reducedHash()).WillOnce(ReturnRefOfCopy(kReducedHash_1));
  auto tx2 = std::make_shared<MockTransaction>();
  EXPECT_CALL(*tx2, hash()).WillOnce(ReturnRefOfCopy(kHash_2));
  EXPECT_CALL(*tx2, reducedHash()).WillOnce(ReturnRefOfCopy(kReducedHash_2));
  auto tx3 = std::make_shared<MockTransaction>();
  EXPECT_CALL(*tx3, hash()).WillOnce(ReturnRefOfCopy(kHash_3));
  EXPECT_CALL(*tx3, reducedHash()).WillOnce(ReturnRefOfCopy(kReducedHash_3));

  shared_model::interface::types::SharedTxsCollectionType txs{tx1, tx2, tx3};
  shared_model::interface::TransactionBatchImpl batch{std::move(txs)};

  TxPresenceCacheImpl cache(mock_storage);
  auto batch_statuses = *cache.check(batch);
  ASSERT_EQ(3, batch_statuses.size());
  tx_cache_status_responses::Rejected ts1{iroha::createHash()};
  tx_cache_status_responses::Committed ts2{iroha::createHash()};
  tx_cache_status_responses::Missing ts3{iroha::createHash()};
  ASSERT_NO_THROW(ts1 = std::get<tx_cache_status_responses::Rejected>(
                      batch_statuses.at(0)));
  ASSERT_NO_THROW(ts2 = std::get<tx_cache_status_responses::Committed>(
                      batch_statuses.at(1)));
  ASSERT_NO_THROW(
      ts3 = std::get<tx_cache_status_responses::Missing>(batch_statuses.at(2)));
  ASSERT_EQ(kHash_1, ts1.hash);
  ASSERT_EQ(kHash_2, ts2.hash);
  ASSERT_EQ(kHash_3, ts3.hash);
}
