/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include <boost/range/adaptor/indirected.hpp>
#include <chrono>
#include "datetime/time.hpp"
#include "module/shared_model/interface_mocks.hpp"
#include "multi_sig_transactions/state/mst_state.hpp"

using namespace iroha;
using namespace testing;

/**
 * @given batch with 3 transactions: first one with quorum 1 and 1 signature,
 * second one with quorum 2 and 2 signatures, third one with quorum 3 and 3
 * signatures
 * @when completer was called for the batch
 * @then batch is complete
 */
TEST(CompleterTest, BatchQuorumTestEnoughSignatures) {
  auto completer = std::make_shared<DefaultCompleter>(std::chrono::minutes(0));

  std::vector<std::shared_ptr<MockSignature>> sigs1{
      1, std::make_shared<MockSignature>()};
  std::vector<std::shared_ptr<MockSignature>> sigs2{
      2, std::make_shared<MockSignature>()};
  std::vector<std::shared_ptr<MockSignature>> sigs3{
      3, std::make_shared<MockSignature>()};

  auto tx1 = std::make_shared<MockTransaction>();
  EXPECT_CALL(*tx1, quorum()).WillOnce(Return(1));
  EXPECT_CALL(*tx1, signatures())
      .WillOnce(Return<shared_model::interface::types::SignatureRangeType>(
          sigs1 | boost::adaptors::indirected));

  auto tx2 = std::make_shared<MockTransaction>();
  EXPECT_CALL(*tx2, quorum()).WillOnce(Return(2));
  EXPECT_CALL(*tx2, signatures())
      .WillOnce(Return<shared_model::interface::types::SignatureRangeType>(
          sigs2 | boost::adaptors::indirected));

  auto tx3 = std::make_shared<MockTransaction>();
  EXPECT_CALL(*tx3, quorum()).WillOnce(Return(3));
  EXPECT_CALL(*tx3, signatures())
      .WillOnce(Return<shared_model::interface::types::SignatureRangeType>(
          sigs3 | boost::adaptors::indirected));

  auto batch = createMockBatchWithTransactions({tx1, tx2, tx3}, "");
  ASSERT_TRUE(completer->isCompleted(batch));
}

/**
 * @given batch with 3 transactions: first one with quorum 1 and 1 signature,
 * second one with quorum 2 and 1 signature, third one with quorum 3 and 3
 * signatures
 * @when completer was called for the batch
 * @then batch is not complete
 */
TEST(CompleterTest, BatchQuorumTestNotEnoughSignatures) {
  auto completer = std::make_shared<DefaultCompleter>(std::chrono::minutes(0));

  std::vector<std::shared_ptr<MockSignature>> sigs1{
      1, std::make_shared<MockSignature>()};
  std::vector<std::shared_ptr<MockSignature>> sigs2{
      1, std::make_shared<MockSignature>()};
  std::vector<std::shared_ptr<MockSignature>> sigs3{
      3, std::make_shared<MockSignature>()};

  auto tx1 = std::make_shared<MockTransaction>();
  EXPECT_CALL(*tx1, quorum()).WillOnce(Return(1));
  EXPECT_CALL(*tx1, signatures())
      .WillOnce(Return<shared_model::interface::types::SignatureRangeType>(
          sigs1 | boost::adaptors::indirected));

  auto tx2 = std::make_shared<MockTransaction>();
  EXPECT_CALL(*tx2, quorum()).WillOnce(Return(2));
  EXPECT_CALL(*tx2, signatures())
      .WillOnce(Return<shared_model::interface::types::SignatureRangeType>(
          sigs2 | boost::adaptors::indirected));

  auto tx3 = std::make_shared<MockTransaction>();
  EXPECT_CALL(*tx3, quorum()).Times(0);
  EXPECT_CALL(*tx3, signatures()).Times(0);

  auto batch = createMockBatchWithTransactions({tx1, tx2, tx3}, "");
  ASSERT_FALSE(completer->isCompleted(batch));
}

/**
 * @given batch with 3 transactions with now() creation time and completer
 * with 1 minute expiration time
 * @when completer with 2 minute gap was called for the batch
 * @then batch is expired
 */
TEST(CompleterTest, BatchExpirationTestExpired) {
  auto completer = std::make_shared<DefaultCompleter>(std::chrono::minutes(1));
  auto time = iroha::time::now();
  auto tx1 = std::make_shared<MockTransaction>();
  EXPECT_CALL(*tx1, createdTime()).WillRepeatedly(Return(time));
  auto tx2 = std::make_shared<MockTransaction>();
  EXPECT_CALL(*tx2, createdTime()).WillRepeatedly(Return(time));
  auto tx3 = std::make_shared<MockTransaction>();
  EXPECT_CALL(*tx3, createdTime()).WillRepeatedly(Return(time));
  auto batch = createMockBatchWithTransactions({tx1, tx2, tx3}, "");
  ASSERT_TRUE(completer->isExpired(
      batch, time + std::chrono::minutes(2) / std::chrono::milliseconds(1)));
}

/**
 * @given batch with 3 transactions: first one in 2 minutes from now,
 * second one in 3 minutes from now, third one in 4 minutes from now and
 * completer with 5 minute expiration time
 * @when completer without time gap was called for the batch
 * @then batch is not expired
 */
TEST(CompleterTest, BatchExpirationTestNoExpired) {
  auto completer = std::make_shared<DefaultCompleter>(std::chrono::minutes(5));
  auto time = iroha::time::now();
  auto tx1 = std::make_shared<MockTransaction>();
  EXPECT_CALL(*tx1, createdTime())
      .WillRepeatedly(Return(
          time + std::chrono::minutes(2) / std::chrono::milliseconds(1)));
  auto tx2 = std::make_shared<MockTransaction>();
  EXPECT_CALL(*tx2, createdTime())
      .WillRepeatedly(Return(
          time + std::chrono::minutes(3) / std::chrono::milliseconds(1)));
  auto tx3 = std::make_shared<MockTransaction>();
  EXPECT_CALL(*tx3, createdTime())
      .WillRepeatedly(Return(
          time + std::chrono::minutes(4) / std::chrono::milliseconds(1)));
  auto batch = createMockBatchWithTransactions({tx1, tx2, tx3}, "");
  ASSERT_FALSE(completer->isExpired(batch, time));
}
