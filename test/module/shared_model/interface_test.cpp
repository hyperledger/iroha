/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "logger/logger.hpp"

#include "builders/protobuf/transaction.hpp"
#include "framework/test_logger.hpp"

class TransactionFixture : public ::testing::Test {
 public:
  TransactionFixture()
      : keypair(shared_model::crypto::DefaultCryptoAlgorithmType::
                    generateKeypair()),
        time(iroha::time::now()) {}

  shared_model::crypto::Keypair keypair;
  shared_model::interface::types::TimestampType time;

  logger::LoggerPtr log = getTestLogger("TransactionFixture");

  auto makeTx() {
    log->info("keypair = {}, timestemp = {}", keypair, time);
    return std::make_shared<shared_model::proto::Transaction>(
        shared_model::proto::TransactionBuilder()
            .createdTime(time)
            .creatorAccountId("user@test")
            .setAccountQuorum("user@test", 1u)
            .quorum(1)
            .build()
            .signAndAddSignature(keypair)
            .finish());
  }
};

/**
 * @given two same transactions
 * @when  nothing to do
 * @then  checks that transactions are the same
 */
TEST_F(TransactionFixture, checkEqualsOperatorObvious) {
  auto tx1 = makeTx();
  auto tx2 = makeTx();
  ASSERT_EQ(*tx1, *tx2);
}

/**
 * @given two same transactions
 * @when  add same signatures to them
 * @then  checks that transactions are the same
 */
TEST_F(TransactionFixture, checkEqualsOperatorSameOrder) {
  auto tx1 = makeTx();
  auto tx2 = makeTx();

  tx1->addSignature(shared_model::crypto::Signed("signed_blob"),
                    shared_model::crypto::PublicKey("pub_key"));
  tx2->addSignature(shared_model::crypto::Signed("signed_blob"),
                    shared_model::crypto::PublicKey("pub_key"));

  ASSERT_EQ(*tx1, *tx2);
}

/**
 * @given two same transactions
 * @when  add N signatures to first one and same but in reverse order to second
 * @then  checks that transactions are the same
 */
TEST_F(TransactionFixture, checkEqualsOperatorDifferentOrder) {
  auto tx1 = makeTx();
  auto tx2 = makeTx();

  auto N = 5;

  for (int i = 0; i < N; ++i) {
    tx1->addSignature(
        shared_model::crypto::Signed("signed_blob_" + std::to_string(i)),
        shared_model::crypto::PublicKey("pub_key_" + std::to_string(i)));
  }

  for (int i = N - 1; i >= 0; --i) {
    tx2->addSignature(
        shared_model::crypto::Signed("signed_blob_" + std::to_string(i)),
        shared_model::crypto::PublicKey("pub_key_" + std::to_string(i)));
  }

  ASSERT_EQ(*tx1, *tx2);
}
