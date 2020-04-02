/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "logger/logger.hpp"

#include "builders/protobuf/transaction.hpp"
#include "framework/test_logger.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"
#include "module/shared_model/cryptography/make_default_crypto_signer.hpp"

class TransactionFixture : public ::testing::Test {
 public:
  TransactionFixture()
      : signer_(shared_model::crypto::makeDefaultSigner()),
        time(iroha::time::now()) {}

  std::shared_ptr<shared_model::crypto::CryptoSigner> signer_;
  shared_model::interface::types::TimestampType time;

  logger::LoggerPtr log = getTestLogger("TransactionFixture");

  auto makeTx() {
    log->info("signer = {}, timestemp = {}", *signer_, time);
    return std::make_shared<shared_model::proto::Transaction>(
        shared_model::proto::TransactionBuilder()
            .createdTime(time)
            .creatorAccountId("user@test")
            .setAccountQuorum("user@test", 1u)
            .quorum(1)
            .build()
            .signAndAddSignature(*signer_)
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
  using namespace std::literals;
  auto tx1 = makeTx();
  auto tx2 = makeTx();
  shared_model::interface::types::SignedHexStringView signature{"0A"sv};
  shared_model::interface::types::PublicKeyHexStringView public_key{"0B"sv};

  tx1->addSignature(signature, public_key);
  tx2->addSignature(signature, public_key);

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
    auto signature = "0A0" + std::to_string(i);
    auto public_key = "0B0" + std::to_string(i);

    tx1->addSignature(
        shared_model::interface::types::SignedHexStringView{signature},
        shared_model::interface::types::PublicKeyHexStringView{public_key});

    signature = "0A0" + std::to_string(N - 1 - i);
    public_key = "0B0" + std::to_string(N - 1 - i);

    tx2->addSignature(
        shared_model::interface::types::SignedHexStringView{signature},
        shared_model::interface::types::PublicKeyHexStringView{public_key});
  }

  ASSERT_EQ(*tx1, *tx2);
}
