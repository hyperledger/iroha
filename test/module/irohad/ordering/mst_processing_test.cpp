/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>

#include "framework/crypto_literals.hpp"
#include "module/irohad/ordering/mst_test_helpers.hpp"
#include "ordering/impl/batches_cache.hpp"

using ::testing::ByMove;
using ::testing::Ref;
using ::testing::Return;
using ::testing::ReturnRefOfCopy;

struct MSTProcessingTest : public ::testing::Test {
  void SetUp() override {
    batches_cache_ = std::make_shared<iroha::ordering::BatchesCache>();
  }
  std::shared_ptr<iroha::ordering::BatchesCache> batches_cache_;
};

TEST_F(MSTProcessingTest, SimpleAdd) {
  auto batch = addSignaturesFromKeyPairs(
      makeTestBatch(txBuilder(1, iroha::time::now(), 1)), 0, makeKey());
  batches_cache_->insert(batch);
  ASSERT_EQ(batches_cache_->availableTxsCount(), 1);
}

TEST_F(MSTProcessingTest, SimpleUnsubscribedAdd) {
  auto batch = addSignaturesFromKeyPairs(
      makeTestBatch(txBuilder(1, iroha::time::now(), 2)), 0, makeKey());
  batches_cache_->insert(batch);
  ASSERT_EQ(batches_cache_->availableTxsCount(), 0);
}

TEST_F(MSTProcessingTest, SubscribedAdd) {
  auto first_signature = makeSignature("1"_hex_sig, "pub_key_1"_hex_pubkey);
  auto second_signature = makeSignature("2"_hex_sig, "pub_key_2"_hex_pubkey);
  auto base_tx = makeTestBatch(txBuilder(1, iroha::time::now(), 2));

  auto first_tx = addSignatures(base_tx, 0, first_signature);
  batches_cache_->insert(first_tx);
  ASSERT_EQ(batches_cache_->availableTxsCount(), 0);

  auto second_tx = addSignatures(base_tx, 0, second_signature);
  batches_cache_->insert(second_tx);
  ASSERT_EQ(batches_cache_->availableTxsCount(), 1);
}

TEST_F(MSTProcessingTest, SubscribeDifferentTx) {
  auto first_signature = makeSignature("1"_hex_sig, "pub_key_1"_hex_pubkey);
  auto second_signature = makeSignature("2"_hex_sig, "pub_key_2"_hex_pubkey);

  auto base_tx_1 = makeTestBatch(txBuilder(1, iroha::time::now(), 2));
  auto base_tx_2 = makeTestBatch(txBuilder(2, iroha::time::now(), 2));

  auto first_tx = addSignatures(base_tx_1, 0, first_signature);
  batches_cache_->insert(first_tx);
  ASSERT_EQ(batches_cache_->availableTxsCount(), 0);

  auto second_tx = addSignatures(base_tx_2, 0, second_signature);
  batches_cache_->insert(second_tx);
  ASSERT_EQ(batches_cache_->availableTxsCount(), 0);
}

TEST_F(MSTProcessingTest, NotFullySubscribed) {
  auto first_signature = makeSignature("1"_hex_sig, "pub_key_1"_hex_pubkey);
  auto second_signature = makeSignature("2"_hex_sig, "pub_key_2"_hex_pubkey);
  auto base_tx = makeTestBatch(txBuilder(1, iroha::time::now(), 2),
                               txBuilder(2, iroha::time::now(), 2));

  auto batch = addSignatures(
      addSignatures(base_tx, 0, first_signature, second_signature),
      1,
      first_signature);
  batches_cache_->insert(batch);
  ASSERT_EQ(batches_cache_->availableTxsCount(), 0);
}

TEST_F(MSTProcessingTest, FullySubscribed) {
  auto first_signature = makeSignature("1"_hex_sig, "pub_key_1"_hex_pubkey);
  auto second_signature = makeSignature("2"_hex_sig, "pub_key_2"_hex_pubkey);
  auto base_tx = makeTestBatch(txBuilder(1, iroha::time::now(), 2),
                               txBuilder(2, iroha::time::now(), 2));

  auto batch = addSignatures(
      addSignatures(base_tx, 0, first_signature, second_signature),
      1,
      first_signature);
  batches_cache_->insert(batch);
  ASSERT_EQ(batches_cache_->availableTxsCount(), 0);

  auto batch2 = addSignatures(base_tx, 1, second_signature);
  batches_cache_->insert(batch2);
  ASSERT_EQ(batches_cache_->availableTxsCount(), 2);
}

TEST_F(MSTProcessingTest, StepByStepSubscribed) {
  auto first_signature = makeSignature("1"_hex_sig, "pub_key_1"_hex_pubkey);
  auto second_signature = makeSignature("2"_hex_sig, "pub_key_2"_hex_pubkey);

  auto base_tx = [ts{iroha::time::now()}]() {
    return makeTestBatch(txBuilder(1, ts, 2), txBuilder(2, ts, 2));
  };

  batches_cache_->insert(addSignatures(base_tx(), 0, first_signature));
  ASSERT_EQ(batches_cache_->availableTxsCount(), 0);

  batches_cache_->insert(addSignatures(base_tx(), 1, second_signature));
  ASSERT_EQ(batches_cache_->availableTxsCount(), 0);

  batches_cache_->insert(addSignatures(base_tx(), 0, second_signature));
  ASSERT_EQ(batches_cache_->availableTxsCount(), 0);

  batches_cache_->insert(addSignatures(base_tx(), 1, first_signature));
  ASSERT_EQ(batches_cache_->availableTxsCount(), 2);
}

TEST_F(MSTProcessingTest, StepByStepSubscribed2) {
  auto base_tx = [ts{iroha::time::now()}]() {
    return makeTestBatch(txBuilder(1, ts, 3));
  };

  batches_cache_->insert(addSignaturesFromKeyPairs(base_tx(), 0, makeKey()));
  ASSERT_EQ(batches_cache_->availableTxsCount(), 0);

  batches_cache_->insert(addSignaturesFromKeyPairs(base_tx(), 0, makeKey()));
  ASSERT_EQ(batches_cache_->availableTxsCount(), 0);

  batches_cache_->insert(addSignaturesFromKeyPairs(base_tx(), 0, makeKey()));
  ASSERT_EQ(batches_cache_->availableTxsCount(), 1);
}

TEST_F(MSTProcessingTest, StepByStepNotSubscribed) {
  auto get_batch = [ts{iroha::time::now()}]() {
    return makeTestBatch(txBuilder(1, ts, 3), txBuilder(2, ts, 1));
  };

  batches_cache_->insert(addSignaturesFromKeyPairs(get_batch(), 1, makeKey()));
  ASSERT_EQ(batches_cache_->availableTxsCount(), 0);

  batches_cache_->insert(addSignaturesFromKeyPairs(get_batch(), 0, makeKey()));
  ASSERT_EQ(batches_cache_->availableTxsCount(), 0);

  batches_cache_->insert(addSignaturesFromKeyPairs(get_batch(), 0, makeKey()));
  ASSERT_EQ(batches_cache_->availableTxsCount(), 0);
}

TEST_F(MSTProcessingTest, DoublicateSignature) {
  auto get_batch = [ts{iroha::time::now()}]() {
    return makeTestBatch(txBuilder(1, ts, 2));
  };

  auto key = makeKey();

  batches_cache_->insert(addSignaturesFromKeyPairs(get_batch(), 0, key));
  ASSERT_EQ(batches_cache_->availableTxsCount(), 0);

  batches_cache_->insert(addSignaturesFromKeyPairs(get_batch(), 0, key));
  ASSERT_EQ(batches_cache_->availableTxsCount(), 0);
}

TEST_F(MSTProcessingTest, DoubleTxs) {
  auto get_batch = [ts{iroha::time::now()}]() {
    return makeTestBatch(txBuilder(1, ts, 2));
  };
  auto get_batch_2 = [ts{iroha::time::now()}]() {
    return makeTestBatch(txBuilder(1, ts, 1));
  };

  batches_cache_->insert(addSignaturesFromKeyPairs(get_batch(), 0, makeKey()));
  ASSERT_EQ(batches_cache_->availableTxsCount(), 0);

  batches_cache_->insert(addSignaturesFromKeyPairs(get_batch(), 0, makeKey()));
  ASSERT_EQ(batches_cache_->availableTxsCount(), 1);

  batches_cache_->insert(
      addSignaturesFromKeyPairs(get_batch_2(), 0, makeKey()));
  ASSERT_EQ(batches_cache_->availableTxsCount(), 2);
}
