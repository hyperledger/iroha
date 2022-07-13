/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>

#include "framework/crypto_literals.hpp"
#include "main/subscription.hpp"
#include "module/irohad/ordering/mst_test_helpers.hpp"
#include "ordering/impl/batches_cache.hpp"

using ::testing::ByMove;
using ::testing::Ref;
using ::testing::Return;
using ::testing::ReturnRefOfCopy;

struct MSTNotificationsTest : public ::testing::Test {
  using MstStateSubscriber = iroha::BaseSubscriber<
      bool,
      std::shared_ptr<shared_model::interface::TransactionBatch>>;
  std::shared_ptr<MstStateSubscriber> mst_state_update_;
  std::shared_ptr<MstStateSubscriber> mst_state_prepared_;
  std::shared_ptr<MstStateSubscriber> mst_state_expired_;

  std::vector<std::shared_ptr<shared_model::interface::TransactionBatch>>
      event_updated_, event_prepared_, event_expired_;

  void SetUp() override {
    manager_ = iroha::getSubscription();
    mst_state_update_ = iroha::SubscriberCreator<
        bool,
        std::shared_ptr<shared_model::interface::TransactionBatch>>::
        template create<iroha::EventTypes::kOnMstStateUpdate>(
            iroha::SubscriptionEngineHandlers::kNotifications,
            [&](auto &,
                std::shared_ptr<shared_model::interface::TransactionBatch>
                    batch) {
              ASSERT_TRUE(batch);
              event_updated_.push_back(batch);
            });
    mst_state_prepared_ = iroha::SubscriberCreator<
        bool,
        std::shared_ptr<shared_model::interface::TransactionBatch>>::
        template create<iroha::EventTypes::kOnMstPreparedBatches>(
            iroha::SubscriptionEngineHandlers::kNotifications,
            [&](auto &,
                std::shared_ptr<shared_model::interface::TransactionBatch>
                    batch) {
              ASSERT_TRUE(batch);
              event_prepared_.push_back(batch);
            });
    mst_state_expired_ = iroha::SubscriberCreator<
        bool,
        std::shared_ptr<shared_model::interface::TransactionBatch>>::
        template create<iroha::EventTypes::kOnMstExpiredBatches>(
            iroha::SubscriptionEngineHandlers::kNotifications,
            [&](auto &,
                std::shared_ptr<shared_model::interface::TransactionBatch>
                    batch) {
              ASSERT_TRUE(batch);
              event_expired_.push_back(batch);
            });
    batches_cache_ = std::make_shared<iroha::ordering::BatchesCache>();
  }

  void TearDown() override {
    mst_state_update_->unsubscribe();
    mst_state_prepared_->unsubscribe();
    mst_state_expired_->unsubscribe();

    manager_->dispose();
    manager_.reset();

    event_updated_.clear();
    event_prepared_.clear();
    event_expired_.clear();
  }

  void checkEvents(size_t prepared, size_t updated, size_t expired) {
    ASSERT_EQ(event_expired_.size(), expired);
    ASSERT_EQ(event_prepared_.size(), prepared);
    ASSERT_EQ(event_updated_.size(), updated);

    event_prepared_.clear();
    event_updated_.clear();
    event_expired_.clear();
  }

  std::shared_ptr<iroha::Subscription> manager_;
  std::shared_ptr<iroha::ordering::BatchesCache> batches_cache_;
};

TEST_F(MSTNotificationsTest, SimpleAdd) {
  auto batch = addSignaturesFromKeyPairs(
      makeTestBatch(txBuilder(1, iroha::time::now(), 1)), 0, makeKey());
  batches_cache_->insert(batch);
  checkEvents(1, 0, 0);
  ASSERT_EQ(batch, event_prepared_[0]);
}

TEST_F(MSTNotificationsTest, SimpleUnsubscribedAdd) {
  auto batch = addSignaturesFromKeyPairs(
      makeTestBatch(txBuilder(1, iroha::time::now(), 2)), 0, makeKey());
  batches_cache_->insert(batch);
  checkEvents(0, 1, 0);
  ASSERT_EQ(batch, event_updated_[0]);
}

TEST_F(MSTNotificationsTest, SubscribedAdd) {
  auto first_signature = makeSignature("1"_hex_sig, "pub_key_1"_hex_pubkey);
  auto second_signature = makeSignature("2"_hex_sig, "pub_key_2"_hex_pubkey);
  auto base_tx = makeTestBatch(txBuilder(1, iroha::time::now(), 2));

  auto first_tx = addSignatures(base_tx, 0, first_signature);
  batches_cache_->insert(first_tx);
  checkEvents(0, 1, 0);

  auto second_tx = addSignatures(base_tx, 0, second_signature);
  batches_cache_->insert(second_tx);
  checkEvents(1, 0, 0);
}

TEST_F(MSTNotificationsTest, SubscribeDifferentTx) {
  auto first_signature = makeSignature("1"_hex_sig, "pub_key_1"_hex_pubkey);
  auto second_signature = makeSignature("2"_hex_sig, "pub_key_2"_hex_pubkey);

  auto base_tx_1 = makeTestBatch(txBuilder(1, iroha::time::now(), 2));
  auto base_tx_2 = makeTestBatch(txBuilder(2, iroha::time::now(), 2));

  auto first_tx = addSignatures(base_tx_1, 0, first_signature);
  batches_cache_->insert(first_tx);
  checkEvents(0, 1, 0);

  auto second_tx = addSignatures(base_tx_2, 0, second_signature);
  batches_cache_->insert(second_tx);
  checkEvents(0, 1, 0);
}

TEST_F(MSTNotificationsTest, NotFullySubscribed) {
  auto first_signature = makeSignature("1"_hex_sig, "pub_key_1"_hex_pubkey);
  auto second_signature = makeSignature("2"_hex_sig, "pub_key_2"_hex_pubkey);
  auto base_tx = makeTestBatch(txBuilder(1, iroha::time::now(), 2),
                               txBuilder(2, iroha::time::now(), 2));

  auto batch = addSignatures(
      addSignatures(base_tx, 0, first_signature, second_signature),
      1,
      first_signature);
  batches_cache_->insert(batch);
  checkEvents(0, 1, 0);
}

TEST_F(MSTNotificationsTest, StepByStepSubscribed) {
  auto get_batch = [ts{iroha::time::now()}]() {
    return makeTestBatch(txBuilder(1, ts, 2), txBuilder(2, ts, 2));
  };

  batches_cache_->insert(addSignaturesFromKeyPairs(get_batch(), 0, makeKey()));
  checkEvents(0, 1, 0);

  batches_cache_->insert(addSignaturesFromKeyPairs(get_batch(), 1, makeKey()));
  checkEvents(0, 1, 0);

  batches_cache_->insert(addSignaturesFromKeyPairs(get_batch(), 0, makeKey()));
  checkEvents(0, 1, 0);

  batches_cache_->insert(addSignaturesFromKeyPairs(get_batch(), 1, makeKey()));
  checkEvents(1, 0, 0);
}

TEST_F(MSTNotificationsTest, StepByStepNotSubscribed) {
  auto get_batch = [ts{iroha::time::now()}]() {
    return makeTestBatch(txBuilder(1, ts, 3), txBuilder(2, ts, 1));
  };

  batches_cache_->insert(addSignaturesFromKeyPairs(get_batch(), 1, makeKey()));
  checkEvents(0, 1, 0);

  batches_cache_->insert(addSignaturesFromKeyPairs(get_batch(), 0, makeKey()));
  checkEvents(0, 1, 0);

  batches_cache_->insert(addSignaturesFromKeyPairs(get_batch(), 0, makeKey()));
  checkEvents(0, 1, 0);
}

TEST_F(MSTNotificationsTest, DoubleTxs) {
  auto get_batch = [ts{iroha::time::now()}]() {
    return makeTestBatch(txBuilder(1, ts, 2));
  };
  auto get_batch_2 = [ts{iroha::time::now()}]() {
    return makeTestBatch(txBuilder(1, ts, 1));
  };

  batches_cache_->insert(addSignaturesFromKeyPairs(get_batch(), 0, makeKey()));
  checkEvents(0, 1, 0);

  batches_cache_->insert(addSignaturesFromKeyPairs(get_batch(), 0, makeKey()));
  checkEvents(1, 0, 0);

  batches_cache_->insert(
      addSignaturesFromKeyPairs(get_batch_2(), 0, makeKey()));
  checkEvents(1, 0, 0);
}
