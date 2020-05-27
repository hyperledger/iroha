/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "multi_sig_transactions/storage/mst_storage_impl.hpp"

#include <chrono>
#include <memory>

#include <gtest/gtest.h>
#include "framework/test_logger.hpp"
#include "logger/logger.hpp"
#include "module/irohad/multi_sig_transactions/mst_mocks.hpp"
#include "module/irohad/multi_sig_transactions/mst_test_helpers.hpp"

using namespace iroha;
using namespace std::chrono_literals;

static constexpr std::chrono::milliseconds kMstStalledThreshold(10);
static constexpr std::chrono::milliseconds kMstExpiredThreshold(1min);

auto log_ = getTestLogger("MstStorageTest");

class StorageTest : public testing::Test {
 public:
  StorageTest() : absent_peer_key("absent") {}

  void SetUp() override {
    completer_ = std::make_shared<TestCompleter>(
        std::chrono::duration_cast<std::chrono::minutes>(kMstExpiredThreshold));
    ON_CALL(*mock_time_provider_, getCurrentTime())
        .WillByDefault(::testing::Return(creation_time));
    EXPECT_CALL(*mock_time_provider_, getCurrentTime())
        .Times(::testing::AnyNumber());
    storage =
        std::make_shared<MstStorageStateImpl>(completer_,
                                              mock_time_provider_,
                                              kMstStalledThreshold,
                                              getTestLogger("MstState"),
                                              getTestLogger("MstStorage"));
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
  const std::shared_ptr<MockTimeProvider> mock_time_provider_ =
      std::make_shared<MockTimeProvider>();
  const shared_model::interface::types::TimestampType creation_time =
      iroha::time::now();
  std::shared_ptr<TestCompleter> completer_;
};

TEST_F(StorageTest, StorageWhenApplyOtherState) {
  log_->info(
      "create state with default peers and other state => "
      "apply state");

  {
    auto new_state = MstState::empty(getTestLogger("MstState"), completer_);
    new_state += makeTestBatch(txBuilder(5, creation_time));
    new_state += makeTestBatch(txBuilder(6, creation_time));
    new_state += makeTestBatch(txBuilder(7, creation_time));

    storage->apply(shared_model::crypto::PublicKey("another"),
                   std::move(new_state));
  }

  ASSERT_EQ(6, storage->getDiffState(absent_peer_key).getBatches().size());
}

TEST_F(StorageTest, StorageInsertOtherState) {
  log_->info("init fixture state => get expired state");

  EXPECT_CALL(*mock_time_provider_, getCurrentTime())
      .WillRepeatedly(
          ::testing::Return(creation_time + kMstExpiredThreshold / 1ms + 1));

  ASSERT_EQ(3, storage->extractExpiredTransactions().getBatches().size());
  ASSERT_EQ(0, storage->getDiffState(absent_peer_key).getBatches().size());
}

TEST_F(StorageTest, StorageWhenCreateValidDiff) {
  log_->info("insert transactions => check their presence");

  ASSERT_EQ(3, storage->getDiffState(absent_peer_key).getBatches().size());
}

TEST_F(StorageTest, StorageWhenCreate) {
  log_->info(
      "insert transactions => wait until expiring => "
      " check their absence");

  EXPECT_CALL(*mock_time_provider_, getCurrentTime())
      .WillRepeatedly(
          ::testing::Return(creation_time + kMstExpiredThreshold / 1ms + 1));

  ASSERT_EQ(0, storage->getDiffState(absent_peer_key).getBatches().size());
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

/**
 * @given storage with a batch from peer A (quorum = 3, 1 signature)
 * @when the batch gets updated with a new signature from Torii
 * @then the diff for peer A has the new signature
 */
TEST_F(StorageTest, ClearStalledPeerStatesTest) {
  using namespace testing;
  using namespace shared_model::interface;

  std::vector<shared_model::crypto::Keypair> keypairs;
  std::generate_n(std::back_inserter(keypairs), 2, [] {
    return shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair();
  });

  const auto batch =
      framework::batch::makeTestBatch(txBuilder(1, creation_time));

  const auto peerAKey = shared_model::crypto::PublicKey("A");

  // storage gets a batch from peer A with 1st signature
  {
    auto new_state = MstState::empty(getTestLogger("MstState"), completer_);
    new_state += addSignaturesFromKeyPairs(clone(*batch), 0, keypairs[0]);

    storage->apply(peerAKey, std::move(new_state));
  }

  // diff with peer A does not have this batch
  ASSERT_THAT(storage->getDiffState(peerAKey).getBatches(),
              Not(Contains(Pointee(Property(
                  &TransactionBatch::transactions,
                  Contains(Pointee(Property(
                      &Transaction::reducedHash,
                      Eq(batch->transactions().front()->reducedHash())))))))));

  // storage gets another signature for the batch from Torii
  storage->updateOwnState(
      addSignaturesFromKeyPairs(clone(*batch), 0, keypairs[1]));

  // diff with peer A now has the batch with the signature that just came Torii
  EXPECT_THAT(
      storage->getDiffState(peerAKey).getBatches(),
      Contains(Pointee(Property(
          &TransactionBatch::transactions,
          ElementsAre(Pointee(AllOf(
              Property(&Transaction::reducedHash,
                       Eq(batch->transactions().front()->reducedHash())),
              Property(&Transaction::signatures,
                       Contains(Property(&Signature::publicKey,
                                         Eq(keypairs[1].publicKey())))))))))));
}

/**
 * @given storage with two batches from peer A
 * @when time passes, clearStalledPeerStates is called
 * @then as the batches pass the stalling threshold, they appear in the diff
 * with peer A
 */
TEST_F(StorageTest, StalledBatchesTest) {
  const auto keypair =
      shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair();

  const auto batch1 = addSignaturesFromKeyPairs(
      framework::batch::makeTestBatch(txBuilder(100, creation_time)),
      0,
      keypair);
  const auto batch2 = addSignaturesFromKeyPairs(
      framework::batch::makeTestBatch(txBuilder(500, creation_time)),
      0,
      keypair);

  const auto has_batch = [](const auto &batch) {
    using namespace testing;
    using namespace shared_model::interface;
    std::vector<Matcher<std::shared_ptr<Transaction>>> tx_matchers;
    for (const auto &tx : batch->transactions()) {
      tx_matchers.emplace_back(
          Pointee(Property(&Transaction::reducedHash, Eq(tx->reducedHash()))));
    }
    return Property(&MstState::getBatches,
                    Contains(Pointee(Property(&TransactionBatch::transactions,
                                              ElementsAreArray(tx_matchers)))));
  };

  const auto peerAKey = shared_model::crypto::PublicKey("A");

  const auto stall_time_ms = kMstStalledThreshold / 1ms;

  // Timeline:
  const auto batch1_received_time = creation_time + 100;
  const auto batch2_received_time = batch1_received_time + stall_time_ms / 2;
  const auto batch1_stalled_time = batch1_received_time + stall_time_ms + 1;
  const auto batch2_stalled_time = batch2_received_time + stall_time_ms + 1;
  assert(batch2_stalled_time
         < batch1_received_time + kMstExpiredThreshold / 1ms);

  // storage gets batch1 from peer A
  {
    EXPECT_CALL(*mock_time_provider_, getCurrentTime())
        .WillRepeatedly(::testing::Return(batch1_received_time));
    auto new_state = MstState::empty(getTestLogger("MstState"), completer_);
    new_state += batch1;
    storage->apply(peerAKey, std::move(new_state));
  }

  // diff with peer A has none of the batches
  ASSERT_THAT(storage->getDiffState(peerAKey),
              ::testing::AllOf(::testing::Not(has_batch(batch1)),
                               ::testing::Not(has_batch(batch2))));

  // storage gets batch2 from peer A
  {
    EXPECT_CALL(*mock_time_provider_, getCurrentTime())
        .WillRepeatedly(::testing::Return(batch2_received_time));
    auto new_state = MstState::empty(getTestLogger("MstState"), completer_);
    new_state += batch2;
    storage->apply(peerAKey, std::move(new_state));
  }

  // diff with peer A still has none of the batches since no one has stalled yet
  ASSERT_THAT(storage->getDiffState(peerAKey),
              ::testing::AllOf(::testing::Not(has_batch(batch1)),
                               ::testing::Not(has_batch(batch2))));

  // storage gets cleaned after the older batch stalling threshold
  EXPECT_CALL(*mock_time_provider_, getCurrentTime())
      .WillRepeatedly(::testing::Return(batch1_stalled_time));
  storage->clearStalledPeerStates();

  // diff with peer A has the older batch
  EXPECT_THAT(
      storage->getDiffState(peerAKey),
      ::testing::AllOf(has_batch(batch1), ::testing::Not(has_batch(batch2))));

  // storage gets cleaned after the newer batch stalling threshold
  EXPECT_CALL(*mock_time_provider_, getCurrentTime())
      .WillRepeatedly(::testing::Return(batch2_stalled_time));
  storage->clearStalledPeerStates();

  // diff with peer A has both batches
  EXPECT_THAT(storage->getDiffState(peerAKey),
              ::testing::AllOf(has_batch(batch1), has_batch(batch2)));
}
