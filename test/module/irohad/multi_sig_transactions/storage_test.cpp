/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include <memory>
#include "framework/test_logger.hpp"
#include "logger/logger.hpp"
#include "module/irohad/multi_sig_transactions/mst_test_helpers.hpp"
#include "multi_sig_transactions/storage/mst_storage_impl.hpp"

using namespace iroha;

auto log_ = getTestLogger("MstStorageTest");

class StorageTest : public testing::Test {
 public:
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
  const shared_model::interface::types::PublicKeyHexStringView absent_peer_key{
      std::string_view{"0A"}};

  const unsigned quorum = 3u;
  const shared_model::interface::types::TimestampType creation_time =
      iroha::time::now();
  std::shared_ptr<TestCompleter> completer_;
};

TEST_F(StorageTest, StorageWhenApplyOtherState) {
  using namespace std::literals;
  log_->info(
      "create state with default peers and other state => "
      "apply state");

  auto new_state = MstState::empty(getTestLogger("MstState"), completer_);
  new_state += makeTestBatch(txBuilder(5, creation_time));
  new_state += makeTestBatch(txBuilder(6, creation_time));
  new_state += makeTestBatch(txBuilder(7, creation_time));

  storage->apply(shared_model::interface::types::PublicKeyHexStringView{"0B"sv},
                 new_state);

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

/**
 * @given storage with a batch from peer A (quorum = 3, 1 signature)
 * @when the batch gets updated with a new signature from Torii
 * @then the diff for peer A has the new signature
 */
TEST_F(StorageTest, DiffStateContainsNewSignature) {
  using namespace testing;
  using namespace shared_model::interface;

  std::vector<shared_model::crypto::Keypair> keypairs;
  std::generate_n(std::back_inserter(keypairs), 2, [] {
    return shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair();
  });

  auto make_batch = [this] {
    return framework::batch::makeTestBatch(txBuilder(1, creation_time));
  };

  auto const reduced_hash = make_batch()->transactions().front()->reducedHash();
  shared_model::interface::types::PublicKeyHexStringView const peer_A_key{"OB"};

  // storage gets a batch from peer A with 1st signature
  {
    auto new_state = MstState::empty(getTestLogger("MstState"), completer_);
    new_state += addSignaturesFromKeyPairs(make_batch(), 0, keypairs[0]);

    storage->apply(peer_A_key, std::move(new_state));
  }

  // diff with peer A does not have this batch
  ASSERT_THAT(storage->getDiffState(peer_A_key, creation_time).getBatches(),
              Not(Contains(Pointee(
                  Property(&TransactionBatch::transactions,
                           Contains(Pointee(Property(&Transaction::reducedHash,
                                                     Eq(reduced_hash)))))))));

  // storage gets another signature for the batch from Torii
  storage->updateOwnState(
      addSignaturesFromKeyPairs(make_batch(), 0, keypairs[1]));

  // diff with peer A now has the batch with the signature that just came Torii
  EXPECT_THAT(storage->getDiffState(peer_A_key, creation_time).getBatches(),
              Contains(Pointee(Property(
                  &TransactionBatch::transactions,
                  ElementsAre(Pointee(AllOf(
                      Property(&Transaction::reducedHash, Eq(reduced_hash)),
                      Property(&Transaction::signatures,
                               Contains(Property(
                                   &Signature::publicKey,
                                   Eq(keypairs[1].publicKey().hex())))))))))));
}
