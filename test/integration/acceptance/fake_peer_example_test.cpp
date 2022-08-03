/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/acceptance/fake_peer_fixture.hpp"

#include <rxcpp/operators/rx-observe_on.hpp>
#include "ametsuchi/block_query.hpp"
#include "ametsuchi/storage.hpp"
#include "consensus/yac/vote_message.hpp"
#include "consensus/yac/yac_hash_provider.hpp"
#include "framework/integration_framework/fake_peer/behaviour/honest.hpp"
#include "framework/integration_framework/fake_peer/block_storage.hpp"
#include "framework/integration_framework/iroha_instance.hpp"
#include "framework/integration_framework/test_irohad.hpp"
#include "framework/test_logger.hpp"
#include "main/subscription.hpp"
#include "module/shared_model/builders/protobuf/block.hpp"

using namespace common_constants;
using namespace shared_model;
using namespace integration_framework;
using namespace shared_model::interface::permissions;

using ::testing::_;
using ::testing::Invoke;

static constexpr std::chrono::seconds kMstStateWaitingTime(20);
static constexpr std::chrono::seconds kSynchronizerWaitingTime(20);

struct FakePeerExampleTest : FakePeerFixture {};
INSTANTIATE_TEST_SUITE_P_DifferentStorageTypes(FakePeerExampleTest);

/**
 * Check that Irohad loads correct block version when having a malicious fork on
 * the network.
 * @given a less then 1/3 of peers having a malicious fork of the ledger
 * @when the irohad needs to synchronize
 * @then it refuses the malicious fork and applies the valid one
 */
TEST_P(FakePeerExampleTest, SynchronizeTheRightVersionOfForkedLedger) {
  constexpr size_t num_bad_peers = 3;  ///< bad fake peers - the ones
                                       ///< creating a malicious fork
  // the real peer is added to the bad peers as they once are failing together
  constexpr size_t num_peers = (num_bad_peers + 1) * 3 + 1;  ///< BFT
  constexpr size_t num_fake_peers = num_peers - 1;  ///< one peer is real

  createFakePeers(num_fake_peers);
  auto &itf = prepareState();

  // let the first peers be bad
  const std::vector<std::shared_ptr<FakePeer>> bad_fake_peers(
      fake_peers_.begin(), fake_peers_.begin() + num_bad_peers);
  const std::vector<std::shared_ptr<FakePeer>> good_fake_peers(
      fake_peers_.begin() + num_bad_peers, fake_peers_.end());
  const std::shared_ptr<FakePeer> &rantipole_peer =
      bad_fake_peers.front();  // the malicious actor

  // Add two blocks to the ledger.
  itf.sendTxAwait(
      complete(baseTx(kAdminId).transferAsset(
                   kAdminId, kUserId, kAssetId, "common_tx1", "1.0"),
               kAdminKeypair),
      [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); });
  itf.sendTxAwait(
      complete(baseTx(kAdminId).transferAsset(
                   kAdminId, kUserId, kAssetId, "common_tx2", "2.0"),
               kAdminKeypair),
      [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); });

  // Create the valid branch, supported by the good fake peers:
  auto valid_block_storage =
      std::make_shared<fake_peer::BlockStorage>(getTestLogger("BlockStorage"));
  const auto block_query = itf.getBlockQuery();
  auto top_height = block_query->getTopBlockHeight();
  for (decltype(top_height) i = 1; i <= top_height; ++i) {
    auto block_result = block_query->getBlock(i);

    std::shared_ptr<shared_model::interface::Block> block =
        boost::get<decltype(block_result)::ValueType>(std::move(block_result))
            .value;
    valid_block_storage->storeBlock(
        std::static_pointer_cast<const shared_model::proto::Block>(block));
  }

  // From now the itf peer is considered unreachable from the rest network. //
  for (auto &fake_peer : fake_peers_) {
    fake_peer->setBehaviour(std::make_shared<fake_peer::EmptyBehaviour>());
  }

  // Function to sign a block with a peer's key.
  auto sign_block_by_peers = [](auto &&block, const auto &peers) {
    for (auto &peer : peers) {
      block.signAndAddSignature(peer->getKeypair());
    }
    return std::move(block);
  };

  // Function to create a block
  auto build_block =
      [](const auto &parent_block,
         std::initializer_list<shared_model::proto::Transaction> transactions) {
        return proto::BlockBuilder()
            .height(parent_block->height() + 1)
            .prevHash(parent_block->hash())
            .createdTime(iroha::time::now())
            .transactions(transactions)
            .build();
      };

  // Add a common block committed before fork but without the real peer:
  valid_block_storage->storeBlock(std::make_shared<shared_model::proto::Block>(
      sign_block_by_peers(
          build_block(
              valid_block_storage->getTopBlock(),
              {complete(baseTx(kAdminId).transferAsset(
                            kAdminId, kUserId, kAssetId, "valid_tx3", "3.0"),
                        kAdminKeypair)}),
          good_fake_peers)
          .finish()));

  // Create the malicious fork of the ledger:
  auto bad_block_storage =
      std::make_shared<fake_peer::BlockStorage>(*valid_block_storage);
  bad_block_storage->storeBlock(std::make_shared<shared_model::proto::Block>(
      sign_block_by_peers(
          build_block(
              valid_block_storage->getTopBlock(),
              {complete(baseTx(kAdminId).transferAsset(
                            kAdminId, kUserId, kAssetId, "bad_tx4", "300.0"),
                        kAdminKeypair)}),
          bad_fake_peers)
          .finish()));
  for (auto &bad_fake_peer : bad_fake_peers) {
    bad_fake_peer->setBlockStorage(bad_block_storage);
  }

  // Extend the valid ledger:
  valid_block_storage->storeBlock(std::make_shared<shared_model::proto::Block>(
      sign_block_by_peers(
          build_block(
              valid_block_storage->getTopBlock(),
              {complete(baseTx(kAdminId).transferAsset(
                            kAdminId, kUserId, kAssetId, "valid_tx4", "3.0"),
                        kAdminKeypair)}),
          good_fake_peers)
          .finish()));
  for (auto &good_fake_peer : good_fake_peers) {
    good_fake_peer->setBlockStorage(valid_block_storage);
  }

  // Create the new block that the good peers are about to commit now.
  auto new_valid_block = std::make_shared<shared_model::proto::Block>(
      sign_block_by_peers(
          build_block(
              valid_block_storage->getTopBlock(),
              {complete(baseTx(kAdminId).transferAsset(
                            kAdminId, kUserId, kAssetId, "valid_tx5", "4.0"),
                        kAdminKeypair)})
              .signAndAddSignature(rantipole_peer->getKeypair()),
          good_fake_peers)
          .finish());

  // From now the itf peer is considered reachable from the rest network. //
  for (auto &fake_peer : fake_peers_) {
    fake_peer->setBehaviour(std::make_shared<fake_peer::HonestBehaviour>());
  }

  // Suppose the rantipole peer created a valid Commit message for the tip of
  // the valid branch, containing its own vote in the beginning of the votes
  // list. So he forces the real peer to download the missing blocks from it.
  std::vector<iroha::consensus::yac::VoteMessage> valid_votes;
  valid_votes.reserve(good_fake_peers.size() + 1);
  const iroha::consensus::yac::YacHash good_yac_hash(
      iroha::consensus::Round(new_valid_block->height(), 0),
      new_valid_block->hash().hex(),
      new_valid_block->hash().hex());
  valid_votes.emplace_back(rantipole_peer->makeVote(good_yac_hash));
  std::transform(good_fake_peers.begin(),
                 good_fake_peers.end(),
                 std::back_inserter(valid_votes),
                 [&good_yac_hash](auto &good_fake_peer) {
                   return good_fake_peer->makeVote(good_yac_hash);
                 });
  rantipole_peer->sendYacState(valid_votes);

  // the good peers committed the block
  valid_block_storage->storeBlock(new_valid_block);

  // wait for the real peer to commit the blocks and check they are from the
  // valid branch
  iroha::utils::WaitForSingleObject completed;
  auto subscriber = iroha::SubscriberCreator<
      bool,
      std::shared_ptr<shared_model::interface::Block const>>::
      template create<iroha::EventTypes::kOnBlock>(
          static_cast<iroha::SubscriptionEngineHandlers>(
              iroha::getSubscription()->dispatcher()->kExecuteInPool),
          [&valid_block_storage,
           &completed,
           expected_height = valid_block_storage->getTopBlock()->height()](
              auto, auto block) {
            const auto valid_hash =
                valid_block_storage->getBlockByHeight(block->height())
                    ->hash()
                    .hex();
            const auto commited_hash = block->hash().hex();
            ASSERT_EQ(commited_hash, valid_hash)
                << "Wrong block got committed!";
            if (block->height() == expected_height) {
              completed.set();
            }
          });
  ASSERT_TRUE(completed.wait(kSynchronizerWaitingTime))
      << "Error waiting for synchronization";
}
