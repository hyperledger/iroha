/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/storage_impl.hpp"
#include "backend/protobuf/proto_proposal_factory.hpp"
#include "consensus/yac/vote_message.hpp"
#include "datetime/time.hpp"
#include "framework/integration_framework/fake_peer/behaviour/honest.hpp"
#include "framework/integration_framework/fake_peer/block_storage.hpp"
#include "framework/integration_framework/fake_peer/fake_peer.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "framework/test_logger.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"
#include "module/irohad/multi_sig_transactions/mst_mocks.hpp"
#include "module/shared_model/builders/protobuf/block.hpp"
#include "module/shared_model/validators/validators.hpp"

using namespace common_constants;
using namespace shared_model;
using namespace integration_framework;
using namespace shared_model::interface::permissions;

using ::testing::_;
using ::testing::Invoke;

static constexpr std::chrono::seconds kMstStateWaitingTime(20);
static constexpr std::chrono::seconds kSynchronizerWaitingTime(20);

class FakePeerExampleFixture : public AcceptanceFixture {
 public:
  using FakePeer = fake_peer::FakePeer;

  std::unique_ptr<IntegrationTestFramework> itf_;

  /**
   * Create honest fake iroha peers
   *
   * @param num_fake_peers - the amount of fake peers to create
   */
  void createFakePeers(size_t num_fake_peers) {
    fake_peers_ = itf_->addFakePeers(num_fake_peers);
  }

  /**
   * Prepare state of ledger:
   * - create account of target user
   * - add assets to admin
   *
   * @return reference to ITF
   */
  IntegrationTestFramework &prepareState() {
    itf_->setGenesisBlock(itf_->defaultBlock()).subscribeQueuesAndRun();

    // inside prepareState we can use lambda for such assert, since
    // prepare transactions are not going to fail
    auto block_with_tx = [](auto &block) {
      ASSERT_EQ(block->transactions().size(), 1);
    };

    auto permissions =
        interface::RolePermissionSet({Role::kReceive, Role::kTransfer});

    return itf_->sendTxAwait(makeUserWithPerms(permissions), block_with_tx)
        .sendTxAwait(
            complete(baseTx(kAdminId).addAssetQuantity(kAssetId, "20000.0"),
                     kAdminKeypair),
            block_with_tx);
  }

 protected:
  void SetUp() override {
    itf_ =
        std::make_unique<IntegrationTestFramework>(1, boost::none, true, true);
    itf_->initPipeline(kAdminKeypair);
  }

  std::vector<std::shared_ptr<FakePeer>> fake_peers_;
};

/**
 * Check that after sending a not fully signed transaction, an MST state
 * propagates to another peer
 * @given a not fully signed transaction
 * @when such transaction is sent to one of two iroha peers in the network
 * @then that peer propagates MST state to another peer
 */
TEST_F(FakePeerExampleFixture,
       MstStateOfTransactionWithoutAllSignaturesPropagtesToOtherPeer) {
  createFakePeers(1);
  auto &itf = prepareState();
  auto mst_states_observable =
      fake_peers_.front()->getMstStatesObservable().replay();
  mst_states_observable.connect();

  itf.sendTxWithoutValidation(complete(
      baseTx(kAdminId)
          .transferAsset(kAdminId, kUserId, kAssetId, "income", "500.0")
          .quorum(2),
      kAdminKeypair));

  mst_states_observable
      .timeout(kMstStateWaitingTime, rxcpp::observe_on_new_thread())
      .take(1)
      .as_blocking()
      .subscribe([](const auto &) {},
                 [](std::exception_ptr ep) {
                   try {
                     std::rethrow_exception(ep);
                   } catch (const std::exception &e) {
                     FAIL() << "Error waiting for MST state: " << e.what();
                   }
                 });
}

/**
 * Check that Irohad loads correct block version when having a malicious fork on
 * the network.
 * @given a less then 1/3 of peers having a malicious fork of the ledger
 * @when the irohad needs to synchronize
 * @then it refuses the malicious fork and applies the valid one
 */
TEST_F(FakePeerExampleFixture, SynchronizeTheRightVersionOfForkedLedger) {
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
  itf.sendTx(complete(baseTx(kAdminId).transferAsset(
                          kAdminId, kUserId, kAssetId, "common_tx1", "1.0"),
                      kAdminKeypair))
      .skipBlock();
  itf.sendTx(complete(baseTx(kAdminId).transferAsset(
                          kAdminId, kUserId, kAssetId, "common_tx2", "2.0"),
                      kAdminKeypair))
      .skipBlock();

  // Create the valid branch, supported by the good fake peers:
  auto valid_block_storage =
      std::make_shared<fake_peer::BlockStorage>(getTestLogger("BlockStorage"));
  for (const auto &block : itf.getIrohaInstance()
                               .getIrohaInstance()
                               ->getStorage()
                               ->getBlockQuery()
                               ->getBlocksFrom(1)) {
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

  // Create the malicious fork of the ledger:
  auto bad_block_storage =
      std::make_shared<fake_peer::BlockStorage>(*valid_block_storage);
  bad_block_storage->storeBlock(std::make_shared<shared_model::proto::Block>(
      sign_block_by_peers(
          build_block(
              valid_block_storage->getTopBlock(),
              {complete(baseTx(kAdminId).transferAsset(
                            kAdminId, kUserId, kAssetId, "bad_tx3", "300.0"),
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
                            kAdminId, kUserId, kAssetId, "valid_tx3", "3.0"),
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
                            kAdminId, kUserId, kAssetId, "valid_tx4", "4.0"),
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
  itf.getIrohaInstance()
      .getIrohaInstance()
      ->getStorage()
      ->on_commit()
      .tap([&valid_block_storage](
               const std::shared_ptr<const shared_model::interface::Block>
                   &committed_block) {
        const auto valid_hash =
            valid_block_storage->getBlockByHeight(committed_block->height())
                ->hash()
                .hex();
        const auto commited_hash = committed_block->hash().hex();
        ASSERT_EQ(commited_hash, valid_hash) << "Wrong block got committed!";
      })
      .filter([expected_height = valid_block_storage->getTopBlock()->height()](
                  const auto &committed_block) {
        return committed_block->height() == expected_height;
      })
      .take(1)
      .timeout(kSynchronizerWaitingTime, rxcpp::observe_on_new_thread())
      .as_blocking()
      .subscribe([](const auto &) {},
                 [](std::exception_ptr ep) {
                   try {
                     std::rethrow_exception(ep);
                   } catch (const std::exception &e) {
                     FAIL()
                         << "Error waiting for synchronization: " << e.what();
                   }
                 });
}

/**
 * Check that after receiving a valid command the ITF peer provides a proposal
 * containing it.
 *
 * \attention this code is nothing more but an example of Fake Peer usage
 *
 * @given a network of one real and one fake peers
 * @when fake peer provides a proposal with valid tx
 * @then the real peer must commit the transaction from that proposal
 */
TEST_F(FakePeerExampleFixture,
       OnDemandOrderingProposalAfterValidCommandReceived) {
  // Create the tx:
  const auto tx = complete(
      baseTx(kAdminId).transferAsset(kAdminId, kUserId, kAssetId, "tx1", "1.0"),
      kAdminKeypair);

  createFakePeers(1);

  auto &itf = prepareState();

  // provide the proposal
  fake_peers_.front()->getProposalStorage().addTransactions({clone(tx)});

  // watch the proposal requests to fake peer
  constexpr std::chrono::seconds kCommitWaitingTime(20);
  itf.getIrohaInstance()
      .getIrohaInstance()
      ->getStorage()
      ->on_commit()
      .flat_map([](const auto &block) {
        std::vector<shared_model::interface::types::HashType> hashes;
        hashes.reserve(boost::size(block->transactions()));
        for (const auto &tx : block->transactions()) {
          hashes.emplace_back(tx.reducedHash());
        }
        return rxcpp::observable<>::iterate(hashes);
      })
      .filter([my_hash = tx.reducedHash()](const auto &incoming_hash) {
        return incoming_hash == my_hash;
      })
      .take(1)
      .timeout(kCommitWaitingTime, rxcpp::observe_on_new_thread())
      .as_blocking()
      .subscribe([](const auto &) {},
                 [](std::exception_ptr ep) {
                   try {
                     std::rethrow_exception(ep);
                   } catch (const std::exception &e) {
                     FAIL() << "Error waiting for the commit: " << e.what();
                   }
                 });
}
