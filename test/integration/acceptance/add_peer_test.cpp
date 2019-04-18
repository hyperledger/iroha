/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "datetime/time.hpp"
#include "framework/integration_framework/fake_peer/fake_peer.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "framework/test_logger.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"
#include "main/server_runner.hpp"
#include "module/irohad/multi_sig_transactions/mst_mocks.hpp"
#include "module/shared_model/builders/protobuf/block.hpp"

using namespace common_constants;
using namespace shared_model;
using namespace integration_framework;
using namespace shared_model::interface::permissions;

static constexpr std::chrono::seconds kMstStateWaitingTime(20);

template <size_t N>
void checkBlockHasNTxs(const std::shared_ptr<const interface::Block> &block) {
  ASSERT_EQ(block->transactions().size(), N);
}

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

    auto permissions =
        interface::RolePermissionSet({Role::kReceive, Role::kTransfer});

    return itf_
        ->sendTxAwait(makeUserWithPerms(permissions), checkBlockHasNTxs<1>)
        .sendTxAwait(
            complete(baseTx(kAdminId).addAssetQuantity(kAssetId, "20000.0"),
                     kAdminKeypair),
            checkBlockHasNTxs<1>);
  }

 protected:
  void SetUp() override {
    itf_ =
        std::make_unique<IntegrationTestFramework>(1, boost::none, true, true);
    itf_->initPipeline(kAdminKeypair);
  }

  std::vector<std::shared_ptr<FakePeer>> fake_peers_;
};

auto makePeerPointeeMatcher(interface::types::AddressType address,
                            interface::types::PubkeyType pubkey) {
  return ::testing::Truly(
      [address = std::move(address),
       pubkey = std::move(pubkey)](std::shared_ptr<interface::Peer> peer) {
        return peer->address() == address and peer->pubkey() == pubkey;
      });
}

auto makePeerPointeeMatcher(std::shared_ptr<interface::Peer> peer) {
  return makePeerPointeeMatcher(peer->address(), peer->pubkey());
}

/**
 * @given a network of single peer
 * @when it receives a valid signed addPeer command
 * @then the transaction is committed
 *    @and the WSV reports that there are two peers: the initial and the added one
 */
TEST_F(FakePeerExampleFixture, CheckPeerIsAdded) {
  // init the real peer with no other peers in the genesis block
  auto &itf = prepareState();

  const std::string new_peer_address = "127.0.0.1:1234";
  const auto new_peer_pubkey =
      shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair()
          .publicKey();

  itf.sendTxAwait(
      complete(baseTx(kAdminId).addPeer(new_peer_address, new_peer_pubkey),
               kAdminKeypair),
      checkBlockHasNTxs<1>);

  auto opt_peers = itf.getIrohaInstance()
                       .getIrohaInstance()
                       ->getStorage()
                       ->createPeerQuery()
                       .value()
                       ->getLedgerPeers();

  ASSERT_TRUE(opt_peers);
  EXPECT_THAT(*opt_peers,
              ::testing::UnorderedElementsAre(
                  makePeerPointeeMatcher(itf.getThisPeer()),
                  makePeerPointeeMatcher(new_peer_address, new_peer_pubkey)));
}

/**
 * @given a network of single peer
 * @given
 * @when it receives a not fully signed transaction and then a new peer is added
 * @then the first peer propagates MST state to the newly added peer
 */
TEST_F(FakePeerExampleFixture, MstStatePropagtesToNewPeer) {
  // init the real peer with no other peers in the genesis block
  auto &itf = prepareState();

  // then create a fake peer
  auto new_peer = itf.addFakePeer(boost::none);
  auto mst_states_observable = new_peer->getMstStatesObservable().replay();
  mst_states_observable.connect();
  auto new_peer_server = new_peer->run();

  // and add it with addPeer
  itf.sendTxAwait(
      complete(baseTx(kAdminId).addPeer(new_peer->getAddress(),
                                        new_peer->getKeypair().publicKey()),
               kAdminKeypair),
      checkBlockHasNTxs<1>);

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

  new_peer_server->shutdown();
}
