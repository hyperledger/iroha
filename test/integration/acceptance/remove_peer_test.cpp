/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/acceptance/fake_peer_fixture.hpp"

#include "ametsuchi/block_query.hpp"
#include "ametsuchi/storage.hpp"
#include "builders/protobuf/transaction.hpp"
#include "consensus/yac/vote_message.hpp"
#include "consensus/yac/yac_hash_provider.hpp"
#include "framework/integration_framework/fake_peer/behaviour/honest.hpp"
#include "framework/integration_framework/fake_peer/block_storage.hpp"
#include "framework/integration_framework/iroha_instance.hpp"
#include "framework/integration_framework/test_irohad.hpp"
#include "framework/test_logger.hpp"
#include "main/subscription.hpp"
#include "module/shared_model/builders/protobuf/block.hpp"
#include "ordering/impl/on_demand_common.cpp"

using namespace common_constants;
using namespace shared_model;
using namespace integration_framework;
using namespace iroha;
using namespace shared_model::interface::permissions;

using interface::types::PublicKeyHexStringView;

static constexpr std::chrono::seconds kSynchronizerWaitingTime(20);

struct RemovePeerTest : FakePeerFixture {};
INSTANTIATE_TEST_SUITE_P_DifferentStorageTypes(RemovePeerTest);

/**
 * @given a network of one real and one fake peers
 * @when fake peer is removed
 * @then the transaction is committed
 *    @and the ledger state after commit contains one peer,
 *    @and the WSV reports that there is one peer
 */
TEST_P(RemovePeerTest, FakePeerIsRemoved) {
  // ------------------------ GIVEN ------------------------
  // init the real peer with one fake peer in the genesis block
  createFakePeers(1);
  auto &itf = prepareState();
  const auto prepared_height = itf.getBlockQuery()->getTopBlockHeight();
  auto fake_peer = fake_peers_.front();

  // capture itf synchronization events
  utils::WaitForSingleObject completed;
  auto subscriber =
      SubscriberCreator<bool, synchronizer::SynchronizationEvent>::
          template create<EventTypes::kOnSynchronization>(
              static_cast<SubscriptionEngineHandlers>(decltype(
                  getSubscription())::element_type::Dispatcher::kExecuteInPool),
              [prepared_height, &completed, itf_peer = itf_->getThisPeer()](
                  auto, auto sync_event) {
                if (sync_event.ledger_state->top_block_info.height
                    > prepared_height) {
                  EXPECT_THAT(sync_event.ledger_state->ledger_peers,
                              ::testing::UnorderedElementsAre(
                                  makePeerPointeeMatcher(itf_peer)));
                  completed.set();
                }
              });

  // ------------------------ WHEN -------------------------
  // send removePeer command
  itf.sendTxAwait(complete(baseTx(kAdminId).removePeer(PublicKeyHexStringView{
                               fake_peer->getKeypair().publicKey()}),
                           kAdminKeypair),
                  checkBlockHasNTxs<1>);

  // ------------------------ THEN -------------------------
  // check that ledger state contains one peer
  ASSERT_TRUE(completed.wait(kSynchronizerWaitingTime))
      << "Error waiting for synchronization";

  // query WSV peers
  auto opt_peers = itf.getIrohaInstance()
                       .getTestIrohad()
                       ->getStorage()
                       ->createPeerQuery()
                       .value()
                       ->getLedgerPeers(false);

  // check only one peer is there
  ASSERT_TRUE(opt_peers);
  EXPECT_THAT(*opt_peers,
              ::testing::UnorderedElementsAre(
                  makePeerPointeeMatcher(itf.getThisPeer())));
}

/**
 * @given a network of one real and one fake peers
 * @when real peer is removed
 * @then the transaction is committed
 *    @and the ledger state after commit contains one peer,
 *    @and the WSV reports that there is one peer
 */
TEST_P(RemovePeerTest, RealPeerIsRemoved) {
  // ------------------------ GIVEN ------------------------
  // init the real peer with one fake peer in the genesis block
  createFakePeers(1);
  auto &itf = prepareState();
  const auto prepared_height = itf.getBlockQuery()->getTopBlockHeight();
  auto fake_peer = fake_peers_.front();

  // capture itf synchronization events
  utils::WaitForSingleObject completed;
  auto subscriber =
      SubscriberCreator<bool, synchronizer::SynchronizationEvent>::
          template create<EventTypes::kOnSynchronization>(
              static_cast<SubscriptionEngineHandlers>(decltype(
                  getSubscription())::element_type::Dispatcher::kExecuteInPool),
              [prepared_height,
               &completed,
               fake_peer = fake_peer->getThisPeer()](auto, auto sync_event) {
                if (sync_event.ledger_state->top_block_info.height
                    > prepared_height) {
                  EXPECT_THAT(sync_event.ledger_state->ledger_peers,
                              ::testing::UnorderedElementsAre(
                                  makePeerPointeeMatcher(fake_peer)));
                  completed.set();
                }
              });

  // ------------------------ WHEN -------------------------
  // send removePeer command
  itf.sendTxAwait(complete(baseTx(kAdminId).removePeer(PublicKeyHexStringView{
                               itf_->getThisPeer()->pubkey()}),
                           kAdminKeypair),
                  checkBlockHasNTxs<1>);

  // ------------------------ THEN -------------------------
  // check that ledger state contains one peer
  ASSERT_TRUE(completed.wait(kSynchronizerWaitingTime))
      << "Error waiting for synchronization";

  // query WSV peers
  auto opt_peers = itf.getIrohaInstance()
                       .getTestIrohad()
                       ->getStorage()
                       ->createPeerQuery()
                       .value()
                       ->getLedgerPeers(false);

  // check only one peer is there
  ASSERT_TRUE(opt_peers);
  EXPECT_THAT(*opt_peers,
              ::testing::UnorderedElementsAre(
                  makePeerPointeeMatcher(fake_peer->getThisPeer())));
}
