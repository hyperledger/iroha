/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/acceptance/fake_peer_fixture.hpp"

#include <rxcpp/operators/rx-filter.hpp>
#include <rxcpp/operators/rx-observe_on.hpp>
#include <rxcpp/operators/rx-replay.hpp>
#include <rxcpp/operators/rx-take.hpp>
#include <rxcpp/operators/rx-timeout.hpp>
#include "ametsuchi/block_query.hpp"
#include "builders/protobuf/transaction.hpp"
#include "consensus/yac/vote_message.hpp"
#include "consensus/yac/yac_hash_provider.hpp"
#include "framework/integration_framework/fake_peer/behaviour/honest.hpp"
#include "framework/integration_framework/fake_peer/block_storage.hpp"
#include "framework/integration_framework/iroha_instance.hpp"
#include "framework/integration_framework/test_irohad.hpp"
#include "framework/test_logger.hpp"
#include "module/shared_model/builders/protobuf/block.hpp"
#include "ordering/impl/on_demand_common.cpp"

using namespace common_constants;
using namespace shared_model;
using namespace integration_framework;
using namespace shared_model::interface::permissions;

using interface::types::PublicKeyHexStringView;

static constexpr std::chrono::seconds kSynchronizerWaitingTime(20);

/**
 * @given a network of one real and one fake peers
 * @when fake peer is removed
 * @then the transaction is committed
 *    @and the ledger state after commit contains one peer,
 *    @and the WSV reports that there is one peer
 */
TEST_F(FakePeerFixture, FakePeerIsRemoved) {
  // ------------------------ GIVEN ------------------------
  // init the real peer with one fake peer in the genesis block
  createFakePeers(1);
  auto &itf = prepareState();
  const auto prepared_height = itf.getBlockQuery()->getTopBlockHeight();
  auto fake_peer = fake_peers_.front();

  // capture itf synchronization events
  auto itf_sync_events_observable = itf_->getPcsOnCommitObservable().replay();
  itf_sync_events_observable.connect();

  // ------------------------ WHEN -------------------------
  // send removePeer command
  itf.sendTxAwait(complete(baseTx(kAdminId).removePeer(PublicKeyHexStringView{
                               fake_peer->getKeypair().publicKey()}),
                           kAdminKeypair),
                  checkBlockHasNTxs<1>);

  // ------------------------ THEN -------------------------
  // check that ledger state contains one peer
  itf_sync_events_observable
      .filter([prepared_height](const auto &sync_event) {
        return sync_event.ledger_state->top_block_info.height > prepared_height;
      })
      .take(1)
      .timeout(kSynchronizerWaitingTime, rxcpp::observe_on_new_thread())
      .as_blocking()
      .subscribe(
          [&, itf_peer = itf_->getThisPeer()](const auto &sync_event) {
            EXPECT_THAT(sync_event.ledger_state->ledger_peers,
                        ::testing::UnorderedElementsAre(
                            makePeerPointeeMatcher(itf_peer)));
          },
          [](std::exception_ptr ep) {
            try {
              std::rethrow_exception(ep);
            } catch (const std::exception &e) {
              FAIL() << "Error waiting for synchronization: " << e.what();
            }
          });

  // query WSV peers
  auto opt_peers = itf.getIrohaInstance()
                       .getIrohaInstance()
                       ->getStorage()
                       ->createPeerQuery()
                       .value()
                       ->getLedgerPeers();

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
TEST_F(FakePeerFixture, RealPeerIsRemoved) {
  // ------------------------ GIVEN ------------------------
  // init the real peer with one fake peer in the genesis block
  createFakePeers(1);
  auto &itf = prepareState();
  const auto prepared_height = itf.getBlockQuery()->getTopBlockHeight();
  auto fake_peer = fake_peers_.front();

  // capture itf synchronization events
  auto itf_sync_events_observable = itf_->getPcsOnCommitObservable().replay();
  itf_sync_events_observable.connect();

  // ------------------------ WHEN -------------------------
  // send removePeer command
  itf.sendTxAwait(complete(baseTx(kAdminId).removePeer(PublicKeyHexStringView{
                               itf_->getThisPeer()->pubkey()}),
                           kAdminKeypair),
                  checkBlockHasNTxs<1>);

  // ------------------------ THEN -------------------------
  // check that ledger state contains one peer
  itf_sync_events_observable
      .filter([prepared_height](const auto &sync_event) {
        return sync_event.ledger_state->top_block_info.height > prepared_height;
      })
      .take(1)
      .timeout(kSynchronizerWaitingTime, rxcpp::observe_on_new_thread())
      .as_blocking()
      .subscribe(
          [&, fake_peer = fake_peer->getThisPeer()](const auto &sync_event) {
            EXPECT_THAT(sync_event.ledger_state->ledger_peers,
                        ::testing::UnorderedElementsAre(
                            makePeerPointeeMatcher(fake_peer)));
          },
          [](std::exception_ptr ep) {
            try {
              std::rethrow_exception(ep);
            } catch (const std::exception &e) {
              FAIL() << "Error waiting for synchronization: " << e.what();
            }
          });

  // query WSV peers
  auto opt_peers = itf.getIrohaInstance()
                       .getIrohaInstance()
                       ->getStorage()
                       ->createPeerQuery()
                       .value()
                       ->getLedgerPeers();

  // check only one peer is there
  ASSERT_TRUE(opt_peers);
  EXPECT_THAT(*opt_peers,
              ::testing::UnorderedElementsAre(
                  makePeerPointeeMatcher(fake_peer->getThisPeer())));
}
