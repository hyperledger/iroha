/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ordering/impl/on_demand_connection_manager.hpp"

#include <gtest/gtest.h>
#include <boost/range/combine.hpp>

#include "datetime/time.hpp"
#include "framework/test_logger.hpp"
#include "interfaces/iroha_internal/proposal.hpp"
#include "module/irohad/ordering/ordering_mocks.hpp"
#include "module/shared_model/interface_mocks.hpp"
#include "ordering/impl/on_demand_common.hpp"
#include "ordering/ordering_types.hpp"

using namespace iroha;
using namespace iroha::ordering;
using namespace iroha::ordering::transport;

using ::testing::ByMove;
using ::testing::Ref;
using ::testing::Return;
using ::testing::ReturnRefOfCopy;

/**
 * Create unique_ptr with MockOdOsNotification, save to var, and return it
 */
ACTION_P(CreateAndSave, var) {
  auto result = std::make_unique<MockOdOsNotification>();
  *var = result.get();
  return std::unique_ptr<OdOsNotification>(std::move(result));
}

struct OnDemandConnectionManagerTest : public ::testing::Test {
  void SetUp() override {
    factory = std::make_shared<MockOdOsNotificationFactory>();

    auto set = [this](size_t ix, auto &field, auto &ptr) {
      auto peer = std::make_shared<MockPeer>();
      EXPECT_CALL(*peer, pubkey())
          .WillRepeatedly(ReturnRefOfCopy(
              iroha::bytestringToHexstring(std::string(32, '0'))));
      EXPECT_CALL(*peer, address())
          .WillRepeatedly(testing::ReturnRefOfCopy(std::string{"address"}
                                                   + std::to_string(ix)));

      field = peer;
      EXPECT_CALL(*factory, create(Ref(*field)))
          .WillRepeatedly(CreateAndSave(&ptr));
    };

    size_t ix = 0;
    for (auto &&pair : boost::combine(cpeers.peers, connections)) {
      set(ix++, boost::get<0>(pair), boost::get<1>(pair));
    }

    std::vector<std::shared_ptr<shared_model::interface::Peer>> all_peers;
    for (auto const &p : cpeers.peers) all_peers.push_back(p);
    manager = std::make_shared<OnDemandConnectionManager>(
        factory, cpeers, all_peers, getTestLogger("OsConnectionManager"));
  }

  OnDemandConnectionManager::CurrentPeers cpeers;
  OnDemandConnectionManager::PeerCollectionType<MockOdOsNotification *>
      connections;

  std::shared_ptr<MockOdOsNotificationFactory> factory;
  std::shared_ptr<OnDemandConnectionManager> manager;
};

/**
 * @given OnDemandConnectionManager
 * @when peers observable is triggered
 * @then new peers are requested from factory
 */
TEST_F(OnDemandConnectionManagerTest, FactoryUsed) {
  for (auto &peer : connections) {
    ASSERT_NE(peer, nullptr);
  }
}

/**
 * @given initialized OnDemandConnectionManager
 * @when onBatches is called
 * @then peers get data for propagation
 */
TEST_F(OnDemandConnectionManagerTest, onBatches) {
  OdOsNotification::CollectionType collection;

  auto set_expect = [&](OnDemandConnectionManager::PeerType type) {
    EXPECT_CALL(*connections[type], onBatches(collection)).Times(1);
  };

  set_expect(OnDemandConnectionManager::kIssuer);
  set_expect(OnDemandConnectionManager::kRejectConsumer);
  set_expect(OnDemandConnectionManager::kCommitConsumer);

  manager->onBatches(collection);
}

/**
 * @given initialized OnDemandConnectionManager
 * @when onRequestProposal is called
 * @then peer is triggered
 */
TEST_F(OnDemandConnectionManagerTest, onRequestProposal) {
  consensus::Round round{};
  auto proposal = std::make_shared<const MockProposal>();
  auto p = std::make_optional(PackedProposalContainer{std::make_pair(
      std::shared_ptr<const shared_model::interface::Proposal>{proposal},
      ordering::BloomFilter256{})});

  EXPECT_CALL(*connections[OnDemandConnectionManager::kIssuer],
              onRequestProposal(round, p))
      .Times(1);

  manager->onRequestProposal(round, p);
}
