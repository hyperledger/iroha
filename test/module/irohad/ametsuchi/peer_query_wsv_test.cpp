/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/peer_query_wsv.hpp"

#include <gtest/gtest.h>
#include "backend/plain/peer.hpp"
#include "main/subscription.hpp"
#include "module/irohad/ametsuchi/mock_wsv_query.hpp"

class PeerQueryWSVTest : public ::testing::Test {
  std::shared_ptr<iroha::Subscription> se_ = iroha::getSubscription();
  void SetUp() override {
    wsv_query_ = std::make_shared<iroha::ametsuchi::MockWsvQuery>();
    peer_query_ = std::make_unique<iroha::ametsuchi::PeerQueryWsv>(wsv_query_);
  }

 protected:
  std::unique_ptr<iroha::ametsuchi::PeerQuery> peer_query_;
  std::shared_ptr<iroha::ametsuchi::MockWsvQuery> wsv_query_;
};

/**
 * @given storage with peer
 * @when trying to get all peers in the ledger
 * @then get a vector with all peers in the ledger
 */
TEST_F(PeerQueryWSVTest, GetPeers) {
  std::vector<std::shared_ptr<shared_model::interface::Peer>> peers;
  std::shared_ptr<shared_model::interface::Peer> peer1 =
      std::make_shared<shared_model::plain::Peer>(
          "some-address", "0A", std::nullopt);
  std::shared_ptr<shared_model::interface::Peer> peer2 =
      std::make_shared<shared_model::plain::Peer>(
          "another-address", "0B", std::nullopt);
  peers.push_back(peer1);
  peers.push_back(peer2);
  EXPECT_CALL(*wsv_query_, getPeers()).WillOnce(::testing::Return(peers));

  auto result = peer_query_->getLedgerPeers();
  ASSERT_TRUE(result);
  ASSERT_THAT(result.get(),
              testing::ElementsAreArray(peers.cbegin(), peers.cend()));
}
