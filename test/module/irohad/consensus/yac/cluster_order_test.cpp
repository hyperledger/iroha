/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include "consensus/yac/cluster_order.hpp"

#include "module/irohad/consensus/yac/yac_test_util.hpp"

class ClusterOrderTest : public ::testing::Test {
 protected:
  void SetUp() override {
    p1 = iroha::consensus::yac::makePeer("1");
    p2 = iroha::consensus::yac::makePeer("2");
    peers_list = {p1, p2};
  }

  std::shared_ptr<shared_model::interface::Peer> p1;
  std::shared_ptr<shared_model::interface::Peer> p2;

  std::vector<std::shared_ptr<shared_model::interface::Peer>> peers_list;
  std::vector<std::shared_ptr<shared_model::interface::Peer>> empty_peers_list;
};

/**
 * @given nonempty peers list
 * @when cluster order is created
 * @then create function returns nonempty object
 */
TEST_F(ClusterOrderTest, GoodClusterOrderCreation) {
  auto order = iroha::consensus::yac::ClusterOrdering::create(peers_list);
  ASSERT_TRUE(order);
}

/**
 * @given empty peers list
 * @when cluster order is created
 * @then create function returns empty object
 */
TEST_F(ClusterOrderTest, BadClusterOrderCreation) {
  auto empty_order =
      iroha::consensus::yac::ClusterOrdering::create(empty_peers_list);
  ASSERT_FALSE(empty_order);
}

TEST_F(ClusterOrderTest, ClusterOrderOnNext) {
  auto order = iroha::consensus::yac::ClusterOrdering::create(peers_list);
  ASSERT_TRUE(order);
  ASSERT_EQ("1", order->currentLeader().address());
  ASSERT_EQ("2", order->switchToNext().currentLeader().address());
  ASSERT_EQ("1", order->switchToNext().currentLeader().address());
}
