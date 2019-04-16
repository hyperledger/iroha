/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/impl/supermajority_checker_bft.hpp"
#include "consensus/yac/storage/yac_proposal_storage.hpp"
#include "framework/test_subscriber.hpp"

#include "module/irohad/consensus/yac/yac_fixture.hpp"

using ::testing::_;
using ::testing::An;
using ::testing::AtLeast;
using ::testing::Return;

using namespace iroha::consensus::yac;
using namespace framework::test_subscriber;

/**
 * @given yac consensus with 4 peers
 * @when half of peers vote for one hash and the rest for another
 * @then commit does not happen, instead send_reject is triggered on transport
 */
TEST_F(YacTest, InvalidCaseWhenNotReceiveSupermajority) {
  const size_t N = 4; // number of peers
  auto my_peers = decltype(default_peers)(
      {default_peers.begin(), default_peers.begin() + N});
  ASSERT_EQ(N, my_peers.size());

  auto my_order = ClusterOrdering::create(my_peers);
  ASSERT_TRUE(my_order);

  initYac(my_order.value());

  EXPECT_CALL(*network, sendState(_, _)).Times(2 * N);

  EXPECT_CALL(*timer, deny()).Times(0);

  EXPECT_CALL(*crypto, verify(_)).WillRepeatedly(Return(true));

  YacHash hash1(iroha::consensus::Round{1, 1}, "proposal_hash", "block_hash");
  YacHash hash2(iroha::consensus::Round{1, 1}, "proposal_hash", "block_hash2");
  yac->vote(hash1, my_order.value());

  for (size_t i = 0; i < N / 2; ++i) {
    yac->onState({createVote(hash1, std::to_string(i))});
  };
  for (size_t i = N / 2; i < N; ++i) {
    yac->onState({createVote(hash2, std::to_string(i))});
  };
}

/**
 * @given yac consensus
 * @when 2 peers vote for one hash and 2 for another, but yac_crypto verify
 * always returns false
 * @then reject is not propagated
 */
TEST_F(YacTest, InvalidCaseWhenDoesNotVerify) {
  auto my_peers = decltype(default_peers)(
      {default_peers.begin(), default_peers.begin() + 4});
  ASSERT_EQ(4, my_peers.size());

  auto my_order = ClusterOrdering::create(my_peers);
  ASSERT_TRUE(my_order);

  initYac(my_order.value());

  EXPECT_CALL(*network, sendState(_, _)).Times(0);

  EXPECT_CALL(*timer, deny()).Times(0);

  EXPECT_CALL(*crypto, verify(_)).WillRepeatedly(Return(false));

  YacHash hash1(iroha::consensus::Round{1, 1}, "proposal_hash", "block_hash");
  YacHash hash2(iroha::consensus::Round{1, 1}, "proposal_hash", "block_hash2");

  for (auto i = 0; i < 2; ++i) {
    yac->onState({createVote(hash1, std::to_string(i))});
  };
  for (auto i = 2; i < 4; ++i) {
    yac->onState({createVote(hash2, std::to_string(i))});
  };
}

/**
 * @given yac consensus with 6 peers
 * @when on_reject happens due to enough peers vote for different hashes
 * and then when another peer votes for any hash, he directly receives
 * reject message, because on_reject already happened
 * @then reject message will be called in total 7 times (peers size + 1 who
 * receives reject directly)
 */
TEST_F(YacTest, ValidCaseWhenReceiveOnVoteAfterReject) {
  size_t peers_number = 6;
  auto my_peers = decltype(default_peers)(
      {default_peers.begin(), default_peers.begin() + peers_number});
  ASSERT_EQ(peers_number, my_peers.size());

  auto my_order = ClusterOrdering::create(my_peers);
  ASSERT_TRUE(my_order);

  initYac(my_order.value());

  EXPECT_CALL(*network, sendState(_, _))
      .Times(my_peers.size() + 1);  // $(peers.size()) sendings done during
                                    // multicast + 1 for single peer, who votes
                                    // after reject happened

  EXPECT_CALL(*timer, deny()).Times(1);

  EXPECT_CALL(*crypto, verify(_)).WillRepeatedly(Return(true));

  const auto makeYacHash = [](size_t i) {
    return YacHash(iroha::consensus::Round{1, 1},
                   "proposal_hash",
                   "block_hash" + std::to_string(i));
  };

  SupermajorityCheckerBft super_checker;
  std::vector<VoteMessage> votes;
  std::vector<PeersNumberType> vote_groups;
  for (size_t i = 0;
       super_checker.canHaveSupermajority(vote_groups, peers_number);
       ++i) {
    ASSERT_LT(i, peers_number) << "Reject must had already happened when "
                                  "all peers have voted for different hashes.";
    auto peer = my_order->getPeers().at(i);
    auto pubkey = shared_model::crypto::toBinaryString(peer->pubkey());
    votes.push_back(createVote(makeYacHash(i), pubkey));
    vote_groups.push_back({1});
  };

  for (const auto &vote : votes) {
    yac->onState({vote});
  }

  yac->onState(votes);
  auto peer = my_order->getPeers().back();
  auto pubkey = shared_model::crypto::toBinaryString(peer->pubkey());
  yac->onState({createVote(makeYacHash(peers_number), pubkey)});
}
