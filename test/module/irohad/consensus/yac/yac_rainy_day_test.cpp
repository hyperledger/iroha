/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <cstddef>

#include "consensus/yac/impl/supermajority_checker_bft.hpp"
#include "consensus/yac/storage/yac_proposal_storage.hpp"

#include "module/irohad/consensus/yac/yac_fixture.hpp"

using ::testing::_;
using ::testing::Return;

using namespace iroha::consensus::yac;

static constexpr size_t kFixedRandomNumber = 9;

/**
 * @given yac consensus with 4 peers
 * @when half of peers vote for one hash and the rest for another
 * @then commit does not happen, instead send_reject is triggered on transport
 */
TEST_F(YacTest, InvalidCaseWhenNotReceiveSupermajority) {
  const size_t N = 4;  // number of peers
  auto my_peers = decltype(default_peers)(
      {default_peers.begin(), default_peers.begin() + N});
  ASSERT_EQ(N, my_peers.size());

  auto my_order = ClusterOrdering::create(my_peers);
  ASSERT_TRUE(my_order);

  initYac(my_order.value());

  EXPECT_CALL(*crypto, verify(_)).WillRepeatedly(Return(true));

  YacHash hash1(iroha::consensus::Round{1, 1}, "proposal_hash", "block_hash");
  YacHash hash2(iroha::consensus::Round{1, 1}, "proposal_hash", "block_hash2");

  {
    using namespace testing;
    InSequence seq;
    setNetworkOrderCheckerSingleVote(
        my_order.value(), AnyOf(hash1, hash2), kFixedRandomNumber);
    setNetworkOrderCheckerYacState(
        my_order.value(),
        UnorderedElementsAre(makeVoteMatcher(hash1),
                             makeVoteMatcher(hash1),
                             makeVoteMatcher(hash2),
                             makeVoteMatcher(hash2)));
  }

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

  EXPECT_CALL(*crypto, verify(_)).WillRepeatedly(Return(true));

  const auto makeYacHash = [](size_t i) {
    return YacHash(iroha::consensus::Round{1, 1},
                   "proposal_hash",
                   "block_hash" + std::to_string(i));
  };

  SupermajorityCheckerBft super_checker;
  std::vector<VoteMessage> votes;
  votes.reserve(peers_number);
  std::vector<testing::Matcher<const VoteMessage &>> vote_matchers;
  vote_matchers.reserve(peers_number);
  std::vector<PeersNumberType> vote_groups;
  vote_groups.reserve(peers_number);
  for (size_t i = 0;
       super_checker.canHaveSupermajority(vote_groups, peers_number);
       ++i) {
    ASSERT_LT(i, peers_number) << "Reject must had already happened when "
                                  "all peers have voted for different hashes.";
    auto peer = my_order->getPeers().at(i);
    auto pubkey =
        iroha::hexstringToBytestringResult(peer->pubkey()).assumeValue();
    votes.push_back(createVote(makeYacHash(i), pubkey));
    vote_matchers.push_back(makeVoteMatcher(votes.back().hash));
    vote_groups.push_back({1});
  };

  setNetworkOrderCheckerYacState(
      my_order.value(), ::testing::UnorderedElementsAreArray(vote_matchers));

  for (const auto &vote : votes) {
    yac->onState({vote});
  }

  yac->onState(votes);

  // yac goes into next reject round
  YacHash next_reject_hash(
      iroha::consensus::Round{1, 2}, "proposal_hash", "block_hash");

  setNetworkOrderCheckerSingleVote(
      my_order.value(), testing::AnyOf(next_reject_hash), kFixedRandomNumber);

  yac->processRoundSwitch(next_reject_hash.vote_round,
                          my_order->getPeers(),
                          shared_model::interface::types::PeerList{});
  yac->vote(next_reject_hash, my_order.value());

  // -- now yac receives a vote from another peer when we already have a reject

  auto peer = my_order->getPeers().back();
  auto pubkey =
      iroha::hexstringToBytestringResult(peer->pubkey()).assumeValue();
  const auto slowpoke_hash = makeYacHash(peers_number);

  EXPECT_CALL(*network,
              sendState(_, ::testing::UnorderedElementsAreArray(vote_matchers)))
      .Times(1);

  yac->onState({createVote(slowpoke_hash, pubkey)});
}
