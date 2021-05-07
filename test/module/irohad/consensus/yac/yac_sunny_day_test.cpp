/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string>
#include <utility>

#include "consensus/yac/storage/yac_proposal_storage.hpp"

#include "module/irohad/consensus/yac/yac_fixture.hpp"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::Return;

using namespace iroha::consensus::yac;
using namespace std;

static constexpr size_t kRandomFixedNumber = 9;

/**
 * @given yac & 4 peers
 * @when the 3 peers send the yac votes for the same hash
 * @then sendState is called twice per peer
 * @and the round keeps open
 */
TEST_F(YacTest, ValidCaseWhenReceiveSupermajority) {
  auto my_peers = decltype(default_peers)(
      {default_peers.begin(), default_peers.begin() + 4});
  ASSERT_EQ(4, my_peers.size());

  auto my_order = ClusterOrdering::create(my_peers);
  ASSERT_TRUE(my_order);

  initYac(my_order.value());

  EXPECT_CALL(*crypto, verify(_)).WillRepeatedly(Return(true));

  YacHash my_hash(iroha::consensus::Round{1, 1}, "proposal_hash", "block_hash");

  {
    ::testing::InSequence seq;
    setNetworkOrderCheckerSingleVote(my_order.value(), my_hash, 2);
    setNetworkOrderCheckerYacState(my_order.value(),
                                   makeCommitMatcher(my_hash, 3));
  }

  yac->vote(my_hash, my_order.value());

  for (auto i = 0; i < 3; ++i) {
    auto peer = my_peers.at(i);
    auto pubkey =
        iroha::hexstringToBytestringResult(peer->pubkey()).assumeValue();
    yac->onState({createVote(my_hash, pubkey)});
  };
}

TEST_F(YacTest, ValidCaseWhenReceiveCommit) {
  auto my_peers = decltype(default_peers)(
      {default_peers.begin(), default_peers.begin() + 4});
  ASSERT_EQ(4, my_peers.size());

  auto my_order = ClusterOrdering::create(my_peers);
  ASSERT_TRUE(my_order);

  initYac(my_order.value());

  YacHash my_hash(iroha::consensus::Round{1, 1}, "proposal_hash", "block_hash");

  EXPECT_CALL(*crypto, verify(_)).WillRepeatedly(Return(true));

  setNetworkOrderCheckerSingleVote(
      my_order.value(), my_hash, kRandomFixedNumber);

  yac->vote(my_hash, my_order.value());

  auto votes = std::vector<VoteMessage>();

  for (auto i = 0; i < 4; ++i) {
    votes.push_back(createVote(my_hash, std::to_string(i)));
  };
  auto val = *yac->onState(votes);
  ASSERT_EQ(my_hash, boost::get<CommitMessage>(val).votes.at(0).hash);
}

/**
 * @given initialized YAC with empty state
 * @when vote for hash
 * AND receive commit for voted hash
 * AND receive second commit for voted hash
 * @then commit is emitted once
 */
TEST_F(YacTest, ValidCaseWhenReceiveCommitTwice) {
  auto my_peers = decltype(default_peers)(
      {default_peers.begin(), default_peers.begin() + 4});
  ASSERT_EQ(4, my_peers.size());

  auto my_order = ClusterOrdering::create(my_peers);
  ASSERT_TRUE(my_order);

  initYac(my_order.value());

  YacHash my_hash(iroha::consensus::Round{1, 1}, "proposal_hash", "block_hash");

  EXPECT_CALL(*crypto, verify(_)).WillRepeatedly(Return(true));

  setNetworkOrderCheckerSingleVote(
      my_order.value(), my_hash, kRandomFixedNumber);

  yac->vote(my_hash, my_order.value());

  auto votes = std::vector<VoteMessage>();

  // first commit
  for (auto i = 0; i < 3; ++i) {
    votes.push_back(createVote(my_hash, std::to_string(i)));
  };
  auto val = *yac->onState(votes);
  ASSERT_EQ(my_hash, boost::get<CommitMessage>(val).votes.at(0).hash);

  // second commit
  for (auto i = 1; i < 4; ++i) {
    votes.push_back(createVote(my_hash, std::to_string(i)));
  };
  ASSERT_FALSE(yac->onState(votes));
}

TEST_F(YacTest, ValidCaseWhenSoloConsensus) {
  auto my_peers = decltype(default_peers)({default_peers.at(0)});
  ASSERT_EQ(1, my_peers.size());

  auto my_order = ClusterOrdering::create(my_peers);
  ASSERT_TRUE(my_order);

  initYac(my_order.value());

  EXPECT_CALL(*crypto, verify(_)).Times(2).WillRepeatedly(Return(true));

  YacHash my_hash(iroha::consensus::Round{1, 1}, "proposal_hash", "block_hash");

  auto vote_message = createVote(my_hash, std::to_string(0));

  setNetworkOrderCheckerSingleVote(my_order.value(), my_hash, 2);

  yac->vote(my_hash, my_order.value());

  auto val = *yac->onState({vote_message});
  ASSERT_EQ(my_hash, boost::get<CommitMessage>(val).votes.at(0).hash);

  auto commit_message = CommitMessage({vote_message});

  ASSERT_FALSE(yac->onState(commit_message.votes));
}

/**
 * @given yac & 6 peers
 * @when first 5 peers' votes for the same hash are sent to the yac
 * @and after that the last peer's vote for the same hash is sent to yac
 * @then sendState is not called
 * @and round is closed
 * @and crypto verification is called once
 */
TEST_F(YacTest, ValidCaseWhenVoteAfterCommit) {
  auto my_peers = decltype(default_peers)(
      {default_peers.begin(), default_peers.begin() + 4});
  ASSERT_EQ(4, my_peers.size());

  auto my_order = ClusterOrdering::create(my_peers);
  ASSERT_TRUE(my_order);

  initYac(my_order.value());

  EXPECT_CALL(*network, sendState(_, _)).Times(0);

  EXPECT_CALL(*crypto, verify(_)).Times(1).WillRepeatedly(Return(true));

  YacHash my_hash(iroha::consensus::Round{1, 1}, "proposal_hash", "block_hash");

  std::vector<VoteMessage> votes;

  for (auto i = 0; i < 3; ++i) {
    votes.push_back(createVote(my_hash, std::to_string(i)));
  };
  yac->onState(votes);

  yac->vote(my_hash, my_order.value());
}
