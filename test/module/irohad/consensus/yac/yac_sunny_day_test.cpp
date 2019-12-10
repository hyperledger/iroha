/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string>
#include <utility>

#include "consensus/yac/storage/yac_proposal_storage.hpp"

#include "framework/test_subscriber.hpp"
#include "module/irohad/consensus/yac/yac_fixture.hpp"

using ::testing::_;
using ::testing::An;
using ::testing::AtLeast;
using ::testing::Return;

using namespace iroha::consensus::yac;
using namespace framework::test_subscriber;
using namespace std;

/**
 * @given yac & 6 peers
 * @when the 6 peers send the yac votes for the same hash
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

  EXPECT_CALL(*network, sendState(_, _)).Times(2 * my_peers.size());

  EXPECT_CALL(*timer, deny()).Times(0);

  EXPECT_CALL(*crypto, verify(_)).WillRepeatedly(Return(true));

  YacHash my_hash(iroha::consensus::Round{1, 1}, "proposal_hash", "block_hash");
  yac->vote(my_hash, my_order.value());

  for (auto i = 0; i < 3; ++i) {
    auto peer = my_peers.at(i);
    yac->onState({createVote(my_hash, peer->pubkey().blob())});
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
  auto wrapper = make_test_subscriber<CallExact>(yac->onOutcome(), 1);
  wrapper.subscribe([my_hash](auto val) {
    ASSERT_EQ(my_hash, boost::get<CommitMessage>(val).votes.at(0).hash);
  });

  EXPECT_CALL(*network, sendState(_, _)).Times(my_peers.size());

  EXPECT_CALL(*timer, deny()).Times(AtLeast(1));

  EXPECT_CALL(*crypto, verify(_)).WillRepeatedly(Return(true));

  yac->vote(my_hash, my_order.value());

  auto votes = std::vector<VoteMessage>();

  for (auto i = 0; i < 4; ++i) {
    votes.push_back(createVote(my_hash, std::to_string(i)));
  };
  yac->onState(votes);
  ASSERT_TRUE(wrapper.validate());
}

/**
 * @given initialized YAC with empty state
 * @when vote for hash
 * AND receive commit for voted hash
 * AND receive second commit for voted hash
 * @then commit is emitted once
 * AND timer is denied once
 */
TEST_F(YacTest, ValidCaseWhenReceiveCommitTwice) {
  auto my_peers = decltype(default_peers)(
      {default_peers.begin(), default_peers.begin() + 4});
  ASSERT_EQ(4, my_peers.size());

  auto my_order = ClusterOrdering::create(my_peers);
  ASSERT_TRUE(my_order);

  EXPECT_CALL(*timer, deny()).Times(1);

  initYac(my_order.value());

  YacHash my_hash(iroha::consensus::Round{1, 1}, "proposal_hash", "block_hash");
  auto wrapper = make_test_subscriber<CallExact>(yac->onOutcome(), 1);
  wrapper.subscribe([my_hash](auto val) {
    ASSERT_EQ(my_hash, boost::get<CommitMessage>(val).votes.at(0).hash);
  });

  EXPECT_CALL(*network, sendState(_, _)).Times(my_peers.size());

  EXPECT_CALL(*crypto, verify(_)).WillRepeatedly(Return(true));

  yac->vote(my_hash, my_order.value());

  auto votes = std::vector<VoteMessage>();

  // first commit
  for (auto i = 0; i < 3; ++i) {
    votes.push_back(createVote(my_hash, std::to_string(i)));
  };
  yac->onState(votes);

  // second commit
  for (auto i = 1; i < 4; ++i) {
    votes.push_back(createVote(my_hash, std::to_string(i)));
  };
  yac->onState(votes);

  ASSERT_TRUE(wrapper.validate());
}

TEST_F(YacTest, ValidCaseWhenSoloConsensus) {
  auto my_peers = decltype(default_peers)({default_peers.at(0)});
  ASSERT_EQ(1, my_peers.size());

  auto my_order = ClusterOrdering::create(my_peers);
  ASSERT_TRUE(my_order);

  initYac(my_order.value());

  EXPECT_CALL(*network, sendState(_, _)).Times(2 * my_peers.size());

  EXPECT_CALL(*timer, deny()).Times(AtLeast(1));

  EXPECT_CALL(*crypto, verify(_)).Times(2).WillRepeatedly(Return(true));

  YacHash my_hash(iroha::consensus::Round{1, 1}, "proposal_hash", "block_hash");

  auto wrapper = make_test_subscriber<CallExact>(yac->onOutcome(), 1);
  wrapper.subscribe([my_hash](auto val) {
    ASSERT_EQ(my_hash, boost::get<CommitMessage>(val).votes.at(0).hash);
  });

  yac->vote(my_hash, my_order.value());

  auto vote_message = createVote(my_hash, std::to_string(0));

  yac->onState({vote_message});

  auto commit_message = CommitMessage({vote_message});

  yac->onState(commit_message.votes);

  ASSERT_TRUE(wrapper.validate());
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

  EXPECT_CALL(*timer, deny()).Times(AtLeast(1));

  EXPECT_CALL(*crypto, verify(_)).Times(1).WillRepeatedly(Return(true));

  YacHash my_hash(iroha::consensus::Round{1, 1}, "proposal_hash", "block_hash");

  std::vector<VoteMessage> votes;

  for (auto i = 0; i < 3; ++i) {
    votes.push_back(createVote(my_hash, std::to_string(i)));
  };
  yac->onState(votes);

  yac->vote(my_hash, my_order.value());
}
