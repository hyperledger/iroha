/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "consensus/yac/impl/supermajority_checker_bft.hpp"
#include "consensus/yac/storage/yac_proposal_storage.hpp"

#include "backend/plain/peer.hpp"
#include "framework/test_subscriber.hpp"
#include "module/irohad/consensus/yac/yac_fixture.hpp"

using ::testing::_;
using ::testing::An;
using ::testing::AtLeast;
using ::testing::Invoke;
using ::testing::Ref;
using ::testing::Return;

using namespace iroha::consensus::yac;
using namespace framework::test_subscriber;
using namespace std;

/**
 * Test provide scenario when yac vote for hash
 */
TEST_F(YacTest, YacWhenVoting) {
  cout << "----------|YacWhenAchieveOneVote|----------" << endl;

  EXPECT_CALL(*network, sendState(_, _)).Times(default_peers.size());

  YacHash my_hash(initial_round, "my_proposal_hash", "my_block_hash");

  auto order = ClusterOrdering::create(default_peers);
  ASSERT_TRUE(order);

  yac->vote(my_hash, *order);
}

/**
 * Test provide scenario when yac cold started and achieve one vote
 */
TEST_F(YacTest, YacWhenColdStartAndAchieveOneVote) {
  cout << "----------|Coldstart - receive one vote|----------" << endl;

  // verify that commit not emitted
  auto wrapper = make_test_subscriber<CallExact>(yac->onOutcome(), 0);
  wrapper.subscribe();

  EXPECT_CALL(*network, sendState(_, _)).Times(0);

  EXPECT_CALL(*crypto, verify(_)).Times(1).WillRepeatedly(Return(true));

  YacHash received_hash(initial_round, "my_proposal", "my_block");
  // assume that our peer receive message
  network->notification->onState({crypto->getVote(received_hash, "0")});

  ASSERT_TRUE(wrapper.validate());
}

/**
 * Test provide scenario
 * when yac cold started and achieve supermajority of votes
 *
 * TODO 13.03.2019 mboldyrev IR-396: fix the test if needed
 * the test passed successfully due to votes being equal and hence
 * YacProposalStorage::checkPeerUniqueness(const VoteMessage &)
 * returning `false'. This does not meet the `when' clause in this test
 * description.
 */
TEST_F(YacTest, DISABLED_YacWhenColdStartAndAchieveSupermajorityOfVotes) {
  cout << "----------|Start => receive supermajority of votes"
          "|----------"
       << endl;

  // verify that commit not emitted
  auto wrapper = make_test_subscriber<CallExact>(yac->onOutcome(), 0);
  wrapper.subscribe();

  EXPECT_CALL(*network, sendState(_, _)).Times(0);

  EXPECT_CALL(*crypto, verify(_))
      .Times(default_peers.size())
      .WillRepeatedly(Return(true));

  YacHash received_hash(initial_round, "my_proposal", "my_block");
  for (size_t i = 0; i < default_peers.size(); ++i) {
    network->notification->onState(
        {crypto->getVote(received_hash, std::to_string(i))});
  }

  ASSERT_TRUE(wrapper.validate());
}

/**
 * @given initialized YAC with empty storage
 * @when receive commit message
 * @then commit is not broadcasted
 * AND commit is emitted to observable
 */
TEST_F(YacTest, YacWhenColdStartAndAchieveCommitMessage) {
  YacHash propagated_hash(initial_round, "my_proposal", "my_block");

  // verify that commit emitted
  auto wrapper = make_test_subscriber<CallExact>(yac->onOutcome(), 1);
  wrapper.subscribe([propagated_hash](auto commit_hash) {
    ASSERT_EQ(propagated_hash,
              boost::get<CommitMessage>(commit_hash).votes.at(0).hash);
  });

  EXPECT_CALL(*network, sendState(_, _)).Times(0);

  EXPECT_CALL(*crypto, verify(_)).WillOnce(Return(true));

  EXPECT_CALL(*timer, deny()).Times(AtLeast(1));

  auto committed_peer = default_peers.at(0);
  auto msg = CommitMessage(std::vector<VoteMessage>{});
  for (size_t i = 0; i < default_peers.size(); ++i) {
    msg.votes.push_back(createVote(propagated_hash, std::to_string(i)));
  }
  network->notification->onState(msg.votes);

  ASSERT_TRUE(wrapper.validate());
}

/**
 * @given initialized YAC
 * @when receive supermajority of votes for a hash
 * @then commit is sent to the network before notifying subscribers
 *
 * TODO 13.03.2019 mboldyrev IR-396: fix the test if needed
 * the test passed successfully due to votes being equal and hence
 * YacProposalStorage::checkPeerUniqueness(const VoteMessage &)
 * returning `false'. This does not meet the `when' clause in this test
 * description.
 */
TEST_F(YacTest, DISABLED_PropagateCommitBeforeNotifyingSubscribersApplyVote) {
  EXPECT_CALL(*crypto, verify(_))
      .Times(default_peers.size())
      .WillRepeatedly(Return(true));
  std::vector<std::vector<VoteMessage>> messages;
  EXPECT_CALL(*network, sendState(_, _))
      .Times(default_peers.size() + 1)
      .WillRepeatedly(Invoke(
          [&](const auto &, const auto &msg) { messages.push_back(msg); }));

  yac->onOutcome().subscribe([&](auto msg) {
    // verify that commits are already sent to the network
    ASSERT_EQ(default_peers.size(), messages.size());
    messages.push_back(boost::get<CommitMessage>(msg).votes);
  });

  for (size_t i = 0; i < default_peers.size(); ++i) {
    yac->onState(
        {createVote(YacHash(initial_round, "proposal_hash", "block_hash"),
                    std::to_string(i))});
  }

  // verify that on_commit subscribers are notified
  ASSERT_EQ(default_peers.size() + 2, messages.size());
}

/**
 * @given initialized YAC
 * @when receive 2 * f votes for one hash
 * AND receive reject message which triggers commit
 * @then commit is NOT propagated in the network
 * AND it is passed to pipeline
 */
TEST_F(YacTest, PropagateCommitBeforeNotifyingSubscribersApplyReject) {
  EXPECT_CALL(*crypto, verify(_)).WillRepeatedly(Return(true));
  EXPECT_CALL(*timer, deny()).Times(AtLeast(1));
  std::vector<std::vector<VoteMessage>> messages;
  EXPECT_CALL(*network, sendState(_, _)).Times(0);

  yac->onOutcome().subscribe([&](auto msg) {
    messages.push_back(boost::get<CommitMessage>(msg).votes);
  });

  std::vector<VoteMessage> commit;

  auto yac_hash = YacHash(initial_round, "proposal_hash", "block_hash");

  auto f = (default_peers.size() - 1)
      / iroha::consensus::yac::detail::kSupermajorityCheckerKfPlus1Bft;
  for (size_t i = 0; i < default_peers.size() - f - 1; ++i) {
    auto vote = createVote(yac_hash, std::to_string(i));
    yac->onState({vote});
    commit.push_back(vote);
  }

  auto vote = createVote(yac_hash, std::to_string(default_peers.size() - f));
  RejectMessage reject(
      {vote,
       createVote(YacHash(initial_round, "", "my_block"),
                  std::to_string(default_peers.size() - f + 1))});
  commit.push_back(vote);

  yac->onState(reject.votes);
  yac->onState(commit);

  // verify that on_commit subscribers are notified
  ASSERT_EQ(1, messages.size());
}

/**
 * @given initialized yac
 * @when receive state with same hashes from future
 * @then commit for synchronization is emitted
 */
TEST_F(YacTest, PossibleCommitFromFuture) {
  YacHash hash({initial_round.block_round + 1, 0}, "my_proposal", "my_block");

  auto wrapper = make_test_subscriber<CallExact>(yac->onOutcome(), 1);
  wrapper.subscribe([hash](auto message) {
    auto commit_message = boost::get<CommitMessage>(message);
    ASSERT_EQ(hash, commit_message.votes.at(0).hash);
    ASSERT_EQ(hash, commit_message.votes.at(1).hash);
  });

  EXPECT_CALL(*network, sendState(_, _)).Times(0);

  EXPECT_CALL(*crypto, verify(_)).Times(1).WillRepeatedly(Return(true));

  network->notification->onState(
      {createVote(hash, "1"), createVote(hash, "2")});

  ASSERT_TRUE(wrapper.validate());
}

/**
 * @given initialized yac
 * @when receive state with different hashes from future
 * @then reject for synchronization is emitted
 */
TEST_F(YacTest, PossibleRejectFromFuture) {
  YacHash hash({initial_round.block_round + 1, 0}, "my_proposal", "my_block"),
      hash2({initial_round.block_round + 1, 0}, "my_proposal", "my_block2");

  auto wrapper = make_test_subscriber<CallExact>(yac->onOutcome(), 1);
  wrapper.subscribe([hash, hash2](auto message) {
    auto reject_message = boost::get<RejectMessage>(message);
    ASSERT_EQ(hash, reject_message.votes.at(0).hash);
    ASSERT_EQ(hash2, reject_message.votes.at(1).hash);
  });

  EXPECT_CALL(*network, sendState(_, _)).Times(0);

  EXPECT_CALL(*crypto, verify(_)).Times(1).WillRepeatedly(Return(true));

  network->notification->onState(
      {createVote(hash, "1"), createVote(hash2, "2")});

  ASSERT_TRUE(wrapper.validate());
}

class YacAlternativeOrderTest : public YacTest {
 public:
  ClusterOrdering order = *ClusterOrdering::create({makePeer("default_peer")});
  YacHash my_hash{initial_round, "my_proposal_hash", "my_block_hash"};

  std::string peer_id{"alternative_peer"};
  std::shared_ptr<shared_model::interface::Peer> peer = makePeer(peer_id);
  ClusterOrdering alternative_order = *ClusterOrdering::create({peer});
};

/**
 * @given yac
 * @when vote is called with alternative order
 * @then alternative order is used for sending votes
 */
TEST_F(YacAlternativeOrderTest, Voting) {
  EXPECT_CALL(*network, sendState(Ref(*peer), _)).Times(1);

  yac->vote(my_hash, order, alternative_order);
}

/**
 * @given yac, vote called with alternative order
 * @when alternative peer state with vote from future is received from the
 *       network
 * @then peers from alternative order are used to filter out the votes
 *       and an outcome for synchronization is emitted
 */
TEST_F(YacAlternativeOrderTest, OnState) {
  yac->vote(my_hash, order, alternative_order);

  auto wrapper = make_test_subscriber<CallExact>(yac->onOutcome(), 1);
  wrapper.subscribe();

  EXPECT_CALL(*crypto, verify(_)).Times(1).WillRepeatedly(Return(true));

  YacHash received_hash(
      {initial_round.block_round + 1, 0}, "my_proposal", "my_block");
  // assume that our peer receive message
  network->notification->onState({createVote(received_hash, peer_id)});

  ASSERT_TRUE(wrapper.validate());
}

/**
 * @given yac, vote called with alternative order, which does not contain peers
 *        from cluster order
 * @when alternative peer state with vote for the same round is received from
 *       the network
 * @then peers from cluster order are used to filter out the votes and
 *       kNotSentNotProcessed action is not executed
 */
TEST_F(YacAlternativeOrderTest, OnStateCurrentRoundAlternativePeer) {
  yac->vote(my_hash, order, alternative_order);

  EXPECT_CALL(*network, sendState(_, _)).Times(0);

  EXPECT_CALL(*crypto, verify(_)).Times(1).WillRepeatedly(Return(true));

  YacHash received_hash(initial_round, "my_proposal", "my_block");
  // assume that our peer receive message
  network->notification->onState({createVote(received_hash, peer_id)});
}
