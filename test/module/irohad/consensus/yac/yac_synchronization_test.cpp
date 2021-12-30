/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "module/irohad/consensus/yac/yac_fixture.hpp"

#include "common/hexutils.hpp"

using namespace iroha::consensus::yac;

using ::testing::_;
using ::testing::Return;

using iroha::consensus::Round;

namespace {
  YacHash createHash(const iroha::consensus::Round &r,
                     const std::string &block_hash = "default_block",
                     const std::string &proposal_hash = "default_proposal") {
    return YacHash(r, proposal_hash, block_hash);
  }
}  // namespace

/**
 * The class helps to create fake network for unit testing of consensus
 */
class NetworkUtil {
 public:
  /// creates fake network of number_of_peers size
  NetworkUtil(size_t number_of_peers) {
    for (size_t i = 0; i < number_of_peers; ++i) {
      peers_.push_back(makePeer(std::to_string(i)));
    }
    order_ = ClusterOrdering::create(peers_);
  }

  auto createVote(size_t from, const YacHash &yac_hash) const {
    BOOST_ASSERT_MSG(from < peers_.size(), "Requested unknown index of peer");
    return iroha::consensus::yac::createVote(
        yac_hash,
        iroha::hexstringToBytestringResult(peers_.at(from)->pubkey())
            .assumeValue());
  }

  /// create votes of peers by their number
  /// @param peers indices of peers in @a peers_
  /// @param hash for all votes
  /// @return vector of votes for the @a hash from each of @peers
  auto createVotes(const std::vector<size_t> &peers,
                   const YacHash &hash) const {
    std::vector<VoteMessage> result;
    for (auto &peer_number : peers) {
      result.push_back(createVote(peer_number, hash));
    }
    return result;
  }

  std::vector<std::shared_ptr<shared_model::interface::Peer>> peers_;
  std::optional<ClusterOrdering> order_;
};

class YacSynchronizationTest : public YacTest {
 public:
  void SetUp() override {
    YacTest::SetUp();

    network_util_ = NetworkUtil(7);
    initAndCommitState(network_util_);
  }

  /// inits initial state and commits some rounds
  void initAndCommitState(const NetworkUtil &network_util) {
    const auto &order = network_util.order_.value();

    initYac(order);
    EXPECT_CALL(*crypto, verify(_)).WillRepeatedly(Return(true));

    for (auto i = initial_round.block_round;
         i < initial_round.block_round + number_of_committed_rounds_;
         i++) {
      top_hash_ = createHash(Round{i, 0});
      setNetworkOrderCheckerSingleVote(order, top_hash_.value(), 2);
      yac->processRoundSwitch(top_hash_->vote_round,
                              order.getPeers(),
                              shared_model::interface::types::PeerList{});
      yac->vote(top_hash_.value(), order);
      yac->onState(network_util.createVotes(voters_, top_hash_.value()));
    }
    const YacHash next_hash = createHash(
        {initial_round.block_round + number_of_committed_rounds_, 0});
    setNetworkOrderCheckerSingleVote(order, next_hash, 2);
    yac->processRoundSwitch(next_hash.vote_round,
                            order.getPeers(),
                            shared_model::interface::types::PeerList{});
    yac->vote(next_hash, order);
  }

  /// expect yac to send the top commit to the given @a peer
  /// @param peer index in @ref NetworkUtil::peers_
  auto expectSendTopCommitTo(size_t peer) {
    assert(top_hash_);
    EXPECT_CALL(
        *network,
        sendState(testing::Ref(*network_util_.order_.value().getPeers()[peer]),
                  makeCommitMatcher(top_hash_.value(), voters_.size())))
        .Times(1);
  }

  NetworkUtil network_util_{1};
  const size_t number_of_committed_rounds_ = 10;
  boost::optional<YacHash> top_hash_;
  const std::vector<size_t> voters_{{1, 2, 3, 4, 5, 6}};
};

/**
 * @given Yac which stores commit
 * @when  Vote from known peer from old round which was presented in the cache
 * @then  Yac sends commit for the last round
 */
TEST_F(YacSynchronizationTest, SynchronizationOnCommitInTheCache) {
  expectSendTopCommitTo(0);
  yac->onState(network_util_.createVotes({0}, createHash(Round{1, 0})));
}

/**
 * @given Yac which stores commit
 * @when  Vote from known peer from old round which presents in a cache
 * @then  Yac sends commit for the last round
 */
TEST_F(YacSynchronizationTest, SynchronizationOnCommitOutOfTheCache) {
  expectSendTopCommitTo(0);
  yac->onState(network_util_.createVotes({0}, createHash(Round{9, 0})));
}

/**
 * @given Yac received reject
 * @when  Vote from known peer from old round which doesn't present in the cache
 * @then  Yac sends last commit
 */
TEST_F(YacSynchronizationTest, SynchronizationRejectOutOfTheCache) {
  expectSendTopCommitTo(0);
  yac->onState(network_util_.createVotes({0}, createHash(Round{5, 5})));
}
