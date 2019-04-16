/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "module/irohad/consensus/yac/yac_fixture.hpp"

#include "common/hexutils.hpp"

using namespace iroha::consensus::yac;

using ::testing::_;
using ::testing::Return;

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

  auto createHash(const iroha::consensus::Round &r,
                  const std::string &block_hash = "default_block",
                  const std::string &proposal_hash = "default_proposal") const {
    return YacHash(r, proposal_hash, block_hash);
  }

  auto createVote(size_t from, const YacHash &yac_hash) const {
    BOOST_ASSERT_MSG(from < peers_.size(), "Requested unknown index of peer");
    return iroha::consensus::yac::createVote(
        yac_hash,
        *iroha::hexstringToBytestring(peers_.at(from)->pubkey().hex()));
  }
  /// create votes of peers by their number
  auto createVotes(
      const std::vector<size_t> &peers,
      const iroha::consensus::Round &r,
      const std::string &block_hash = "default_block",
      const std::string &proposal_hash = "default_proposal") const {
    return std::accumulate(
        peers.begin(),
        peers.end(),
        std::vector<VoteMessage>(),
        [&, this](auto vector, const auto &peer_number) {
          vector.push_back(this->createVote(
              peer_number, this->createHash(r, block_hash, proposal_hash)));
          return std::move(vector);
        });
  }

  std::vector<std::shared_ptr<shared_model::interface::Peer>> peers_;
  boost::optional<ClusterOrdering> order_;
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
    size_t number_of_committed_rounds = 10;

    initYac(*network_util.order_);
    EXPECT_CALL(*crypto, verify(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*timer, deny()).Times(number_of_committed_rounds);

    for (auto i = 0u; i < number_of_committed_rounds; i++) {
      iroha::consensus::Round r{i, 0};
      yac->vote(network_util.createHash(r), *network_util.order_);
      yac->onState(network_util.createVotes({1, 2, 3, 4, 5, 6}, r));
    }
    EXPECT_CALL(*network, sendState(_, _)).Times(8);
    yac->vote(network_util.createHash({10, 0}), *network_util.order_);
  }

  NetworkUtil network_util_{1};
};

/**
 * @given Yac which stores commit
 * @when  Vote from known peer from old round which was presented in the cache
 * @then  Yac sends commit for the last round
 */
TEST_F(YacSynchronizationTest, SynchronizationOncommitInTheCahe) {
  yac->onState(network_util_.createVotes({0}, iroha::consensus::Round{1, 0}));
}

/**
 * @given Yac which stores commit
 * @when  Vote from known peer from old round which presents in a cache
 * @then  Yac sends commit for the last round
 */
TEST_F(YacSynchronizationTest, SynchronizationOnCommitOutOfTheCahe) {
  yac->onState(network_util_.createVotes({0}, iroha::consensus::Round{9, 0}));
}

/**
 * @given Yac received reject
 * @when  Vote from known peer from old round which doesn't present in the cache
 * @then  Yac sends last commit
 */
TEST_F(YacSynchronizationTest, SynchronizationRejectOutOfTheCahe) {
  yac->onState(network_util_.createVotes({0}, iroha::consensus::Round{5, 5}));
}
