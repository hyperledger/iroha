/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/supermajority_checker.hpp"

#include "consensus/yac/impl/supermajority_checker_bft.hpp"
#include "consensus/yac/impl/supermajority_checker_cft.hpp"

#include <gtest/gtest.h>

#include <boost/foreach.hpp>
#include "boost/tuple/tuple.hpp"
#include "logger/logger.hpp"

#include "framework/test_logger.hpp"
#include "module/shared_model/interface_mocks.hpp"

using namespace iroha::consensus::yac;

using ::testing::ReturnRefOfCopy;

static logger::LoggerPtr log_ = getTestLogger("YacCommon");

static const std::map<ConsistencyModel, unsigned int> kf1_param{
    {ConsistencyModel::kCft, detail::kSupermajorityCheckerKfPlus1Cft},
    {ConsistencyModel::kBft, detail::kSupermajorityCheckerKfPlus1Bft}};

class SupermajorityCheckerTest
    : public ::testing::TestWithParam<ConsistencyModel>,
      public SupermajorityChecker {
 public:
  void SetUp() override {}

  unsigned int getK() const {
    return kf1_param.at(GetParam());
  }

  size_t getAllowedFaultyPeers(size_t total_peers) const {
    return (total_peers - 1) / getK();
  }

  size_t getSupermajority(size_t total_peers) const {
    return total_peers - getAllowedFaultyPeers(total_peers);
  }

  size_t getTolerance(size_t total_peers) const {
    return getAllowedFaultyPeers(total_peers) + 1;
  }

  std::string modelToString() const {
    return "`" + std::to_string(getK()) + " * f + 1' "
        + (GetParam() == ConsistencyModel::kBft ? "BFT" : "CFT") + " model";
  }

  bool hasSupermajority(PeersNumberType current,
                        PeersNumberType all) const override {
    return checker->hasSupermajority(current, all);
  }

  bool isTolerated(PeersNumberType number, PeersNumberType all) const override {
    return checker->isTolerated(number, all);
  }

  bool canHaveSupermajority(const VoteGroups &votes,
                            PeersNumberType all) const override {
    return checker->canHaveSupermajority(votes, all);
  }

  std::unique_ptr<SupermajorityChecker> checker{
      getSupermajorityChecker(GetParam())};
};

using CftAndBftSupermajorityCheckerTest = SupermajorityCheckerTest;
using BftSupermajorityCheckerTest = SupermajorityCheckerTest;

INSTANTIATE_TEST_SUITE_P(Instance,
                         CftAndBftSupermajorityCheckerTest,
                         ::testing::Values(ConsistencyModel::kCft,
                                           ConsistencyModel::kBft));

INSTANTIATE_TEST_SUITE_P(Instance,
                         BftSupermajorityCheckerTest,
                         ::testing::Values(ConsistencyModel::kBft));

/**
 * @given 2 participants
 * @when check range of voted participants
 * @then correct result
 */
TEST_P(CftAndBftSupermajorityCheckerTest, SuperMajorityCheckWithSize2) {
  log_->info("-----------| F(x, 2), x in [0..3] |-----------");

  size_t A = 2;  // number of all peers
  for (size_t i = 0; i < 4; ++i) {
    if (i >= getSupermajority(A)  // enough votes
        and i <= A                // not more than total peers amount
    ) {
      ASSERT_TRUE(hasSupermajority(i, A))
          << i << " votes out of " << A << " are supermajority in "
          << modelToString();
    } else {
      ASSERT_FALSE(hasSupermajority(i, A))
          << i << " votes out of " << A << " are not a supermajority in "
          << modelToString();
    }
  }
}

/**
 * @given 4 participants
 * @when check range of voted participants
 * @then correct result
 */
TEST_P(CftAndBftSupermajorityCheckerTest, SuperMajorityCheckWithSize4) {
  log_->info("-----------| F(x, 4), x in [0..5] |-----------");

  size_t A = 6;  // number of all peers
  for (size_t i = 0; i < 5; ++i) {
    if (i >= getSupermajority(A)  // enough votes
        and i <= A                // not more than total peers amount
    ) {
      ASSERT_TRUE(hasSupermajority(i, A))
          << i << " votes out of " << A << " are supermajority in "
          << modelToString();
    } else {
      ASSERT_FALSE(hasSupermajority(i, A))
          << i << " votes out of " << A << " are not a supermajority in "
          << modelToString();
    }
  }
}

/**
 * @given 4 participants
 * @when check range of voted participants
 * @then correct result
 */
TEST_P(CftAndBftSupermajorityCheckerTest, ToleranceWithSize4) {
  size_t A = 4;
  for (size_t i = 0; i < 5; ++i) {
    if (i >= getTolerance(A) and i <= A) {
      ASSERT_TRUE(isTolerated(i, A))
          << i << " votes out of " << A << " in " << modelToString();
    } else {
      ASSERT_FALSE(isTolerated(i, A))
          << i << " votes out of " << A << " in " << modelToString();
    }
  }
}

/**
 * \attention this test does not address possible supermajority on other peers
 * due to malicious peers sending then votes for other hashes
 *
 * @given some peers vote all for one option, others vote each for own option,
 * and the rest do not vote
 * @when different amounts of described peer kinds
 * @then correct decision on supermajority possibility
 */
TEST_P(CftAndBftSupermajorityCheckerTest, OneLargeAndManySingleVoteGroups) {
  /**
   * Make vote groups out of given votes amount such that the largest one has
   * the given amount of votes.
   */
  auto makeVoteGroups = [](size_t largest_group, size_t voted_peers) {
    BOOST_ASSERT_MSG(
        largest_group <= voted_peers,
        "A votes group cannot have more votes than the amount of voted peers!");
    const size_t num_groups = voted_peers - largest_group + 1;
    std::vector<size_t> vote_groups(num_groups, 1);
    vote_groups[0] = largest_group;
    return vote_groups;
  };

  struct Case {
    size_t V;  // Voted peers
    size_t A;  // All peers
  };

  for (const auto &c : std::vector<Case>{{6, 7}, {8, 12}}) {
    log_->info("--------| ProofOfReject(x, {0}, {1}), x in [1..{0}] |---------",
               c.V,
               c.A);

    size_t L;  // number of votes for the Leading option
    for (L = 1; L <= c.V; ++L) {
      const auto vote_groups = makeVoteGroups(L, c.V);
      const size_t N = c.A - c.V;              // not yet voted
      const size_t S = getSupermajority(c.A);  // supermajority
      const size_t Lp =  // max possible votes amount for the largest group
          L              // the votes we know
          + N;           // the peers that we have no votes from
      // Check if any peer on the network can get supermajority:
      if (Lp >= S) {
        EXPECT_TRUE(canHaveSupermajority(vote_groups, c.A))
            << "if " << N << " not yet voted peers "
            << "vote for option already having " << L << " votes, "
            << "it will reach supermajority in " << modelToString();
      } else {
        EXPECT_FALSE(canHaveSupermajority(vote_groups, c.A))
            << "even if all " << N << " not yet voted peers "
            << "vote for option already having " << L << " votes, "
            << "it will not reach supermajority in " << modelToString();
      }
    }
  }
}
