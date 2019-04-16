/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/storage/yac_block_storage.hpp"

#include <gtest/gtest.h>

#include "consensus/yac/impl/supermajority_checker_bft.hpp"
#include "consensus/yac/storage/yac_proposal_storage.hpp"
#include "logger/logger.hpp"

#include "framework/test_logger.hpp"
#include "module/irohad/consensus/yac/yac_test_util.hpp"

using namespace iroha::consensus::yac;

// TODO mboldyrev 14.02.2019 IR-324 Use supermajority checker mock
static const iroha::consensus::yac::ConsistencyModel kConsistencyModel =
    iroha::consensus::yac::ConsistencyModel::kBft;

static logger::LoggerPtr log_ = getTestLogger("YacBlockStorage");

class YacBlockStorageTest : public ::testing::Test {
 public:
  const PeersNumberType number_of_peers = 4;
  const PeersNumberType supermajority = number_of_peers
      - (number_of_peers - 1)
          / detail::kSupermajorityCheckerKfPlus1Bft;  // `kf+1' consistency
                                                      // model
  const YacHash hash =
      YacHash(iroha::consensus::Round{1, 1}, "proposal", "commit");
  YacBlockStorage storage =
      YacBlockStorage(hash,
                      number_of_peers,
                      // todo mboldyrev 13.12.2018 IR-324 use mock super checker
                      getSupermajorityChecker(kConsistencyModel),
                      getTestLogger("YacBlockStorage"));
  std::vector<VoteMessage> valid_votes;

  void SetUp() override {
    valid_votes.reserve(number_of_peers);
    std::generate_n(std::back_inserter(valid_votes), number_of_peers, [this] {
      return createVote(this->hash, std::to_string(this->valid_votes.size()));
    });
  }
};

TEST_F(YacBlockStorageTest, YacBlockStorageWhenNormalDataInput) {
  log_->info("------------| Sequential insertion of votes |------------");

  for (size_t num_inserted = 0; num_inserted < number_of_peers;) {
    auto insert_result = storage.insert(valid_votes.at(num_inserted++));
    if (num_inserted < supermajority) {
      EXPECT_EQ(boost::none, insert_result)
          << "Got an Answer after inserting " << num_inserted
          << " votes, before the supermajority reached at " << supermajority;
    } else {
      // after supermajority reached we have a CommitMessage
      ASSERT_NE(boost::none, insert_result)
          << "Did not get an Answer after inserting " << num_inserted
          << " votes and the supermajority reached at " << supermajority;
      ASSERT_EQ(num_inserted,
                boost::get<CommitMessage>(*insert_result).votes.size())
          << " The commit message must have all the previously inserted votes.";
    }
  }
}

TEST_F(YacBlockStorageTest, YacBlockStorageWhenNotCommittedAndCommitAcheive) {
  log_->info("-----------| Insert vote => insert commit |-----------");

  auto insert_1 = storage.insert(valid_votes.at(0));
  ASSERT_EQ(boost::none, insert_1);

  decltype(YacBlockStorageTest::valid_votes) for_insert(valid_votes.begin() + 1,
                                                        valid_votes.end());
  auto insert_commit = storage.insert(for_insert);
  ASSERT_TRUE(insert_commit) << "Must be a commit!";
  ASSERT_EQ(number_of_peers,
            boost::get<CommitMessage>(*insert_commit).votes.size());
}

TEST_F(YacBlockStorageTest, YacBlockStorageWhenGetVotes) {
  log_->info("-----------| Init storage => verify internal votes |-----------");

  storage.insert(valid_votes);
  ASSERT_EQ(valid_votes, storage.getVotes());
}

TEST_F(YacBlockStorageTest, YacBlockStorageWhenIsContains) {
  log_->info(
      "-----------| Init storage => "
      "verify ok and fail cases of contains |-----------");

  decltype(YacBlockStorageTest::valid_votes) for_insert(
      valid_votes.begin(), valid_votes.begin() + 2);

  storage.insert(for_insert);

  ASSERT_TRUE(storage.isContains(valid_votes.at(0)));
  ASSERT_FALSE(storage.isContains(valid_votes.at(3)));
}
