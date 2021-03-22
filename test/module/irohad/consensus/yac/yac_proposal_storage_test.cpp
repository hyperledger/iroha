/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/storage/yac_proposal_storage.hpp"

#include <gtest/gtest.h>

#include "consensus/yac/impl/supermajority_checker_bft.hpp"  // for detail::kSupermajorityCheckerKfPlus1Bft
#include "consensus/yac/storage/yac_common.hpp"
#include "logger/logger.hpp"

#include "framework/test_logger.hpp"
#include "logger/logger_manager.hpp"
#include "module/irohad/consensus/yac/mock_yac_supermajority_checker.hpp"
#include "module/irohad/consensus/yac/yac_test_util.hpp"

using namespace iroha::consensus::yac;
using namespace ::testing;

static logger::LoggerPtr log_ = getTestLogger("YacProposalStorage");

class YacProposalStorageTest : public ::testing::Test {
 public:
  const PeersNumberType number_of_peers = 7;
  const PeersNumberType supermajority = number_of_peers
      - (number_of_peers - 1)
          / detail::kSupermajorityCheckerKfPlus1Bft;  // `kf+1' consistency
                                                      // model
  const YacHash hash =
      YacHash(iroha::consensus::Round{1, 1}, "proposal", "commit");
  const std::shared_ptr<MockSupermajorityChecker> supermajority_checker =
      std::make_shared<MockSupermajorityChecker>();
  YacProposalStorage storage = YacProposalStorage(
      iroha::consensus::Round{1, 1},
      number_of_peers,
      supermajority_checker,
      getTestLoggerManager()->getChild("YacProposalStorage"));
  std::vector<VoteMessage> valid_votes;

  void SetUp() override {
    valid_votes.reserve(number_of_peers);
    std::generate_n(std::back_inserter(valid_votes), number_of_peers, [this] {
      return createVote(this->hash, std::to_string(this->valid_votes.size()));
    });

    EXPECT_CALL(*supermajority_checker, hasSupermajority(_, _))
        .WillRepeatedly(
            Invoke([this](auto c, auto) { return c >= supermajority; }));
    EXPECT_CALL(*supermajority_checker, canHaveSupermajority(_, _))
        .WillRepeatedly(Return(true));
  }
};

TEST_F(YacProposalStorageTest, YacProposalStorageWhenCommitCase) {
  log_->info(
      "Init storage => insert unique votes => "
      "expected commit");

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

TEST_F(YacProposalStorageTest, YacProposalStorageWhenInsertNotUnique) {
  log_->info(
      "Init storage => insert not-unique votes => "
      "expected absence of commit");

  for (PeersNumberType i = 0; i < number_of_peers; ++i) {
    auto fixed_index = 0;
    ASSERT_EQ(boost::none, storage.insert(valid_votes.at(fixed_index)));
  }
}

TEST_F(YacProposalStorageTest, YacProposalStorageWhenRejectCase) {
  log_->info(
      "Init storage => insert votes for reject case => "
      "expected absence of commit");

  size_t num_inserted = 0;
  const size_t super_reject = number_of_peers - 2;

  EXPECT_CALL(*supermajority_checker, hasSupermajority(_, _))
      .WillRepeatedly(Return(false));
  EXPECT_CALL(*supermajority_checker, canHaveSupermajority(_, _))
      .WillRepeatedly(Invoke([&num_inserted, &super_reject](auto, auto) {
        return num_inserted < super_reject;
      }));

  while (num_inserted < number_of_peers) {
    auto insert_result = storage.insert(valid_votes.at(num_inserted++));
    if (num_inserted < super_reject) {
      EXPECT_EQ(boost::none, insert_result)
          << "Got an Answer after inserting " << num_inserted
          << " votes, before the supermajority reject reached at "
          << super_reject;
    } else {
      // after supermajority reached we have a CommitMessage
      ASSERT_NE(boost::none, insert_result)
          << "Did not get an Answer after inserting " << num_inserted
          << " votes and the supermajority reject reached at " << super_reject;
      ASSERT_EQ(num_inserted,
                boost::get<RejectMessage>(*insert_result).votes.size())
          << " The reject message must have all the previously inserted votes.";
    }
  }
}
