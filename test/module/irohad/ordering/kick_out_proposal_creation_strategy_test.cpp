/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ordering/impl/kick_out_proposal_creation_strategy.hpp"

#include <vector>

// dependencies for the concurrent test
#include <atomic>
#include <mutex>
#include <thread>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "module/irohad/consensus/yac/mock_yac_supermajority_checker.hpp"

using namespace iroha::ordering;

using testing::_;
using testing::Return;

class KickOutProposalCreationStrategyTest : public testing::Test {
 public:
  void SetUp() override {
    is_invoked = false;

    for (auto i = 0u; i < number_of_peers; ++i) {
      peers.emplace_back(std::to_string(i));
    }

    supermajority_checker_ =
        std::make_shared<iroha::consensus::yac::MockSupermajorityChecker>();
    strategy_ = std::make_shared<KickOutProposalCreationStrategy>(
        supermajority_checker_);
  }

  std::shared_ptr<KickOutProposalCreationStrategy> strategy_;
  std::shared_ptr<iroha::consensus::yac::MockSupermajorityChecker>
      supermajority_checker_;

  std::vector<KickOutProposalCreationStrategy::PeerType> peers;
  size_t number_of_peers = 7;
  size_t f = 2;
  bool is_invoked;
  std::function<void()> invocation_checker = [this] { is_invoked = true; };
};

/**
 * @given initialized kickOutStrategy
 *        @and onCollaborationOutcome is invoked for the first round
 * @when  onProposal calls F times with different peers for further rounds
 * @then  shouldCreateRound returns true
 */
TEST_F(KickOutProposalCreationStrategyTest, OnNonMaliciousCase) {
  EXPECT_CALL(*supermajority_checker_, isTolerated(0, number_of_peers))
      .WillOnce(Return(false));

  strategy_->onCollaborationOutcome(peers);

  strategy_->shouldCreateRound({2, 0}, invocation_checker);
  ASSERT_EQ(true, is_invoked);
  is_invoked = false;

  for (auto i = 0u; i < f; ++i) {
    strategy_->onProposalRequest(peers.at(i), {2, 0});
  }

  EXPECT_CALL(*supermajority_checker_, isTolerated(f, number_of_peers))
      .WillOnce(Return(false));
  strategy_->shouldCreateRound({2, 0}, invocation_checker);
  ASSERT_EQ(true, is_invoked);
}

/**
 * @given initialized kickOutStrategy
 *        @and onCollaborationOutcome is invoked for the first round
 * @when  onProposal calls F + 1 times with different peers for further rounds
 * @then  onCollaborationOutcome returns false
 */
TEST_F(KickOutProposalCreationStrategyTest, OnMaliciousCase) {
  strategy_->onCollaborationOutcome(peers);

  auto requested = f + 1;
  for (auto i = 0u; i < requested; ++i) {
    strategy_->onProposalRequest(peers.at(i), {2, 0});
  }

  EXPECT_CALL(*supermajority_checker_, isTolerated(requested, number_of_peers))
      .WillOnce(Return(true));
  strategy_->shouldCreateRound({2, 0}, invocation_checker);
  ASSERT_EQ(false, is_invoked);
}

/**
 * @given initialized kickOutStrategy
 *        @and onCollaborationOutcome is invoked for the first round
 * @when  onProposal calls F + 1 times with one peer
 * @then  onCollaborationOutcome call returns true
 */
TEST_F(KickOutProposalCreationStrategyTest, RepeadedRequest) {
  strategy_->onCollaborationOutcome(peers);

  auto requested = f + 1;
  for (auto i = 0u; i < requested; ++i) {
    strategy_->onProposalRequest(peers.at(0), {2, 0});
  }
  EXPECT_CALL(*supermajority_checker_, isTolerated(1, number_of_peers))
      .WillOnce(Return(false));
  strategy_->shouldCreateRound({2, 0}, invocation_checker);
  ASSERT_EQ(true, is_invoked);
}

/**
 * @given initialized kickOutStrategy
 *        @and onCollaborationOutcome is invoked for the first round
 * @when  onProposal calls F times different peers
 *        @and 1 time with unknown peer
 * @then  onCollaborationOutcome call returns true
 */
TEST_F(KickOutProposalCreationStrategyTest, UnknownPeerRequestsProposal) {
  strategy_->onCollaborationOutcome(peers);

  for (auto i = 0u; i < f; ++i) {
    strategy_->onProposalRequest(peers.at(i), {2, 0});
  }
  strategy_->onProposalRequest(shared_model::crypto::PublicKey{"unknown"},
                               {2, 0});
  EXPECT_CALL(*supermajority_checker_, isTolerated(f, number_of_peers))
      .WillOnce(Return(false));
  strategy_->shouldCreateRound({2, 0}, invocation_checker);
  ASSERT_EQ(true, is_invoked);
}

/**
 * This is a probabilistic concurrent test which guarantees safety of lambda
 * invocation calls in shouldCreateRound method
 * @given main_thread - lambda which responsible for updating round counter and
 * shouldCreateRound invocation. Lambda emulates work in on demand ordering
 * service.
 *        @and requester_thread - lambda which calls onProposalRequest with
 * corresponding round. The lambda emulates requester peers in on demand
 * ordering service.
 *
 * @when  starts main_thread and two worker threads
 * @then  check that situation where lambda in shouldCreateRound see
 * inconsistent state
 *
 * @note: The test is disabled because of CI can't perform concurrent tests well
 */
TEST_F(KickOutProposalCreationStrategyTest, DISABLED_ConcurrentTest) {
  EXPECT_CALL(*supermajority_checker_, isTolerated(0, number_of_peers))
      .WillRepeatedly(Return(false));
  EXPECT_CALL(*supermajority_checker_, isTolerated(1, number_of_peers))
      .WillRepeatedly(Return(false));
  EXPECT_CALL(*supermajority_checker_, isTolerated(2, number_of_peers))
      .WillRepeatedly(Return(true));

  std::atomic<uint64_t> commit_round{1};

  size_t number_of_threads = 2;
  std::vector<uint64_t> last_requested(number_of_threads);

  std::mutex mutex;

  auto main_thread = [this, &commit_round, &last_requested, &mutex]() {
    for (int i = 0; i < 10000; ++i) {
      auto round = iroha::consensus::Round{commit_round.load(), 0};
      strategy_->onCollaborationOutcome(peers);
      bool all_the_same = false;
      uint64_t last_val = 0;
      {
        std::lock_guard<std::mutex> guard(mutex);
        all_the_same = std::all_of(last_requested.begin(),
                                   last_requested.end(),
                                   [&last_requested](const auto &val) {
                                     return last_requested.at(0) == val;
                                   });
        last_val = last_requested.at(0);
      }
      strategy_->shouldCreateRound(round, [&] {
        if (all_the_same) {
          ASSERT_NE(round.block_round, last_val);
        }
      });
      ++commit_round;
    }
  };

  auto requester_thread =
      [this, &commit_round, &last_requested, &mutex](size_t num) {
        for (int i = 0; i < 10000; ++i) {
          auto round = iroha::consensus::Round{commit_round.load(), 0};
          strategy_->onProposalRequest(peers.at(num), round);
          {
            std::lock_guard<std::mutex> guard(mutex);
            last_requested.at(num) = round.block_round;
          }
        }
      };

  std::thread main(main_thread);
  std::thread _0(requester_thread, 0);
  std::thread _1(requester_thread, 1);

  main.join();
  _0.join();
  _1.join();
}
