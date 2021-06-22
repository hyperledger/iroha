/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_YAC_FIXTURE_HPP
#define IROHA_YAC_FIXTURE_HPP

#include <gtest/gtest.h>

#include "consensus/yac/cluster_order.hpp"
#include "consensus/yac/storage/buffered_cleanup_strategy.hpp"
#include "consensus/yac/yac.hpp"

#include "framework/test_logger.hpp"
#include "logger/logger_manager.hpp"
#include "module/irohad/consensus/yac/mock_yac_crypto_provider.hpp"
#include "module/irohad/consensus/yac/mock_yac_network.hpp"
#include "module/irohad/consensus/yac/mock_yac_timer.hpp"
#include "module/irohad/consensus/yac/yac_test_util.hpp"

// TODO mboldyrev 14.02.2019 IR-324 Use supermajority checker mock
static const iroha::consensus::yac::ConsistencyModel kConsistencyModel =
    iroha::consensus::yac::ConsistencyModel::kBft;

namespace iroha {
  namespace consensus {
    namespace yac {

      class YacTest : public ::testing::Test {
       public:
        // ------|Network|------
        std::shared_ptr<MockYacNetwork> network;
        std::shared_ptr<MockYacCryptoProvider> crypto;
        std::shared_ptr<MockTimer> timer;
        std::shared_ptr<Yac> yac;

        // ------|One round|------
        std::vector<std::shared_ptr<shared_model::interface::Peer>>
            default_peers = [] {
              std::vector<std::shared_ptr<shared_model::interface::Peer>>
                  result;
              for (size_t i = 0; i < 7; ++i) {
                result.push_back(makePeer(std::to_string(i)));
              }
              return result;
            }();
        Round initial_round{1, 1};

        void SetUp() override {
          network = std::make_shared<MockYacNetwork>();
          crypto = std::make_shared<MockYacCryptoProvider>();
          timer = std::make_shared<MockTimer>();
          auto ordering = ClusterOrdering::create(default_peers);
          ASSERT_TRUE(ordering);
          initYac(ordering.value());
        }

        void initYac(ClusterOrdering ordering) {
          yac = Yac::create(
              YacVoteStorage(
                  std::make_shared<
                      iroha::consensus::yac::BufferedCleanupStrategy>(),
                  getSupermajorityChecker(kConsistencyModel),
                  getTestLoggerManager()->getChild("YacVoteStorage")),
              network,
              crypto,
              timer,
              ordering.getPeers(),
              initial_round,
              getTestLogger("Yac"));
        }

       private:
        /**
         * Make a checker of sendState invocations that matches the destination
         * peer with the @a order.
         * @param order the order to check
         * @return a lambda to be executed in sendState mock function.
         */
        auto makeSendStateOrderChecker(const ClusterOrdering &order) {
          auto times_sent_state = std::make_shared<size_t>(0);
          return [&peers = order.getPeers(), times_sent_state](
                     const auto &peer, const auto & /* state */) {
            const auto it =
                std::find_if(peers.begin(), peers.end(), [&](auto &peer_ptr) {
                  return *peer_ptr == peer;
                });
            EXPECT_NE(it, peers.end()) << "peer out of list";
            EXPECT_EQ(it - peers.begin(), (*times_sent_state)++ % peers.size())
                << "wrong order";
          };
        }

       protected:
        /**
         * Set expectations for sendState call and timer that let yac send a
         * vote for @a hash @a times_to_send_state times according to the @a
         * order.
         * @param order of the sends to check
         * @param hash to expect in the message
         * @param times_to_send_state times to recur the sending through timer
         */
        void setNetworkOrderCheckerSingleVote(
            const ClusterOrdering &order,
            ::testing::Matcher<const YacHash &> hash,
            size_t times_to_send_state) {
          using namespace testing;

          timer->setInvokeEnabled(true);

          InSequence seq;

          EXPECT_CALL(
              *network,
              sendState(_, ElementsAre(Field(&VoteMessage::hash, hash))))
              .Times(times_to_send_state)
              .WillRepeatedly(makeSendStateOrderChecker(order));

          // stop after sending a vote \a times_to_send_state times.
          EXPECT_CALL(
              *network,
              sendState(_, ElementsAre(Field(&VoteMessage::hash, hash))))
              .WillOnce(InvokeWithoutArgs(
                  [this] { timer->setInvokeEnabled(false); }));
        }

        /**
         * Set expectations for sendState call that the given yac @a state is
         * sent to each peer according to the @a order
         * @param order of the sends to check
         * @param state to expect
         */
        void setNetworkOrderCheckerYacState(
            const ClusterOrdering &order,
            ::testing::Matcher<const std::vector<VoteMessage> &> state) {
          EXPECT_CALL(*network, sendState(::testing::_, state))
              .Times(order.getPeers().size())
              .WillRepeatedly(makeSendStateOrderChecker(order));
        }

        /**
         * This is a temporary solution to match votes, while we
         * cannot use regular == comparison on mock peers from expected mock
         * function call (this causes a deadlock in gtest).
         * @param hash that peers agreed on
         * @return a matcher that checks that the vote has matching hash
         */
        ::testing::Matcher<const VoteMessage &> makeVoteMatcher(
            ::testing::Matcher<const YacHash &> hash) {
          return ::testing::Field(&VoteMessage::hash, hash);
        }

        /**
         * This is a temporary solution to match commit messagess, while we
         * cannot use regular == comparison on mock peers from expected mock
         * function call (this causes a deadlock in gtest).
         * @param hash that peers agreed on
         * @param number_of_votes in the commit message
         * @return a matcher that checks that the vote vector has @a
         * number_of_votes and each has a matching @a hash
         */
        ::testing::Matcher<const std::vector<VoteMessage> &> makeCommitMatcher(
            ::testing::Matcher<const YacHash &> hash,
            ::testing::Matcher<size_t> number_of_votes) {
          using namespace ::testing;
          return AllOf(SizeIs(number_of_votes), Each(makeVoteMatcher(hash)));
        }
      };

    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha

#endif  // IROHA_YAC_FIXTURE_HPP
