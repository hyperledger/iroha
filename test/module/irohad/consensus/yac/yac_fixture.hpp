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

        void TearDown() override {
          network->release();
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
              ordering,
              initial_round,
              rxcpp::observe_on_one_worker(
                  rxcpp::schedulers::make_current_thread()),
              getTestLogger("Yac"));
          network->subscribe(yac);
        }
      };

    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha

#endif  // IROHA_YAC_FIXTURE_HPP
