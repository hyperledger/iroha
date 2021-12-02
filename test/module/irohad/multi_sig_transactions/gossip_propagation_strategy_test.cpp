/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "multi_sig_transactions/gossip_propagation_strategy.hpp"

#include <algorithm>
#include <iterator>
#include <memory>
#include <numeric>
#include <string>
#include <thread>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <boost/range/irange.hpp>
#include <rxcpp/rx-lite.hpp>
#include "ametsuchi/peer_query_factory.hpp"
#include "module/irohad/ametsuchi/ametsuchi_mocks.hpp"
#include "module/irohad/multi_sig_transactions/mst_test_helpers.hpp"
#include "module/shared_model/interface_mocks.hpp"

#include <rxcpp/operators/rx-take.hpp>

using namespace iroha;

using namespace std::chrono_literals;
using namespace iroha::ametsuchi;
using PropagationData = GossipPropagationStrategy::PropagationData;

/**
 * Generates peers with empty pub keys
 * @param ids generated addresses of peers
 * @param amount for generation
 * @return generated peers
 */
PropagationData generate(std::vector<std::string> &ids, size_t num) {
  ids.resize(num);
  std::iota(ids.begin(), ids.end(), 'a');
  PropagationData peers;
  std::transform(
      ids.begin(), ids.end(), std::back_inserter(peers), [](auto &s) {
        return makePeer(
            s, shared_model::interface::types::PublicKeyHexStringView{});
      });
  return peers;
}

/**
 * Perform subscription and the emitting from specified strategy
 * @param strategy is emitter source
 * @param take is amount taken from the strategy emitter
 * @return emitted data
 */
PropagationData subscribeAndEmit(GossipPropagationStrategy &strategy,
                                 uint32_t take) {
  PropagationData emitted;
  auto subscriber = rxcpp::make_subscriber<PropagationData>([&emitted](auto v) {
    std::copy(v.begin(), v.end(), std::back_inserter(emitted));
  });
  strategy.emitter().take(take).as_blocking().subscribe(subscriber);

  return emitted;
}

/**
 * Perform subscription and the emitting from created strategy
 * @param data retrieved from the PeerProvider
 * @param period of the strategy
 * @param amount emit per once
 * @param take is amount taken from the strategy emitter
 * @return emitted data
 */
PropagationData subscribeAndEmit(boost::optional<PropagationData> data,
                                 std::chrono::milliseconds period,
                                 uint32_t amount,
                                 uint32_t take) {
  auto query = std::make_shared<MockPeerQuery>();
  EXPECT_CALL(*query, getLedgerPeers(false))
      .WillRepeatedly(testing::Return(data));
  auto pbfactory = std::make_shared<MockPeerQueryFactory>();
  EXPECT_CALL(*pbfactory, createPeerQuery())
      .WillRepeatedly(testing::Return(boost::make_optional(
          std::shared_ptr<iroha::ametsuchi::PeerQuery>(query))));
  iroha::GossipPropagationStrategyParams gossip_params;
  gossip_params.emission_period = period;
  gossip_params.amount_per_once = amount;
  GossipPropagationStrategy strategy(
      pbfactory, rxcpp::observe_on_event_loop(), gossip_params);
  return subscribeAndEmit(strategy, take);
}

/**
 * Checks the emitted data is being subset of peers
 * @param emitted is data from observable
 * @param peersId is a collection of peers
 * @return true if the emitted data is a peer subset
 */
bool validateEmitted(const PropagationData &emitted,
                     const std::vector<std::string> &peersId) {
  return std::find_if(
             emitted.begin(),
             emitted.end(),
             [&peersId, flag = true](const auto &v) mutable {
               if (flag
                   and std::find(peersId.begin(), peersId.end(), v->address())
                       == peersId.end())
                 flag = false;
               return flag;
             })
      != emitted.end();
}

/**
 * @given list of peers and
 *        strategy that emits two peers
 * @when strategy emits this peers
 * @then ensure that all peers are being emitted
 */
TEST(GossipPropagationStrategyTest, EmittingAllPeers) {
  auto peers_size = 23, amount = 2, take = peers_size / amount;
  std::vector<std::string> peersId;
  PropagationData peers = generate(peersId, peers_size);

  auto emitted = subscribeAndEmit(peers, 1ms, amount, take);

  // emitted.size() can be less than peers.size()
  ASSERT_GE(peers.size(), emitted.size());
  // because emitted size should be increased by amount at once
  ASSERT_FALSE(emitted.size() % amount);
  ASSERT_TRUE(validateEmitted(emitted, peersId));
}

/**
 * @given list of peers and
 *        strategy that emits two peers
 * @when strategy emits more than peers available
 * @then ensure that there's been emitted peers
 */
TEST(GossipPropagationStrategyTest, EmitEvenOnOddPeers) {
  auto peers_size = 11, amount = 2, take = 6;
  std::vector<std::string> peersId;
  PropagationData peers = generate(peersId, peers_size);

  auto emitted = subscribeAndEmit(peers, 1ms, amount, take);

  ASSERT_EQ(emitted.size(), take * amount);
  ASSERT_LE(peers.size(), emitted.size());
  ASSERT_TRUE(validateEmitted(emitted, peersId));
}

/**
 * @given no peers and strategy
 * @when strategy emits this peers
 * @then ensure that empty peer list is emitted
 */
TEST(GossipPropagationStrategyTest, EmptyEmitting) {
  auto emitted = subscribeAndEmit(PropagationData{}, 1ms, 1, 13);
  ASSERT_EQ(emitted.size(), 0);
}

/**
 * @given nullopt emitting instead of peers list and strategy
 * @when strategy emits this peers
 * @then ensure that empty peer list is emitted
 */
TEST(GossipPropagationStrategyTest, ErrorEmitting) {
  auto emitted = subscribeAndEmit(boost::none, 1ms, 1, 13);
  ASSERT_EQ(emitted.size(), 0);
}

/**
 * @given list of peers and
 *        strategy that emits two peers
 * @when strategy emits more than peers available
 * @then ensure that there's been emitted peers
 */
TEST(GossipPropagationStrategyTest, MultipleSubsEmission) {
  auto peers_size = 10, take = 10;
  uint32_t amount = 2;
  constexpr auto threads = 10;
  std::vector<std::string> peersId;
  PropagationData peers = generate(peersId, peers_size);

  // subscribers for the propagation emitter
  std::thread ths[threads];
  // Emitted data
  PropagationData result[threads];
  auto range = boost::irange(0, threads);

  auto query = std::make_shared<MockPeerQuery>();
  auto pbfactory = std::make_shared<MockPeerQueryFactory>();
  EXPECT_CALL(*pbfactory, createPeerQuery())
      .WillRepeatedly(testing::Return(boost::make_optional(
          std::shared_ptr<iroha::ametsuchi::PeerQuery>(query))));
  EXPECT_CALL(*query, getLedgerPeers(false))
      .WillRepeatedly(testing::Return(peers));
  iroha::GossipPropagationStrategyParams gossip_params;
  gossip_params.emission_period = 1ms;
  gossip_params.amount_per_once = amount;
  GossipPropagationStrategy strategy(
      pbfactory, rxcpp::observe_on_new_thread(), gossip_params);

  // Create separate subscriber for every thread
  // Use result[i] as storage for emitent for i-th one
  std::transform(range.begin(), range.end(), std::begin(ths), [&](auto i) {
    return std::thread([take, &res = result[i], &strategy] {
      res = subscribeAndEmit(strategy, take);
    });
  });

  // Wait until all thread is finished and ensure all threads have emitted peers
  std::for_each(range.begin(), range.end(), [&](auto i) {
    ths[i].join();
    ASSERT_EQ(result[i].size(), take * amount);
    ASSERT_TRUE(validateEmitted(result[i], peersId));
  });
}
