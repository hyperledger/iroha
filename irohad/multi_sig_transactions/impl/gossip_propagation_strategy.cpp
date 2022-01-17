/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "multi_sig_transactions/gossip_propagation_strategy.hpp"

#include <numeric>
#include <random>

#include <boost/assert.hpp>
#include <boost/range/irange.hpp>
#include <rxcpp/operators/rx-map.hpp>
#include "common/bind.hpp"

namespace iroha {

  using PropagationData = PropagationStrategy::PropagationData;
  using OptPeer = GossipPropagationStrategy::OptPeer;
  using PeerProviderFactory = GossipPropagationStrategy::PeerProviderFactory;
  using std::chrono::steady_clock;

  GossipPropagationStrategy::GossipPropagationStrategy(
      PeerProviderFactory peer_factory,
      rxcpp::observe_on_one_worker emit_worker,
      const GossipPropagationStrategyParams &params)
      : peer_factory(peer_factory),
        non_visited({}),
        emit_worker(emit_worker),
        emitent(rxcpp::observable<>::interval(
                    steady_clock::now(), params.emission_period, emit_worker)
                    .map([this, params](int) {
                      PropagationData vec;
                      auto range = boost::irange(0u, params.amount_per_once);
                      // push until find empty element
                      std::find_if_not(
                          range.begin(), range.end(), [this, &vec](int) {
                            return this->visit() | [&vec](auto e) -> bool {
                              vec.push_back(e);
                              return true;  // proceed
                            };
                          });
                      return vec;
                    })) {}

  rxcpp::observable<PropagationData> GossipPropagationStrategy::emitter() {
    return emitent;
  }

  GossipPropagationStrategy::~GossipPropagationStrategy() {
    // Make sure that emitent callback have finish and haven't started yet
    std::lock_guard<std::mutex> lock(m);
    peer_factory.reset();
  }

  bool GossipPropagationStrategy::initQueue() {
    return peer_factory->createPeerQuery() | [](const auto &query) {
      return query->getLedgerPeers(false);
    } | [](auto &&data) -> boost::optional<PropagationData> {
      if (data.size() == 0) {
        return {};
      }
      return std::move(data);
    } | [this](auto &&data) -> bool {  // nullopt implicitly casts to false
      this->last_data = std::move(data);
      this->non_visited.resize(this->last_data.size());
      std::iota(this->non_visited.begin(), this->non_visited.end(), 0);
      std::shuffle(this->non_visited.begin(),
                   this->non_visited.end(),
                   std::default_random_engine{});
      return true;
    };
  }

  OptPeer GossipPropagationStrategy::visit() {
    std::lock_guard<std::mutex> lock(m);
    if (not peer_factory or (non_visited.empty() and not initQueue())) {
      // either PeerProvider doesn't gives peers / dtor have been called
      return {};
    }
    // or non_visited non-empty
    BOOST_ASSERT(not non_visited.empty());
    BOOST_ASSERT(non_visited.back() < last_data.size());

    auto el = last_data[non_visited.back()];
    non_visited.pop_back();
    return el;
  }

}  // namespace iroha
