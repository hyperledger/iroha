/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_GOSSIP_PROPAGATION_STRATEGY_HPP
#define IROHA_GOSSIP_PROPAGATION_STRATEGY_HPP

#include <optional>
#include <chrono>
#include <mutex>

#include <rxcpp/rx-lite.hpp>
#include "ametsuchi/peer_query_factory.hpp"
#include "multi_sig_transactions/gossip_propagation_strategy_params.hpp"
#include "multi_sig_transactions/mst_propagation_strategy.hpp"

#include <rxcpp/operators/rx-observe_on.hpp>

namespace iroha {

  /**
   * This class provides strategy for propagation states in network
   * Emits exactly (or zero if provider is empty) amount of peers
   * at some period
   * note: it can be inconsistent with the peer provider
   */
  class GossipPropagationStrategy : public PropagationStrategy {
   public:
    using PeerProviderFactory = std::shared_ptr<ametsuchi::PeerQueryFactory>;
    using OptPeer = std::optional<PropagationData::value_type>;
    /**
     * Initialize strategy with
     * @param peer_factory is a provider of peer list
     * @param emit_worker is the coordinator for the data emitting
     * @param params configuration parameters
     */
    GossipPropagationStrategy(
        // TODO 30.01.2019 lebdron: IR-266 Remove PeerQueryFactory
        PeerProviderFactory peer_factory,
        rxcpp::observe_on_one_worker emit_worker,
        const GossipPropagationStrategyParams &params);

    ~GossipPropagationStrategy();

    // ------------------| PropagationStrategy override |------------------

    rxcpp::observable<PropagationData> emitter() override;

    // --------------------------| end override |---------------------------
   private:
    /**
     * Source of peers for propagation
     */
    PeerProviderFactory peer_factory;

    /**
     * Cache of peer provider's data
     */
    PropagationData last_data;

    /**
     * Queue that contains non-emitted indexes of peers
     */
    std::vector<size_t> non_visited;

    /**
     * Worker that performs internal loop handling
     */
    rxcpp::observe_on_one_worker emit_worker;

    /*
     * Observable for the emitting propagated data
     */
    rxcpp::observable<PropagationData> emitent;

    /*
     * Mutex for handling observable stopping
     */
    std::mutex m;

    /**
     * Fill a queue with a random ordered list of peers
     * @return true if query to PeerProvider was successful
     */
    bool initQueue();

    /**
     * Visit next element of non_visited
     * @return following peer
     */
    OptPeer visit();
  };
}  // namespace iroha

#endif  // IROHA_GOSSIP_PROPAGATION_STRATEGY_HPP
