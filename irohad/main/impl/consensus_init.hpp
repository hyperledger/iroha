/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CONSENSUS_INIT_HPP
#define IROHA_CONSENSUS_INIT_HPP

#include <memory>

#include "consensus/consensus_block_cache.hpp"
#include "consensus/gate_object.hpp"
#include "consensus/yac/consensus_outcome_type.hpp"
#include "consensus/yac/consistency_model.hpp"
#include "consensus/yac/outcome_messages.hpp"
#include "consensus/yac/timer.hpp"
#include "consensus/yac/transport/impl/consensus_service_impl.hpp"
#include "consensus/yac/yac_gate.hpp"
#include "consensus/yac/yac_hash_provider.hpp"
#include "consensus/yac/yac_peer_orderer.hpp"
#include "cryptography/keypair.hpp"
#include "logger/logger_manager_fwd.hpp"
#include "main/subscription_fwd.hpp"
#include "network/block_loader.hpp"

namespace iroha::network {
  class GenericClientFactory;
}

namespace iroha::consensus::yac {
  class Yac;
  class YacGateImpl;

  class YacInit {
   public:
    std::shared_ptr<YacGate> initConsensusGate(
        Round initial_round,
        std::optional<shared_model::interface::types::PeerList>
            alternative_peers,
        std::shared_ptr<const LedgerState> ledger_state,
        std::shared_ptr<network::BlockLoader> block_loader,
        const shared_model::crypto::Keypair &keypair,
        std::shared_ptr<consensus::ConsensusResultCache> block_cache,
        std::chrono::milliseconds vote_delay_milliseconds,
        ConsistencyModel consistency_model,
        const logger::LoggerManagerTreePtr &consensus_log_manager,
        std::shared_ptr<iroha::network::GenericClientFactory> client_factory,
        bool syncing_mode);

    std::shared_ptr<ServiceImpl> getConsensusNetwork() const;

    void subscribe(std::function<void(GateObject const &)> callback);

    std::optional<GateObject> processRoundSwitch(
        consensus::Round const &round,
        std::shared_ptr<LedgerState const> ledger_state);

   private:
    auto createTimer(std::chrono::milliseconds delay_milliseconds);

    bool initialized_{false};
    std::shared_ptr<ServiceImpl> consensus_network_;
    std::shared_ptr<Yac> yac_;
    std::shared_ptr<YacGateImpl> yac_gate_;
    std::shared_ptr<BaseSubscriber<bool, std::vector<VoteMessage>>>
        states_subscription_;
  };
}  // namespace iroha::consensus::yac

#endif  // IROHA_CONSENSUS_INIT_HPP
