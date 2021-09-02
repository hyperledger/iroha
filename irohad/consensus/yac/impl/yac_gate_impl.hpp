/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_YAC_GATE_IMPL_HPP
#define IROHA_YAC_GATE_IMPL_HPP

#include "consensus/yac/yac_gate.hpp"

#include <memory>
#include <optional>

#include "consensus/consensus_block_cache.hpp"
#include "consensus/gate_object.hpp"
#include "consensus/yac/consensus_outcome_type.hpp"
#include "consensus/yac/storage/storage_result.hpp"
#include "consensus/yac/yac_hash_provider.hpp"
#include "logger/logger_fwd.hpp"

namespace iroha {
  namespace simulator {
    class BlockCreator;
  }
  namespace network {
    class BlockLoader;
  }
}  // namespace iroha

namespace iroha::consensus::yac {
  struct CommitMessage;
  class YacPeerOrderer;

  class YacGateImpl : public YacGate {
   public:
    YacGateImpl(
        std::shared_ptr<HashGate> hash_gate,
        std::shared_ptr<YacPeerOrderer> orderer,
        std::optional<ClusterOrdering> alternative_order,
        std::shared_ptr<const LedgerState> ledger_state,
        std::shared_ptr<YacHashProvider> hash_provider,
        std::shared_ptr<consensus::ConsensusResultCache> consensus_result_cache,
        logger::LoggerPtr log);
    void vote(const simulator::BlockCreatorEvent &event) override;

    std::optional<GateObject> processOutcome(Answer const &outcome);

    void stop() override;

    std::optional<GateObject> processRoundSwitch(
        consensus::Round const &round,
        std::shared_ptr<LedgerState const> ledger_state);

   private:
    /**
     * Update current block with signatures from commit message
     * @param commit - commit message to get signatures from
     */
    void copySignatures(const CommitMessage &commit);

    std::optional<GateObject> handleCommit(const CommitMessage &msg);
    std::optional<GateObject> handleReject(const RejectMessage &msg);
    std::optional<GateObject> handleFuture(const FutureMessage &msg);

    logger::LoggerPtr log_;

    std::optional<std::shared_ptr<shared_model::interface::Block>>
        current_block_;
    YacHash current_hash_;
    std::optional<ClusterOrdering> alternative_order_;
    std::shared_ptr<const LedgerState> current_ledger_state_;

    std::shared_ptr<YacPeerOrderer> orderer_;
    std::shared_ptr<YacHashProvider> hash_provider_;
    std::shared_ptr<consensus::ConsensusResultCache> consensus_result_cache_;
    std::shared_ptr<HashGate> hash_gate_;
  };
}  // namespace iroha::consensus::yac

#endif  // IROHA_YAC_GATE_IMPL_HPP
