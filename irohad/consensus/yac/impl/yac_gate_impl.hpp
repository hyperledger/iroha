/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_YAC_GATE_IMPL_HPP
#define IROHA_YAC_GATE_IMPL_HPP

#include "consensus/yac/yac_gate.hpp"

#include <memory>

#include <rxcpp/rx-lite.hpp>
#include "consensus/consensus_block_cache.hpp"
#include "consensus/yac/consensus_outcome_type.hpp"
#include "consensus/yac/impl/consensus_outcome_delay.hpp"
#include "consensus/yac/yac_hash_provider.hpp"
#include "logger/logger_fwd.hpp"
#include "main/subscription.hpp"
#include "synchronizer/synchronizer_common.hpp"

namespace iroha {

  namespace simulator {
    class BlockCreator;
  }

  namespace network {
    class BlockLoader;
  }

  namespace consensus {
    namespace yac {

      struct CommitMessage;
      class YacPeerOrderer;

      class YacGateImpl : public YacGate,
                          public std::enable_shared_from_this<YacGateImpl> {
       public:
        YacGateImpl(
            std::shared_ptr<HashGate> hash_gate,
            std::shared_ptr<YacPeerOrderer> orderer,
            boost::optional<ClusterOrdering> alternative_order,
            std::shared_ptr<const LedgerState> ledger_state,
            std::shared_ptr<YacHashProvider> hash_provider,
            std::shared_ptr<simulator::BlockCreator> block_creator,
            std::shared_ptr<consensus::ConsensusResultCache>
                consensus_result_cache,
            logger::LoggerPtr log,
            std::function<std::chrono::milliseconds(ConsensusOutcomeType)>
                delay_func =
                    ConsensusOutcomeDelay(std::chrono::milliseconds(0)));
        void vote(const simulator::BlockCreatorEvent &event) override;
        void initialize();

        void stop() override;

       private:
        /**
         * Update current block with signatures from commit message
         * @param commit - commit message to get signatures from
         */
        void copySignatures(const CommitMessage &commit);

        void handleCommit(const CommitMessage &msg);
        void handleReject(const RejectMessage &msg);
        void handleFuture(const FutureMessage &msg);

        logger::LoggerPtr log_;

        boost::optional<std::shared_ptr<shared_model::interface::Block>>
            current_block_;
        YacHash current_hash_;
        boost::optional<ClusterOrdering> alternative_order_;
        std::shared_ptr<const LedgerState> current_ledger_state_;

        std::shared_ptr<YacPeerOrderer> orderer_;
        std::shared_ptr<YacHashProvider> hash_provider_;
        std::shared_ptr<simulator::BlockCreator> block_creator_;
        std::shared_ptr<consensus::ConsensusResultCache>
            consensus_result_cache_;
        std::shared_ptr<HashGate> hash_gate_;

        std::shared_ptr<BaseSubscriber<bool, Answer>> outcome_subscription_;
        std::shared_ptr<BaseSubscriber<bool, Answer>>
            delayed_outcome_subscription_;
        std::shared_ptr<BaseSubscriber<bool, simulator::BlockCreatorEvent>>
            block_creator_subscription_;
        std::shared_ptr<
            BaseSubscriber<bool, synchronizer::SynchronizationEvent>>
            ledger_state_subscription_;
        std::function<std::chrono::milliseconds(ConsensusOutcomeType)>
            delay_func_;
      };

    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha

#endif  // IROHA_YAC_GATE_IMPL_HPP
