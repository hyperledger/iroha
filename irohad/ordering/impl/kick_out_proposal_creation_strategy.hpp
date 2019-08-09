/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_KICK_OUT_PROPOSAL_CREATION_STRATEGY_HPP
#define IROHA_KICK_OUT_PROPOSAL_CREATION_STRATEGY_HPP

#include "ordering/ordering_service_proposal_creation_strategy.hpp"

#include <map>
#include <memory>
#include <mutex>

#include "consensus/yac/supermajority_checker.hpp"

namespace iroha {
  namespace ordering {

    /**
     * Creation strategy based on supermajority checker tolerance condition
     */
    class KickOutProposalCreationStrategy : public ProposalCreationStrategy {
     public:
      using SupermajorityCheckerType =
          iroha::consensus::yac::SupermajorityChecker;
      KickOutProposalCreationStrategy(
          std::shared_ptr<SupermajorityCheckerType> tolerance_checker);

      void onCollaborationOutcome(RoundType round,
                                  size_t peers_in_round) override;

      bool shouldCreateRound(RoundType round) override;

      boost::optional<RoundType> onProposalRequest(
          RoundType requested_round) override;

     private:
      using RoundCollectionType = std::map<RoundType, size_t>;

      std::mutex mutex_;
      std::shared_ptr<SupermajorityCheckerType> tolerance_checker_;
      size_t peers_in_round_;
      RoundCollectionType requested_count_;
    };
  }  // namespace ordering
}  // namespace iroha

#endif  // IROHA_KICK_OUT_PROPOSAL_CREATION_STRATEGY_HPP
