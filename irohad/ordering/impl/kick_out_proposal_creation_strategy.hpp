/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_KICK_OUT_PROPOSAL_CREATION_STRATEGY_HPP
#define IROHA_KICK_OUT_PROPOSAL_CREATION_STRATEGY_HPP

#include "ordering/ordering_service_proposal_creation_strategy.hpp"

#include <memory>
#include <mutex>
#include <unordered_map>

#include "consensus/yac/supermajority_checker.hpp"
#include "multi_sig_transactions/hash.hpp"

namespace iroha {
  namespace ordering {

    class KickOutProposalCreationStrategy : public ProposalCreationStrategy {
     public:
      using SupermajorityCheckerType =
          iroha::consensus::yac::SupermajorityChecker;
      KickOutProposalCreationStrategy(
          std::shared_ptr<SupermajorityCheckerType> majority_checker);

      /**
       * Update peers state with new peers.
       * Note: the method removes peers which are not participating in consensus
       * and adds new with minimal round
       * @param peers - list of peers which fetched in the last round
       */
      void onCollaborationOutcome(const PeerList &peers) override;

      void shouldCreateRound(RoundType round,
                             const std::function<void()> &on_create) override;

      boost::optional<RoundType> onProposalRequest(
          const PeerType &who, RoundType requested_round) override;

     private:
      using RoundCollectionType =
          std::unordered_map<shared_model::crypto::PublicKey,
                             RoundType,
                             iroha::model::BlobHasher>;

      std::mutex mutex_;
      std::shared_ptr<SupermajorityCheckerType> majority_checker_;
      RoundCollectionType last_requested_;
    };
  }  // namespace ordering
}  // namespace iroha

#endif  // IROHA_KICK_OUT_PROPOSAL_CREATION_STRATEGY_HPP
