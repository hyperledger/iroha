/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ORDERING_SERVICE_PROPOSAL_CREATION_STRATEGY_HPP
#define IROHA_ORDERING_SERVICE_PROPOSAL_CREATION_STRATEGY_HPP

#include <boost/optional.hpp>
#include <boost/range/any_range.hpp>
#include "consensus/round.hpp"
#include "cryptography/public_key.hpp"

namespace iroha {
  namespace ordering {

    /**
     * Class provides a strategy for creation proposals regarding to new rounds
     * and requests from other peers
     */
    class ProposalCreationStrategy {
     public:
      /// shortcut for round type
      using RoundType = consensus::Round;

      /**
       * Indicates the start of new round.
       * @param round - proposal round which has started
       * @param peers_in_round - peers which participate in new round
       */
      virtual void onCollaborationOutcome(RoundType round,
                                          size_t peers_in_round) = 0;

      /**
       * @param round - new consensus round
       * @param on_create - lambda which invokes when the round should be
       * created
       */
      virtual void shouldCreateRound(
          RoundType round, const std::function<void()> &on_create) = 0;

      /**
       * Notify the strategy about proposal request
       * @param requested_round - in which round proposal is requested
       * @return round where proposal is required to be created immediately
       */
      virtual boost::optional<RoundType> onProposalRequest(
          RoundType requested_round) = 0;

      virtual ~ProposalCreationStrategy() = default;
    };
  }  // namespace ordering
}  // namespace iroha

#endif  // IROHA_ORDERING_SERVICE_PROPOSAL_CREATION_STRATEGY_HPP
