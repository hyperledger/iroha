/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_UNIQUE_CREATION_PROPOSAL_STRATEGY_HPP
#define IROHA_UNIQUE_CREATION_PROPOSAL_STRATEGY_HPP

#include "ordering/ordering_service_proposal_creation_strategy.hpp"

#include <memory>
#include <mutex>

#include "common/ring_buffer.hpp"

namespace iroha {
  namespace ordering {

    /**
     * Creating proposal once a round
     */
    class UniqueCreationProposalStrategy : public ProposalCreationStrategy {
      UniqueCreationProposalStrategy(UniqueCreationProposalStrategy const &) = delete;
      UniqueCreationProposalStrategy &operator=(UniqueCreationProposalStrategy const &) = delete;

      UniqueCreationProposalStrategy(UniqueCreationProposalStrategy&&) = delete;
      UniqueCreationProposalStrategy &operator=(UniqueCreationProposalStrategy&&) = delete;

     public:
      UniqueCreationProposalStrategy() = default;

      void onCollaborationOutcome(RoundType /*round*/, size_t /*peers_in_round*/) override { }

      bool shouldCreateRound(RoundType round) override {
        std::lock_guard<std::mutex> guard(mutex_);
        bool was_requested = false;
        requested_.foreach (
            [&was_requested, &round](auto /*h*/, auto const &data) {
              if (round == data) {
                was_requested = true;
                return false;
              }
              return true;
            });

        if (!was_requested) {
          requested_.push([](auto, auto &) {}, [](auto, auto &) {}, round);
        }
        return !was_requested;
      }

      boost::optional<RoundType> onProposalRequest(
          RoundType requested_round) override {
        return boost::none;
      }

     private:
      using RoundCollectionType = containers::RingBuffer<RoundType, 3ull>;

      std::mutex mutex_;
      RoundCollectionType requested_;
    };
  }  // namespace ordering
}  // namespace iroha

#endif  // IROHA_UNIQUE_CREATION_PROPOSAL_STRATEGY_HPP
