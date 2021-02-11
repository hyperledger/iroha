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
      UniqueCreationProposalStrategy(UniqueCreationProposalStrategy const &) =
          delete;
      UniqueCreationProposalStrategy &operator=(
          UniqueCreationProposalStrategy const &) = delete;

      UniqueCreationProposalStrategy(UniqueCreationProposalStrategy &&) =
          delete;
      UniqueCreationProposalStrategy &operator=(
          UniqueCreationProposalStrategy &&) = delete;

      inline bool contains(RoundType round) {
        bool is_exists = false;
        requested_.foreach ([&is_exists, &round](auto /*h*/, auto const &data) {
          if (round == data) {
            is_exists = true;
            return false;
          }
          return true;
        });
        return is_exists;
      }

     public:
      UniqueCreationProposalStrategy() = default;

      void onCollaborationOutcome(RoundType /*round*/,
                                  size_t /*peers_in_round*/) override {}

      bool shouldCreateRound(RoundType round) override {
        std::lock_guard<std::mutex> guard(mutex_);
        return !contains(round);
      }

      boost::optional<RoundType> onProposalRequest(RoundType round) override {
        std::lock_guard<std::mutex> guard(mutex_);
        if (!contains(round)) {
          requested_.push([](auto, auto &) {}, [](auto, auto &) {}, round);
        }
        return boost::none;
      }

     private:
      /// items count is something random must be more than 3
      using RoundCollectionType = containers::RingBuffer<RoundType, 5ull>;

      std::mutex mutex_;
      RoundCollectionType requested_;
    };
  }  // namespace ordering
}  // namespace iroha

#endif  // IROHA_UNIQUE_CREATION_PROPOSAL_STRATEGY_HPP
