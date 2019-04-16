/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ON_DEMAND_ORDERING_SERVICE_IMPL_HPP
#define IROHA_ON_DEMAND_ORDERING_SERVICE_IMPL_HPP

#include "ordering/on_demand_ordering_service.hpp"

#include <map>
#include <shared_mutex>

#include <tbb/concurrent_unordered_set.h>
#include "interfaces/iroha_internal/unsafe_proposal_factory.hpp"
#include "logger/logger_fwd.hpp"
#include "multi_sig_transactions/hash.hpp"
// TODO 2019-03-15 andrei: IR-403 Separate BatchHashEquality and MstState
#include "multi_sig_transactions/state/mst_state.hpp"
#include "ordering/impl/on_demand_common.hpp"

namespace iroha {
  namespace ametsuchi {
    class TxPresenceCache;
  }
  namespace ordering {
    namespace detail {
      using BatchSetType = tbb::concurrent_unordered_set<
          transport::OdOsNotification::TransactionBatchType,
          model::PointerBatchHasher,
          BatchHashEquality>;

      using ProposalMapType = std::map<
          consensus::Round,
          std::shared_ptr<const transport::OdOsNotification::ProposalType>>;
    }  // namespace detail

    class OnDemandOrderingServiceImpl : public OnDemandOrderingService {
     public:
      /**
       * Create on_demand ordering service with following options:
       * @param transaction_limit - number of maximum transactions in one
       * proposal
       * @param proposal_factory - used to generate proposals
       * @param tx_cache - cache of transactions
       * @param log to print progress
       * @param number_of_proposals - number of stored proposals, older will be
       * removed. Default value is 3
       * @param initial_round - first round of agreement.
       * Default value is {2, kFirstRejectRound} since genesis block height is 1
       */
      OnDemandOrderingServiceImpl(
          size_t transaction_limit,
          std::shared_ptr<shared_model::interface::UnsafeProposalFactory>
              proposal_factory,
          std::shared_ptr<ametsuchi::TxPresenceCache> tx_cache,
          logger::LoggerPtr log,
          size_t number_of_proposals = 3,
          const consensus::Round &initial_round = {2, kFirstRejectRound});

      // --------------------- | OnDemandOrderingService |_---------------------

      void onCollaborationOutcome(consensus::Round round) override;

      // ----------------------- | OdOsNotification | --------------------------

      void onBatches(CollectionType batches) override;

      boost::optional<std::shared_ptr<const ProposalType>> onRequestProposal(
          consensus::Round round) override;

     private:
      /**
       * Packs new proposals and creates new rounds
       * Note: method is not thread-safe
       */
      void packNextProposals(const consensus::Round &round);

      /**
       * Removes last elements if it is required
       * Method removes the oldest commit or chain of the oldest rejects
       * Note: method is not thread-safe
       */
      void tryErase(const consensus::Round &current_round);

      /**
       * Check if batch was already processed by the peer
       */
      bool batchAlreadyProcessed(
          const shared_model::interface::TransactionBatch &batch);

      /**
       * Max number of transaction in one proposal
       */
      size_t transaction_limit_;

      /**
       * Max number of available proposals in one OS
       */
      size_t number_of_proposals_;

      /**
       * Map of available proposals
       */
      detail::ProposalMapType proposal_map_;

      /**
       * Collections of batches for current round
       */
      detail::BatchSetType pending_batches_;

      /**
       * Batches and proposal collection mutexes for public methods
       */
      std::shared_timed_mutex batches_mutex_, proposals_mutex_;

      std::shared_ptr<shared_model::interface::UnsafeProposalFactory>
          proposal_factory_;

      /**
       * Processed transactions cache used for replay prevention
       */
      std::shared_ptr<ametsuchi::TxPresenceCache> tx_cache_;

      /**
       * Logger instance
       */
      logger::LoggerPtr log_;
    };
  }  // namespace ordering
}  // namespace iroha

#endif  // IROHA_ON_DEMAND_ORDERING_SERVICE_IMPL_HPP
