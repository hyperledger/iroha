/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ON_DEMAND_ORDERING_SERVICE_IMPL_HPP
#define IROHA_ON_DEMAND_ORDERING_SERVICE_IMPL_HPP

#include "ordering/on_demand_ordering_service.hpp"

#include <map>
#include <mutex>
#include <shared_mutex>

#include "interfaces/iroha_internal/unsafe_proposal_factory.hpp"
#include "logger/logger_fwd.hpp"
#include "ordering/impl/batches_cache.hpp"
// TODO 2019-03-15 andrei: IR-403 Separate BatchHashEquality and MstState
#include "main/subscription.hpp"
#include "ordering/impl/on_demand_common.hpp"

namespace iroha {
  namespace ametsuchi {
    class TxPresenceCache;
  }
  namespace ordering {
    namespace detail {
      using ProposalMapType =
          std::map<consensus::BlockRoundType, PackedProposalData>;
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
       */
      OnDemandOrderingServiceImpl(
          size_t transaction_limit,
          uint32_t max_proposal_pack,
          std::shared_ptr<shared_model::interface::UnsafeProposalFactory>
              proposal_factory,
          std::shared_ptr<ametsuchi::TxPresenceCache> tx_cache,
          logger::LoggerPtr log,
          size_t number_of_proposals = 3);

      ~OnDemandOrderingServiceImpl() override;

      // --------------------- | OnDemandOrderingService |_---------------------

      void onBatches(CollectionType batches) override;

      PackedProposalData onRequestProposal(consensus::Round round) override;

      void onCollaborationOutcome(consensus::Round round) override;

      void onTxsCommitted(const HashesSetType &hashes) override {
        removeFromBatchesCache(hashes);
      }

      void onDuplicates(const HashesSetType &hashes) override {
        removeFromBatchesCache(hashes);
      }

      void processReceivedProposal(CollectionType batches) override;

      PackedProposalData waitForLocalProposal(
          consensus::Round const &round,
          std::chrono::milliseconds const &delay) override;

     private:
      /**
       * Packs new proposals and creates new rounds
       * Note: method is not thread-safe
       */
      PackedProposalData packNextProposals(const consensus::Round &round);

      using TransactionsCollectionType =
          std::vector<std::shared_ptr<shared_model::interface::Transaction>>;

      std::optional<std::shared_ptr<shared_model::interface::Proposal>>
      tryCreateProposal(
          consensus::Round const &round,
          const TransactionsCollectionType &txs,
          shared_model::interface::types::TimestampType created_time);

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

      bool insertBatchToCache(
          std::shared_ptr<shared_model::interface::TransactionBatch> const
              &batch);

      void removeFromBatchesCache(
          const OnDemandOrderingService::HashesSetType &hashes);

      bool isEmptyBatchesCache() override;

      uint32_t availableTxsCountBatchesCache() override;

      bool hasEnoughBatchesInCache() const override;

      void forCachedBatches(
          std::function<void(BatchesSetType &)> const &f) override;

      bool hasProposal(consensus::Round round) const override;

      /**
       * Max number of transaction in one proposal
       */
      size_t transaction_limit_;

      /**
       * Max number of available proposals in one OS
       */
      size_t number_of_proposals_;

      /**
       * Maximum proposals count in a pack.
       */
      uint32_t const max_proposal_pack_;

      /**
       * Map of available proposals
       */
      detail::ProposalMapType proposal_map_;

      /**
       * Proposal collection mutexes for public methods
       */
      mutable std::mutex proposals_mutex_;

      BatchesCache batches_cache_;

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

      /**
       * Current round
       */
      consensus::Round current_round_;

      std::shared_ptr<
          iroha::BaseSubscriber<bool, RemoteProposalDownloadedEvent>>
          remote_proposal_observer_;
    };
  }  // namespace ordering
}  // namespace iroha

#endif  // IROHA_ON_DEMAND_ORDERING_SERVICE_IMPL_HPP
