/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ON_DEMAND_ORDERING_SERVICE_HPP
#define IROHA_ON_DEMAND_ORDERING_SERVICE_HPP

#include <unordered_set>

#include "consensus/round.hpp"
#include "cryptography/hash.hpp"
#include "interfaces/iroha_internal/transaction_batch.hpp"

namespace shared_model {
  namespace interface {
    class TransactionBatch;
    class Proposal;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {
  namespace ordering {

    using ProposalWithHash = std::tuple<
        std::optional<std::shared_ptr<const shared_model::interface::Proposal>>,
        shared_model::crypto::Hash>;

    /**
     * Ordering Service aka OS which can share proposals by request
     */
    class OnDemandOrderingService {
     public:
      virtual ~OnDemandOrderingService() = default;

      /**
       * Type of stored proposals
       */
      using ProposalType = shared_model::interface::Proposal;

      struct BatchPointerHasher {
        shared_model::crypto::Hash::Hasher hasher_;
        size_t operator()(
            const std::shared_ptr<shared_model::interface::TransactionBatch> &a)
            const {
          return hasher_(a->reducedHash());
        }
      };

      using BatchesSetType =
          std::set<std::shared_ptr<shared_model::interface::TransactionBatch>,
                   shared_model::interface::BatchHashLess>;
      //          BatchPointerHasher,
      //          shared_model::interface::BatchHashEquality>;

      /**
       * Type of stored transaction batches
       */
      using TransactionBatchType =
          std::shared_ptr<shared_model::interface::TransactionBatch>;

      /**
       * Type of inserted collections
       */
      using CollectionType = std::vector<TransactionBatchType>;

      /**
       * Callback on receiving transactions
       * @param batches - vector of passed transaction batches
       */
      virtual void onBatches(CollectionType batches) = 0;

      virtual ProposalWithHash onRequestProposal(consensus::Round const &) = 0;

      using HashesSetType =
          std::unordered_set<shared_model::crypto::Hash,
                             shared_model::crypto::Hash::Hasher>;

      /**
       * Method which should be invoked on outcome of collaboration for round
       * @param round - proposal_or_hash round which has started
       */
      virtual void onCollaborationOutcome(consensus::Round round) = 0;

      /**
       * Method to be invoked when transactions commited into ledger.
       * @param hashes - txs list
       */
      virtual void onTxsCommitted(const HashesSetType &hashes) = 0;

      /**
       * Method to be invoked when duplicated transactions detected.
       * @param hashes - txs list
       */
      virtual void onDuplicates(const HashesSetType &hashes) = 0;

      /**
       * Method to get betches under lock
       * @param f - callback function
       */
      virtual void forCachedBatches(
          std::function<void(const BatchesSetType &)> const &f) const = 0;

      virtual bool isEmptyBatchesCache() const = 0;

      virtual bool hasEnoughBatchesInCache() const = 0;

      virtual bool hasProposal(consensus::Round round) const = 0;

      virtual void processReceivedProposal(CollectionType batches) = 0;

      virtual shared_model::crypto::Hash getProposalHash(
          consensus::Round round) = 0;

      virtual ProposalWithHash getProposalWithHash(consensus::Round round) = 0;
    };

  }  // namespace ordering
}  // namespace iroha

#endif  // IROHA_ON_DEMAND_ORDERING_SERVICE_HPP
