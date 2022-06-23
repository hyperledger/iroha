/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ON_DEMAND_OS_TRANSPORT_HPP
#define IROHA_ON_DEMAND_OS_TRANSPORT_HPP

#include <chrono>
#include <memory>
#include <utility>
#include <vector>

#include "common/result_fwd.hpp"
#include "consensus/round.hpp"
#include "interfaces/iroha_internal/proposal.hpp"
#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "ordering/ordering_types.hpp"

namespace shared_model {
  namespace interface {
    class TransactionBatch;
    class Proposal;
    class Peer;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {
  namespace ordering {
    namespace transport {

      /**
       * Notification interface of on demand ordering service.
       */
      class OdOsNotification {
       public:
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

        /**
         * Callback on receiving transactions, propagated to whole network.
         * @param batches - vector of passed transaction batches
         */
        virtual void onBatchesToWholeNetwork(CollectionType batches) = 0;

        /**
         * Callback on request about proposal
         * @param round - number of collaboration round.
         * Calculated as block_height + 1
         * @param proposal data with Bloom filter
         */
        virtual void onRequestProposal(consensus::Round round,
                                       PackedProposalData ref_proposal) = 0;

        /**
         * @return delay proposal to wait for.
         */
        virtual std::chrono::milliseconds getRequestDelay() const = 0;

        virtual ~OdOsNotification() = default;
      };

      /**
       * Factory for creating communication interface to a specific peer
       */
      class OdOsNotificationFactory {
       public:
        /**
         * Create corresponding OdOsNotification interface for peer
         * Returned pointer is guaranteed to be not equal to nullptr
         * @param peer - peer to connect
         * @return connection represented with OdOsNotification interface
         */
        virtual iroha::expected::Result<std::unique_ptr<OdOsNotification>,
                                        std::string>
        create(const shared_model::interface::Peer &to) = 0;

        /**
         * @return delay proposal to wait for.
         */
        virtual std::chrono::milliseconds getRequestDelay() const = 0;

        virtual ~OdOsNotificationFactory() = default;
      };

    }  // namespace transport
  }    // namespace ordering
}  // namespace iroha

#endif  // IROHA_ON_DEMAND_OS_TRANSPORT_HPP
