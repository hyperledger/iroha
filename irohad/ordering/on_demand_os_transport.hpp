/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ON_DEMAND_OS_TRANSPORT_HPP
#define IROHA_ON_DEMAND_OS_TRANSPORT_HPP

#include <memory>
#include <utility>
#include <vector>

#include <boost/optional.hpp>
#include "common/result_fwd.hpp"
#include "consensus/round.hpp"

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
         * Type of stored proposals
         */
        using ProposalType = shared_model::interface::Proposal;

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
         * Callback on request about proposal
         * @param round - number of collaboration round.
         * Calculated as block_height + 1
         * @return proposal for requested round
         */
        virtual boost::optional<std::shared_ptr<const ProposalType>>
        onRequestProposal(consensus::Round round) = 0;

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

        virtual ~OdOsNotificationFactory() = default;
      };

    }  // namespace transport
  }    // namespace ordering
}  // namespace iroha

#endif  // IROHA_ON_DEMAND_OS_TRANSPORT_HPP
