/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ON_DEMAND_ORDERING_SERVICE_HPP
#define IROHA_ON_DEMAND_ORDERING_SERVICE_HPP

#include "ordering/on_demand_os_transport.hpp"

namespace iroha {
  namespace ordering {

    /**
     * Ordering Service aka OS which can share proposals by request
     */
    class OnDemandOrderingService : public transport::OdOsNotification {
     public:
      using HashesSetType =
          std::unordered_set<shared_model::crypto::Hash,
                             shared_model::crypto::Hash::Hasher>;

      /**
       * Method which should be invoked on outcome of collaboration for round
       * @param round - proposal round which has started
       */
      virtual void onCollaborationOutcome(consensus::Round round) = 0;

      /**
       * Method to be invoked when transactions commited into ledger.
       * @param hashes - txs list
       */
      virtual void onTxsCommitted(const HashesSetType &hashes) = 0;

      /**
       * Method to get betches under lock
       * @param f - callback function
       */
      virtual void forCachedBatches(
          std::function<void(const transport::OdOsNotification::BatchesSetType
                                 &)> const &f) = 0;
    };

  }  // namespace ordering
}  // namespace iroha

#endif  // IROHA_ON_DEMAND_ORDERING_SERVICE_HPP
