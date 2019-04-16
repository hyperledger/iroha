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
      /**
       * Method which should be invoked on outcome of collaboration for round
       * @param round - proposal round which has started
       */
      virtual void onCollaborationOutcome(consensus::Round round) = 0;
    };

  }  // namespace ordering
}  // namespace iroha

#endif  // IROHA_ON_DEMAND_ORDERING_SERVICE_HPP
