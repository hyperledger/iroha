/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ORDERINGSERVICE_H
#define IROHA_ORDERINGSERVICE_H

#include "network/ordering_service_transport.hpp"

namespace iroha {
  namespace network {
    class OrderingService : public network::OrderingServiceNotification {
     public:
      /**
       * Transform model proposal to transport object and send to peers
       * @param proposal - object for propagation
       */
      virtual void publishProposal(
          std::unique_ptr<shared_model::interface::Proposal> proposal) = 0;
    };
  }  // namespace network
}  // namespace iroha
#endif  // IROHA_ORDERINGSERVICE_H
