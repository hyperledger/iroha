/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_ORDERING_SERVICE_TRANSPORT_H
#define IROHA_ORDERING_SERVICE_TRANSPORT_H

#include <memory>
#include "interfaces/iroha_internal/proposal.hpp"
#include "interfaces/iroha_internal/transaction_batch.hpp"

namespace iroha {
  namespace network {

    /**
     * OrderingServiceNotification is a base class for any ordering service
     * implementation that want to be notified about incoming proposals
     */
    class OrderingServiceNotification {
     public:
      /**
       * Callback on receiving transaction(s)
       * @param batch object, in which transaction(s) are packed
       */
      virtual void onBatch(
          std::unique_ptr<shared_model::interface::TransactionBatch> batch) = 0;

      virtual ~OrderingServiceNotification() = default;
    };

    /**
     * A generic transport interface for ordering service, any output
     * transaction must go through this transport Moreover, it receives
     * transaction and then routes it to a subscriber
     */
    class OrderingServiceTransport {
     public:
      /**
       * Subscribes a notification class to current transport
       * @param subscriber : A pointer to OrderingServiceNotification, that
       * needs to be notified
       */
      virtual void subscribe(
          std::shared_ptr<OrderingServiceNotification> subscriber) = 0;

      /**
       * Publishes proposal over network
       * @param proposal : proposal to be published
       */
      virtual void publishProposal(
          std::unique_ptr<shared_model::interface::Proposal> proposal,
          const std::vector<std::string> &peers) = 0;

      virtual ~OrderingServiceTransport() = default;
    };

  }  // namespace network
}  // namespace iroha

#endif  // IROHA_ORDERING_SERVICE_TRANSPORT_H
