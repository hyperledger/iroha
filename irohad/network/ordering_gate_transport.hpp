/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_ORDERING_GATE_TRANSPORT_H
#define IROHA_ORDERING_GATE_TRANSPORT_H

#include <memory>

namespace shared_model {
  namespace interface {
    class TransactionBatch;
    class Proposal;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {
  namespace network {

    /**
     * OrderingGateNotification is a base class for any ordering gate
     * implementation that want to be notified about incoming proposals
     */
    class OrderingGateNotification {
     public:
      /**
       * Callback on receiving proposal
       * @param proposal - proposal object itself
       */
      virtual void onProposal(
          std::shared_ptr<shared_model::interface::Proposal>) = 0;

      virtual ~OrderingGateNotification() = default;
    };

    /**
     * A generic transport interface for ordering gate, any output transaction
     * must go through this transport Moreover, it receives transaction and then
     * routes it to a subscriber
     */
    class OrderingGateTransport {
     public:
      /**
       * Subscribes a notification class to current transport
       * @param subscriber : A pointer to OrderingGateNotification, that needs
       * to be notified
       */
      virtual void subscribe(
          std::shared_ptr<OrderingGateNotification> subscriber) = 0;

      /**
       * Propagates transaction batch over network
       * @param batch to be propagated
       */
      virtual void propagateBatch(
          std::shared_ptr<shared_model::interface::TransactionBatch> batch) = 0;

      virtual ~OrderingGateTransport() = default;
    };

  }  // namespace network
}  // namespace iroha

#endif  // IROHA_ORDERING_GATE_TRANSPORT_H
