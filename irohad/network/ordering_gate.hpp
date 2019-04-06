/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ORDERING_GATE_HPP
#define IROHA_ORDERING_GATE_HPP

#include <memory>

#include <rxcpp/rx.hpp>
#include "network/ordering_gate_common.hpp"
#include "network/peer_communication_service.hpp"

namespace shared_model {
  namespace interface {
    class Proposal;
    class TransactionBatch;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {
  namespace network {

    /**
     * Ordering gate provide interface with network transaction order
     */
    class OrderingGate {
     public:
      /**
       * Propagate a transaction batch for further processing
       * @param batch
       * @return bool true if batch was accepted for processing
       */
      virtual bool propagateBatch(
          std::shared_ptr<shared_model::interface::TransactionBatch> batch) = 0;

      /**
       * Return observable of all proposals in the consensus
       * @return observable with notifications
       */
      virtual rxcpp::observable<OrderingEvent> onProposal() = 0;

      /**
       * If propagateBatch returns false, which means the batch was not
       * accepted by the OrderingGate, this observable signals when the
       * OrderingGate is ready to accept more batches, so the propagateBatch
       * method can be called again. The observable emits a rough amount of
       * transactions that the gate is ready to accept for propagation.
       */
      virtual rxcpp::observable<size_t> onReadyToAcceptTxs() = 0;

      virtual ~OrderingGate() = default;
    };
  }  // namespace network
}  // namespace iroha

#endif  // IROHA_ORDERING_GATE_HPP
