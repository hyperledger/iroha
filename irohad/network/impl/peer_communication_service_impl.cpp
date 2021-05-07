/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "network/impl/peer_communication_service_impl.hpp"

#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "logger/logger.hpp"
#include "network/ordering_gate.hpp"

namespace iroha {
  namespace network {
    PeerCommunicationServiceImpl::PeerCommunicationServiceImpl(
        std::shared_ptr<OrderingGate> ordering_gate, logger::LoggerPtr log)
        : ordering_gate_(std::move(ordering_gate)), log_{std::move(log)} {}

    void PeerCommunicationServiceImpl::propagate_batch(
        std::shared_ptr<shared_model::interface::TransactionBatch> batch)
        const {
      log_->info("propagate batch");
      ordering_gate_->propagateBatch(batch);
    }
  }  // namespace network
}  // namespace iroha
