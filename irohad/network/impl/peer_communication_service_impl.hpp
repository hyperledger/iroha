/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PEER_COMMUNICATION_SERVICE_IMPL_HPP
#define IROHA_PEER_COMMUNICATION_SERVICE_IMPL_HPP

#include "network/peer_communication_service.hpp"

#include "logger/logger_fwd.hpp"

namespace iroha {
  namespace network {
    class OrderingGate;

    class PeerCommunicationServiceImpl : public PeerCommunicationService {
     public:
      PeerCommunicationServiceImpl(std::shared_ptr<OrderingGate> ordering_gate,
                                   logger::LoggerPtr log);

      void propagate_batch(
          std::shared_ptr<shared_model::interface::TransactionBatch> batch)
          const override;

     private:
      std::shared_ptr<OrderingGate> ordering_gate_;
      logger::LoggerPtr log_;
    };
  }  // namespace network
}  // namespace iroha

#endif  // IROHA_PEER_COMMUNICATION_SERVICE_IMPL_HPP
