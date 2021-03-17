/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PEER_COMMUNICATION_SERVICE_HPP
#define IROHA_PEER_COMMUNICATION_SERVICE_HPP

#include <rxcpp/rx-observable-fwd.hpp>
#include "network/ordering_gate_common.hpp"
#include "simulator/verified_proposal_creator_common.hpp"
#include "synchronizer/synchronizer_common.hpp"

namespace shared_model {
  namespace interface {
    class Proposal;
    class TransactionBatch;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {
  namespace network {

    /**
     * Public API for notification about domain data
     */
    class PeerCommunicationService {
     public:
      /**
       * Propagate batch to the network
       * @param batch - batch for propagation
       */
      virtual void propagate_batch(
          std::shared_ptr<shared_model::interface::TransactionBatch> batch)
          const = 0;

      virtual ~PeerCommunicationService() = default;
    };

  }  // namespace network
}  // namespace iroha

#endif  // IROHA_PEER_COMMUNICATION_SERVICE_HPP
