/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PEER_COMMUNICATION_SERVICE_HPP
#define IROHA_PEER_COMMUNICATION_SERVICE_HPP

#include <rxcpp/rx.hpp>
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
       * @return bool - true if successfully propagated
       */
      virtual bool propagate_batch(
          std::shared_ptr<shared_model::interface::TransactionBatch> batch)
          const = 0;

      /**
       * Event is triggered when proposal arrives from network.
       * @return observable with Proposals.
       * (List of Proposals)
       */
      virtual rxcpp::observable<OrderingEvent> onProposal() const = 0;

      /**
       * Event is triggered when verified proposal arrives
       * @return verified proposal and list of stateful validation errors
       */
      virtual rxcpp::observable<simulator::VerifiedProposalCreatorEvent>
      onVerifiedProposal() const = 0;

      /**
       * Event is triggered when commit block arrives.
       * @return observable with sequence of committed blocks.
       * In common case observable<Block> will contain one element.
       * But there are scenarios when consensus provide many blocks, e.g.
       * on peer startup - peer will get all actual blocks.
       * Also, it can provide no blocks at all, if commit was empty
       */
      virtual rxcpp::observable<synchronizer::SynchronizationEvent>
      onSynchronization() const = 0;

      virtual ~PeerCommunicationService() = default;
    };

  }  // namespace network
}  // namespace iroha

#endif  // IROHA_PEER_COMMUNICATION_SERVICE_HPP
