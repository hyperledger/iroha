/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INTEGRATION_FRAMEWORK_FAKE_PEER_BEHAVIOUR_EMPTY_HPP_
#define INTEGRATION_FRAMEWORK_FAKE_PEER_BEHAVIOUR_EMPTY_HPP_

#include <memory>
#include <vector>

#include "framework/integration_framework/fake_peer/behaviour/behaviour.hpp"
#include "framework/integration_framework/fake_peer/fake_peer.hpp"
#include "logger/logger.hpp"

namespace integration_framework {
  namespace fake_peer {

    class EmptyBehaviour : public Behaviour {
     public:
      virtual ~EmptyBehaviour() = default;

      void processYacMessage(
          std::shared_ptr<const YacMessage> message) override;
      void processOsBatch(
          std::shared_ptr<shared_model::interface::TransactionBatch> batch)
          override;
      void processOgProposal(
          std::shared_ptr<shared_model::interface::Proposal> proposal) override;
      LoaderBlockRequestResult processLoaderBlockRequest(
          LoaderBlockRequest request) override;
      LoaderBlocksRequestResult processLoaderBlocksRequest(
          LoaderBlocksRequest request) override;
      OrderingProposalRequestResult processOrderingProposalRequest(
          const OrderingProposalRequest &request) override;
      void processOrderingBatches(const BatchesCollection &batches) override;
    };

  }  // namespace fake_peer
}  // namespace integration_framework

#endif /* INTEGRATION_FRAMEWORK_FAKE_PEER_BEHAVIOUR_EMPTY_HPP_ */
