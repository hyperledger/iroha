/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INTEGRATION_FRAMEWORK_FAKE_PEER_BEHAVIOUR_HONEST_HPP_
#define INTEGRATION_FRAMEWORK_FAKE_PEER_BEHAVIOUR_HONEST_HPP_

#include "framework/integration_framework/fake_peer/behaviour/empty.hpp"

#include "interfaces/iroha_internal/proposal_factory.hpp"

namespace integration_framework {
  namespace fake_peer {

    class HonestBehaviour : public EmptyBehaviour {
     public:
      void processYacMessage(
          std::shared_ptr<const YacMessage> message) override;
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

#endif /* INTEGRATION_FRAMEWORK_FAKE_PEER_BEHAVIOUR_HONEST_HPP_ */
