/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "framework/integration_framework/fake_peer/behaviour/honest.hpp"

#include <boost/algorithm/string/join.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include "backend/protobuf/proto_proposal_factory.hpp"
#include "backend/protobuf/transaction.hpp"
#include "common/result.hpp"
#include "framework/integration_framework/fake_peer/block_storage.hpp"
#include "framework/integration_framework/fake_peer/proposal_storage.hpp"
#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "logger/logger.hpp"
#include "module/shared_model/builders/protobuf/proposal.hpp"
#include "validators/default_validator.hpp"

using namespace iroha::expected;

namespace integration_framework {
  namespace fake_peer {

    void HonestBehaviour::processYacMessage(
        std::shared_ptr<const YacMessage> message) {
      getFakePeer().voteForTheSame(message);
    }

    LoaderBlockRequestResult HonestBehaviour::processLoaderBlockRequest(
        LoaderBlockRequest request) {
      const auto &block_storage = getFakePeer().getBlockStorage();
      if (!block_storage) {
        getLogger()->debug(
            "Got a Loader.retrieveBlock call, but have no block storage!");
        return {};
      }
      const auto block = block_storage->getBlockByHash(*request);
      if (!block) {
        getLogger()->debug(
            "Got a Loader.retrieveBlock call for {}, but have no such block!",
            request->toString());
        return {};
      }
      return block;
    }

    LoaderBlocksRequestResult HonestBehaviour::processLoaderBlocksRequest(
        LoaderBlocksRequest request) {
      const auto block_storage = getFakePeer().getBlockStorage();
      if (!block_storage) {
        getLogger()->debug(
            "Got a Loader.retrieveBlocks call, but have no block storage!");
        return {};
      }
      BlockStorage::HeightType current_height = request;
      std::shared_ptr<const shared_model::proto::Block> block;
      LoaderBlocksRequestResult blocks;
      while ((block = block_storage->getBlockByHeight(current_height++))
             != nullptr) {
        blocks.emplace_back(block);
      }
      return blocks;
    }

    OrderingProposalRequestResult
    HonestBehaviour::processOrderingProposalRequest(
        const OrderingProposalRequest &request) {
      auto opt_proposal =
          getFakePeer().getProposalStorage().getProposal(request);
      getLogger()->debug(
          "Got an OnDemandOrderingService.GetProposal call for round {}, "
          "{}returning a proposal.",
          request.toString(),
          opt_proposal ? "" : "NOT ");
      return opt_proposal;
    }

    void HonestBehaviour::processOrderingBatches(
        const BatchesCollection &batches) {
      if (batches.empty()) {
        getLogger()->debug(
            "Got an OnDemandOrderingService.SendBatches call with "
            "empty batches set. Ignoring it.");
        return;
      }
      auto &fake_peer = getFakePeer();
      getLogger()->debug(
          "Got an OnDemandOrderingService.SendBatches call, storing the "
          "following batches: {}",
          boost::algorithm::join(
              batches | boost::adaptors::transformed([](const auto &batch) {
                return batch->toString();
              }),
              ",\n"));

      fake_peer.getProposalStorage().addBatches(batches);
    }

  }  // namespace fake_peer
}  // namespace integration_framework
