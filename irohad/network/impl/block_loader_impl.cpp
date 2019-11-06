/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "network/impl/block_loader_impl.hpp"

#include <chrono>

#include <fmt/core.h>
#include <grpc++/create_channel.h>
#include <rxcpp/rx-lite.hpp>
#include "backend/protobuf/block.hpp"
#include "builders/protobuf/transport_builder.hpp"
#include "common/bind.hpp"
#include "interfaces/common_objects/peer.hpp"
#include "logger/logger.hpp"
#include "network/impl/client_factory.hpp"

using namespace iroha::ametsuchi;
using namespace iroha::expected;
using namespace iroha::network;
using namespace shared_model::crypto;
using namespace shared_model::interface;

namespace {
  const std::chrono::seconds kBlocksRequestTimeout{5};
}  // namespace

BlockLoaderImpl::BlockLoaderImpl(
    std::shared_ptr<PeerQueryFactory> peer_query_factory,
    std::shared_ptr<shared_model::proto::ProtoBlockFactory> factory,
    logger::LoggerPtr log,
    std::unique_ptr<ClientFactory> client_factory)
    : peer_query_factory_(std::move(peer_query_factory)),
      block_factory_(std::move(factory)),
      client_factory_(std::move(client_factory)),
      log_(std::move(log)) {}

Result<rxcpp::observable<std::shared_ptr<Block>>, std::string>
BlockLoaderImpl::retrieveBlocks(
    const shared_model::interface::types::HeightType height,
    const PublicKey &peer_pubkey) {
  return findPeer(peer_pubkey) | [&](const auto &peer) {
    struct SharedState {
      proto::BlockRequest request;
      grpc::ClientContext context;
    };

    auto shared_state = std::make_shared<SharedState>();

    // set a timeout to avoid being hung
    shared_state->context.set_deadline(std::chrono::system_clock::now()
                                       + kBlocksRequestTimeout);

    // request next block to our top
    shared_state->request.set_height(height + 1);

    return client_factory_->createClient(*peer) | [&](auto client) {
      std::shared_ptr<typename decltype(client)::element_type> shared_client(
          std::move(client));
      return Result<rxcpp::observable<std::shared_ptr<Block>>, std::string>(
          rxcpp::observable<std::shared_ptr<Block>>(
              rxcpp::observable<>::create<std::shared_ptr<Block>>(
                  [shared_state, shared_client, block_factory = block_factory_](
                      auto subscriber) {
                    auto reader = shared_client->retrieveBlocks(
                        &shared_state->context, shared_state->request);
                    protocol::Block block;
                    while (subscriber.is_subscribed()
                           and reader->Read(&block)) {
                      block_factory->createBlock(std::move(block))
                          .match(
                              [&](auto &&result) {
                                subscriber.on_next(std::move(result.value));
                              },
                              [&](const auto &error) {
                                subscriber.on_error(std::make_exception_ptr(
                                    std::runtime_error(fmt::format(
                                        "Failed to parse received block: {}.",
                                        error.error))));
                                shared_state->context.TryCancel();
                              });
                    }
                    reader->Finish();
                    subscriber.on_completed();
                  })));
    };
  };
}

Result<std::unique_ptr<Block>, std::string> BlockLoaderImpl::retrieveBlock(
    const PublicKey &peer_pubkey, types::HeightType block_height) {
  return findPeer(peer_pubkey) | [&](const auto &peer) {
    proto::BlockRequest request;
    grpc::ClientContext context;
    protocol::Block block;

    // request block with specified height
    request.set_height(block_height);

    return client_factory_->createClient(*peer) | [&](auto &&client)
               -> Result<std::unique_ptr<Block>, std::string> {
      auto status = client->retrieveBlock(&context, request, &block);
      if (not status.ok()) {
        return makeError(
            fmt::format("Block request failed: {}.", status.error_message()));
      }

      return block_factory_->createBlock(std::move(block));
    };
  };
}

Result<std::shared_ptr<shared_model::interface::Peer>, std::string>
BlockLoaderImpl::findPeer(const shared_model::crypto::PublicKey &pubkey) {
  return peer_query_factory_->createPeerQuery() | [&pubkey](const auto &query) {
    return optionalToResult(
        query->getLedgerPeerByPublicKey(pubkey),
        fmt::format("Cannot find peer with public key {}.", pubkey));
  };
}
