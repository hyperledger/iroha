/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "network/impl/block_loader_impl.hpp"

#include <chrono>
#include <string_view>

#include <fmt/core.h>
#include <grpc++/create_channel.h>
#include <rxcpp/rx-lite.hpp>
#include "backend/protobuf/block.hpp"
#include "builders/protobuf/transport_builder.hpp"
#include "common/bind.hpp"
#include "common/to_string.hpp"
#include "interfaces/common_objects/peer.hpp"
#include "logger/logger.hpp"
#include "network/impl/client_factory.hpp"

using namespace iroha::ametsuchi;
using namespace iroha::expected;
using namespace iroha::network;
using namespace shared_model::crypto;
using namespace shared_model::interface;

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
    types::PublicKeyHexStringView peer_pubkey) {
  return findPeer(peer_pubkey) | [&](const auto &peer) {
    return client_factory_->createClient(*peer) | [&](auto client) {
      std::shared_ptr<typename decltype(client)::element_type> shared_client(
          std::move(client));
      return rxcpp::observable<std::shared_ptr<Block>>(
          rxcpp::observable<>::create<std::shared_ptr<Block>>(
              [height, shared_client, block_factory = block_factory_](
                  auto subscriber) {
                grpc::ClientContext context;
                context.set_deadline(std::chrono::system_clock::now() + std::chrono::minutes(1ull));

                proto::BlockRequest request;
                request.set_height(height
                                   + 1);  // request next block to our top
                auto reader = shared_client->retrieveBlocks(&context, request);
                protocol::Block block;
                while (subscriber.is_subscribed() and reader->Read(&block)) {
                  block_factory->createBlock(std::move(block))
                      .match(
                          [&](auto &&result) {
                            subscriber.on_next(std::move(result.value));
                          },
                          [&](const auto &error) {
                            context.TryCancel();
                            reader->Finish();
                            subscriber.on_error(std::make_exception_ptr(
                                std::runtime_error(fmt::format(
                                    "Failed to parse received block: {}.",
                                    error.error))));
                          });
                }
                reader->Finish();
                subscriber.on_completed();
              }));
    };
  };
}

Result<std::unique_ptr<Block>, std::string> BlockLoaderImpl::retrieveBlock(
    types::PublicKeyHexStringView peer_pubkey, types::HeightType block_height) {
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
BlockLoaderImpl::findPeer(types::PublicKeyHexStringView pubkey) {
  return peer_query_factory_->createPeerQuery() | [pubkey](const auto &query) {
    return optionalValueToResult(
        query->getLedgerPeerByPublicKey(pubkey),
        fmt::format("Cannot find peer with public key {}.",
                    iroha::to_string::toString(pubkey)));
  };
}
