/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "network/impl/block_loader_impl.hpp"

#include <chrono>
#include <string_view>

#include <fmt/core.h>
#include <grpc++/create_channel.h>
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

namespace {
  class BlockReaderImpl : public BlockReader {
   public:
    BlockReaderImpl(
        std::weak_ptr<shared_model::proto::ProtoBlockFactory> block_factory,
        std::unique_ptr<iroha::network::proto::Loader::StubInterface> client,
        proto::BlockRequest request)
        : block_factory_(std::move(block_factory)),
          client_(std::move(client)),
          reader_(client_->retrieveBlocks(&context_, std::move(request))) {
      context_.set_deadline(std::chrono::system_clock::now()
                            + std::chrono::minutes(1ull));
    }

    std::variant<iteration_complete,
                 std::shared_ptr<const shared_model::interface::Block>,
                 std::string>
    read() override {
      iroha::protocol::Block proto_block;
      auto maybe_block_factory = block_factory_.lock();
      if (not maybe_block_factory) {
        return fmt::format("Failed to lock block factory");
      }

      if (not reader_->Read(&proto_block)) {
        auto status = reader_->Finish();
        if (not status.ok()) {
          return fmt::format("Failed to read block: {}",
                             status.error_message());
        }
        return iteration_complete{};
      }

      auto maybe_block =
          maybe_block_factory->createBlock(std::move(proto_block));
      if (hasError(maybe_block)) {
        context_.TryCancel();
        return fmt::format("Failed to parse received block: {}",
                           std::move(maybe_block).assumeError());
      }

      return std::move(maybe_block).assumeValue();
    }

   private:
    std::weak_ptr<shared_model::proto::ProtoBlockFactory> block_factory_;
    grpc::ClientContext context_;
    std::unique_ptr<iroha::network::proto::Loader::StubInterface> client_;
    std::unique_ptr<grpc::ClientReaderInterface<iroha::protocol::Block>>
        reader_;
  };
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

Result<std::unique_ptr<BlockReader>> BlockLoaderImpl::retrieveBlocks(
    const shared_model::interface::types::HeightType height,
    types::PublicKeyHexStringView peer_pubkey) {
  auto maybe_peer = findPeer(peer_pubkey);
  if (hasError(maybe_peer)) {
    return maybe_peer.assumeError();
  }

  auto maybe_client = client_factory_->createClient(*maybe_peer.assumeValue());
  if (hasError(maybe_client)) {
    return maybe_client.assumeError();
  }

  proto::BlockRequest request;
  request.set_height(height + 1);  // request next block to our top

  return std::make_unique<BlockReaderImpl>(
      block_factory_,
      std::move(maybe_client).assumeValue(),
      std::move(request));
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
