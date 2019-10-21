/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "network/impl/block_loader_impl.hpp"

#include <chrono>

#include <grpc++/create_channel.h>
#include <rxcpp/rx-lite.hpp>
#include "backend/protobuf/block.hpp"
#include "builders/protobuf/transport_builder.hpp"
#include "common/bind.hpp"
#include "interfaces/common_objects/peer.hpp"
#include "logger/logger.hpp"
#include "network/impl/grpc_channel_builder.hpp"

using namespace iroha::ametsuchi;
using namespace iroha::network;
using namespace shared_model::crypto;
using namespace shared_model::interface;

namespace {
  const char *kPeerNotFound = "Cannot find peer";
  const char *kPeerRetrieveFail = "Failed to retrieve peers";
  const char *kPeerFindFail = "Failed to find requested peer";
  const std::chrono::seconds kBlocksRequestTimeout{5};
}  // namespace

BlockLoaderImpl::BlockLoaderImpl(
    std::shared_ptr<PeerQueryFactory> peer_query_factory,
    shared_model::proto::ProtoBlockFactory factory,
    logger::LoggerPtr log)
    : peer_query_factory_(std::move(peer_query_factory)),
      block_factory_(std::move(factory)),
      log_(std::move(log)) {}

rxcpp::observable<std::shared_ptr<Block>> BlockLoaderImpl::retrieveBlocks(
    const shared_model::interface::types::HeightType height,
    const PublicKey &peer_pubkey) {
  return rxcpp::observable<>::create<std::shared_ptr<Block>>(
      [this, height, &peer_pubkey](auto subscriber) {
        auto peer = this->findPeer(peer_pubkey);
        if (not peer) {
          log_->error("{}", kPeerNotFound);
          subscriber.on_completed();
          return;
        }

        proto::BlockRequest request;
        grpc::ClientContext context;
        protocol::Block block;

        // set a timeout to avoid being hung
        context.set_deadline(std::chrono::system_clock::now()
                             + kBlocksRequestTimeout);

        // request next block to our top
        request.set_height(height + 1);

        auto reader =
            this->getPeerStub(**peer).retrieveBlocks(&context, request);
        while (subscriber.is_subscribed() and reader->Read(&block)) {
          block_factory_.createBlock(std::move(block))
              .match(
                  [&subscriber](auto &&result) {
                    subscriber.on_next(std::move(result.value));
                  },
                  [this, &context](const auto &error) {
                    log_->error("{}", error.error);
                    context.TryCancel();
                  });
        }
        reader->Finish();
        subscriber.on_completed();
      });
}

boost::optional<std::shared_ptr<Block>> BlockLoaderImpl::retrieveBlock(
    const PublicKey &peer_pubkey, types::HeightType block_height) {
  auto peer = findPeer(peer_pubkey);
  if (not peer) {
    log_->error("{}", kPeerNotFound);
    return boost::none;
  }

  proto::BlockRequest request;
  grpc::ClientContext context;
  protocol::Block block;

  // request block with specified height
  request.set_height(block_height);

  auto status = getPeerStub(**peer).retrieveBlock(&context, request, &block);
  if (not status.ok()) {
    log_->warn("{}", status.error_message());
    return boost::none;
  }

  return block_factory_.createBlock(std::move(block))
      .match(
          [](auto &&v) {
            return boost::make_optional(
                std::shared_ptr<Block>(std::move(v.value)));
          },
          [this](const auto &e) -> boost::optional<std::shared_ptr<Block>> {
            log_->error("{}", e.error);
            return boost::none;
          });
}

boost::optional<std::shared_ptr<shared_model::interface::Peer>>
BlockLoaderImpl::findPeer(const shared_model::crypto::PublicKey &pubkey) {
  auto peers = peer_query_factory_->createPeerQuery() |
      [](const auto &query) { return query->getLedgerPeers(); };
  if (not peers) {
    log_->error("{}", kPeerRetrieveFail);
    return boost::none;
  }

  auto &blob = pubkey.blob();
  auto it = std::find_if(
      peers.value().begin(), peers.value().end(), [&blob](const auto &peer) {
        return peer->pubkey().blob() == blob;
      });
  if (it == peers.value().end()) {
    log_->error("{}", kPeerFindFail);
    return boost::none;
  }
  return *it;
}

proto::Loader::StubInterface &BlockLoaderImpl::getPeerStub(
    const shared_model::interface::Peer &peer) {
  auto it = peer_connections_.find(peer.address());
  if (it == peer_connections_.end()) {
    it = peer_connections_
             .insert(std::make_pair(
                 peer.address(),
                 network::createClient<proto::Loader>(peer.address())))
             .first;
  }
  return *it->second;
}
