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

BlockLoaderImpl::BlockLoaderImpl(
    std::shared_ptr<PeerQueryFactory> peer_query_factory,
    std::shared_ptr<shared_model::proto::ProtoBlockFactory> factory,
    logger::LoggerPtr log,
    std::unique_ptr<ClientFactory> client_factory)
    : peer_query_factory_(std::move(peer_query_factory)),
      block_factory_(std::move(factory)),
      client_factory_(std::move(client_factory)),
      log_(std::move(log)) {}

Result<boost::any_range<std::shared_ptr<const shared_model::interface::Block>,
                        boost::single_pass_traversal_tag>,
       std::string>
BlockLoaderImpl::retrieveBlocks(
    const shared_model::interface::types::HeightType height,
    types::PublicKeyHexStringView peer_pubkey) {
  return findPeer(peer_pubkey) | [&](const auto &peer) {
    return client_factory_->createClient(*peer) | [&](auto client) {
      using ClientType = decltype(client);

      proto::BlockRequest request;
      request.set_height(height + 1);  // request next block to our top

      struct iterator {
        using iterator_category = std::input_iterator_tag;
        using value_type =
            std::shared_ptr<const shared_model::interface::Block>;
        using difference_type = std::ptrdiff_t;
        using pointer = std::add_pointer_t<value_type>;
        using reference =
            std::add_lvalue_reference_t<std::add_const_t<value_type>>;

        iterator() {}

        iterator(
            std::weak_ptr<shared_model::proto::ProtoBlockFactory> block_factory,
            std::weak_ptr<logger::Logger> log,
            ClientType client,
            proto::BlockRequest request)
            : state(std::make_shared<struct state>()) {
          state->block_factory = std::move(block_factory);
          state->log = std::move(log);
          state->reader = client->retrieveBlocks(&state->context, request);
          state->client = std::move(client);
          state->context.set_deadline(std::chrono::system_clock::now()
                                      + std::chrono::minutes(1ull));
          ++(*this);
        }

        iterator &operator++() {
          auto maybe_block_factory = state->block_factory.lock();
          auto maybe_log = state->log.lock();
          protocol::Block proto_block;
          if (maybe_block_factory and state->reader->Read(&proto_block)) {
            maybe_block_factory->createBlock(std::move(proto_block))
                .match([&](auto &&result) { block = std::move(result.value); },
                       [&](const auto &error) {
                         state->context.TryCancel();
                         state->reader->Finish();
                         block.reset();
                         maybe_log->error("Failed to parse received block: {}.",
                                          error.error);
                       });
          } else {
            state->reader->Finish();
            block.reset();
          }
          return *this;
        }

        iterator operator++(int) {
          iterator ret = *this;
          ++(*this);
          return ret;
        }

        reference operator*() const {
          return block;
        }

        bool operator==(iterator const &other) const {
          return block == other.block;
        }

        bool operator!=(iterator const &other) const {
          return !(*this == other);
        }

        struct state {
          std::weak_ptr<shared_model::proto::ProtoBlockFactory> block_factory;
          std::weak_ptr<logger::Logger> log;
          grpc::ClientContext context;
          ClientType client;
          std::unique_ptr<grpc::ClientReaderInterface<protocol::Block>> reader;
        };

        std::shared_ptr<state> state;
        std::shared_ptr<const shared_model::interface::Block> block;
      };

      return boost::make_iterator_range(
          iterator(block_factory_, log_, std::move(client), std::move(request)),
          iterator{});
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
