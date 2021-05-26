/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_BLOCK_LOADER_IMPL_HPP
#define IROHA_BLOCK_LOADER_IMPL_HPP

#include "network/block_loader.hpp"

#include <unordered_map>

#include "ametsuchi/peer_query_factory.hpp"
#include "backend/protobuf/proto_block_factory.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "loader.grpc.pb.h"
#include "logger/logger_fwd.hpp"

namespace iroha {
  namespace network {
    template <typename Service>
    class ClientFactory;

    class BlockLoaderImpl : public BlockLoader {
     public:
      using Service = proto::Loader;
      using ClientFactory = iroha::network::ClientFactory<Service>;

      // TODO 30.01.2019 lebdron: IR-264 Remove PeerQueryFactory
      BlockLoaderImpl(
          std::shared_ptr<ametsuchi::PeerQueryFactory> peer_query_factory,
          std::shared_ptr<shared_model::proto::ProtoBlockFactory> factory,
          logger::LoggerPtr log,
          std::unique_ptr<ClientFactory> client_factory);

      expected::Result<std::unique_ptr<BlockReader>> retrieveBlocks(
          const shared_model::interface::types::HeightType height,
          shared_model::interface::types::PublicKeyHexStringView peer_pubkey)
          override;

      iroha::expected::Result<std::unique_ptr<shared_model::interface::Block>,
                              std::string>
      retrieveBlock(
          shared_model::interface::types::PublicKeyHexStringView peer_pubkey,
          shared_model::interface::types::HeightType block_height) override;

     private:
      /**
       * Retrieve peers from database, and find the requested peer by pubkey
       * @param pubkey - public key of requested peer
       * @return peer, if it was found, otherwise nullopt
       */
      iroha::expected::Result<std::shared_ptr<shared_model::interface::Peer>,
                              std::string>
      findPeer(shared_model::interface::types::PublicKeyHexStringView pubkey);

      std::shared_ptr<ametsuchi::PeerQueryFactory> peer_query_factory_;
      std::shared_ptr<shared_model::proto::ProtoBlockFactory> block_factory_;
      std::shared_ptr<ClientFactory> client_factory_;

      logger::LoggerPtr log_;
    };
  }  // namespace network
}  // namespace iroha

#endif  // IROHA_BLOCK_LOADER_IMPL_HPP
