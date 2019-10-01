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
#include "loader.grpc.pb.h"
#include "logger/logger_fwd.hpp"
#include "network/impl/client_factory.hpp"

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
          shared_model::proto::ProtoBlockFactory factory,
          logger::LoggerPtr log,
          std::unique_ptr<ClientFactory> client_factory);

      rxcpp::observable<std::shared_ptr<shared_model::interface::Block>>
      retrieveBlocks(
          const shared_model::interface::types::HeightType height,
          const shared_model::crypto::PublicKey &peer_pubkey) override;

      boost::optional<std::shared_ptr<shared_model::interface::Block>>
      retrieveBlock(
          const shared_model::crypto::PublicKey &peer_pubkey,
          shared_model::interface::types::HeightType block_height) override;

     private:
      /**
       * Retrieve peers from database, and find the requested peer by pubkey
       * @param pubkey - public key of requested peer
       * @return peer, if it was found, otherwise nullopt
       * TODO 14/02/17 (@l4l) IR-960 rework method with returning result
       */
      boost::optional<std::shared_ptr<shared_model::interface::Peer>> findPeer(
          const shared_model::crypto::PublicKey &pubkey);

      std::shared_ptr<ametsuchi::PeerQueryFactory> peer_query_factory_;
      shared_model::proto::ProtoBlockFactory block_factory_;
      std::unique_ptr<ClientFactory> client_factory_;

      logger::LoggerPtr log_;
    };
  }  // namespace network
}  // namespace iroha

#endif  // IROHA_BLOCK_LOADER_IMPL_HPP
