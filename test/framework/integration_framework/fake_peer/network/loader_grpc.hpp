/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INTEGRATION_FRAMEWORK_FAKE_PEER_LOADER_GRPC_HPP_
#define INTEGRATION_FRAMEWORK_FAKE_PEER_LOADER_GRPC_HPP_

#include <rxcpp/rx-lite.hpp>
#include "common/result_fwd.hpp"
#include "framework/integration_framework/fake_peer/types.hpp"
#include "loader.grpc.pb.h"
#include "logger/logger_fwd.hpp"

namespace iroha {
  namespace network {
    class GenericClientFactory;
  }
}  // namespace iroha

namespace integration_framework {
  namespace fake_peer {

    class LoaderGrpc : public iroha::network::proto::Loader::Service {
     public:
      explicit LoaderGrpc(
          const std::shared_ptr<FakePeer> &fake_peer,
          logger::LoggerPtr log,
          std::shared_ptr<iroha::network::GenericClientFactory> client_factory);

      /**
       * Send a `retrieveBlock' request to the peer at given address.
       *
       * @param peer - the destination of the request.
       * @param request - the data of the request.
       * @return true if the grpc request succeeded, false otherwise.
       */
      iroha::expected::Result<void, std::string> sendBlockRequest(
          const shared_model::interface::Peer &peer,
          const LoaderBlockRequest &request);

      /**
       * Send a `retrieveBlocks' request to the peer at given address.
       *
       * @param peer - the destination of the request.
       * @param request - the data of the request.
       * @return the number of received in reply blocks.
       */
      iroha::expected::Result<size_t, std::string> sendBlocksRequest(
          const shared_model::interface::Peer &peer,
          const LoaderBlocksRequest &request);

      /// Get the observable of block requests.
      rxcpp::observable<LoaderBlockRequest> getLoaderBlockRequestObservable();

      /// Get the observable of blocks requests.
      rxcpp::observable<LoaderBlocksRequest> getLoaderBlocksRequestObservable();

      // --------------| iroha::network::proto::Loader::Service |--------------

      /// Handler of grpc retrieveBlocks calls.
      grpc::Status retrieveBlocks(
          ::grpc::ServerContext *context,
          const iroha::network::proto::BlockRequest *request,
          ::grpc::ServerWriter<iroha::protocol::Block> *writer) override;

      /// Handler of grpc retrieveBlock calls.
      grpc::Status retrieveBlock(
          ::grpc::ServerContext *context,
          const iroha::network::proto::BlockRequest *request,
          iroha::protocol::Block *response) override;

     private:
      std::weak_ptr<FakePeer> fake_peer_wptr_;

      rxcpp::subjects::subject<LoaderBlockRequest> block_requests_subject_;
      rxcpp::subjects::subject<LoaderBlocksRequest> blocks_requests_subject_;

      logger::LoggerPtr log_;

      std::shared_ptr<iroha::network::GenericClientFactory> client_factory_;
    };
  }  // namespace fake_peer
}  // namespace integration_framework

#endif /* INTEGRATION_FRAMEWORK_FAKE_PEER_LOADER_GRPC_HPP_ */
