/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INTEGRATION_FRAMEWORK_FAKE_PEER_LOADER_GRPC_HPP_
#define INTEGRATION_FRAMEWORK_FAKE_PEER_LOADER_GRPC_HPP_

#include <rxcpp/rx.hpp>
#include "framework/integration_framework/fake_peer/types.hpp"
#include "loader.grpc.pb.h"
#include "logger/logger_fwd.hpp"
#include "network/impl/client_factory.hpp"

namespace integration_framework {
  namespace fake_peer {

    class LoaderGrpc : public iroha::network::proto::Loader::Service {
     public:
      explicit LoaderGrpc(
          const std::shared_ptr<FakePeer> &fake_peer,
          logger::LoggerPtr log,
          std::shared_ptr<iroha::network::ClientFactory> client_factory);

      /**
       * Send a `retrieveBlock' request to the peer at given address.
       *
       * @param dest_address - the destination of the request.
       * @param request - the data of the request.
       * @return true if the grpc request succeeded, false otherwise.
       */
      bool sendBlockRequest(const std::string &dest_address,
                            const LoaderBlockRequest &request);

      /**
       * Send a `retrieveBlocks' request to the peer at given address.
       *
       * @param dest_address - the destination of the request.
       * @param request - the data of the request.
       * @return the number of received in reply blocks.
       */
      size_t sendBlocksRequest(const std::string &dest_address,
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
      std::shared_ptr<iroha::network::ClientFactory> client_factory_;

      rxcpp::subjects::subject<LoaderBlockRequest> block_requests_subject_;
      rxcpp::subjects::subject<LoaderBlocksRequest> blocks_requests_subject_;

      logger::LoggerPtr log_;
    };
  }  // namespace fake_peer
}  // namespace integration_framework

#endif /* INTEGRATION_FRAMEWORK_FAKE_PEER_LOADER_GRPC_HPP_ */
