/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "framework/integration_framework/fake_peer/network/loader_grpc.hpp"

#include "backend/protobuf/block.hpp"
#include "framework/integration_framework/fake_peer/behaviour/behaviour.hpp"
#include "framework/integration_framework/fake_peer/fake_peer.hpp"
#include "framework/test_client_factory.hpp"
#include "loader.grpc.pb.h"
#include "logger/logger.hpp"

namespace integration_framework {
  namespace fake_peer {

    LoaderGrpc::LoaderGrpc(
        const std::shared_ptr<FakePeer> &fake_peer,
        logger::LoggerPtr log,
        std::shared_ptr<iroha::network::ClientFactory> client_factory)
        : fake_peer_wptr_(fake_peer),
          log_(std::move(log)),
          client_factory_(client_factory) {}

    bool LoaderGrpc::sendBlockRequest(const std::string &dest_address,
                                      const LoaderBlockRequest &height) {
      iroha::network::proto::BlockRequest request;
      request.set_height(height);
      grpc::ClientContext context;
      iroha::protocol::Block block;
      auto client =
          client_factory_->createClient<iroha::network::proto::Loader>(
              dest_address);

      const auto status = client->retrieveBlock(&context, request, &block);
      if (not status.ok()) {
        log_->warn("Error retrieving block: " + status.error_message());
        return false;
      }
      return true;
    }

    size_t LoaderGrpc::sendBlocksRequest(const std::string &dest_address,
                                         const LoaderBlocksRequest &height) {
      iroha::network::proto::BlockRequest request;
      request.set_height(height);
      grpc::ClientContext context;
      iroha::protocol::Block block;
      auto client =
          client_factory_->createClient<iroha::network::proto::Loader>(
              dest_address);

      auto reader = client->retrieveBlocks(&context, request);
      size_t num_read_blocks = 0;
      while (reader->Read(&block)) {
        ++num_read_blocks;
      }

      return num_read_blocks;
    }

    rxcpp::observable<LoaderBlockRequest>
    LoaderGrpc::getLoaderBlockRequestObservable() {
      return block_requests_subject_.get_observable();
    }

    rxcpp::observable<LoaderBlocksRequest>
    LoaderGrpc::getLoaderBlocksRequestObservable() {
      return blocks_requests_subject_.get_observable();
    }

    // --------------| iroha::network::proto::Loader::Service |--------------

    ::grpc::Status LoaderGrpc::retrieveBlock(
        ::grpc::ServerContext *context,
        const iroha::network::proto::BlockRequest *request,
        iroha::protocol::Block *response) {
      LoaderBlockRequest height = request->height();
      auto fake_peer = fake_peer_wptr_.lock();
      BOOST_VERIFY_MSG(fake_peer, "Fake Peer is not set!");
      auto behaviour = fake_peer->getBehaviour();
      if (!behaviour) {
        return ::grpc::Status(::grpc::StatusCode::INTERNAL,
                              "Fake Peer has no behaviour set!");
      }
      auto opt_block = behaviour->processLoaderBlockRequest(height);
      if (!opt_block) {
        return ::grpc::Status(::grpc::StatusCode::NOT_FOUND, "Block not found");
      }
      *response->mutable_block_v1() = (*opt_block)->getTransport();
      return ::grpc::Status::OK;
    }

    ::grpc::Status LoaderGrpc::retrieveBlocks(
        ::grpc::ServerContext *context,
        const iroha::network::proto::BlockRequest *request,
        ::grpc::ServerWriter<iroha::protocol::Block> *writer) {
      LoaderBlocksRequest height = request->height();
      auto fake_peer = fake_peer_wptr_.lock();
      BOOST_VERIFY_MSG(fake_peer, "Fake peer is not set!");
      auto behaviour = fake_peer->getBehaviour();
      if (!behaviour) {
        return ::grpc::Status(::grpc::StatusCode::INTERNAL,
                              "Fake Peer has no behaviour set!");
      }
      auto blocks = behaviour->processLoaderBlocksRequest(height);
      for (auto &block : blocks) {
        iroha::protocol::Block proto_block;
        *proto_block.mutable_block_v1() = block->getTransport();
        writer->Write(proto_block);
      }
      return ::grpc::Status::OK;
    }

  }  // namespace fake_peer
}  // namespace integration_framework
