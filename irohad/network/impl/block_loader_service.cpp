/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "network/impl/block_loader_service.hpp"

#include "backend/protobuf/block.hpp"
#include "common/bind.hpp"
#include "logger/logger.hpp"

using namespace iroha;
using namespace iroha::ametsuchi;
using namespace iroha::network;

BlockLoaderService::BlockLoaderService(
    std::shared_ptr<BlockQueryFactory> block_query_factory,
    std::shared_ptr<iroha::consensus::ConsensusResultCache>
        consensus_result_cache,
    logger::LoggerPtr log)
    : block_query_factory_(std::move(block_query_factory)),
      consensus_result_cache_(std::move(consensus_result_cache)),
      log_(std::move(log)) {}

grpc::Status BlockLoaderService::retrieveBlocks(
    ::grpc::ServerContext *context,
    const proto::BlocksRequest *request,
    ::grpc::ServerWriter<::iroha::protocol::Block> *writer) {
  auto blocks = block_query_factory_->createBlockQuery() |
      [height = request->height()](const auto &block_query) {
        return block_query->getBlocksFrom(height);
      };
  std::for_each(blocks.begin(), blocks.end(), [&writer](const auto &block) {
    protocol::Block proto_block;
    *proto_block.mutable_block_v1() =
        std::dynamic_pointer_cast<shared_model::proto::Block>(block)
            ->getTransport();

    writer->Write(proto_block);
  });
  return grpc::Status::OK;
}

grpc::Status BlockLoaderService::retrieveBlock(
    ::grpc::ServerContext *context,
    const proto::BlockRequest *request,
    protocol::Block *response) {
  const auto hash = shared_model::crypto::Hash(request->hash());
  if (hash.size() == 0) {
    log_->error("Bad hash in request");
    return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                        "Bad hash provided");
  }

  // try to fetch block from the consensus cache
  auto block = consensus_result_cache_->get();
  if (block) {
    if (block->hash() == hash) {
      auto block_v1 =
          std::static_pointer_cast<shared_model::proto::Block>(block)
              ->getTransport();
      *response->mutable_block_v1() = block_v1;
      return grpc::Status::OK;
    } else {
      log_->info(
          "Requested to retrieve a block, but cache contains another block: "
          "requested {}, in cache {}",
          hash.hex(),
          block->hash().hex());
    }
  } else {
    log_->info(
        "Tried to retrieve a block from an empty cache: requested block hash "
        "{}",
        hash.hex());
  }

  // cache missed: notify and try to fetch the block from block storage itself
  auto blocks = block_query_factory_->createBlockQuery() |
      // TODO [IR-1757] Akvinikym 12.10.18: use block height to get one block
      // instead of the whole chain
      [](const auto &block_query) {
        return boost::make_optional(block_query->getBlocksFrom(1));
      };
  if (not blocks) {
    log_->error("Could not create block query to retrieve block from storage");
    return grpc::Status(grpc::StatusCode::INTERNAL, "internal error happened");
  }

  auto found_block = std::find_if(
      std::begin(*blocks), std::end(*blocks), [&hash](const auto &block) {
        return block->hash() == hash;
      });
  if (found_block == std::end(*blocks)) {
    log_->error("Could not retrieve a block from block storage: requested {}",
                hash.hex());
    return grpc::Status(grpc::StatusCode::NOT_FOUND, "Block not found");
  }

  auto block_v1 =
      std::static_pointer_cast<shared_model::proto::Block>(*found_block)
          ->getTransport();
  *response->mutable_block_v1() = block_v1;
  return grpc::Status::OK;
}
