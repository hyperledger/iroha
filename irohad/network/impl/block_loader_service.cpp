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

static grpc::Status handleGetBlockError(const BlockQuery::GetBlockError &error,
                                        const logger::LoggerPtr &log) {
  switch (error.code) {
    case BlockQuery::GetBlockError::Code::kNoBlock:
      log->error("Could not retrieve a block from block storage: {}",
                 error.message);
      return grpc::Status(grpc::StatusCode::NOT_FOUND, "No such block.");
    default:
      log->error("Unexpected GetBlockError code!");
      assert(false);
    case BlockQuery::GetBlockError::Code::kInternalError:
      log->error("Could not retrieve a block from block storage: {}",
                 error.message);
      return grpc::Status(grpc::StatusCode::INTERNAL,
                          std::string{"Internal error while retrieving block."}
                              + error.message);
  }
}

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
    const proto::BlockRequest *request,
    ::grpc::ServerWriter<::iroha::protocol::Block> *writer) {
  auto block_query = block_query_factory_->createBlockQuery();
  if (not block_query) {
    log_->error("Could not create block query to retrieve block from storage");
    return grpc::Status(grpc::StatusCode::INTERNAL, "internal error happened");
  }

  auto top_height = (*block_query)->getTopBlockHeight();
  for (decltype(top_height) i = request->height(); i <= top_height; ++i) {
    auto block_result = (*block_query)->getBlock(i);

    if (auto e = expected::resultToOptionalError(block_result)) {
      return handleGetBlockError(e.value(), log_);
    }

    auto &block =
        boost::get<
            expected::Value<std::unique_ptr<shared_model::interface::Block>>>(
            block_result)
            .value;

    protocol::Block proto_block;
    *proto_block.mutable_block_v1() =
        static_cast<shared_model::proto::Block *>(block.get())->getTransport();

    if (not writer->Write(proto_block)) {
      log_->error("Broken stream to {}", context->peer());
      break;
    }
  }

  return grpc::Status::OK;
}

grpc::Status BlockLoaderService::retrieveBlock(
    ::grpc::ServerContext *context,
    const proto::BlockRequest *request,
    protocol::Block *response) {
  const auto height = request->height();

  // try to fetch block from the consensus cache
  auto cached_block = consensus_result_cache_->get();
  if (cached_block) {
    if (cached_block->height() == height) {
      auto block_v1 =
          std::static_pointer_cast<shared_model::proto::Block>(cached_block)
              ->getTransport();
      *response->mutable_block_v1() = block_v1;
      return grpc::Status::OK;
    } else {
      log_->info(
          "Requested to retrieve a block, but cache contains another block: "
          "requested {}, in cache {}",
          height,
          cached_block->height());
    }
  } else {
    log_->info(
        "Tried to retrieve a block from an empty cache: requested block height "
        "{}",
        height);
  }

  // cache missed: notify and try to fetch the block from block storage itself
  auto block_query = block_query_factory_->createBlockQuery();
  if (not block_query) {
    log_->error("Could not create block query to retrieve block from storage");
    return grpc::Status(grpc::StatusCode::INTERNAL, "internal error happened");
  }

  auto block_result = (*block_query)->getBlock(height);

  if (auto e = expected::resultToOptionalError(block_result)) {
    return handleGetBlockError(e.value(), log_);
  }

  auto &block =
      boost::get<expected::ValueOf<decltype(block_result)>>(block_result).value;

  const auto &block_v1 =
      static_cast<shared_model::proto::Block *>(block.get())->getTransport();
  *response->mutable_block_v1() = block_v1;
  return grpc::Status::OK;
}
