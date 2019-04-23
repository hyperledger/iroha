/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/impl/block_loader_init.hpp"

#include "logger/logger_manager.hpp"
#include "validators/default_validator.hpp"
#include "validators/protobuf/proto_block_validator.hpp"

using namespace iroha;
using namespace iroha::ametsuchi;
using namespace iroha::network;

auto BlockLoaderInit::createService(
    std::shared_ptr<BlockQueryFactory> block_query_factory,
    std::shared_ptr<consensus::ConsensusResultCache> consensus_result_cache,
    const logger::LoggerManagerTreePtr &loader_log_manager) {
  return std::make_shared<BlockLoaderService>(
      std::move(block_query_factory),
      std::move(consensus_result_cache),
      loader_log_manager->getChild("Network")->getLogger());
}

auto BlockLoaderInit::createLoader(
    std::shared_ptr<PeerQueryFactory> peer_query_factory,
    std::shared_ptr<shared_model::validation::ValidatorsConfig>
        validators_config,
    logger::LoggerPtr loader_log) {
  auto block_loader_validators_config =
      std::make_shared<shared_model::validation::ValidatorsConfig>(
          validators_config->max_batch_size, true);
  shared_model::proto::ProtoBlockFactory factory(
      std::make_unique<shared_model::validation::DefaultSignedBlockValidator>(
          block_loader_validators_config),
      std::make_unique<shared_model::validation::ProtoBlockValidator>());
  return std::make_shared<BlockLoaderImpl>(
      std::move(peer_query_factory), std::move(factory), std::move(loader_log));
}

std::shared_ptr<BlockLoader> BlockLoaderInit::initBlockLoader(
    std::shared_ptr<PeerQueryFactory> peer_query_factory,
    std::shared_ptr<BlockQueryFactory> block_query_factory,
    std::shared_ptr<consensus::ConsensusResultCache> consensus_result_cache,
    std::shared_ptr<shared_model::validation::ValidatorsConfig>
        validators_config,
    const logger::LoggerManagerTreePtr &loader_log_manager) {
  service = createService(std::move(block_query_factory),
                          std::move(consensus_result_cache),
                          loader_log_manager);
  loader = createLoader(std::move(peer_query_factory),
                        std::move(validators_config),
                        loader_log_manager->getLogger());
  return loader;
}
