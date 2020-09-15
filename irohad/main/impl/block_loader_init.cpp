/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/impl/block_loader_init.hpp"

#include "logger/logger_manager.hpp"
#include "network/impl/client_factory_impl.hpp"
#include "validators/default_validator.hpp"
#include "validators/protobuf/proto_block_validator.hpp"

using namespace iroha;
using namespace iroha::ametsuchi;
using namespace iroha::network;

namespace {

  /**
   * Create block loader service with given storage
   * @param block_query_factory - factory to block query component
   * @param block_cache used to retrieve last block put by consensus
   * @param loader_log - the log of the loader subsystem
   * @return initialized service
   */
  auto createService(
      std::shared_ptr<BlockQueryFactory> block_query_factory,
      std::shared_ptr<consensus::ConsensusResultCache> consensus_result_cache,
      const logger::LoggerManagerTreePtr &loader_log_manager) {
    return std::make_shared<BlockLoaderService>(
        std::move(block_query_factory),
        std::move(consensus_result_cache),
        loader_log_manager->getChild("Network")->getLogger());
  }

  /**
   * Create block loader for loading blocks from given peer factory by top
   * block
   * @param peer_query_factory - factory for peer query component creation
   * @param validators_config - a config for underlying validators
   * @param loader_log - the log of the loader subsystem
   * @param client_factory - a factory to create client stubs
   * @return initialized loader
   */
  auto createLoader(std::shared_ptr<PeerQueryFactory> peer_query_factory,
                    std::shared_ptr<shared_model::validation::ValidatorsConfig>
                        validators_config,
                    logger::LoggerPtr loader_log,
                    std::shared_ptr<GenericClientFactory> client_factory) {
    auto block_factory = std::make_shared<
        shared_model::proto::ProtoBlockFactory>(
        std::make_unique<shared_model::validation::DefaultSignedBlockValidator>(
            validators_config),
        std::make_unique<shared_model::validation::ProtoBlockValidator>());
    return std::make_shared<BlockLoaderImpl>(
        std::move(peer_query_factory),
        std::move(block_factory),
        std::move(loader_log),
        std::make_unique<ClientFactoryImpl<BlockLoaderImpl::Service>>(
            std::move(client_factory)));
  }

}  // namespace

std::shared_ptr<BlockLoader> BlockLoaderInit::initBlockLoader(
    std::shared_ptr<PeerQueryFactory> peer_query_factory,
    std::shared_ptr<BlockQueryFactory> block_query_factory,
    std::shared_ptr<consensus::ConsensusResultCache> consensus_result_cache,
    std::shared_ptr<shared_model::validation::ValidatorsConfig>
        validators_config,
    const logger::LoggerManagerTreePtr &loader_log_manager,
    std::shared_ptr<iroha::network::GenericClientFactory> client_factory) {
  service = createService(std::move(block_query_factory),
                          std::move(consensus_result_cache),
                          loader_log_manager);
  loader = createLoader(std::move(peer_query_factory),
                        std::move(validators_config),
                        loader_log_manager->getLogger(),
                        std::move(client_factory));
  return loader;
}
