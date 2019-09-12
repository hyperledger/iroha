/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_BLOCK_LOADER_INIT_HPP
#define IROHA_BLOCK_LOADER_INIT_HPP

#include "ametsuchi/block_query_factory.hpp"
#include "consensus/consensus_block_cache.hpp"
#include "logger/logger_fwd.hpp"
#include "logger/logger_manager_fwd.hpp"
#include "network/impl/block_loader_impl.hpp"
#include "network/impl/block_loader_service.hpp"
#include "validators/validators_common.hpp"

namespace iroha {
  namespace network {
    class GenericClientFactory;

    /**
     * Initialization context of Block loader: loader itself and service
     */
    class BlockLoaderInit {
     public:
      /**
       * Initialize block loader with service and loader
       * @param peer_query_factory - factory to peer query component
       * @param block_query_factory - factory to block query component
       * @param block_cache used to retrieve last block put by consensus
       * @param validators_config - a config for underlying validators
       * @param loader_log - the log of the loader subsystem
       * @param client_factory - a factory of client stubs
       * @return initialized service
       */
      std::shared_ptr<BlockLoader> initBlockLoader(
          // TODO 30.01.2019 lebdron: IR-264 Remove PeerQueryFactory
          std::shared_ptr<ametsuchi::PeerQueryFactory> peer_query_factory,
          std::shared_ptr<ametsuchi::BlockQueryFactory> block_query_factory,
          std::shared_ptr<consensus::ConsensusResultCache> block_cache,
          std::shared_ptr<shared_model::validation::ValidatorsConfig>
              validators_config,
          const logger::LoggerManagerTreePtr &loader_log_manager,
          std::shared_ptr<iroha::network::GenericClientFactory> client_factory);

      std::shared_ptr<BlockLoaderImpl> loader;
      std::shared_ptr<BlockLoaderService> service;
    };
  }  // namespace network
}  // namespace iroha
#endif  // IROHA_BLOCK_LOADER_INIT_HPP
