/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CONSENSUS_BLOCK_CACHE_HPP
#define IROHA_CONSENSUS_BLOCK_CACHE_HPP

#include "cache/single_pointer_cache.hpp"

namespace shared_model {
  namespace interface {
    class Block;
  }
}  // namespace shared_model

namespace iroha {
  namespace consensus {

    /**
     * Type to represent result of the consensus in form of block
     */
    using ConsensusResult = shared_model::interface::Block;

    /**
     * Type to represent a consensus result cache with a single block
     */
    using ConsensusResultCache = cache::SinglePointerCache<ConsensusResult>;

  }  // namespace consensus
}  // namespace iroha

#endif  // IROHA_CONSENSUS_BLOCK_CACHE_HPP
