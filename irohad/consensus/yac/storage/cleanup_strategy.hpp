/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CLEANUP_STRATEGY_HPP
#define IROHA_CLEANUP_STRATEGY_HPP

#include <vector>

#include <boost/optional.hpp>

#include "consensus/round.hpp"
#include "consensus/yac/storage/storage_result.hpp"

namespace iroha::consensus::yac {
  class CleanupStrategy {
   public:
    /**
     * Collection of rounds type
     */
    using RoundsType = std::vector<Round>;

    /**
     * Notify strategy about new rounds
     * @param round - new round
     * @param answer - outcome of round
     * @return a collection of rounds for removing from the state
     */
    virtual boost::optional<RoundsType> finalize(Round round,
                                                 Answer answer) = 0;

    /**
     * The method checks whether we should add a new round
     * @param round - round for creation
     * @return true if round should be created
     */
    virtual bool shouldCreateRound(const Round &round) = 0;

    virtual ~CleanupStrategy() = default;
  };
}  // namespace iroha::consensus::yac

#endif  // IROHA_CLEANUP_STRATEGY_HPP
