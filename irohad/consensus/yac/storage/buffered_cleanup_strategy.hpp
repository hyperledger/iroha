/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_BUFFERED_CLEANUP_STRATEGY_HPP
#define IROHA_BUFFERED_CLEANUP_STRATEGY_HPP

#include "consensus/yac/storage/cleanup_strategy.hpp"

#include <boost/optional.hpp>
#include <queue>

#include "consensus/yac/outcome_messages.hpp"

namespace iroha::consensus::yac {
  class BufferedCleanupStrategy : public CleanupStrategy {
   public:
    using RoundType = Round;

    /**
     * The method finalizes passed round. On Commit message it purges last
     * reject round if commit is greater.
     * @param consensus_round - finalized round of the consensus
     * @param answer - the output of the round
     * @return rounds to be removed, if any.
     */
    boost::optional<CleanupStrategy::RoundsType> finalize(
        RoundType consensus_round, Answer answer) override;

    bool shouldCreateRound(const RoundType &round) override;

   private:
    /**
     * Remove all rounds before last committed
     * @return rounds to be removed. Also, the same rounds are removed from
     * created_rounds_ collection
     */
    RoundsType truncateCreatedRounds();

    /**
     * @return the lowest round from last committed and last rejected
     * rounds, if the operation can't be applied - returns none
     */
    boost::optional<RoundType> minimalRound() const;

    /**
     * The method creates round into created_rounds_ collection
     * @param round - round for insertion
     */
    void createRound(const Round &round);

    /**
     * Checks whether we should add round into created_rounds_ collection
     * @param round - round for checking
     * @return true if could be inserted
     */
    bool isRequiredCreation(const Round &round) const;

    /// all stored rounds
    std::priority_queue<RoundType,
                        std::vector<RoundType>,
                        std::greater<RoundType>>
        created_rounds_;

    /// maximal reject round, could empty if commit happened
    boost::optional<RoundType> last_reject_round_;
    /// maximal commit round
    boost::optional<RoundType> last_commit_round_;
  };
}  // namespace iroha::consensus::yac

#endif  // IROHA_BUFFERED_CLEANUP_STRATEGY_HPP
