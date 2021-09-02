/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_YAC_VOTE_STORAGE_HPP
#define IROHA_YAC_VOTE_STORAGE_HPP

#include <memory>
#include <unordered_map>
#include <vector>

#include <boost/optional.hpp>
#include "consensus/yac/consistency_model.hpp"
#include "consensus/yac/outcome_messages.hpp"  // because messages passed by value
#include "consensus/yac/storage/cleanup_strategy.hpp"
#include "consensus/yac/storage/storage_result.hpp"  // for Answer
#include "consensus/yac/storage/yac_common.hpp"      // for ProposalHash
#include "consensus/yac/storage/yac_proposal_storage.hpp"
#include "consensus/yac/supermajority_checker.hpp"
#include "consensus/yac/yac_types.hpp"
#include "logger/logger_manager_fwd.hpp"

namespace iroha::consensus::yac {
  /**
   * Proposal outcome states for multicast propagation strategy
   *
   * Outcome is either CommitMessage, which guarantees that supermajority of
   * votes for the proposal-block hashes is collected, or RejectMessage,
   * which states that supermajority of votes for a block hash cannot be
   * achieved
   *
   * kNotSentNotProcessed - outcome was not propagated in the network
   * AND it was not passed to pipeline. Initial state after receiving an
   * outcome from storage. Outcome with votes is propagated to the network
   * in this state.
   *
   * kSentNotProcessed - outcome was propagated in the network
   * AND it was not passed to pipeline. State can be set in two cases:
   * 1. Outcome is received from the network. Some node has already achieved
   * an outcome and has propagated it to the network, so the first state is
   * skipped.
   * 2. Outcome was propagated to the network
   * Outcome is passed to pipeline in this state.
   *
   * kSentProcessed - outcome was propagated in the network
   * AND it was passed to pipeline. Set after passing proposal to pipeline.
   * This state is final. Receiving a network message in this state results
   * in direct propagation of outcome to message sender.
   */
  enum class ProposalState {
    kNotSentNotProcessed,
    kSentNotProcessed,
    kSentProcessed
  };

  /**
   * Class provide storage for votes and useful methods for it.
   */
  class YacVoteStorage {
   private:
    // --------| private api |--------

    /**
     * Retrieve iterator for storage with specified key
     * @param round - key of that storage
     * @return iterator to proposal storage
     */
    auto getProposalStorage(const Round &round);
    auto getProposalStorage(const Round &round) const;

    /**
     * Find existed proposal storage or create new if required
     * @param msg - vote for finding
     * @param peers_in_round - number of peer required
     * for verify supermajority;
     * This parameter used on creation of proposal storage
     * @return - iter for required proposal storage
     */
    boost::optional<std::vector<YacProposalStorage>::iterator>
    findProposalStorage(const VoteMessage &msg, PeersNumberType peers_in_round);

   public:
    // --------| public api |--------

    /**
     * @param cleanup_strategy - strategy for removing elements from storage
     * @param consistency_model - consensus consistency model (CFT, BFT).
     * @param log_manager - log manager to create component loggers
     */
    YacVoteStorage(std::shared_ptr<CleanupStrategy> cleanup_strategy,
                   std::unique_ptr<SupermajorityChecker> supermajority_checker,
                   logger::LoggerManagerTreePtr log_manager);

    /**
     * Insert votes in storage
     * @param state - current message with votes
     * @param peers_in_round - number of peers participated in round
     * @return structure with result of inserting.
     * boost::none if msg not valid.
     */
    boost::optional<Answer> store(std::vector<VoteMessage> state,
                                  PeersNumberType peers_in_round);

    /**
     * Provide status about closing round of proposal/block
     * @param round, in which proposal/block is supposed to be committed
     * @return true, if round closed
     */
    bool isCommitted(const Round &round);

    /**
     * Remove proposal storage by round
     */
    void remove(const Round &round);

    /**
     * Method provide state of processing for concrete proposal/block
     * @param round, in which that proposal/block is being voted
     * @return value attached to parameter's round. Default is
     * kNotSentNotProcessed.
     */
    ProposalState getProcessingState(const Round &round);

    /**
     * Mark round with following transition:
     * kNotSentNotProcessed -> kSentNotProcessed
     * kSentNotProcessed -> kSentProcessed
     * kSentProcessed -> kSentProcessed
     * @see ProposalState description for transition cases
     * @param round - target tag
     */
    void nextProcessingState(const Round &round);

    /**
     * Get last by order finalized round
     * @return round if it exists
     */
    boost::optional<Round> getLastFinalizedRound() const;

    /**
     * Get the state attached of a past round
     * @param round - required round
     * @return state if round exists and finalized
     */
    boost::optional<Answer> getState(const Round &round) const;

   private:
    // --------| fields |--------

    // TODO: 2019-02-28 @muratovv refactor proposal_storages_ &
    // processing_state_ with separate entity IR-360

    /**
     * Active proposal storages
     */
    std::vector<YacProposalStorage> proposal_storages_;

    /**
     * Processing set provide user flags about processing some
     * proposals/blocks.
     * If such round exists <=> processed
     */
    std::unordered_map<Round, ProposalState> processing_state_;

    /**
     * Provides strategy managing rounds (adding and removing) for the
     * storage
     */
    std::shared_ptr<CleanupStrategy> strategy_;

    /// last finalized round
    boost::optional<Round> last_round_;

    std::shared_ptr<SupermajorityChecker> supermajority_checker_;

    logger::LoggerManagerTreePtr log_manager_;
  };
}  // namespace iroha::consensus::yac

#endif  // IROHA_YAC_VOTE_STORAGE_HPP
