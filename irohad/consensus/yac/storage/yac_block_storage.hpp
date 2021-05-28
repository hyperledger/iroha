/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_YAC_BLOCK_VOTE_STORAGE_HPP
#define IROHA_YAC_BLOCK_VOTE_STORAGE_HPP

#include <memory>
#include <vector>

#include <boost/optional.hpp>
#include "consensus/yac/outcome_messages.hpp"
#include "consensus/yac/storage/storage_result.hpp"
#include "consensus/yac/supermajority_checker.hpp"
#include "consensus/yac/yac_types.hpp"
#include "logger/logger_fwd.hpp"

namespace iroha::consensus::yac {
  /**
   * Class provide storage of votes for one block.
   */
  class YacBlockStorage {
   private:
    // --------| fields |--------

    /**
     * All votes stored in block store
     */
    std::vector<VoteMessage> votes_;

   public:
    YacBlockStorage(YacHash hash,
                    PeersNumberType peers_in_round,
                    std::shared_ptr<SupermajorityChecker> supermajority_checker,
                    logger::LoggerPtr log);

    /**
     * Try to insert vote to storage
     * @param msg - vote for insertion
     * @return actual state of storage,
     * boost::none when storage doesn't have supermajority
     */
    boost::optional<Answer> insert(VoteMessage msg);

    /**
     * Insert vector of votes to current storage
     * @param votes - bunch of votes for insertion
     * @return state of storage after insertion last vote,
     * boost::none when storage doesn't have supermajority
     */
    boost::optional<Answer> insert(std::vector<VoteMessage> votes);

    /**
     * @return votes attached to storage
     */
    std::vector<VoteMessage> getVotes() const;

    /**
     * @return number of votes attached to storage
     */
    size_t getNumberOfVotes() const;

    /**
     * @return current block store state
     */
    boost::optional<Answer> getState();

    /**
     * Verify that passed vote contains in storage
     * @param msg  - vote for finding
     * @return true, if contains
     */
    bool isContains(const VoteMessage &msg) const;

    /**
     * Provide key attached to this storage
     */
    YacHash getStorageKey() const;

   private:
    // --------| private api |--------

    /**
     * Verify uniqueness of vote in storage
     * @param msg - vote for verification
     * @return true if vote doesn't appear in storage
     */
    bool uniqueVote(VoteMessage &vote);

    /**
     * Verify that vote has the same hash attached as the storage
     * @param vote - vote to be checked
     * @return true, if validation passed
     */
    bool validScheme(VoteMessage &vote);

    // --------| fields |--------

    /**
     * Key of the storage; currently it's yac hash
     */
    YacHash storage_key_;

    /**
     * Number of peers in current round
     */
    PeersNumberType peers_in_round_;

    /**
     * Provide functions to check supermajority
     */
    std::shared_ptr<SupermajorityChecker> supermajority_checker_;

    /**
     * Storage logger
     */
    logger::LoggerPtr log_;
  };
}  // namespace iroha::consensus::yac

#endif  // IROHA_YAC_BLOCK_VOTE_STORAGE_HPP
