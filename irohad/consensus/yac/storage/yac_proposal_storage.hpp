/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_YAC_PROPOSAL_STORAGE_HPP
#define IROHA_YAC_PROPOSAL_STORAGE_HPP

#include <memory>
#include <vector>

#include <boost/optional.hpp>
#include "consensus/yac/storage/storage_result.hpp"
#include "consensus/yac/storage/yac_block_storage.hpp"
#include "consensus/yac/storage/yac_common.hpp"
#include "consensus/yac/supermajority_checker.hpp"
#include "consensus/yac/yac_types.hpp"
#include "logger/logger_fwd.hpp"
#include "logger/logger_manager_fwd.hpp"

namespace iroha::consensus::yac {
  struct VoteMessage;

  /**
   * Class for storing votes related to given proposal/block round
   * and gain information about commits/rejects for this round
   */
  class YacProposalStorage {
   private:
    // --------| private api |--------

    /**
     * Find block index with provided parameters,
     * if those store absent - create new
     * @param store_hash - hash of store of interest
     * @return iterator to storage
     */
    auto findStore(const YacHash &store_hash);

   public:
    // --------| public api |--------

    YacProposalStorage(
        Round store_round,
        PeersNumberType peers_in_round,
        std::shared_ptr<SupermajorityChecker> supermajority_checker,
        logger::LoggerManagerTreePtr log_manager);

    /**
     * Try to insert vote to storage
     * @param vote - object for insertion
     * @return result, that contains actual state of storage.
     * boost::none if not inserted, possible reasons - duplication,
     * wrong proposal/block round.
     */
    boost::optional<Answer> insert(VoteMessage vote);

    /**
     * Insert bundle of messages into storage
     * @param messages - collection of messages
     * @return result, that contains actual state of storage,
     * after insertion of all votes.
     */
    boost::optional<Answer> insert(std::vector<VoteMessage> messages);

    /**
     * Provides key for storage
     */
    const Round &getStorageKey() const;

    /**
     * @return current state of storage
     */
    boost::optional<Answer> getState() const;

   private:
    // --------| private api |--------

    /**
     * Possible to insert vote
     * @param msg - vote for insertion
     * @return true if possible
     */
    bool shouldInsert(const VoteMessage &msg);

    /**
     * Is this vote valid for insertion in proposal storage
     * @param vote_round - round for verification
     * @return true if it may be applied
     */
    bool checkProposalRound(const Round &vote_round);

    /**
     * Is this peer first time appear in this proposal storage
     * @return true, if peer unique
     */
    bool checkPeerUniqueness(const VoteMessage &msg);

    /**
     * Method try to find proof of reject.
     * This computes as
     * number of not voted peers + most frequent vote count < supermajority
     * @return answer with proof
     */
    boost::optional<Answer> findRejectProof();

    // --------| fields |--------

    /**
     * Current state of storage
     */
    boost::optional<Answer> current_state_;

    /**
     * Vector of block storages based on this proposal
     */
    std::vector<YacBlockStorage> block_storages_;

    /**
     * Key of the storage
     */
    Round storage_key_;

    /**
     * Provide number of peers participated in current round
     */
    PeersNumberType peers_in_round_;

    /**
     * Provide functions to check supermajority
     */
    std::shared_ptr<SupermajorityChecker> supermajority_checker_;

    /**
     * Storage logger manager
     */
    logger::LoggerManagerTreePtr log_manager_;

    /**
     * Storage logger
     */
    logger::LoggerPtr log_;
  };
}  // namespace iroha::consensus::yac

#endif  // IROHA_YAC_PROPOSAL_STORAGE_HPP
