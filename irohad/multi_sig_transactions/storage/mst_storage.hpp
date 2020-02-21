/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MST_STORAGE_HPP
#define IROHA_MST_STORAGE_HPP

#include <mutex>

#include "cryptography/public_key.hpp"
#include "logger/logger_fwd.hpp"
#include "multi_sig_transactions/mst_types.hpp"

namespace iroha {
  class MstState;

  /**
   * MstStorage responsible for manage own and others MstStates.
   * All methods of storage covered by mutex, because we assume that mutex
   * possible to execute in concurrent environment.
   */
  class MstStorage {
   public:
    // ------------------------------| user API |-------------------------------

    /**
     * Apply new state for peer
     * @param target_peer_key - key for for updating state
     * @param new_state - state with new data
     * @return State with completed or updated batches
     * General note: implementation of method covered by lock
     */
    StateUpdateResult apply(
        const shared_model::crypto::PublicKey &target_peer_key,
        MstState &&new_state);

    /**
     * Provide updating state of current peer with new transaction
     * @param tx - new transaction for insertion in state
     * @return completed and updated mst states
     * General note: implementation of method covered by lock
     */
    StateUpdateResult updateOwnState(const DataType &tx);

    /**
     * Remove expired transactions and return them
     * @return State with expired transactions
     * General note: implementation of method covered by lock
     */
    MstState extractExpiredTransactions();

    /**
     * Make state based on diff of own and target states.
     * All expired transactions will be removed from diff.
     * @return difference between own and target state
     * General note: implementation of method covered by lock
     */
    MstState getDiffState(
        const shared_model::crypto::PublicKey &target_peer_key);

    /**
     * Return diff between own and new state
     * @param new_state - state with new data
     * @return state that contains new data with respect to own state
     * General note: implementation of method covered by lock
     */
    MstState whatsNew(ConstRefState new_state) const;

    /**
     * Check, if passed batch is in the storage
     * @param batch to be checked
     * @return true, if batch is already in the storage, false otherwise
     */
    bool batchInStorage(const DataType &batch) const;

    /// Clear stalled transactions from the states of other peers.
    void clearStalledPeerStates();

    virtual ~MstStorage() = default;

   protected:
    // ------------------------------| class API |------------------------------

    /**
     * Constructor provide initialization of protected fields, such as logger.
     */
    explicit MstStorage(logger::LoggerPtr log);

   private:
    virtual auto applyImpl(
        const shared_model::crypto::PublicKey &target_peer_key,
        MstState &&new_state)
        -> decltype(apply(target_peer_key, std::declval<MstState &&>())) = 0;

    virtual auto updateOwnStateImpl(const DataType &tx)
        -> decltype(updateOwnState(tx)) = 0;

    virtual auto extractExpiredTransactionsImpl()
        -> decltype(extractExpiredTransactions()) = 0;

    virtual auto getDiffStateImpl(
        const shared_model::crypto::PublicKey &target_peer_key)
        -> decltype(getDiffState(target_peer_key)) = 0;

    virtual auto whatsNewImpl(ConstRefState new_state) const
        -> decltype(whatsNew(new_state)) = 0;

    virtual bool batchInStorageImpl(const DataType &batch) const = 0;

    virtual void clearStalledPeerStatesImpl() = 0;

    // -------------------------------| fields |--------------------------------

    mutable std::mutex mutex_;

   protected:
    logger::LoggerPtr log_;
  };
}  // namespace iroha
#endif  // IROHA_MST_STORAGE_HPP
