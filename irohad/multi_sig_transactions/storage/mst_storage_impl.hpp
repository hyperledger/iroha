/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MST_STORAGE_IMPL_HPP
#define IROHA_MST_STORAGE_IMPL_HPP

#include <unordered_map>
#include "logger/logger_fwd.hpp"
#include "multi_sig_transactions/hash.hpp"
#include "multi_sig_transactions/storage/mst_storage.hpp"
#include "storage_shared_limit/storage_limit.hpp"

namespace iroha {
  class MstStorageStateImpl : public MstStorage {
   private:
    // -----------------------------| private API |-----------------------------

    /**
     * Return state of a peer by its public key. If state doesn't exist, create
     * new empty state and return it.
     * @param target_peer_key - public key of the peer for searching
     * @return valid iterator for state of peer
     */
    auto getState(const shared_model::crypto::PublicKey &target_peer_key);

   public:
    // ----------------------------| interface API |----------------------------
    /**
     * @param completer - strategy for determine completed and expired batches
     * @param transaction_limit - maximum quantity of transactions stored
     * @param mst_state_logger - the logger for created MST state
     * @param log - the logger to use in the new object
     */
    MstStorageStateImpl(const CompleterType &completer,
                        std::shared_ptr<StorageLimit<BatchPtr>> storage_limit,
                        logger::LoggerPtr mst_state_logger,
                        logger::LoggerPtr log);

    auto applyImpl(const shared_model::crypto::PublicKey &target_peer_key,
                   const MstState &new_state)
        -> decltype(apply(target_peer_key, new_state)) override;

    auto updateOwnStateImpl(const DataType &tx)
        -> decltype(updateOwnState(tx)) override;

    auto extractExpiredTransactionsImpl(const TimeType &current_time)
        -> decltype(extractExpiredTransactions(current_time)) override;

    auto getDiffStateImpl(
        const shared_model::crypto::PublicKey &target_peer_key,
        const TimeType &current_time)
        -> decltype(getDiffState(target_peer_key, current_time)) override;

    auto whatsNewImpl(ConstRefState new_state) const
        -> decltype(whatsNew(new_state)) override;

    bool batchInStorageImpl(const DataType &batch) const override;

   private:
    // ---------------------------| private fields |----------------------------

    const CompleterType completer_;
    std::shared_ptr<StorageLimit<BatchPtr>> storage_limit_;
    std::unordered_map<shared_model::crypto::PublicKey,
                       MstState,
                       iroha::model::BlobHasher>
        peer_states_;
    MstState own_state_;

    logger::LoggerPtr mst_state_logger_;  ///< Logger for created MstState
                                          ///< objects.
  };
}  // namespace iroha

#endif  // IROHA_MST_STORAGE_IMPL_HPP
