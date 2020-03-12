/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MST_STORAGE_IMPL_HPP
#define IROHA_MST_STORAGE_IMPL_HPP

#include "multi_sig_transactions/storage/mst_storage.hpp"

#include <unordered_map>

#include "logger/logger_fwd.hpp"
#include "multi_sig_transactions/hash.hpp"
#include "multi_sig_transactions/mst_types.hpp"
#include "multi_sig_transactions/state/mst_state.hpp"

namespace iroha {
  class MstTimeProvider;

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
    MstStorageStateImpl(const CompleterType &completer,
                        std::shared_ptr<MstTimeProvider> time_provider,
                        std::chrono::milliseconds stalled_batch_threshold,
                        logger::LoggerPtr mst_state_logger,
                        logger::LoggerPtr log);

    auto applyImpl(const shared_model::crypto::PublicKey &target_peer_key,
                   MstState &&new_state)
        -> decltype(apply(target_peer_key,
                          std::declval<MstState &&>())) override;

    auto updateOwnStateImpl(const DataType &tx)
        -> decltype(updateOwnState(tx)) override;

    auto extractExpiredTransactionsImpl()
        -> decltype(extractExpiredTransactions()) override;

    auto getDiffStateImpl(
        const shared_model::crypto::PublicKey &target_peer_key)
        -> decltype(getDiffState(target_peer_key)) override;

    auto whatsNewImpl(ConstRefState new_state) const
        -> decltype(whatsNew(new_state)) override;

    bool batchInStorageImpl(const DataType &batch) const override;

    void clearStalledPeerStatesImpl() override;

    void eraseTransactionImpl(
        shared_model::interface::types::HashType const &hash) override;

   private:
    inline void setLastUpdateTime(const DataType &batch, TimeType time);

    // ---------------------------| private fields |----------------------------

    const CompleterType completer_;
    std::unordered_map<shared_model::crypto::PublicKey,
                       MstState,
                       iroha::model::BlobHasher>
        peer_states_;
    MstState own_state_;

    using BatchToTimestampBimap = boost::bimap<
        boost::bimaps::unordered_set_of<DataType,
                                        iroha::model::PointerBatchHasher,
                                        BatchHashEquality>,
        boost::bimaps::multiset_of<
            shared_model::interface::types::TimestampType>>;

    BatchToTimestampBimap batch_last_update_time_;

    logger::LoggerPtr mst_state_logger_;  ///< Logger for created MstState
                                          ///< objects.
    std::shared_ptr<MstTimeProvider> time_provider_;
    const std::chrono::milliseconds stalled_batch_threshold_;
  };
}  // namespace iroha

#endif  // IROHA_MST_STORAGE_IMPL_HPP
