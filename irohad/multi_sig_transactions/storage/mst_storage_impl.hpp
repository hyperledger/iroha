/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MST_STORAGE_IMPL_HPP
#define IROHA_MST_STORAGE_IMPL_HPP

#include <memory>
#include <unordered_map>

#include "logger/logger_fwd.hpp"
#include "main/subscription.hpp"
#include "multi_sig_transactions/hash.hpp"
#include "multi_sig_transactions/storage/mst_storage.hpp"

namespace iroha {
  class MstStorageStateImpl : public MstStorage {
   private:
    struct private_tag {};

    // -----------------------------| private API |-----------------------------

    /**
     * Return state of a peer by its public key. If state doesn't exist, create
     * new empty state and return it.
     * @param target_peer_key - public key of the peer for searching
     * @return valid iterator for state of peer
     */
    auto getState(
        shared_model::interface::types::PublicKeyHexStringView target_peer_key);

   public:
    // ----------------------------| interface API |----------------------------
    MstStorageStateImpl(MstStorageStateImpl::private_tag,
                        CompleterType const &completer,
                        logger::LoggerPtr mst_state_logger,
                        logger::LoggerPtr log);

    MstStorageStateImpl(MstStorageStateImpl const &) = delete;
    MstStorageStateImpl &operator=(MstStorageStateImpl const &) = delete;

    static std::shared_ptr<MstStorageStateImpl> create(
        CompleterType const &completer,
        logger::LoggerPtr mst_state_logger,
        logger::LoggerPtr log);

    auto applyImpl(
        shared_model::interface::types::PublicKeyHexStringView target_peer_key,
        const MstState &new_state)
        -> decltype(apply(target_peer_key, new_state)) override;

    auto updateOwnStateImpl(const DataType &tx)
        -> decltype(updateOwnState(tx)) override;

    auto extractExpiredTransactionsImpl(const TimeType &current_time)
        -> decltype(extractExpiredTransactions(current_time)) override;

    auto getDiffStateImpl(
        shared_model::interface::types::PublicKeyHexStringView target_peer_key,
        const TimeType &current_time)
        -> decltype(getDiffState(target_peer_key, current_time)) override;

    auto whatsNewImpl(ConstRefState new_state) const
        -> decltype(whatsNew(new_state)) override;

    bool batchInStorageImpl(const DataType &batch) const override;

   private:
    // ---------------------------| private fields |----------------------------

    const CompleterType completer_;
    struct StringViewOrString {
      std::string s;
      std::string_view v;

      explicit StringViewOrString(std::string_view v) : v(v) {}
      explicit StringViewOrString(std::string s) : s(s), v(this->s) {}

      StringViewOrString(StringViewOrString const &o)
          : s(o.s), v(not this->s.empty() ? this->s : o.v) {}
      StringViewOrString(StringViewOrString &&o) noexcept
          : s(std::move(o).s),
            v(not this->s.empty() ? this->s : std::move(o).v) {}

      bool operator==(StringViewOrString const &x) const {
        return v == x.v;
      }

      struct Hash {
        std::size_t operator()(StringViewOrString const &x) const {
          return std::hash<std::string_view>()(x.v);
        }
      };
    };
    std::unordered_map<StringViewOrString, MstState, StringViewOrString::Hash>
        peer_states_;
    MstState own_state_;

    std::shared_ptr<
        BaseSubscriber<bool, shared_model::interface::types::HashType>>
        finalized_txs_subscription_;

    logger::LoggerPtr mst_state_logger_;  ///< Logger for created MstState
                                          ///< objects.
  };
}  // namespace iroha

#endif  // IROHA_MST_STORAGE_IMPL_HPP
