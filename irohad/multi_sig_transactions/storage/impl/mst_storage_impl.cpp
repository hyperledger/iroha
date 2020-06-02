/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "multi_sig_transactions/storage/mst_storage_impl.hpp"

namespace iroha {
  // ------------------------------| private API |------------------------------

  auto MstStorageStateImpl::getState(
      shared_model::interface::types::PublicKeyHexStringView target_peer_key) {
    auto target_state_iter =
        peer_states_.find(StringViewOrString{target_peer_key});
    if (target_state_iter == peer_states_.end()) {
      return peer_states_
          .emplace(StringViewOrString{std::string{target_peer_key}},
                   MstState::empty(mst_state_logger_, completer_))
          .first;
    }
    return target_state_iter;
  }
  // -----------------------------| interface API |-----------------------------
  MstStorageStateImpl::MstStorageStateImpl(MstStorageStateImpl::private_tag,
                                           CompleterType const &completer,
                                           logger::LoggerPtr mst_state_logger,
                                           logger::LoggerPtr log)
      : MstStorage(log),
        completer_(completer),
        own_state_(MstState::empty(mst_state_logger, completer_)),
        mst_state_logger_(std::move(mst_state_logger)) {}

  std::shared_ptr<MstStorageStateImpl> MstStorageStateImpl::create(
      CompleterType const &completer,
      rxcpp::observable<shared_model::interface::types::HashType> finalized_txs,
      logger::LoggerPtr mst_state_logger,
      logger::LoggerPtr log) {
    auto storage = std::make_shared<MstStorageStateImpl>(
        MstStorageStateImpl::private_tag{},
        completer,
        std::move(mst_state_logger),
        std::move(log));
    std::weak_ptr<MstStorageStateImpl> storage_(storage);

    auto subscription = rxcpp::composite_subscription();
    finalized_txs.subscribe(
        subscription,
        [storage_,
         subscription](shared_model::interface::types::HashType const &hash) {
          if (auto storage = storage_.lock()) {
            for (auto &p : storage->peer_states_) {
              p.second.eraseByTransactionHash(hash);
            }
            storage->own_state_.eraseByTransactionHash(hash);
          } else {
            subscription.unsubscribe();
          }
        });

    return storage;
  }

  auto MstStorageStateImpl::applyImpl(
      shared_model::interface::types::PublicKeyHexStringView target_peer_key,
      const MstState &new_state)
      -> decltype(apply(target_peer_key, new_state)) {
    auto target_state_iter = getState(target_peer_key);
    target_state_iter->second += new_state;
    return own_state_ += new_state;
  }

  auto MstStorageStateImpl::updateOwnStateImpl(const DataType &tx)
      -> decltype(updateOwnState(tx)) {
    return own_state_ += tx;
  }

  auto MstStorageStateImpl::extractExpiredTransactionsImpl(
      const TimeType &current_time)
      -> decltype(extractExpiredTransactions(current_time)) {
    for (auto &peer_and_state : peer_states_) {
      peer_and_state.second.eraseExpired(current_time);
    }
    return own_state_.extractExpired(current_time);
  }

  auto MstStorageStateImpl::getDiffStateImpl(
      shared_model::interface::types::PublicKeyHexStringView target_peer_key,
      const TimeType &current_time)
      -> decltype(getDiffState(target_peer_key, current_time)) {
    auto target_current_state_iter = getState(target_peer_key);
    auto new_diff_state = own_state_ - target_current_state_iter->second;
    new_diff_state.eraseExpired(current_time);
    return new_diff_state;
  }

  auto MstStorageStateImpl::whatsNewImpl(ConstRefState new_state) const
      -> decltype(whatsNew(new_state)) {
    return new_state - own_state_;
  }

  bool MstStorageStateImpl::batchInStorageImpl(const DataType &batch) const {
    return own_state_.contains(batch);
  }

}  // namespace iroha
