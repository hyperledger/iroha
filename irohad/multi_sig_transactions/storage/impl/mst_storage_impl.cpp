/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "multi_sig_transactions/storage/mst_storage_impl.hpp"

#include "multi_sig_transactions/mst_time_provider.hpp"

namespace iroha {
  // ------------------------------| private API |------------------------------

  auto MstStorageStateImpl::getState(
      const shared_model::crypto::PublicKey &target_peer_key) {
    auto target_state_iter = peer_states_.find(target_peer_key);
    if (target_state_iter == peer_states_.end()) {
      return peer_states_
          .insert(
              {target_peer_key, MstState::empty(mst_state_logger_, completer_)})
          .first;
    }
    return target_state_iter;
  }
  // -----------------------------| interface API |-----------------------------

  MstStorageStateImpl::MstStorageStateImpl(
      const CompleterType &completer,
      std::shared_ptr<MstTimeProvider> time_provider,
      std::chrono::milliseconds stalled_batch_threshold,
      logger::LoggerPtr mst_state_logger,
      logger::LoggerPtr log)
      : MstStorage(log),
        completer_(completer),
        own_state_(MstState::empty(mst_state_logger, completer_)),
        mst_state_logger_(std::move(mst_state_logger)),
        time_provider_(std::move(time_provider)),
        stalled_batch_threshold_(stalled_batch_threshold) {}

  auto MstStorageStateImpl::applyImpl(
      const shared_model::crypto::PublicKey &target_peer_key,
      MstState &&new_state)
      -> decltype(apply(target_peer_key, std::declval<MstState &&>())) {
    // no need to add already expired batches to local state
    const auto current_time = time_provider_->getCurrentTime();
    new_state.eraseExpired(current_time);
    new_state.iterateBatches([this, current_time](const auto &batch) {
      setLastUpdateTime(batch, current_time);
    });
    auto target_state_iter = getState(target_peer_key);
    target_state_iter->second += new_state;
    auto state_update = (own_state_ += new_state);
    state_update.completed_state_->iterateBatches([this](auto const &batch) {
      batch_last_update_time_.left.erase(batch);
    });
    return state_update;
  }

  auto MstStorageStateImpl::updateOwnStateImpl(const DataType &tx)
      -> decltype(updateOwnState(tx)) {
    auto state_update = (own_state_ += tx);
    state_update.completed_state_->iterateBatches([this](auto const &batch) {
      batch_last_update_time_.left.erase(batch);
    });
    return state_update;
  }

  auto MstStorageStateImpl::extractExpiredTransactionsImpl()
      -> decltype(extractExpiredTransactions()) {
    const auto current_time = time_provider_->getCurrentTime();
    for (auto &peer_and_state : peer_states_) {
      peer_and_state.second.eraseExpired(current_time);
    }
    auto expired_transactions = own_state_.extractExpired(current_time);
    expired_transactions.iterateBatches([this](auto const &batch) {
      batch_last_update_time_.left.erase(batch);
    });
    return expired_transactions;
  }

  auto MstStorageStateImpl::getDiffStateImpl(
      const shared_model::crypto::PublicKey &target_peer_key)
      -> decltype(getDiffState(target_peer_key)) {
    auto target_current_state_iter = getState(target_peer_key);
    auto new_diff_state = own_state_ - target_current_state_iter->second;
    new_diff_state.eraseExpired(time_provider_->getCurrentTime());
    return new_diff_state;
  }

  auto MstStorageStateImpl::whatsNewImpl(ConstRefState new_state) const
      -> decltype(whatsNew(new_state)) {
    return new_state - own_state_;
  }

  bool MstStorageStateImpl::batchInStorageImpl(const DataType &batch) const {
    return own_state_.contains(batch);
  }

  void MstStorageStateImpl::clearStalledPeerStatesImpl() {
    const auto current_time = time_provider_->getCurrentTime();
    // iterate batches sorted by timestamp ascending
    for (auto &time_and_batch : batch_last_update_time_.right) {
      auto &last_update = time_and_batch.first;
      const auto &batch_ptr = time_and_batch.second;
      assert(current_time >= last_update);
      if (current_time < last_update
          or std::chrono::milliseconds(current_time - last_update)
              < stalled_batch_threshold_) {
        // next pairs have more recent timestamp
        break;
      }
      // give up the assumption that peer has this batch
      for (auto &peer_and_state : peer_states_) {
        auto &state = peer_and_state.second;
        state.erase(batch_ptr);
      }
    }
  }

  void MstStorageStateImpl::eraseTransactionImpl(
      shared_model::interface::types::HashType const &hash) {
    for (auto &p : peer_states_) {
      p.second.eraseByTransactionHash(hash);
    }
    own_state_.eraseByTransactionHash(hash);
  }

  void MstStorageStateImpl::setLastUpdateTime(const DataType &batch,
                                              TimeType time) {
    batch_last_update_time_.left.erase(batch);
    batch_last_update_time_.insert(
        BatchToTimestampBimap::value_type(batch, time));
  }

}  // namespace iroha
