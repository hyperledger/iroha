/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <utility>

#include "multi_sig_transactions/storage/mst_storage.hpp"

namespace iroha {
  MstStorage::MstStorage(logger::LoggerPtr log) : log_{std::move(log)} {}

  StateUpdateResult MstStorage::apply(
      shared_model::interface::types::PublicKeyHexStringView target_peer_key,
      const MstState &new_state) {
    std::lock_guard<std::mutex> lock{this->mutex_};
    return applyImpl(target_peer_key, new_state);
  }

  StateUpdateResult MstStorage::updateOwnState(const DataType &tx) {
    std::lock_guard<std::mutex> lock{this->mutex_};
    return updateOwnStateImpl(tx);
  }

  MstState MstStorage::extractExpiredTransactions(
      const TimeType &current_time) {
    std::lock_guard<std::mutex> lock{this->mutex_};
    return extractExpiredTransactionsImpl(current_time);
  }

  MstState MstStorage::getDiffState(
      shared_model::interface::types::PublicKeyHexStringView target_peer_key,
      const TimeType &current_time) {
    std::lock_guard<std::mutex> lock{this->mutex_};
    return getDiffStateImpl(target_peer_key, current_time);
  }

  MstState MstStorage::whatsNew(ConstRefState new_state) const {
    std::lock_guard<std::mutex> lock{this->mutex_};
    return whatsNewImpl(new_state);
  }

  bool MstStorage::batchInStorage(const DataType &batch) const {
    return batchInStorageImpl(batch);
  }

  void MstStorage::processFinalizedTransaction(
      shared_model::interface::types::HashType const &hash) {
    std::lock_guard lock{mutex_};
    processFinalizedTransactionImpl(hash);
  }
}  // namespace iroha
