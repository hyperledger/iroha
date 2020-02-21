/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "multi_sig_transactions/storage/mst_storage.hpp"

#include <utility>

#include "multi_sig_transactions/state/mst_state.hpp"

namespace iroha {
  MstStorage::MstStorage(logger::LoggerPtr log) : log_{std::move(log)} {}

  StateUpdateResult MstStorage::apply(
      const shared_model::crypto::PublicKey &target_peer_key,
      MstState &&new_state) {
    std::lock_guard<std::mutex> lock{this->mutex_};
    return applyImpl(target_peer_key, std::move(new_state));
  }

  StateUpdateResult MstStorage::updateOwnState(const DataType &tx) {
    std::lock_guard<std::mutex> lock{this->mutex_};
    return updateOwnStateImpl(tx);
  }

  MstState MstStorage::extractExpiredTransactions() {
    std::lock_guard<std::mutex> lock{this->mutex_};
    return extractExpiredTransactionsImpl();
  }

  MstState MstStorage::getDiffState(
      const shared_model::crypto::PublicKey &target_peer_key) {
    std::lock_guard<std::mutex> lock{this->mutex_};
    return getDiffStateImpl(target_peer_key);
  }

  MstState MstStorage::whatsNew(ConstRefState new_state) const {
    std::lock_guard<std::mutex> lock{this->mutex_};
    return whatsNewImpl(new_state);
  }

  bool MstStorage::batchInStorage(const DataType &batch) const {
    return batchInStorageImpl(batch);
  }

  void MstStorage::clearStalledPeerStates() {
    std::lock_guard<std::mutex> lock{this->mutex_};
    clearStalledPeerStatesImpl();
  }
}  // namespace iroha
