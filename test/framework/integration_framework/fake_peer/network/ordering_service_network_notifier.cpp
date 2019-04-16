/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "framework/integration_framework/fake_peer/network/ordering_service_network_notifier.hpp"

#include "interfaces/iroha_internal/transaction_batch.hpp"

using TransactionBatch = shared_model::interface::TransactionBatch;

namespace integration_framework {
  namespace fake_peer {

    void OsNetworkNotifier::onBatch(std::unique_ptr<TransactionBatch> batch) {
      std::shared_ptr<TransactionBatch> batch_ptr = std::move(batch);
      std::lock_guard<std::mutex> guard(batches_subject_mutex_);
      batches_subject_.get_subscriber().on_next(std::move(batch_ptr));
    }

    rxcpp::observable<
        std::shared_ptr<shared_model::interface::TransactionBatch>>
    OsNetworkNotifier::getObservable() {
      return batches_subject_.get_observable();
    }

  }  // namespace fake_peer
}  // namespace integration_framework
