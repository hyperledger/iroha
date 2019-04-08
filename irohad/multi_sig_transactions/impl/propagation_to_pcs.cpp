/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "multi_sig_transactions/propagation_to_pcs.hpp"

#include <utility>

#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "logger/logger.hpp"

using namespace iroha;

MstToPcsPropagation::MstToPcsPropagation(
    std::shared_ptr<iroha::network::PeerCommunicationService> pcs,
    std::shared_ptr<StorageLimit<BatchPtr>> storage_limit,
    rxcpp::observable<size_t> propagation_available,
    logger::LoggerPtr log)
    : log_(std::move(log)),
      pcs_(pcs),
      pending_batches_(std::move(storage_limit),
                       std::make_unique<InternalStorage>()),
      propagation_available_subscription_(
          propagation_available.subscribe([this, pcs](size_t available_txs) {
            pending_batches_.extract(
                [pcs, &available_txs](InternalStorage &storage) {
                  std::vector<BatchPtr> extracted;
                  extracted.reserve(storage.pending_batches.size());
                  auto it = storage.pending_batches.begin();
                  while (it != storage.pending_batches.end()) {
                    const auto txs_in_batch = (*it)->transactions().size();
                    if (txs_in_batch <= available_txs
                        and pcs->propagate_batch(*it)) {
                      available_txs -= txs_in_batch;
                      extracted.emplace_back(std::move(*it));
                      it = storage.pending_batches.erase(it);
                    } else {
                      ++it;
                    }
                  }
                  return extracted;
                });
          })) {}

MstToPcsPropagation::~MstToPcsPropagation() {
  propagation_available_subscription_.unsubscribe();
}

void MstToPcsPropagation::notifyCompletedBatch(
    std::shared_ptr<MovedBatch> moved_batch) {
  if (not pcs_->propagate_batch(moved_batch->get())) {
    if (not pending_batches_.insert(std::move(moved_batch))) {
      log_->critical(
          "Dropped a completed MST batch because no place left in storage: {}",
          moved_batch->get());
      assert(false);
    }
  }
}

size_t MstToPcsPropagation::pendingBatchesQuantity() const {
  return pending_batches_.itemsQuantity();
}

bool MstToPcsPropagation::InternalStorage::insert(BatchPtr batch) {
  pending_batches.emplace_back(std::move(batch));
  return true;
}
