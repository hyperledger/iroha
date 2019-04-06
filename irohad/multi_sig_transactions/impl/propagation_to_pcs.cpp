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
    rxcpp::observable<size_t> propagation_available,
    logger::LoggerPtr log)
    : log_(std::move(log)),
      pcs_(pcs),
      propagation_available_subscription_(
          propagation_available.subscribe([this, pcs](size_t available_txs) {
            auto it = pending_batches_.begin();
            while (it != pending_batches_.end()) {
              const auto txs_in_batch = (*it)->transactions().size();
              if (txs_in_batch <= available_txs and pcs->propagate_batch(*it)) {
                available_txs -= txs_in_batch;
                it = pending_batches_.erase(it);
              } else {
                ++it;
              }
            }
          })) {}

MstToPcsPropagation::~MstToPcsPropagation() {
  propagation_available_subscription_.unsubscribe();
}

void MstToPcsPropagation::notifyCompletedBatch(BatchPtr batch) {
  if (not pcs_->propagate_batch(batch)) {
    pending_batches_.emplace_back(batch);
  }
}
