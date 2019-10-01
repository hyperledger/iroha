/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "multi_sig_transactions/mst_processor.hpp"

#include <rxcpp/rx-lite.hpp>

namespace iroha {

  MstProcessor::MstProcessor(logger::LoggerPtr log) : log_(std::move(log)) {}

  void MstProcessor::propagateBatch(const DataType &batch) {
    this->propagateBatchImpl(batch);
  }

  rxcpp::observable<std::shared_ptr<MstState>> MstProcessor::onStateUpdate()
      const {
    return this->onStateUpdateImpl();
  }

  rxcpp::observable<DataType> MstProcessor::onPreparedBatches() const {
    return this->onPreparedBatchesImpl();
  }

  rxcpp::observable<DataType> MstProcessor::onExpiredBatches() const {
    return this->onExpiredBatchesImpl();
  }

  bool MstProcessor::batchInStorage(const DataType &batch) const {
    return this->batchInStorageImpl(batch);
  }

}  // namespace iroha
