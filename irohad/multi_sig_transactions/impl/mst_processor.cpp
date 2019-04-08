/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "multi_sig_transactions/mst_processor.hpp"

namespace iroha {

  MstProcessor::MstProcessor(logger::LoggerPtr log) : log_(std::move(log)) {}

  bool MstProcessor::propagateBatch(const DataType &batch) {
    return this->propagateBatchImpl(batch);
  }

  rxcpp::observable<std::shared_ptr<const MstState>>
  MstProcessor::onStateUpdate() const {
    return this->onStateUpdateImpl();
  }

  rxcpp::observable<std::shared_ptr<MovedBatch>>
  MstProcessor::onPreparedBatches() const {
    return this->onPreparedBatchesImpl();
  }

  rxcpp::observable<DataType> MstProcessor::onExpiredBatches() const {
    return this->onExpiredBatchesImpl();
  }

  bool MstProcessor::batchInStorage(const DataType &batch) const {
    return this->batchInStorageImpl(batch);
  }

}  // namespace iroha
