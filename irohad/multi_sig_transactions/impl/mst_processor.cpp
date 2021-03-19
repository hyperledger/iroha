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

  bool MstProcessor::batchInStorage(const DataType &batch) const {
    return this->batchInStorageImpl(batch);
  }

}  // namespace iroha
