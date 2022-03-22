/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/iroha_internal/transaction_batch.hpp"

#include <string_view>

#include "interfaces/transaction.hpp"
#include "utils/string_builder.hpp"

namespace shared_model {
  namespace interface {

    std::string TransactionBatch::toString() const {
      return detail::PrettyStringBuilder()
          .init("TransactionBatch")
          .appendNamed("Transactions", transactions())
          .finalize();
    }

    bool BatchHashEquality::operator()(
        const std::shared_ptr<TransactionBatch> &left_tx,
        const std::shared_ptr<TransactionBatch> &right_tx) const {
      return left_tx->reducedHash() == right_tx->reducedHash();
    }

    size_t BatchPointerHasher::operator()(
        const std::shared_ptr<shared_model::interface::TransactionBatch> &a)
        const {
      return hasher_(a->reducedHash());
    }

    bool BatchHashLess::operator()(
        const std::shared_ptr<TransactionBatch> &left_tx,
        const std::shared_ptr<TransactionBatch> &right_tx) const {
      return std::less<shared_model::crypto::Blob::Bytes>{}(
          left_tx->reducedHash().blob(), right_tx->reducedHash().blob());
    }
  }  // namespace interface
}  // namespace shared_model
