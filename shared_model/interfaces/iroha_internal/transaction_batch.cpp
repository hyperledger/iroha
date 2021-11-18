/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/iroha_internal/transaction_batch.hpp"

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

    bool BatchHashLess::operator()(
        const std::shared_ptr<TransactionBatch> &left_tx,
        const std::shared_ptr<TransactionBatch> &right_tx) const {
      return left_tx->reducedHash() < right_tx->reducedHash();
    }

  }  // namespace interface
}  // namespace shared_model
