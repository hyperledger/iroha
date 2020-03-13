/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/query_responses/pending_transactions_page_response.hpp"

#include "interfaces/transaction.hpp"

namespace shared_model {
  namespace interface {
    std::string PendingTransactionsPageResponse::BatchInfo::toString() const {
      return detail::PrettyStringBuilder()
          .init("BatchInfo")
          .appendNamed("first tx hash", first_tx_hash.hex())
          .appendNamed("size", batch_size)
          .finalize();
    }

    std::string PendingTransactionsPageResponse::toString() const {
      return detail::PrettyStringBuilder()
          .init("PendingTransactionsPageResponse")
          .appendNamed("transactions", transactions())
          .appendNamed("all transactions size", allTransactionsSize())
          .appendNamed("next batch", nextBatchInfo())
          .finalize();
    }

    bool PendingTransactionsPageResponse::operator==(
        const ModelType &rhs) const {
      return transactions() == rhs.transactions()
          and nextBatchInfo() == rhs.nextBatchInfo()
          and allTransactionsSize() == rhs.allTransactionsSize();
    }

  }  // namespace interface
}  // namespace shared_model
