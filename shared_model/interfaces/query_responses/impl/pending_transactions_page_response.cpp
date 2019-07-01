/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/query_responses/pending_transactions_page_response.hpp"

#include "interfaces/transaction.hpp"

namespace shared_model {
  namespace interface {

    std::string PendingTransactionsPageResponse::toString() const {
      auto builder = detail::PrettyStringBuilder()
                         .init("PendingTransactionsPageResponse")
                         .appendAll("transactions",
                                    transactions(),
                                    [](auto &tx) { return tx.toString(); })
                         .append("all transactions size",
                                 std::to_string(allTransactionsSize()));
      if (auto next_batch_info = nextBatchInfo()) {
        builder
            .append("next batch first tx hash",
                    next_batch_info->first_tx_hash.hex())
            .append("next batch size",
                    std::to_string(next_batch_info->batch_size));
      } else {
        builder.append("no next batch info is set");
      }
      return builder.finalize();
    }

    bool PendingTransactionsPageResponse::operator==(
        const ModelType &rhs) const {
      return transactions() == rhs.transactions()
          and nextBatchInfo() == rhs.nextBatchInfo()
          and allTransactionsSize() == rhs.allTransactionsSize();
    }

  }  // namespace interface
}  // namespace shared_model
