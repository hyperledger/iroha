/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/query_responses/transactions_page_response.hpp"
#include "interfaces/transaction.hpp"

namespace shared_model {
  namespace interface {

    std::string TransactionsPageResponse::toString() const {
      auto builder = detail::PrettyStringBuilder()
                         .init("TransactionsPageResponse")
                         .appendAll("transactions",
                                    transactions(),
                                    [](auto &tx) { return tx.toString(); })
                         .append("all transactions size",
                                 std::to_string(allTransactionsSize()));
      if (nextTxHash()) {
        return builder.append("next tx hash", nextTxHash()->hex()).finalize();
      }
      return builder.finalize();
    }

    bool TransactionsPageResponse::operator==(const ModelType &rhs) const {
      return transactions() == rhs.transactions()
          and nextTxHash() == rhs.nextTxHash()
          and allTransactionsSize() == rhs.allTransactionsSize();
    }

  }  // namespace interface
}  // namespace shared_model
