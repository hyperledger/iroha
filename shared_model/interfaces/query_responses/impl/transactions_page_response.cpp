/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/query_responses/transactions_page_response.hpp"
#include "interfaces/transaction.hpp"

namespace shared_model {
  namespace interface {

    std::string TransactionsPageResponse::toString() const {
      return detail::PrettyStringBuilder()
          .init("TransactionsPageResponse")
          .appendNamed("transactions", transactions())
          .appendNamed("all transactions size", allTransactionsSize())
          .appendNamed("next tx", nextTxHash())
          .finalize();
    }

    bool TransactionsPageResponse::operator==(const ModelType &rhs) const {
      return transactions() == rhs.transactions()
          and nextTxHash() == rhs.nextTxHash()
          and allTransactionsSize() == rhs.allTransactionsSize();
    }

  }  // namespace interface
}  // namespace shared_model
