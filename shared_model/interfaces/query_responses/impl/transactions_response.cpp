/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/query_responses/transactions_response.hpp"
#include "interfaces/transaction.hpp"
#include "utils/string_builder.hpp"

namespace shared_model {
  namespace interface {

    std::string TransactionsResponse::toString() const {
      return detail::PrettyStringBuilder()
          .init("TransactionsResponse")
          .append(transactions())
          .finalize();
    }

    bool TransactionsResponse::operator==(const ModelType &rhs) const {
      return transactions() == rhs.transactions();
    }

  }  // namespace interface
}  // namespace shared_model
