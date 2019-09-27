/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TRANSACTIONS_RESPONSE_HPP
#define IROHA_TRANSACTIONS_RESPONSE_HPP

#include <rxcpp/rx-lite.hpp>
#include "model/transaction.hpp"

namespace iroha {
  namespace model {

    /**
     * Provide responded transactions
     */
    struct TransactionsResponse : public QueryResponse {
      /**
       * Observable contains transactions
       */
      rxcpp::observable<Transaction> transactions{};
    };
  }  // namespace model
}  // namespace iroha
#endif  // IROHA_TRANSACTIONS_RESPONSE_HPP
