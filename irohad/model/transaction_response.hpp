/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TRANSACTION_RESPONSE_HPP
#define IROHA_TRANSACTION_RESPONSE_HPP

#include "model/client.hpp"
#include "model/transaction.hpp"

namespace iroha {
  namespace model {

    /**
     * Transaction response is data with status during transaction lifecycle
     */
    struct TransactionResponse {
      /**
       * Processed transaction
       */
      std::string tx_hash{};

      enum Status {
        /// stateless validation failed
        STATELESS_VALIDATION_FAILED,
        /// stateless validation passed
        STATELESS_VALIDATION_SUCCESS,
        /// stateful validation failed
        STATEFUL_VALIDATION_FAILED,
        /// stateful validation passed
        STATEFUL_VALIDATION_SUCCESS,
        /// tx pipeline succeeded, tx is committed
        COMMITTED,
        /// tx is expired in mst validation
        MST_EXPIRED,
        /// transaction is not in handler map
        NOT_RECEIVED,
      };

      Status current_status{};

      virtual ~TransactionResponse() = default;

      TransactionResponse(std::string tx_hash, Status status)
          : tx_hash(tx_hash), current_status(status) {}
    };
  }  // namespace model
}  // namespace iroha
#endif  // IROHA_TRANSACTION_RESPONSE_HPP
