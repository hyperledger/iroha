/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TORII_STATUS_BUS
#define TORII_STATUS_BUS

#include "interfaces/transaction_responses/tx_response.hpp"

namespace iroha {
  namespace torii {
    /**
     * Interface of bus for transaction statuses
     */
    class StatusBus {
     public:
      virtual ~StatusBus() = default;

      /// Objects that represent status to operate with
      using Objects =
          std::shared_ptr<shared_model::interface::TransactionResponse>;

      /**
       * Shares object among the bus subscribers
       * @param object to share
       * note: guaranteed to be non-blocking call
       */
      virtual void publish(Objects) = 0;
    };
  }  // namespace torii
}  // namespace iroha

#endif  // TORII_STATUS_BUS
