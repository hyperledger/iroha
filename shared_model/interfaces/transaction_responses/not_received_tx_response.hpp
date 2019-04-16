/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_UNKNOWN_TX_RESPONSE_HPP
#define IROHA_UNKNOWN_TX_RESPONSE_HPP

#include "interfaces/transaction_responses/abstract_tx_response.hpp"

namespace shared_model {
  namespace interface {
    /**
     * Transaction not found
     */
    class NotReceivedTxResponse
        : public AbstractTxResponse<NotReceivedTxResponse> {
     private:
      std::string className() const override {
        return "NotReceivedTxResponse";
      }
    };

  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_UNKNOWN_TX_RESPONSE_HPP
