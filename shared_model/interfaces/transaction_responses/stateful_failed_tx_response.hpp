/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_STATEFUL_FAILED_TX_RESPONSE_HPP
#define IROHA_STATEFUL_FAILED_TX_RESPONSE_HPP

#include "interfaces/transaction_responses/abstract_tx_response.hpp"

namespace shared_model {
  namespace interface {
    /**
     * Tx response of broken stateful validation
     */
    class StatefulFailedTxResponse
        : public AbstractTxResponse<StatefulFailedTxResponse> {
     private:
      std::string className() const override {
        return "StatefulFailedTxResponse";
      }
    };

  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_STATEFUL_FAILED_TX_RESPONSE_HPP
