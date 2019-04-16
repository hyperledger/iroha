/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_STATELESS_VALID_TX_RESPONSE_HPP
#define IROHA_STATELESS_VALID_TX_RESPONSE_HPP

#include "interfaces/transaction_responses/abstract_tx_response.hpp"

namespace shared_model {
  namespace interface {
    /**
     * Stateless validation passed
     */
    class StatelessValidTxResponse
        : public AbstractTxResponse<StatelessValidTxResponse> {
     private:
      std::string className() const override {
        return "StatelessValidTxResponse";
      }
    };

  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_STATELESS_VALID_TX_RESPONSE_HPP
