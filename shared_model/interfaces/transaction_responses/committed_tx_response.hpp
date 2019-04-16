/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_COMMITTED_TX_RESPONSE_HPP
#define IROHA_COMMITTED_TX_RESPONSE_HPP

#include "interfaces/transaction_responses/abstract_tx_response.hpp"

namespace shared_model {
  namespace interface {
    /**
     * Tx pipeline succeeded, tx is committed in ledger
     */
    class CommittedTxResponse : public AbstractTxResponse<CommittedTxResponse> {
     private:
      std::string className() const override {
        return "CommittedTxResponse";
      }
    };

  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_COMMITTED_TX_RESPONSE_HPP
