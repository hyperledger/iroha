/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MST_EXPIRED_RESPONSE_HPP
#define IROHA_MST_EXPIRED_RESPONSE_HPP

#include "interfaces/transaction_responses/abstract_tx_response.hpp"

namespace shared_model {
  namespace interface {
    /**
     * Multisignature transactions, has not received required number of
     * confirmations of creator signatories
     */
    class MstExpiredResponse : public AbstractTxResponse<MstExpiredResponse> {
     private:
      std::string className() const override {
        return "MstExpiredResponse";
      }
    };

  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_MST_EXPIRED_RESPONSE_HPP
