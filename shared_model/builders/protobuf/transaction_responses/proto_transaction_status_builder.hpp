/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_TRANSACTION_STATUS_BUILDER_HPP
#define IROHA_PROTO_TRANSACTION_STATUS_BUILDER_HPP

#include "backend/protobuf/transaction_responses/proto_tx_response.hpp"

namespace shared_model {
  namespace proto {
    class [[deprecated]] TransactionStatusBuilder {
     public:
      shared_model::proto::TransactionResponse build() &&;

      shared_model::proto::TransactionResponse build() &;

      TransactionStatusBuilder statelessValidationSuccess();

      TransactionStatusBuilder statelessValidationFailed();

      TransactionStatusBuilder mstPending();

      TransactionStatusBuilder enoughSignaturesCollected();

      TransactionStatusBuilder statefulValidationSuccess();

      TransactionStatusBuilder statefulValidationFailed();

      TransactionStatusBuilder committed();

      TransactionStatusBuilder notReceived();

      TransactionStatusBuilder mstExpired();

      TransactionStatusBuilder txHash(const crypto::Hash &hash);

      TransactionStatusBuilder statelessErrorOrCmdName(const std::string &name);

      TransactionStatusBuilder failedCmdIndex(uint32_t index);

      TransactionStatusBuilder errorCode(uint32_t code);

     private:
      iroha::protocol::ToriiResponse tx_response_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_TRANSACTION_STATUS_BUILDER_HPP
