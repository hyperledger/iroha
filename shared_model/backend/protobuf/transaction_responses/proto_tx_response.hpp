/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_TX_RESPONSE_HPP
#define IROHA_PROTO_TX_RESPONSE_HPP

#include "interfaces/transaction_responses/tx_response.hpp"

#include "endpoint.pb.h"

namespace shared_model {
  namespace proto {
    /**
     * TransactionResponse is a status of transaction in system
     */
    class TransactionResponse final : public interface::TransactionResponse {
     public:
      using TransportType = iroha::protocol::ToriiResponse;

      TransactionResponse(const TransactionResponse &r);
      TransactionResponse(TransactionResponse &&r) noexcept;

      explicit TransactionResponse(const TransportType &ref);
      explicit TransactionResponse(TransportType &&ref);

      ~TransactionResponse() override;

      const interface::types::HashType &transactionHash() const override;

      /**
       * @return attached interface tx response
       */
      const ResponseVariantType &get() const override;

      const StatelessErrorOrFailedCommandNameType &statelessErrorOrCommandName()
          const override;

      FailedCommandIndexType failedCommandIndex() const override;

      ErrorCodeType errorCode() const override;

      const TransportType &getTransport() const;

     private:
      struct Impl;
      std::unique_ptr<Impl> impl_;

      int priority() const noexcept override;
    };
  }  // namespace  proto
}  // namespace shared_model

#endif  // IROHA_PROTO_TX_RESPONSE_HPP
