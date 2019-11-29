/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_TX_RESPONSE_HPP
#define IROHA_PROTO_TX_RESPONSE_HPP

#include "interfaces/transaction_responses/tx_response.hpp"

#include "common/result_fwd.hpp"

namespace iroha {
  namespace protocol {
    class ToriiResponse;
  }
}  // namespace iroha

namespace shared_model {
  namespace proto {
    /**
     * TransactionResponse is a status of transaction in system
     */
    class TransactionResponse final : public interface::TransactionResponse {
     public:
      using TransportType = iroha::protocol::ToriiResponse;

      static iroha::expected::Result<std::unique_ptr<TransactionResponse>,
                                     std::string>
      create(TransportType proto);

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
      explicit TransactionResponse(std::unique_ptr<Impl> impl);
      std::unique_ptr<Impl> impl_;

      int priority() const noexcept override;
    };
  }  // namespace  proto
}  // namespace shared_model

#endif  // IROHA_PROTO_TX_RESPONSE_HPP
