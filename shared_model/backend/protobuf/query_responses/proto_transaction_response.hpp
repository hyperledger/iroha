/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_TRANSACTION_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PROTO_TRANSACTION_RESPONSE_HPP

#include "interfaces/query_responses/transactions_response.hpp"

#include "common/result_fwd.hpp"
#include "interfaces/common_objects/types.hpp"

namespace iroha {
  namespace protocol {
    class QueryResponse;
  }
}  // namespace iroha

namespace shared_model {
  namespace proto {
    class Transaction;

    class TransactionsResponse final : public interface::TransactionsResponse {
     public:
      static iroha::expected::Result<std::unique_ptr<TransactionsResponse>,
                                     std::string>
      create(const iroha::protocol::QueryResponse &query_response);

      explicit TransactionsResponse(
          std::vector<std::unique_ptr<Transaction>> transactions);

      ~TransactionsResponse() override;

      interface::types::TransactionsCollectionType transactions()
          const override;

     private:
      const std::vector<std::unique_ptr<Transaction>> transactions_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_TRANSACTION_RESPONSE_HPP
