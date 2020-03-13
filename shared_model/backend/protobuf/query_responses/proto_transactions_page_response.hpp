/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_TRANSACTION_PAGE_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PROTO_TRANSACTION_PAGE_RESPONSE_HPP

#include "interfaces/query_responses/transactions_page_response.hpp"

#include <optional>

#include <boost/optional/optional.hpp>
#include "common/result_fwd.hpp"
#include "cryptography/hash.hpp"
#include "interfaces/common_objects/types.hpp"

namespace iroha {
  namespace protocol {
    class QueryResponse;
    class TransactionsPageResponse;
  }  // namespace protocol
}  // namespace iroha

namespace shared_model {
  namespace proto {
    class Transaction;

    class TransactionsPageResponse final
        : public interface::TransactionsPageResponse {
     public:
      static iroha::expected::Result<std::unique_ptr<TransactionsPageResponse>,
                                     std::string>
      create(const iroha::protocol::QueryResponse &query_response);

      TransactionsPageResponse(
          const iroha::protocol::QueryResponse &query_response,
          std::vector<std::unique_ptr<Transaction>> transactions,
          std::optional<interface::types::HashType> next_hash);

      ~TransactionsPageResponse() override;

      interface::types::TransactionsCollectionType transactions()
          const override;

      const std::optional<interface::types::HashType> &nextTxHash()
          const override;

      interface::types::TransactionsNumberType allTransactionsSize()
          const override;

     private:
      const iroha::protocol::TransactionsPageResponse &transactionPageResponse_;
      std::vector<std::unique_ptr<Transaction>> transactions_;
      std::optional<interface::types::HashType> next_hash_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_TRANSACTION_PAGE_RESPONSE_HPP
