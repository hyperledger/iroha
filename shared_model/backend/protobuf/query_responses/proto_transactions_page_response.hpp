/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_TRANSACTION_PAGE_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PROTO_TRANSACTION_PAGE_RESPONSE_HPP

#include "interfaces/query_responses/transactions_page_response.hpp"

#include "backend/protobuf/transaction.hpp"
#include "interfaces/common_objects/types.hpp"
#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    class TransactionsPageResponse final
        : public interface::TransactionsPageResponse {
     public:
      explicit TransactionsPageResponse(
          iroha::protocol::QueryResponse &query_response);

      interface::types::TransactionsCollectionType transactions()
          const override;

      std::optional<interface::types::HashType> nextTxHash() const override;

      interface::types::TransactionsNumberType allTransactionsSize()
          const override;

     private:
      const iroha::protocol::TransactionsPageResponse &transactionPageResponse_;
      std::vector<proto::Transaction> transactions_;
      std::optional<interface::types::HashType> next_hash_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_TRANSACTION_PAGE_RESPONSE_HPP
