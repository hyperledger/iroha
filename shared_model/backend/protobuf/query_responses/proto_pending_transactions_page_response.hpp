/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_PENDING_TRANSACTIONS_PAGE_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PROTO_PENDING_TRANSACTIONS_PAGE_RESPONSE_HPP

#include "interfaces/query_responses/pending_transactions_page_response.hpp"

#include <boost/optional/optional.hpp>
#include "common/result_fwd.hpp"
#include "interfaces/common_objects/types.hpp"
#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    class Transaction;

    class PendingTransactionsPageResponse final
        : public interface::PendingTransactionsPageResponse {
     public:
      static iroha::expected::
          Result<std::unique_ptr<PendingTransactionsPageResponse>, std::string>
          create(const iroha::protocol::QueryResponse &query_response);

      PendingTransactionsPageResponse(
          const iroha::protocol::QueryResponse &query_response,
          std::vector<std::unique_ptr<Transaction>> transactions,
          boost::optional<interface::PendingTransactionsPageResponse::BatchInfo>
              next_batch_info);

      ~PendingTransactionsPageResponse() override;

      interface::types::TransactionsCollectionType transactions()
          const override;

      const boost::optional<
          interface::PendingTransactionsPageResponse::BatchInfo>
          &nextBatchInfo() const override;

      interface::types::TransactionsNumberType allTransactionsSize()
          const override;

     private:
      const iroha::protocol::PendingTransactionsPageResponse
          &pending_transactions_page_response_;
      const std::vector<std::unique_ptr<Transaction>> transactions_;
      boost::optional<interface::PendingTransactionsPageResponse::BatchInfo>
          next_batch_info_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_PENDING_TRANSACTIONS_PAGE_RESPONSE_HPP
