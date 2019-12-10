/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_transactions_page_response.hpp"

#include <boost/range/adaptor/indirected.hpp>
#include "backend/protobuf/transaction.hpp"
#include "common/result.hpp"
#include "cryptography/blob.hpp"
#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    iroha::expected::Result<std::unique_ptr<TransactionsPageResponse>,
                            std::string>
    TransactionsPageResponse::create(
        const iroha::protocol::QueryResponse &query_response) {
      using namespace iroha::expected;
      const auto &proto = query_response.transactions_page_response();

      std::vector<std::unique_ptr<Transaction>> txs;
      for (const auto &proto : proto.transactions()) {
        if (auto e = resultToOptionalError(
                Transaction::create(proto) |
                    [&txs](auto &&tx) -> Result<void, std::string> {
                  txs.emplace_back(std::move(tx));
                  return {};
                })) {
          return e.value();
        }
      }

      if (proto.next_page_tag_case()
          == iroha::protocol::TransactionsPageResponse::kNextTxHash) {
        return shared_model::crypto::Blob::fromHexString(proto.next_tx_hash()) |
            [&](auto &&next_hash) {
              return std::make_unique<TransactionsPageResponse>(
                  query_response,
                  std::move(txs),
                  shared_model::crypto::Hash{std::move(next_hash)});
            };
      }
      return std::make_unique<TransactionsPageResponse>(
          query_response, std::move(txs), boost::none);
    }

    TransactionsPageResponse::TransactionsPageResponse(
        const iroha::protocol::QueryResponse &query_response,
        std::vector<std::unique_ptr<Transaction>> transactions,
        boost::optional<interface::types::HashType> next_hash)
        : transactionPageResponse_{query_response.transactions_page_response()},
          transactions_{std::move(transactions)},
          next_hash_{std::move(next_hash)} {}

    interface::types::TransactionsCollectionType
    TransactionsPageResponse::transactions() const {
      return transactions_ | boost::adaptors::indirected;
    }

    const boost::optional<interface::types::HashType>
        &TransactionsPageResponse::nextTxHash() const {
      return next_hash_;
    }

    interface::types::TransactionsNumberType
    TransactionsPageResponse::allTransactionsSize() const {
      return transactionPageResponse_.all_transactions_size();
    }

  }  // namespace proto
}  // namespace shared_model
