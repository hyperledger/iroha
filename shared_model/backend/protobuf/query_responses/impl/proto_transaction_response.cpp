/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_transaction_response.hpp"

#include <boost/range/adaptor/indirected.hpp>
#include "backend/protobuf/transaction.hpp"
#include "common/result.hpp"
#include "cryptography/blob.hpp"
#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    iroha::expected::Result<std::unique_ptr<TransactionsResponse>, std::string>
    TransactionsResponse::create(
        const iroha::protocol::QueryResponse &query_response) {
      using namespace iroha::expected;
      const auto &proto = query_response.transactions_response();

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

      return std::make_unique<TransactionsResponse>(std::move(txs));
    }

    TransactionsResponse::TransactionsResponse(
        std::vector<std::unique_ptr<Transaction>> transactions)
        : transactions_{std::move(transactions)} {}

    interface::types::TransactionsCollectionType
    TransactionsResponse::transactions() const {
      return transactions_ | boost::adaptors::indirected;
    }

  }  // namespace proto
}  // namespace shared_model
