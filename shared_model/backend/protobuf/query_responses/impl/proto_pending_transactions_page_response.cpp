/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_pending_transactions_page_response.hpp"

#include <boost/range/adaptor/indirected.hpp>
#include "backend/protobuf/transaction.hpp"
#include "common/byteutils.hpp"
#include "common/result.hpp"
#include "cryptography/blob.hpp"
#include "cryptography/hash.hpp"

namespace shared_model {
  namespace proto {
    iroha::expected::Result<std::unique_ptr<PendingTransactionsPageResponse>,
                            std::string>
    PendingTransactionsPageResponse::create(
        const iroha::protocol::QueryResponse &query_response) {
      using namespace iroha::expected;
      const auto &proto = query_response.pending_transactions_page_response();

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

      if (proto.has_next_batch_info()) {
        auto &next = proto.next_batch_info();
        using shared_model::interface::types::TransactionsNumberType;
        using ProtoTransactionsNumberType = decltype(next.batch_size());
        static_assert(
            std::numeric_limits<TransactionsNumberType>::min()
                == std::numeric_limits<ProtoTransactionsNumberType>::min(),
            "Lower bounds don't match.");
        if (next.batch_size()
            > std::numeric_limits<TransactionsNumberType>::max()) {
          return "Batch size does not fit the variable type.";
        }
        auto batch_size =
            static_cast<TransactionsNumberType>(next.batch_size());
        return shared_model::crypto::Blob::fromHexString(next.first_tx_hash()) |
            [&](auto &&next_hash) {
              return std::make_unique<PendingTransactionsPageResponse>(
                  query_response,
                  std::move(txs),
                  BatchInfo{shared_model::crypto::Hash{std::move(next_hash)},
                            batch_size});
            };
      }
      return std::make_unique<PendingTransactionsPageResponse>(
          query_response, std::move(txs), std::nullopt);
    }

    PendingTransactionsPageResponse::PendingTransactionsPageResponse(
        const iroha::protocol::QueryResponse &query_response,
        std::vector<std::unique_ptr<Transaction>> transactions,
        std::optional<BatchInfo> next_batch_info)
        : pending_transactions_page_response_{query_response
                                                  .pending_transactions_page_response()},
          transactions_{std::move(transactions)},
          next_batch_info_{std::move(next_batch_info)} {}

    PendingTransactionsPageResponse::~PendingTransactionsPageResponse() =
        default;

    interface::types::TransactionsCollectionType
    PendingTransactionsPageResponse::transactions() const {
      return transactions_ | boost::adaptors::indirected;
    }

    const std::optional<PendingTransactionsPageResponse::BatchInfo>
        &PendingTransactionsPageResponse::nextBatchInfo() const {
      return next_batch_info_;
    }

    interface::types::TransactionsNumberType
    PendingTransactionsPageResponse::allTransactionsSize() const {
      return pending_transactions_page_response_.all_transactions_size();
    }

  }  // namespace proto
}  // namespace shared_model
