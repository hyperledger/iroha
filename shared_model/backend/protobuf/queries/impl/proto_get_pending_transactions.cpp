/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_get_pending_transactions.hpp"

#include "backend/protobuf/queries/proto_tx_pagination_meta.hpp"
#include "common/result.hpp"

namespace shared_model {
  namespace proto {
    iroha::expected::Result<std::unique_ptr<GetPendingTransactions>,
                            std::string>
    GetPendingTransactions::create(const iroha::protocol::Query &query) {
      if (query.payload().get_pending_transactions().has_pagination_meta()) {
        return TxPaginationMeta::create(
                   query.payload().get_pending_transactions().pagination_meta())
            | [&](auto &&pagination_meta) {
                return std::make_unique<GetPendingTransactions>(
                    query,
                    std::unique_ptr<shared_model::interface::TxPaginationMeta>(
                        std::move(pagination_meta)));
              };
      }
      return std::make_unique<GetPendingTransactions>(query, boost::none);
    }

    GetPendingTransactions::GetPendingTransactions(
        const iroha::protocol::Query &query,
        boost::optional<
            std::unique_ptr<shared_model::interface::TxPaginationMeta>>
            pagination_meta)
        : pending_transactions_{query.payload().get_pending_transactions()},
          pagination_meta_{std::move(pagination_meta)} {}

    boost::optional<const interface::TxPaginationMeta &>
    GetPendingTransactions::paginationMeta() const {
      if (pagination_meta_) {
        return *pagination_meta_.value();
      }
      return boost::none;
    }

  }  // namespace proto
}  // namespace shared_model
