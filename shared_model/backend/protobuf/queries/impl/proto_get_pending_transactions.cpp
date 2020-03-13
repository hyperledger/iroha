/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_get_pending_transactions.hpp"

#include "backend/protobuf/queries/proto_tx_pagination_meta.hpp"
#include "common/result.hpp"
#include "queries.pb.h"

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
      return std::make_unique<GetPendingTransactions>(query, std::nullopt);
    }

    GetPendingTransactions::GetPendingTransactions(
        const iroha::protocol::Query &query,
        std::optional<
            std::unique_ptr<shared_model::interface::TxPaginationMeta>>
            pagination_meta)
        : pending_transactions_{query.payload().get_pending_transactions()},
          pagination_meta_{std::move(pagination_meta)} {}

    GetPendingTransactions::~GetPendingTransactions() = default;

    std::optional<std::reference_wrapper<const interface::TxPaginationMeta>>
    GetPendingTransactions::paginationMeta() const {
      if (pagination_meta_) {
        return std::cref<interface::TxPaginationMeta>(
            *pagination_meta_.value());
      }
      return std::nullopt;
    }

  }  // namespace proto
}  // namespace shared_model
