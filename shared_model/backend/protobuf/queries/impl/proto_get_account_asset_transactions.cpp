/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_get_account_asset_transactions.hpp"

#include "backend/protobuf/queries/proto_tx_pagination_meta.hpp"
#include "common/result.hpp"
#include "queries.pb.h"

namespace shared_model {
  namespace proto {
    iroha::expected::Result<std::unique_ptr<GetAccountAssetTransactions>,
                            std::string>
    GetAccountAssetTransactions::create(const iroha::protocol::Query &query) {
      return TxPaginationMeta::create(query.payload()
                                          .get_account_asset_transactions()
                                          .pagination_meta())
          | [&](auto &&pagination_meta) {
              return std::make_unique<GetAccountAssetTransactions>(
                  query,
                  std::unique_ptr<shared_model::interface::TxPaginationMeta>(
                      std::move(pagination_meta)));
            };
    }

    GetAccountAssetTransactions::GetAccountAssetTransactions(
        const iroha::protocol::Query &query,
        std::unique_ptr<shared_model::interface::TxPaginationMeta>
            pagination_meta)
        : account_asset_transactions_{query.payload()
                                          .get_account_asset_transactions()},
          pagination_meta_{std::move(pagination_meta)} {}

    GetAccountAssetTransactions::~GetAccountAssetTransactions() = default;

    const interface::types::AccountIdType &
    GetAccountAssetTransactions::accountId() const {
      return account_asset_transactions_.account_id();
    }

    const interface::types::AssetIdType &GetAccountAssetTransactions::assetId()
        const {
      return account_asset_transactions_.asset_id();
    }

    const interface::TxPaginationMeta &
    GetAccountAssetTransactions::paginationMeta() const {
      return *pagination_meta_;
    }

  }  // namespace proto
}  // namespace shared_model
