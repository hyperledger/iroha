/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_get_account_asset_transactions.hpp"

#include "backend/protobuf/queries/proto_tx_pagination_meta.hpp"

namespace shared_model {
  namespace proto {

    GetAccountAssetTransactions::GetAccountAssetTransactions(
        iroha::protocol::Query &query)
        : account_asset_transactions_{query.payload()
                                          .get_account_asset_transactions()},
          pagination_meta_{*query.mutable_payload()
                                ->mutable_get_account_asset_transactions()
                                ->mutable_pagination_meta()} {}

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
      return pagination_meta_;
    }

  }  // namespace proto
}  // namespace shared_model
