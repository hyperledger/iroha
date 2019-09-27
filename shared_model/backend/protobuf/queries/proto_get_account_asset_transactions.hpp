/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_GET_ACCOUNT_ASSET_TRANSACTIONS_H
#define IROHA_GET_ACCOUNT_ASSET_TRANSACTIONS_H

#include "interfaces/queries/get_account_asset_transactions.hpp"

#include "backend/protobuf/queries/proto_tx_pagination_meta.hpp"
#include "queries.pb.h"

namespace shared_model {
  namespace proto {
    class GetAccountAssetTransactions final
        : public interface::GetAccountAssetTransactions {
     public:
      explicit GetAccountAssetTransactions(iroha::protocol::Query &query);

      const interface::types::AccountIdType &accountId() const override;

      const interface::types::AssetIdType &assetId() const override;

      const interface::TxPaginationMeta &paginationMeta() const override;

     private:
      // ------------------------------| fields |-------------------------------

      const iroha::protocol::GetAccountAssetTransactions
          &account_asset_transactions_;
      const TxPaginationMeta pagination_meta_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_GET_ACCOUNT_ASSET_TRANSACTIONS_H
