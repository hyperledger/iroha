/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/queries/get_account_asset_transactions.hpp"

#include "interfaces/queries/tx_pagination_meta.hpp"

namespace shared_model {
  namespace interface {

    std::string GetAccountAssetTransactions::toString() const {
      return detail::PrettyStringBuilder()
          .init("GetAccountAssetTransactions")
          .appendNamed("account_id", accountId())
          .appendNamed("asset_id", assetId())
          .appendNamed("pagination_meta", paginationMeta())
          .finalize();
    }

    bool GetAccountAssetTransactions::operator==(const ModelType &rhs) const {
      return accountId() == rhs.accountId() and assetId() == rhs.assetId();
    }

  }  // namespace interface
}  // namespace shared_model
