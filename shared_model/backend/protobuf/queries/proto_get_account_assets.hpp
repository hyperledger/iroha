/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_GET_ACCOUNT_ASSETS_H
#define IROHA_PROTO_GET_ACCOUNT_ASSETS_H

#include "interfaces/queries/get_account_assets.hpp"

#include <optional>
#include "backend/protobuf/queries/proto_asset_pagination_meta.hpp"
#include "queries.pb.h"

namespace shared_model {
  namespace proto {
    class GetAccountAssets final : public interface::GetAccountAssets {
     public:
      explicit GetAccountAssets(iroha::protocol::Query &query);

      const interface::types::AccountIdType &accountId() const override;

      std::optional<
          std::reference_wrapper<const interface::AssetPaginationMeta>>
      paginationMeta() const override;

     private:
      // ------------------------------| fields |-------------------------------

      const iroha::protocol::GetAccountAssets &account_assets_;
      const std::optional<const AssetPaginationMeta> pagination_meta_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_GET_ACCOUNT_ASSETS_H
