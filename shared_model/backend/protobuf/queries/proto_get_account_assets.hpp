/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_GET_ACCOUNT_ASSETS_H
#define IROHA_PROTO_GET_ACCOUNT_ASSETS_H

#include "interfaces/queries/get_account_assets.hpp"

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "backend/protobuf/queries/proto_account_asset_pagination_meta.hpp"
#include "queries.pb.h"

namespace shared_model {
  namespace proto {
    class GetAccountAssets final
        : public CopyableProto<interface::GetAccountAssets,
                               iroha::protocol::Query,
                               GetAccountAssets> {
     public:
      template <typename QueryType>
      explicit GetAccountAssets(QueryType &&query);

      GetAccountAssets(const GetAccountAssets &o);

      GetAccountAssets(GetAccountAssets &&o) noexcept;

      const interface::types::AccountIdType &accountId() const override;

      boost::optional<const interface::AccountAssetPaginationMeta &>
      paginationMeta() const override;

     private:
      // ------------------------------| fields |-------------------------------

      const iroha::protocol::GetAccountAssets &account_assets_;
      const boost::optional<const AccountAssetPaginationMeta> pagination_meta_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_GET_ACCOUNT_ASSETS_H
