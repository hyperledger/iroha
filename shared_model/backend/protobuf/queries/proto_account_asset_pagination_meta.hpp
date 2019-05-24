/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_PROTO_MODEL_QUERY_ACCOUNT_ASSET_PAGINATION_META_HPP
#define IROHA_SHARED_PROTO_MODEL_QUERY_ACCOUNT_ASSET_PAGINATION_META_HPP

#include "interfaces/queries/account_asset_pagination_meta.hpp"

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "interfaces/common_objects/types.hpp"
#include "queries.pb.h"

namespace shared_model {
  namespace proto {

    /// Provides query metadata for AccountAsset list pagination.
    class AccountAssetPaginationMeta final
        : public CopyableProto<interface::AccountAssetPaginationMeta,
                               iroha::protocol::AccountAssetPaginationMeta,
                               AccountAssetPaginationMeta> {
     public:
      explicit AccountAssetPaginationMeta(const TransportType &query);
      explicit AccountAssetPaginationMeta(TransportType &&query);
      AccountAssetPaginationMeta(const AccountAssetPaginationMeta &o);
      AccountAssetPaginationMeta(AccountAssetPaginationMeta &&o) noexcept;

      interface::types::TransactionsNumberType pageSize() const override;

      boost::optional<interface::types::AssetIdType> firstAssetId()
          const override;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_PROTO_MODEL_QUERY_ACCOUNT_ASSET_PAGINATION_META_HPP
