/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_PROTO_MODEL_QUERY_ACCOUNT_ASSET_PAGINATION_META_HPP
#define IROHA_SHARED_PROTO_MODEL_QUERY_ACCOUNT_ASSET_PAGINATION_META_HPP

#include "interfaces/queries/asset_pagination_meta.hpp"

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "interfaces/common_objects/types.hpp"
#include "queries.pb.h"

namespace shared_model {
  namespace proto {

    /// Provides query metadata for AccountAsset list pagination.
    class AssetPaginationMeta final
        : public TrivialProto<interface::AssetPaginationMeta,
                              iroha::protocol::AssetPaginationMeta> {
     public:
      explicit AssetPaginationMeta(const TransportType &query);
      explicit AssetPaginationMeta(TransportType &&query);
      AssetPaginationMeta(const AssetPaginationMeta &o);
      AssetPaginationMeta(AssetPaginationMeta &&o) noexcept;

      interface::types::TransactionsNumberType pageSize() const override;

      boost::optional<interface::types::AssetIdType> firstAssetId()
          const override;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_PROTO_MODEL_QUERY_ACCOUNT_ASSET_PAGINATION_META_HPP
