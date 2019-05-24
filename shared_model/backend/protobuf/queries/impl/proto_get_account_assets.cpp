/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_get_account_assets.hpp"

namespace shared_model {
  namespace proto {

    template <typename QueryType>
    GetAccountAssets::GetAccountAssets(QueryType &&query)
        : CopyableProto(std::forward<QueryType>(query)),
          account_assets_{proto_->payload().get_account_assets()},
          pagination_meta_{
              [this]() -> boost::optional<const AccountAssetPaginationMeta> {
                if (this->account_assets_.has_pagination_meta()) {
                  return AccountAssetPaginationMeta{
                      this->account_assets_.pagination_meta()};
                } else {
                  return boost::none;
                }
              }()} {}

    template GetAccountAssets::GetAccountAssets(
        GetAccountAssets::TransportType &);
    template GetAccountAssets::GetAccountAssets(
        const GetAccountAssets::TransportType &);
    template GetAccountAssets::GetAccountAssets(
        GetAccountAssets::TransportType &&);

    GetAccountAssets::GetAccountAssets(const GetAccountAssets &o)
        : GetAccountAssets(o.proto_) {}

    GetAccountAssets::GetAccountAssets(GetAccountAssets &&o) noexcept
        : GetAccountAssets(std::move(o.proto_)) {}

    const interface::types::AccountIdType &GetAccountAssets::accountId() const {
      return account_assets_.account_id();
    }

    boost::optional<const interface::AccountAssetPaginationMeta &>
    GetAccountAssets::paginationMeta() const {
      if (pagination_meta_) {
        return pagination_meta_.value();
      }
      return boost::none;
    }

  }  // namespace proto
}  // namespace shared_model
