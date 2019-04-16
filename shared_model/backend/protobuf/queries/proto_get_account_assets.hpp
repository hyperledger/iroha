/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_GET_ACCOUNT_ASSETS_H
#define IROHA_PROTO_GET_ACCOUNT_ASSETS_H

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "interfaces/queries/get_account_assets.hpp"
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

     private:
      // ------------------------------| fields |-------------------------------

      const iroha::protocol::GetAccountAssets &account_assets_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_GET_ACCOUNT_ASSETS_H
