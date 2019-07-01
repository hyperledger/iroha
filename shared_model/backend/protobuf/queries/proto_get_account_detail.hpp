/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_GET_ACCOUNT_DETAIL_HPP
#define IROHA_PROTO_GET_ACCOUNT_DETAIL_HPP

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "backend/protobuf/queries/proto_account_detail_pagination_meta.hpp"
#include "interfaces/queries/get_account_detail.hpp"
#include "queries.pb.h"

namespace shared_model {
  namespace proto {
    class GetAccountDetail final
        : public CopyableProto<interface::GetAccountDetail,
                               iroha::protocol::Query,
                               GetAccountDetail> {
     public:
      template <typename QueryType>
      explicit GetAccountDetail(QueryType &&query);

      GetAccountDetail(const GetAccountDetail &o);

      GetAccountDetail(GetAccountDetail &&o) noexcept;

      const interface::types::AccountIdType &accountId() const override;

      boost::optional<interface::types::AccountDetailKeyType> key() const override;

      boost::optional<interface::types::AccountIdType> writer() const override;

      boost::optional<const interface::AccountDetailPaginationMeta &>
      paginationMeta() const override;

     private:
      // ------------------------------| fields |-------------------------------

      const iroha::protocol::GetAccountDetail &account_detail_;
      const boost::optional<const AccountDetailPaginationMeta> pagination_meta_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_GET_ACCOUNT_DETAIL_HPP
