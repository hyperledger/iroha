/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_GET_ACCOUNT_DETAIL_HPP
#define IROHA_PROTO_GET_ACCOUNT_DETAIL_HPP

#include "interfaces/queries/get_account_detail.hpp"

#include <optional>
#include "backend/protobuf/queries/proto_account_detail_pagination_meta.hpp"
#include "queries.pb.h"

namespace shared_model {
  namespace proto {
    class GetAccountDetail final : public interface::GetAccountDetail {
     public:
      explicit GetAccountDetail(iroha::protocol::Query &query);

      const interface::types::AccountIdType &accountId() const override;

      std::optional<interface::types::AccountDetailKeyType> key()
          const override;

      std::optional<interface::types::AccountIdType> writer() const override;

      std::optional<
          std::reference_wrapper<const interface::AccountDetailPaginationMeta>>
      paginationMeta() const override;

     private:
      // ------------------------------| fields |-------------------------------

      const iroha::protocol::Query &query_;
      const iroha::protocol::GetAccountDetail &account_detail_;
      const std::optional<const AccountDetailPaginationMeta> pagination_meta_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_GET_ACCOUNT_DETAIL_HPP
