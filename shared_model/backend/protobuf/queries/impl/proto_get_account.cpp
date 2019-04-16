/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_get_account.hpp"

namespace shared_model {
  namespace proto {

    template <typename QueryType>
    GetAccount::GetAccount(QueryType &&query)
        : CopyableProto(std::forward<QueryType>(query)),
          account_{proto_->payload().get_account()} {}

    template GetAccount::GetAccount(GetAccount::TransportType &);
    template GetAccount::GetAccount(const GetAccount::TransportType &);
    template GetAccount::GetAccount(GetAccount::TransportType &&);

    GetAccount::GetAccount(const GetAccount &o) : GetAccount(o.proto_) {}

    GetAccount::GetAccount(GetAccount &&o) noexcept
        : GetAccount(std::move(o.proto_)) {}

    const interface::types::AccountIdType &GetAccount::accountId() const {
      return account_.account_id();
    }

  }  // namespace proto
}  // namespace shared_model
