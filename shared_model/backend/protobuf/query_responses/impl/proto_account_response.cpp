/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_account_response.hpp"

#include <boost/range/numeric.hpp>

namespace shared_model {
  namespace proto {

    template <typename QueryResponseType>
    AccountResponse::AccountResponse(QueryResponseType &&queryResponse)
        : CopyableProto(std::forward<QueryResponseType>(queryResponse)),
          account_response_{proto_->account_response()},
          account_roles_{boost::accumulate(
              account_response_.account_roles(),
              AccountRolesIdType{},
              [](auto &&roles, const auto &role) {
                roles.push_back(interface::types::RoleIdType(role));
                return std::move(roles);
              })},
          account_{account_response_.account()} {}

    template AccountResponse::AccountResponse(AccountResponse::TransportType &);
    template AccountResponse::AccountResponse(
        const AccountResponse::TransportType &);
    template AccountResponse::AccountResponse(
        AccountResponse::TransportType &&);

    AccountResponse::AccountResponse(const AccountResponse &o)
        : AccountResponse(o.proto_) {}

    AccountResponse::AccountResponse(AccountResponse &&o)
        : AccountResponse(std::move(o.proto_)) {}

    const interface::Account &AccountResponse::account() const {
      return account_;
    }

    const AccountResponse::AccountRolesIdType &AccountResponse::roles() const {
      return account_roles_;
    }

  }  // namespace proto
}  // namespace shared_model
