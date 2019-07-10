/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_account_response.hpp"

#include <boost/range/numeric.hpp>

namespace shared_model {
  namespace proto {

    AccountResponse::AccountResponse(
        iroha::protocol::QueryResponse &query_response)
        : account_response_{query_response.account_response()},
          account_roles_{boost::accumulate(
              account_response_.account_roles(),
              AccountRolesIdType{},
              [](auto &&roles, const auto &role) {
                roles.push_back(interface::types::RoleIdType(role));
                return std::move(roles);
              })},
          account_{
              *query_response.mutable_account_response()->mutable_account()} {}

    const interface::Account &AccountResponse::account() const {
      return account_;
    }

    const AccountResponse::AccountRolesIdType &AccountResponse::roles() const {
      return account_roles_;
    }

  }  // namespace proto
}  // namespace shared_model
