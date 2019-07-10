/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_roles_response.hpp"

#include <boost/range/numeric.hpp>

namespace shared_model {
  namespace proto {

    RolesResponse::RolesResponse(iroha::protocol::QueryResponse &query_response)
        : roles_response_{query_response.roles_response()},
          roles_{boost::accumulate(roles_response_.roles(),
                                   RolesIdType{},
                                   [](auto &&roles, const auto &role) {
                                     roles.emplace_back(role);
                                     return std::move(roles);
                                   })} {}

    const RolesResponse::RolesIdType &RolesResponse::roles() const {
      return roles_;
    }

  }  // namespace proto
}  // namespace shared_model
