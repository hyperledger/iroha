/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_role_permissions_response.hpp"

#include <boost/range/numeric.hpp>
#include "backend/protobuf/permissions.hpp"
#include "utils/string_builder.hpp"

namespace shared_model {
  namespace proto {

    RolePermissionsResponse::RolePermissionsResponse(
        iroha::protocol::QueryResponse &query_response)
        : role_permissions_response_{query_response
                                         .role_permissions_response()},
          role_permissions_{boost::accumulate(
              role_permissions_response_.permissions(),
              interface::RolePermissionSet{},
              [](auto &&permissions, const auto &permission) {
                permissions.set(permissions::fromTransport(
                    static_cast<iroha::protocol::RolePermission>(permission)));
                return std::forward<decltype(permissions)>(permissions);
              })} {}

    const interface::RolePermissionSet &
    RolePermissionsResponse::rolePermissions() const {
      return role_permissions_;
    }

    std::string RolePermissionsResponse::toString() const {
      return detail::PrettyStringBuilder()
          .init("RolePermissionsResponse")
          .appendAll(permissions::toString(rolePermissions()),
                     [](auto p) { return p; })
          .finalize();
    }

  }  // namespace proto
}  // namespace shared_model
