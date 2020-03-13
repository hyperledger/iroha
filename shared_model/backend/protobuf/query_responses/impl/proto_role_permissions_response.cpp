/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_role_permissions_response.hpp"

#include "backend/protobuf/permissions.hpp"
#include "utils/string_builder.hpp"

namespace shared_model {
  namespace proto {

    RolePermissionsResponse::RolePermissionsResponse(
        iroha::protocol::QueryResponse &query_response)
        : role_permissions_response_{query_response
                                         .role_permissions_response()},
          role_permissions_{[&query_response] {
            auto &perms_in =
                query_response.role_permissions_response().permissions();
            interface::RolePermissionSet perms_out;
            for (const auto &perm : perms_in) {
              perms_out.set(permissions::fromTransport(
                  static_cast<iroha::protocol::RolePermission>(perm)));
            }
            return perms_out;
          }()} {}

    const interface::RolePermissionSet &
    RolePermissionsResponse::rolePermissions() const {
      return role_permissions_;
    }

    std::string RolePermissionsResponse::toString() const {
      return detail::PrettyStringBuilder()
          .init("RolePermissionsResponse")
          .append(permissions::toString(rolePermissions()))
          .finalize();
    }

  }  // namespace proto
}  // namespace shared_model
