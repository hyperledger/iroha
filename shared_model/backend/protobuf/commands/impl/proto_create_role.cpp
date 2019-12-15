/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_create_role.hpp"

#include "backend/protobuf/permissions.hpp"

namespace shared_model {
  namespace proto {

    CreateRole::CreateRole(iroha::protocol::Command &command)
        : create_role_{command.create_role()}, role_permissions_{[&command] {
            auto &perms_in = command.create_role().permissions();
            interface::RolePermissionSet perms_out;
            for (const auto &perm : perms_in) {
              perms_out.set(permissions::fromTransport(
                  static_cast<iroha::protocol::RolePermission>(perm)));
            }
            return perms_out;
          }()} {}

    const interface::types::RoleIdType &CreateRole::roleName() const {
      return create_role_.role_name();
    }

    const interface::RolePermissionSet &CreateRole::rolePermissions() const {
      return role_permissions_;
    }

    std::string CreateRole::toString() const {
      return detail::PrettyStringBuilder()
          .init("CreateRole")
          .appendNamed("role_name", roleName())
          .append(permissions::toString(rolePermissions()))
          .finalize();
    }

  }  // namespace proto
}  // namespace shared_model
