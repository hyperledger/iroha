/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_create_role.hpp"

#include <boost/range/numeric.hpp>
#include "backend/protobuf/permissions.hpp"

namespace shared_model {
  namespace proto {

    CreateRole::CreateRole(iroha::protocol::Command &command)
        : create_role_{command.create_role()},
          role_permissions_{boost::accumulate(
              create_role_.permissions(),
              interface::RolePermissionSet{},
              [](auto &&acc, const auto &perm) {
                acc.set(permissions::fromTransport(
                    static_cast<iroha::protocol::RolePermission>(perm)));
                return std::forward<decltype(acc)>(acc);
              })} {}

    const interface::types::RoleIdType &CreateRole::roleName() const {
      return create_role_.role_name();
    }

    const interface::RolePermissionSet &CreateRole::rolePermissions() const {
      return role_permissions_;
    }

    std::string CreateRole::toString() const {
      return detail::PrettyStringBuilder()
          .init("CreateRole")
          .append("role_name", roleName())
          .appendAll(permissions::toString(rolePermissions()),
                     [](auto p) { return p; })
          .finalize();
    }

  }  // namespace proto
}  // namespace shared_model
