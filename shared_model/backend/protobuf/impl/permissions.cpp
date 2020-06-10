/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/permissions.hpp"
#include "interfaces/permissions.hpp"
#include "primitive.pb.h"

namespace shared_model {
  namespace proto {
    namespace permissions {

      interface::permissions::Role fromTransport(
          iroha::protocol::RolePermission perm) noexcept {
        return static_cast<interface::permissions::Role>(perm);
      }

      iroha::protocol::RolePermission toTransport(
          interface::permissions::Role r) {
        return static_cast<iroha::protocol::RolePermission>(r);
      }

      std::string toString(interface::permissions::Role r) {
        return iroha::protocol::RolePermission_Name(toTransport(r));
      }

      interface::permissions::Grantable fromTransport(
          iroha::protocol::GrantablePermission perm) noexcept {
        return static_cast<interface::permissions::Grantable>(perm);
      }

      iroha::protocol::GrantablePermission toTransport(
          interface::permissions::Grantable r) {
        return static_cast<iroha::protocol::GrantablePermission>(r);
      }

      std::string toString(interface::permissions::Grantable r) {
        return iroha::protocol::GrantablePermission_Name(toTransport(r));
      }

      std::vector<std::string> toString(
          const interface::PermissionSet<interface::permissions::Role> &set) {
        std::vector<std::string> v;
        for (size_t i = 0; i < set.size(); ++i) {
          auto perm = static_cast<interface::permissions::Role>(i);
          if (set.isSet(perm)) {
            v.push_back(toString(perm));
          }
        }
        return v;
      }

      std::vector<std::string> toString(
          const interface::PermissionSet<interface::permissions::Grantable>
              &set) {
        std::vector<std::string> v;
        for (size_t i = 0; i < set.size(); ++i) {
          auto perm = static_cast<interface::permissions::Grantable>(i);
          if (set.isSet(perm)) {
            v.push_back(toString(perm));
          }
        }
        return v;
      }
    }  // namespace permissions
  }    // namespace proto
}  // namespace shared_model
