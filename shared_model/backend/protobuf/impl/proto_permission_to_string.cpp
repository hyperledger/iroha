/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/proto_permission_to_string.hpp"

#include "backend/protobuf/permissions.hpp"
#include "primitive.pb.h"

namespace shared_model {
  namespace proto {

    std::string ProtoPermissionToString::toString(
        interface::permissions::Role r) {
      return iroha::protocol::RolePermission_Name(
          proto::permissions::toTransport(r));
    }

    std::string ProtoPermissionToString::toString(
        interface::permissions::Grantable r) {
      return iroha::protocol::GrantablePermission_Name(
          proto::permissions::toTransport(r));
    }

    std::vector<std::string> ProtoPermissionToString::toString(
        const interface::RolePermissionSet &set) {
      std::vector<std::string> v;
      for (size_t i = 0; i < set.size(); ++i) {
        auto perm = static_cast<interface::permissions::Role>(i);
        if (set.isSet(perm)) {
          v.push_back(toString(perm));
        }
      }
      return v;
    }

    std::vector<std::string> ProtoPermissionToString::toString(
        const interface::GrantablePermissionSet &set) {
      std::vector<std::string> v;
      for (size_t i = 0; i < set.size(); ++i) {
        auto perm = static_cast<interface::permissions::Grantable>(i);
        if (set.isSet(perm)) {
          v.push_back(toString(perm));
        }
      }
      return v;
    }

  }  // namespace proto
}  // namespace shared_model
