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
        interface::permissions::Role r) const {
      return iroha::protocol::RolePermission_Name(
          proto::permissions::toTransport(r));
    }

    std::string ProtoPermissionToString::toString(
        interface::permissions::Grantable r) const {
      return iroha::protocol::GrantablePermission_Name(
          proto::permissions::toTransport(r));
    }

  }  // namespace proto
}  // namespace shared_model
