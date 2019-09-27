/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_get_role_permissions.hpp"

namespace shared_model {
  namespace proto {

    GetRolePermissions::GetRolePermissions(iroha::protocol::Query &query)
        : role_permissions_{query.payload().get_role_permissions()} {}

    const interface::types::RoleIdType &GetRolePermissions::roleId() const {
      return role_permissions_.role_id();
    }

  }  // namespace proto
}  // namespace shared_model
