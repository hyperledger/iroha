/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/queries/get_role_permissions.hpp"

namespace shared_model {
  namespace interface {

    std::string GetRolePermissions::toString() const {
      return detail::PrettyStringBuilder()
          .init("GetRolePermissions")
          .appendNamed("role_id", roleId())
          .finalize();
    }

    bool GetRolePermissions::operator==(const ModelType &rhs) const {
      return roleId() == rhs.roleId();
    }

  }  // namespace interface
}  // namespace shared_model
