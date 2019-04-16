/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_GET_ROLES_HPP
#define IROHA_GET_ROLES_HPP

#include "model/query.hpp"

namespace iroha {
  namespace model {
    /**
     * Get all roles in the current system
     */
    struct GetRoles : Query {
      GetRoles() {}
    };

    /**
     * Get all permissions related to specific role
     */
    struct GetRolePermissions : Query {
      GetRolePermissions() {}

      GetRolePermissions(std::string role_id) : role_id(role_id) {}
      /**
       * Role to query
       */
      std::string role_id{};
    };
  }  // namespace model
}  // namespace iroha

#endif  // IROHA_GET_ROLES_HPP
