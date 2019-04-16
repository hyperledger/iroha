/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ROLES_RESPONSE_HPP
#define IROHA_ROLES_RESPONSE_HPP

#include "model/query_response.hpp"

namespace iroha {
  namespace model {

    /**
     * Response with all permissions related to role
     */
    struct RolePermissionsResponse : QueryResponse {
      /**
       * All role's permissions
       */
      std::vector<int> role_permissions{};
    };

    /**
     * Provide response with all roles of the current system
     */
    struct RolesResponse : public QueryResponse {
      /**
       * Attached roles
       */
      std::vector<std::string> roles{};
    };
  }  // namespace model
}  // namespace iroha

#endif  // IROHA_ROLES_RESPONSE_HPP
