/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_CREATE_ROLE_HPP
#define IROHA_CREATE_ROLE_HPP

#include <set>
#include <string>
#include "model/command.hpp"

namespace iroha {
  namespace model {

    /**
     * Create new role in the system
     */
    struct CreateRole : public Command {
      /**
       * Role to insert to the system
       */
      std::string role_name;

      /**
       * Role permissions
       */
      std::set<std::string> permissions;

      bool operator==(const Command &command) const override;

      CreateRole() {}
      /**
       * @param role_name_ - name of the role in the system
       * @param perms - set of permissions for the role
       */
      CreateRole(const std::string &role_name_,
                 const std::set<std::string> &perms)
          : role_name(role_name_), permissions(perms) {}
    };
  }  // namespace model
}  // namespace iroha
#endif  // IROHA_CREATE_ROLE_HPP
