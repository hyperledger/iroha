/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_DETACH_ROLE_HPP
#define IROHA_DETACH_ROLE_HPP

#include "model/command.hpp"

namespace iroha {
  namespace model {

    /**
     * Create new role in the system
     */
    struct DetachRole : public Command {
      /**
       * Account from where detach role
       */
      std::string account_id;
      /**
       * Role to detach
       */
      std::string role_name;

      bool operator==(const Command &command) const override;

      DetachRole() {}
      /**
       * @param role_name_ - name of the role in the system
       * @param perms - set of permissions for the role
       */
      DetachRole(const std::string &account_id, const std::string &role_name_)
          : account_id(account_id), role_name(role_name_) {}
    };
  }  // namespace model
}  // namespace iroha

#endif  // IROHA_DETACH_ROLE_HPP
