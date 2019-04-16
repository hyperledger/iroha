/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_GRANT_PERMISSION_HPP
#define IROHA_GRANT_PERMISSION_HPP

#include <string>
#include "model/command.hpp"

namespace iroha {
  namespace model {

    /**
     * Grant permission from creator to account_id
     */
    struct GrantPermission : public Command {
      /**
       * Account to which grant the permission.
       * Permission will be granted from creator to account_id on
       * *permission_name*
       */
      std::string account_id;

      /**
       * Permission to grant (what)
       */
      std::string permission_name;

      bool operator==(const Command &command) const override;

      GrantPermission() {}

      GrantPermission(const std::string &account_id_,
                      const std::string &permission_name_)
          : account_id(account_id_), permission_name(permission_name_) {}
    };
  }  // namespace model
}  // namespace iroha

#endif  // IROHA_GRANT_PERMISSION_HPP
