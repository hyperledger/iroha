/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_REVOKE_PERMISSION_HPP
#define IROHA_REVOKE_PERMISSION_HPP

#include <string>
#include "model/command.hpp"

namespace iroha {
  namespace model {

    /**
     * Revoke permission granted before by creator to account_id
     */
    struct RevokePermission : public Command {
      /**
       * Account from which grant permission
       */
      std::string account_id;

      /**
       * Permission to revoke
       */
      std::string permission_name;

      bool operator==(const Command &command) const override;

      RevokePermission() {}

      RevokePermission(const std::string &account_id_,
                       const std::string &permission_name_)
          : account_id(account_id_), permission_name(permission_name_) {}
    };
  }  // namespace model
}  // namespace iroha

#endif  // IROHA_REVOKE_PERMISSION_HPP
