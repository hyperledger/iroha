/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_APPEND_ROLE_HPP
#define IROHA_APPEND_ROLE_HPP

#include <string>
#include "model/command.hpp"

namespace iroha {
  namespace model {

    /**
     * Add role to account
     */
    struct AppendRole : public Command {
      /**
       * Account to which add new role
       */
      std::string account_id;
      /**
       * Role to add to account
       */
      std::string role_name;

      bool operator==(const Command &command) const override;

      AppendRole() {}

      AppendRole(const std::string &account_id_, const std::string &role_name_)
          : account_id(account_id_), role_name(role_name_) {}
    };
  }  // namespace model
}  // namespace iroha
#endif  // IROHA_APPEND_ROLE_HPP
