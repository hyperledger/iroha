/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_CREATE_DOMAIN_HPP
#define IROHA_CREATE_DOMAIN_HPP

#include "model/command.hpp"

namespace iroha {
  namespace model {

    /**
     * Create new asset in the system
     */
    struct CreateDomain : public Command {
      /**
       * Asset to insert to the system
       */
      std::string domain_id;

      /**
       * Default role for users in the domain
       */
      std::string user_default_role;

      bool operator==(const Command &command) const override;

      CreateDomain() {}

      /**
       * @param domain_id - id of the domain to create
       * @param user_default_role - default role of the user in this domain
       */
      CreateDomain(const std::string &domain_id,
                   const std::string &user_default_role)
          : domain_id(domain_id), user_default_role(user_default_role) {}
    };
  }  // namespace model
}  // namespace iroha
#endif  // IROHA_CREATE_DOMAIN_HPP
