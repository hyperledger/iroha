/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CREATE_ACCOUNT_HPP
#define IROHA_CREATE_ACCOUNT_HPP

#include "model/command.hpp"

namespace iroha {
  namespace model {

    /**
     * Command for creation of a new account in the system
     */
    struct CreateAccount : public Command {
      /**
       * Account's user name
       */
      std::string account_name;

      /**
       * Account's domain (full name)
       */
      std::string domain_id;

      /**
       * Signatory of account
       */
      pubkey_t pubkey;

      bool operator==(const Command &command) const override;

      CreateAccount() {}

      CreateAccount(const std::string &account_name,
                    const std::string &domain_id,
                    const pubkey_t &pubkey)
          : account_name(account_name), domain_id(domain_id), pubkey(pubkey) {}
    };
  }  // namespace model
}  // namespace iroha
#endif  // IROHA_CREATE_ACCOUNT_HPP
