/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ADD_SIGNATURE_HPP
#define IROHA_ADD_SIGNATURE_HPP

#include <string>
#include "crypto/keypair.hpp"
#include "model/command.hpp"

namespace iroha {
  namespace model {

    /**
     * Attach signatory for account
     */
    struct AddSignatory : public Command {
      /**
       * Account to add new signatory
       */
      std::string account_id;

      /**
       * New signatory is identified with public key
       */
      pubkey_t pubkey;

      bool operator==(const Command &command) const override;

      AddSignatory() {}

      AddSignatory(const std::string &account_id, const pubkey_t &pubkey)
          : account_id(account_id), pubkey(pubkey) {}
    };
  }  // namespace model
}  // namespace iroha
#endif  // IROHA_ADD_SIGNATURE_HPP
