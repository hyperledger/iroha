/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_REMOVE_SIGNATORY_HPP
#define IROHA_REMOVE_SIGNATORY_HPP

#include <string>
#include "crypto/keypair.hpp"
#include "model/command.hpp"

namespace iroha {
  namespace model {

    /**
     * Attach signatory for account
     */
    struct RemoveSignatory : public Command {
      /**
       * Account to remove from
       */
      std::string account_id;

      /**
       * Public key of signatory to remove.
       * Note: This public key must be attach to account.
       * There must be at least two signatories to perform this operation.
       */
      pubkey_t pubkey;

      bool operator==(const Command &command) const override;

      RemoveSignatory() {}

      RemoveSignatory(const std::string &account_id, const pubkey_t &pubkey)
          : account_id(account_id), pubkey(pubkey) {}
    };
  }  // namespace model
}  // namespace iroha

#endif  // IROHA_REMOVE_SIGNATORY_HPP
