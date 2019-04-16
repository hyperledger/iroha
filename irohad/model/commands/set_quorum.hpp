/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SET_QUORUM_HPP
#define IROHA_SET_QUORUM_HPP

#include <string>
#include "model/command.hpp"

namespace iroha {
  namespace model {
    /**
     * Change quorum for account
     */
    struct SetQuorum : public Command {
      /**
       * Account in which change the quorum
       */
      std::string account_id;

      /**
       * New value of quorum
       */
      uint32_t new_quorum;

      bool operator==(const Command &command) const override;

      SetQuorum() {}

      SetQuorum(const std::string &account_id, uint32_t new_quorum)
          : account_id(account_id), new_quorum(new_quorum) {}
    };
  }  // namespace model
}  // namespace iroha
#endif  // IROHA_SET_QUORUM_HPP
