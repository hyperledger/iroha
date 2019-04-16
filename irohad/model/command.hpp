/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_COMMAND_HPP
#define IROHA_COMMAND_HPP

namespace iroha {
  namespace model {
    /**
     * Abstract Command Model
     */
    struct Command {
      virtual ~Command() = default;

      virtual bool operator==(const Command &rhs) const = 0;

      virtual bool operator!=(const Command &rhs) const;
    };
  }  // namespace model
}  // namespace iroha

#endif  // IROHA_COMMAND_HPP
