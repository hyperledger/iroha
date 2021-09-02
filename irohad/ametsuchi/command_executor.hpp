/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_AMETSUCHI_COMMAND_EXECUTOR_HPP
#define IROHA_AMETSUCHI_COMMAND_EXECUTOR_HPP

#include "ametsuchi/impl/db_transaction.hpp"
#include "common/result.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {
    class Command;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {
  namespace ametsuchi {

    /**
     * Error for command execution or validation
     * Contains command name, as well as an error message
     */
    struct CommandError {
      using ErrorCodeType = uint32_t;

      CommandError(std::string_view command_name,
                   ErrorCodeType error_code,
                   std::string_view error_extra);

      std::string command_name;
      ErrorCodeType error_code;
      std::string error_extra;

      std::string toString() const;
    };

    /**
     *  If command is successful, we assume changes are made,
     *  and do not need anything
     *  If something goes wrong, Result will contain Error
     *  with additional information
     */
    using CommandResult = expected::Result<void, CommandError>;

    class CommandExecutor {
     public:
      virtual ~CommandExecutor() = default;

      virtual CommandResult execute(
          const shared_model::interface::Command &cmd,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          const std::string &tx_hash,
          shared_model::interface::types::CommandIndexType cmd_index,
          bool do_validation) = 0;

      virtual void skipChanges() = 0;

      virtual DatabaseTransaction &dbSession() = 0;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_AMETSUCHI_COMMAND_EXECUTOR_HPP
