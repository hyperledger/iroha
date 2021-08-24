/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_COMMAND_EXECUTOR_HPP
#define IROHA_MOCK_COMMAND_EXECUTOR_HPP

#include "ametsuchi/command_executor.hpp"

#include <gmock/gmock.h>

namespace iroha {
  namespace ametsuchi {

    struct MockCommandExecutor : public CommandExecutor {
      MOCK_METHOD5(
          execute,
          CommandResult(const shared_model::interface::Command &,
                        const shared_model::interface::types::AccountIdType &,
                        const std::string &,
                        shared_model::interface::types::CommandIndexType,
                        bool));

      MOCK_METHOD0(skipChanges, void());
      MOCK_METHOD0(dbSession, DatabaseTransaction &());
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_MOCK_COMMAND_EXECUTOR_HPP
