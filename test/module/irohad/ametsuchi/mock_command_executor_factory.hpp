/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_COMMAND_EXECUTOR_FACTORY_HPP
#define IROHA_MOCK_COMMAND_EXECUTOR_FACTORY_HPP

#include "ametsuchi/command_executor_factory.hpp"

#include <gmock/gmock.h>
#include "module/irohad/ametsuchi/mock_command_executor.hpp"

namespace iroha {
  namespace ametsuchi {

    struct MockCommandExecutorFactory : public CommandExecutorFactory {
      MockCommandExecutorFactory() {
        ON_CALL(*this, createCommandExecutor()).WillByDefault([] {
          return std::make_unique<MockCommandExecutor>();
        });
      }

      virtual ~MockCommandExecutorFactory() = default;

      MOCK_METHOD0(
          createCommandExecutor,
          expected::Result<std::unique_ptr<CommandExecutor>, std::string>());
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif
