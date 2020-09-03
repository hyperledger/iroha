/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_AMETSUCHI_COMMAND_EXECUTOR_FACTORY_HPP
#define IROHA_AMETSUCHI_COMMAND_EXECUTOR_FACTORY_HPP

#include <memory>
#include <string>

#include "common/result_fwd.hpp"

namespace iroha {
  namespace ametsuchi {

    class CommandExecutor;

    class CommandExecutorFactory {
     public:
      /**
       * Create new command executor that holds a database session within.
       * @return The command executor or string error message.
       */
      virtual expected::Result<std::unique_ptr<CommandExecutor>, std::string>
      createCommandExecutor() = 0;
    };

  }  // namespace ametsuchi

}  // namespace iroha

#endif
