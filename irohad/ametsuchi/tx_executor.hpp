/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_AMETSUCHI_TX_EXECUTOR_HPP
#define IROHA_AMETSUCHI_TX_EXECUTOR_HPP

#include "ametsuchi/command_executor.hpp"
#include "common/result.hpp"

namespace shared_model {
  namespace interface {
    class Command;
    class Transaction;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {
  namespace ametsuchi {

    struct TxExecutionError {
      CommandError command_error;
      size_t command_index;
    };

    class TransactionExecutor {
     public:
      explicit TransactionExecutor(
          std::shared_ptr<CommandExecutor> command_executor);

      iroha::expected::Result<void, TxExecutionError> execute(
          const shared_model::interface::Transaction &transaction,
          bool do_validation) const;

     private:
      std::shared_ptr<CommandExecutor> command_executor_;
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_AMETSUCHI_TX_EXECUTOR_HPP
