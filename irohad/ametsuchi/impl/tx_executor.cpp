#include "ametsuchi/tx_executor.hpp"

#include "interfaces/commands/command.hpp"
#include "interfaces/transaction.hpp"

using namespace iroha::ametsuchi;

TransactionExecutor::TransactionExecutor(
    std::shared_ptr<CommandExecutor> command_executor)
    : command_executor_(std::move(command_executor)) {}

iroha::expected::Result<void, TxExecutionError> TransactionExecutor::execute(
    const shared_model::interface::Transaction &transaction,
    bool do_validation) const {
  const auto &tx_creator = transaction.creatorAccountId();
  command_executor_->setCreatorAccountId(tx_creator);
  command_executor_->doValidation(do_validation);

  size_t cmd_index = 0;
  for (const auto &cmd : transaction.commands()) {
    if (auto cmd_error = iroha::expected::resultToOptionalError(
            command_executor_->execute(cmd))) {
      return iroha::expected::makeError(
          TxExecutionError{std::move(cmd_error.value()), cmd_index});
    }
    ++cmd_index;
  }
  return {};
}
