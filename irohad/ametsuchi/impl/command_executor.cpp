#include "ametsuchi/command_executor.hpp"

#include "interfaces/commands/command.hpp"

using namespace iroha::ametsuchi;

CommandResult CommandExecutor::execute(
    const shared_model::interface::Command &cmd) {
  return boost::apply_visitor(*this, cmd.get());
}
