/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/proto_command_executor.h"

#include "ametsuchi/command_executor.hpp"
#include "backend/protobuf/commands/proto_command.hpp"

Iroha_CommandError Iroha_ProtoCommandExecutorExecute(void *executor,
                                                     void *data,
                                                     int size) {
  Iroha_CommandError result{};

  iroha::protocol::Command command;
  if (!command.ParseFromArray(data, size)) {
    result.error_code = 100;
    return result;
  }

  reinterpret_cast<iroha::ametsuchi::CommandExecutor *>(executor)
      ->execute(shared_model::proto::Command(command), "", true)
      .match([](const auto &) {},
             [&result](const auto &error) {
               result.error_code = error.error.error_code;
             });
  return result;
}
