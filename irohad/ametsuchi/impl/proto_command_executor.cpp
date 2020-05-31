/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/proto_command_executor.h"

#include "ametsuchi/command_executor.hpp"
#include "ametsuchi/impl/common_c_types_helpers.hpp"
#include "backend/protobuf/commands/proto_command.hpp"
#include "validators/field_validator.hpp"
#include "validators/protobuf/proto_command_validator.hpp"
#include "validators/transaction_validator.hpp"
#include "validators/validators_common.hpp"

Iroha_CommandError Iroha_ProtoCommandExecutorExecute(void *executor,
                                                     void *data,
                                                     int size,
                                                     char *account_id) {
  Iroha_CommandError result{};
  iroha::clearCharBuffer(result.command_name);

  iroha::protocol::Command protocol_command;
  if (!protocol_command.ParseFromArray(data, size)) {
    result.error_code = 100;
    return result;
  }

  if (auto maybe_error =
          shared_model::validation::ProtoCommandValidator().validate(
              protocol_command)) {
    result.error_code = 200;
    iroha::toCharBuffer(result.error_extra, maybe_error.value().toString());
    return result;
  }

  shared_model::proto::Command proto_command(protocol_command);

  auto maybe_error = boost::apply_visitor(
      shared_model::validation::CommandValidatorVisitor<
          shared_model::validation::FieldValidator>{
          std::make_shared<shared_model::validation::ValidatorsConfig>(0)},
      proto_command.get());

  if (maybe_error) {
    result.error_code = 300;
    iroha::toCharBuffer(result.error_extra, maybe_error.value().toString());
    return result;
  }

  reinterpret_cast<iroha::ametsuchi::CommandExecutor *>(executor)
      ->execute(proto_command, account_id, {}, 0, true)
      .match([](const auto &) {},
             [&result](const auto &error) {
               result.error_code = error.error.error_code;
               iroha::toCharBuffer(result.error_extra, error.error.error_extra);
             });
  return result;
}
