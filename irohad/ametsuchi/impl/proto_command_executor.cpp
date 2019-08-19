/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/proto_command_executor.h"

#include "ametsuchi/command_executor.hpp"
#include "backend/protobuf/commands/proto_command.hpp"
#include "validators/field_validator.hpp"
#include "validators/protobuf/proto_command_validator.hpp"
#include "validators/transaction_validator.hpp"
#include "validators/validators_common.hpp"

namespace {
  char *clone(const std::string &string) {
    char *cstr = new char[string.length() + 1];
    strcpy(cstr, string.c_str());
    return cstr;
  }
}  // namespace

Iroha_CommandError Iroha_ProtoCommandExecutorExecute(void *executor,
                                                     void *data,
                                                     int size,
                                                     char *account_id) {
  Iroha_CommandError result{};

  iroha::protocol::Command protocol_command;
  if (!protocol_command.ParseFromArray(data, size)) {
    result.error_code = 100;
    return result;
  }

  if (auto answer = shared_model::validation::ProtoCommandValidator().validate(
          protocol_command)) {
    result.error_code = 200;
    result.error_extra = clone(answer.reason());
    return result;
  }

  shared_model::proto::Command proto_command(protocol_command);

  auto reasons = boost::apply_visitor(
      shared_model::validation::CommandValidatorVisitor<
          shared_model::validation::FieldValidator>{
          std::make_shared<shared_model::validation::ValidatorsConfig>(0)},
      proto_command.get());

  if (not reasons.second.empty()) {
    result.error_code = 300;
    result.error_extra = clone(reasons.second.front());
    return result;
  }

  reinterpret_cast<iroha::ametsuchi::CommandExecutor *>(executor)
      ->execute(proto_command, account_id, true)
      .match([](const auto &) {},
             [&result](const auto &error) {
               result.error_code = error.error.error_code;
               result.error_extra = clone(error.error.error_extra);
             });
  return result;
}
