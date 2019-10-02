/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_call_engine.hpp"

#include "commands.pb.h"

using shared_model::proto::CallEngine;

CallEngine::CallEngine(iroha::protocol::Command &command)
    : call_engine_{command.call_engine()} {
  switch (call_engine_.type()) {
    case iroha::protocol::CallEngine::EngineType::
        CallEngine_EngineType_kSolidity:
      type_ = shared_model::interface::EngineType::kSolidity;
      break;
    default:
      assert(false);
  }
}

CallEngine::~CallEngine() = default;

shared_model::interface::EngineType CallEngine::type() const {
  return type_;
}

const std::string &CallEngine::caller() const {
  return call_engine_.caller();
}

std::optional<std::reference_wrapper<const std::string>> CallEngine::callee()
    const {
  if (call_engine_.opt_callee_case() == iroha::protocol::CallEngine::kCallee) {
    return call_engine_.callee();
  }
  return std::nullopt;
}

const std::string &CallEngine::input() const {
  return call_engine_.input();
}
