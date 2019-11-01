/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/query_responses/engine_response_record.hpp"

using namespace shared_model::interface;

bool EngineResponseRecord::operator==(const ModelType &rhs) const {
  return commandIndex() == rhs.commandIndex() and response() == rhs.response();
}

std::string EngineResponseRecord::toString() const {
  return detail::PrettyStringBuilder()
      .init("EngineResponseRecord")
      .append("command_index", std::to_string(commandIndex()))
      .append("reponse", response())
      .finalize();
}
