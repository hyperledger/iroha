/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/query_responses/engine_log.hpp"

using namespace shared_model::interface;

bool EngineLog::operator==(ModelType const &rhs) const {
  if (&rhs == static_cast<ModelType const *>(this)) {
    return true;
  }

  return getAddress() == rhs.getAddress() && getData() == rhs.getData()
      && getTopics() == rhs.getTopics();
}

std::string EngineLog::toString() const {
  return detail::PrettyStringBuilder()
      .init("EngineLog")
      .appendNamed("address", getAddress())
      .appendNamed("data", getData())
      .appendNamed("topics", getTopics())
      .finalize();
}
