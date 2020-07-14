/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/commands/call_model.hpp"

#include <ciso646>
#include <string>

#include "common/optional_reference_equal.hpp"
#include "utils/string_builder.hpp"

using namespace shared_model::interface;

CallModel::~CallModel() = default;

std::string CallModel::toString() const {
  return detail::PrettyStringBuilder()
      .init("CallModel")
      .appendNamed("name", name())
      .appendNamed("version", version())
      .finalize();
}

bool CallModel::operator==(const CallModel &rhs) const {
  return name() == rhs.name() and version() == rhs.version();
}
