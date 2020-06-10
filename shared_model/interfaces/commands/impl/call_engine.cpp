/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/commands/call_engine.hpp"

#include <ciso646>

#include "common/optional_reference_equal.hpp"
#include "utils/string_builder.hpp"

using namespace shared_model::interface;

namespace {
  const char *engineTypeToString(EngineType type) {
    switch (type) {
      case EngineType::kSolidity:
        return "Solidity";
      default:
        assert(false);
        return "<unknown>";
    }
  }
}  // namespace

CallEngine::~CallEngine() = default;

std::string CallEngine::toString() const {
  return detail::PrettyStringBuilder()
      .init("CallEngine")
      .appendNamed("type", engineTypeToString(type()))
      .appendNamed("caller", caller())
      .appendNamed("callee", callee())
      .appendNamed("input", input())
      .finalize();
}

bool CallEngine::operator==(const CallEngine &rhs) const {
  return type() == rhs.type() and caller() == rhs.caller()
      and iroha::optionalReferenceEqual(callee(), rhs.callee())
      and input() == rhs.input();
}
