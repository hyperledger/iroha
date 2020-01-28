/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "interfaces/commands/engine_call.hpp"

namespace shared_model {
  namespace interface {

    std::string EngineCall::toString() const {
      return detail::PrettyStringBuilder()
          .init("EngineCall")
          .appendNamed("callee", callee())
          .appendNamed("input", input())
          .finalize();
    }

    bool EngineCall::operator==(const ModelType &rhs) const {
      return callee() == rhs.callee() && input() == rhs.input();
      ;
    }

  }  // namespace interface
}  // namespace shared_model
