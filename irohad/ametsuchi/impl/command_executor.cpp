/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/command_executor.hpp"

#include <fmt/core.h>

using namespace iroha::ametsuchi;

CommandError::CommandError(std::string_view command_name,
                           ErrorCodeType error_code,
                           std::string_view error_extra)
    : command_name(command_name),
      error_code(error_code),
      error_extra(error_extra) {}

std::string CommandError::toString() const {
  return fmt::format(
      "{}: {} with extra info '{}'", command_name, error_code, error_extra);
}
