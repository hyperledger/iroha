/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/validators_common.hpp"

#include <regex>

namespace shared_model {
  namespace validation {

    ValidatorsConfig::ValidatorsConfig(const uint64_t max_batch_size)
        : max_batch_size(max_batch_size) {}

    bool validateHexString(const std::string &str) {
      static const std::regex hex_regex{R"([0-9a-fA-F]*)"};
      return std::regex_match(str, hex_regex);
    }

  }  // namespace validation
}  // namespace shared_model
