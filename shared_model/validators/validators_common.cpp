/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/validators_common.hpp"

#include <regex>

namespace shared_model {
  namespace validation {

    ValidatorsConfig::ValidatorsConfig(uint64_t max_batch_size,
                                       bool partial_ordered_batches_are_valid)
        : max_batch_size(max_batch_size),
          partial_ordered_batches_are_valid(partial_ordered_batches_are_valid) {
    }

    bool validateHexString(const std::string &str) {
      static const std::regex hex_regex{R"([0-9a-fA-F]*)"};
      return std::regex_match(str, hex_regex);
    }

  }  // namespace validation
}  // namespace shared_model
