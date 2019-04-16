/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_VALIDATORS_COMMON_HPP
#define IROHA_VALIDATORS_COMMON_HPP

#include <string>

namespace shared_model {
  namespace validation {

    /**
     * A struct that contains configuration parameters for all validators.
     * A validator may read only specific fields.
     */
    struct ValidatorsConfig {
      ValidatorsConfig(const uint64_t max_batch_size);
      /// Maximum allowed amount of transactions within a batch
      const uint64_t max_batch_size;
    };

    /**
     * Check if given string has hex format
     * @param str string to check
     * @return true if string is in hex, false otherwise
     */
    bool validateHexString(const std::string &str);

  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_VALIDATORS_COMMON_HPP
