/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_VALIDATORS_COMMON_HPP
#define IROHA_VALIDATORS_COMMON_HPP

#include <memory>
#include <string>
#include "validators/settings.hpp"

namespace shared_model {
  namespace validation {
    /**
     * A struct that contains configuration parameters for all validators.
     * A validator may read only specific fields.
     */
    struct ValidatorsConfig {
      ValidatorsConfig(
          uint64_t max_batch_size,
          std::shared_ptr<const Settings> settings = getDefaultSettings(),
          bool partial_ordered_batches_are_valid = false,
          bool txs_duplicates_allowed = false);

      /// Maximum allowed amount of transactions within a batch
      const uint64_t max_batch_size;

      /// Batch meta can contain more hashes of batch transactions than it
      /// actually has. Used for block validation
      const bool partial_ordered_batches_are_valid;

      /// Settings
      const std::shared_ptr<const Settings> settings;

      /**
       * Defines whether a transactions collection, with duplicated
       * transactions, valid or not. Used in:
       * - TransactionBatchValidator (ListTorii)
       * - MST & OrderingGate & OrderingService
       * - BlockLoader
       */
      const bool txs_duplicates_allowed;
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
