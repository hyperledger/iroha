/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_VALIDATORS_COMMON_HPP
#define IROHA_VALIDATORS_COMMON_HPP

#include <google/protobuf/util/time_util.h>
#include <optional>
#include <string>

namespace shared_model {
  namespace validation {

    /**
     * A struct that contains configuration parameters for all validators.
     * A validator may read only specific fields.
     */
    struct ValidatorsConfig {
      ValidatorsConfig(uint64_t max_batch_size,
                       bool partial_ordered_batches_are_valid = false,
                       bool txs_duplicates_allowed = false,
                       std::optional<uint32_t> max_past_created_hours = {});
      /// Maximum allowed amount of transactions within a batch
      const uint64_t max_batch_size;

      /// Batch meta can contain more hashes of batch transactions than it
      /// actually has. Used for block validation
      const bool partial_ordered_batches_are_valid;

      /**
       * Defines whether a transactions collection, with duplicated
       * transactions, valid or not. Used in:
       * - TransactionBatchValidator (ListTorii)
       * - MST & OrderingGate & OrderingService
       * - BlockLoader
       */
      const bool txs_duplicates_allowed;

      /**
       * A parameter, which specifies how many hours before the current peer's
       * `created_time` can the transaction be set.
       * Default is `FieldValidator::KDefaultMaxDelay` (hours).
       * The value must be synchronised across all peers.
       */
      std::optional<uint32_t> max_past_created_hours;
    };

    /**
     * Check if given string has hex format
     * @param str string to check
     * @return true if string is in hex, false otherwise
     */
    bool validateHexString(const std::string &str);
    /**
     * Check if given Timestamp has correct range
     * @param timestamp Timestamp to check
     * @return true if timestamp is in proper range, false otherwise
     */
    bool validateTimeStamp(const int64_t &timestamp);
    /**
     * Check if given block height has correct value
     * @param height Height to check
     * @return true if height is corect value, false otherwise
     */
    bool validateHeight(const uint64_t &height);
    /**
     * Check if two given block heights has correct value ordering
     * @param first_height Height to check
     * @param second_height Height to check
     * @return true if first_height <= last_height, false otherwise
     */
    bool validateHeightOrder(const uint64_t &first_height,
                             const uint64_t &last_height);
    /**
     * Check if two given timestamps has correct ordering
     * @param first_time Time to check
     * @param last_time Time to check
     * @return true if first_height <= last_height, false otherwise
     */
    bool validateTimeOrder(const int64_t &first_time,
                             const int64_t &last_time);
  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_VALIDATORS_COMMON_HPP
