/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/validators_common.hpp"

#include <regex>

using google::protobuf::util::TimeUtil;
namespace shared_model {
  namespace validation {

    ValidatorsConfig::ValidatorsConfig(uint64_t max_batch_size,
                                       bool partial_ordered_batches_are_valid,
                                       bool txs_duplicates_allowed,
                                       std::optional<uint32_t> max_past_created_hours)
        : max_batch_size(max_batch_size),
          partial_ordered_batches_are_valid(partial_ordered_batches_are_valid),
          txs_duplicates_allowed(txs_duplicates_allowed),
          max_past_created_hours(max_past_created_hours)
    {}

    bool validateHexString(const std::string &str) {
      static const std::regex hex_regex{R"([0-9a-fA-F]*)"};
      return std::regex_match(str, hex_regex);
    }
    bool validateTimeStamp(const int64_t &timestamp) {
      const int64_t seconds_to_miliseconds = 1000;
      return timestamp >= google::protobuf::util::TimeUtil::kTimestampMinSeconds * seconds_to_miliseconds
          && timestamp
          <= google::protobuf::util::TimeUtil::kTimestampMaxSeconds * seconds_to_miliseconds;
    }
    bool validateHeight(const uint64_t &height) {
      const u_int64_t min_height = 1;
      return height >= min_height;
    }
    bool validateHeightOrder(const uint64_t &first_height,
                             const uint64_t &last_height){
      return first_height <= last_height;
    }
    bool validateTimeOrder(const int64_t &first_time,
                             const int64_t &last_time){
      return first_time <= last_time;
    }
  }  // namespace validation
}  // namespace shared_model
