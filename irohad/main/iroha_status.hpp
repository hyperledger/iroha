/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_STATUS_HPP
#define IROHA_STATUS_HPP

#include <rapidjson/stringbuffer.h>
#include <cstdint>
#include <optional>
#include <string>

#include "consensus/round.hpp"

namespace iroha {

  struct IrohaStatus {
    std::optional<uint64_t> memory_consumption;
    std::optional<consensus::Round> last_round;
    std::optional<bool> is_syncing;
    std::optional<bool> is_healthy;
  };

  struct IrohaStoredStatus {
    IrohaStatus status;
    rapidjson::StringBuffer serialized_status;
  };

}  // namespace iroha

#endif  // IROHA_STATUS_HPP
