/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_STATUS_HPP
#define IROHA_STATUS_HPP

#include <optional>
#include <cstdint>
#include <string>

namespace iroha {

  struct IrohaStatus {
    std::optional<uint64_t> memory_consumption;
    std::optional<bool> is_syncing;
    std::optional<bool> is_healthy;
  };

  struct IrohaStoredStatus {
    IrohaStatus status;
    std::string serialized_status;
  };

}

#endif  // IROHA_STATUS_HPP
