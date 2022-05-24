/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TIME_H
#define IROHA_TIME_H

#include <chrono>

namespace iroha {

  // timestamps
  using ts64_t = uint64_t;
  using ts32_t = uint32_t;

  namespace time {

    /**
     * Returns current UNIX timestamp.
     * Represents number of milliseconds since epoch.
     */
    inline auto now() {
      return std::chrono::system_clock::now().time_since_epoch()
          / std::chrono::milliseconds(1);
    }

    /**
     * Returns current UNIX timestamp.
     * Represents number of milliseconds since epoch.
     */
    inline auto nowUs() {
      return std::chrono::high_resolution_clock::now().time_since_epoch()
          / std::chrono::microseconds(1);
    }

    /**
     * Return UNIX timestamp with given offset.
     * Represents number of milliseconds since epoch.
     */
    template <typename T>
    inline auto now(const T &offset) {
      return (std::chrono::system_clock::now().time_since_epoch() + offset)
          / std::chrono::milliseconds(1);
    }

    using time_t = decltype(iroha::time::now());
  }  // namespace time
}  // namespace iroha

#endif  // IROHA_TIME_H
