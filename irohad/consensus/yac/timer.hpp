/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_YAC_TIMER_HPP
#define IROHA_YAC_TIMER_HPP

#include <functional>

namespace iroha::consensus::yac {
  /**
   * Interface provide timer for yac implementation
   */
  class Timer {
   public:
    /**
     * Invoke handler with class-specific strategy
     * @param handler - function, that will be invoked
     */
    virtual void invokeAfterDelay(std::function<void()> handler) = 0;

    virtual ~Timer() = default;
  };
}  // namespace iroha::consensus::yac

#endif  // IROHA_YAC_TIMER_HPP
