/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_YAC_TIMER_HPP
#define IROHA_YAC_TIMER_HPP

#include <chrono>
#include <functional>

namespace iroha {
  namespace consensus {
    namespace yac {

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

        /**
         * Getter of the delay value
         * @return delay in ms
         */
        virtual std::chrono::milliseconds getDelay() const = 0;

        /**
         * Stop timer
         */
        virtual void deny() = 0;

        virtual ~Timer() = default;
      };
    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha
#endif  // IROHA_YAC_TIMER_HPP
