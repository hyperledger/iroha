/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_YAC_TIMER_HPP
#define IROHA_MOCK_YAC_TIMER_HPP

#include "consensus/yac/timer.hpp"

#include <atomic>

#include <gmock/gmock.h>

namespace iroha {
  namespace consensus {
    namespace yac {

      class MockTimer : public Timer {
       public:
        void invokeAfterDelay(std::function<void()> handler) override {
          int32_t invoke_times{invoke_times_.load()};
          while (invoke_times > 0
                 and not std::atomic_compare_exchange_weak(
                         &invoke_times_, &invoke_times, invoke_times - 1))
            ;
          if (invoke_times != 0) {
            handler();
          }
        }

        /**
         * Toggle invoking the handler by @a invokeAfterDelay.
         * @param invoke_is_enabled invoke eternally if true, otherwise stop
         * invoking.
         */
        void setInvokeEnabled(bool invoke_is_enabled) {
          invoke_times_.store(invoke_is_enabled ? -1 : 0);
        }

        /**
         * Set number of times of invoking the handler by @a invokeAfterDelay.
         * @param times handler will be invoked @a times times and then stop.
         */
        void setInvokeThisMoreTimes(int32_t times) {
          assert(times > 0);
          invoke_times_.store(times);
        }

        MockTimer() = default;

        MockTimer(const MockTimer &rhs) {}

        MockTimer &operator=(const MockTimer &rhs) {
          return *this;
        }

       private:
        std::atomic<int32_t> invoke_times_{-1};
      };

    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha
#endif  // IROHA_MOCK_YAC_TIMER_HPP
