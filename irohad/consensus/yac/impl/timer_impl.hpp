/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TIMER_IMPL_HPP
#define IROHA_TIMER_IMPL_HPP

#include "consensus/yac/timer.hpp"

#include <chrono>

namespace iroha {
  namespace consensus {
    namespace yac {
      class TimerImpl : public Timer {
       public:
        /**
         * Constructor
         * @param delay_milliseconds delay before the next method invoke
         */
        TimerImpl(std::chrono::milliseconds delay_milliseconds);

        void invokeAfterDelay(std::function<void()> handler) override;

       private:
        std::chrono::milliseconds delay_milliseconds_;
      };
    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha

#endif  // IROHA_TIMER_IMPL_HPP
