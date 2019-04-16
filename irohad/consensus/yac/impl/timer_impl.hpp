/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TIMER_IMPL_HPP
#define IROHA_TIMER_IMPL_HPP

#include <mutex>

#include <rxcpp/rx.hpp>
#include "consensus/yac/timer.hpp"

namespace iroha {
  namespace consensus {
    namespace yac {
      class TimerImpl : public Timer {
       public:
        /**
         * Constructor
         * @param delay_milliseconds delay before the next method invoke
         * @param coordination factory for coordinators to run the timer on
         */
        TimerImpl(std::chrono::milliseconds delay_milliseconds,
                  rxcpp::observe_on_one_worker coordination);
        TimerImpl(const TimerImpl &) = delete;
        TimerImpl &operator=(const TimerImpl &) = delete;

        void invokeAfterDelay(std::function<void()> handler) override;
        void deny() override;

        ~TimerImpl() override;

       private:
        std::mutex timer_lifetime_mutex;
        std::chrono::milliseconds delay_milliseconds_;
        rxcpp::composite_subscription coordinator_lifetime_;
        rxcpp::observe_on_one_worker coordination_;
        rxcpp::composite_subscription timer_lifetime_;
      };
    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha

#endif  // IROHA_TIMER_IMPL_HPP
