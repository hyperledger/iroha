/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/impl/timer_impl.hpp"
#include <iostream>

namespace iroha {
  namespace consensus {
    namespace yac {
      TimerImpl::TimerImpl(std::chrono::milliseconds delay_milliseconds,
                           rxcpp::observe_on_one_worker coordination)
          : delay_milliseconds_(delay_milliseconds),
            // use the same worker for all the invocations
            coordination_(coordination.create_coordinator(coordinator_lifetime_)
                              .get_scheduler()) {}

      void TimerImpl::invokeAfterDelay(std::function<void()> handler) {
        deny();
        auto timer_lifetime =
            rxcpp::observable<>::timer(delay_milliseconds_, coordination_)
                .subscribe([handler{std::move(handler)}](auto) { handler(); });
        {
          std::lock_guard<std::mutex> lock(timer_lifetime_mutex);
          timer_lifetime_ = timer_lifetime;
        }
      }

      std::chrono::milliseconds TimerImpl::getDelay() const {
        return delay_milliseconds_;
      }

      void TimerImpl::deny() {
        rxcpp::composite_subscription timer_lifetime;
        {
          std::lock_guard<std::mutex> lock(timer_lifetime_mutex);
          timer_lifetime = timer_lifetime_;
        }
        timer_lifetime.unsubscribe();
      }

      TimerImpl::~TimerImpl() {
        deny();
        coordinator_lifetime_.unsubscribe();
      }
    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha
