/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_RUN_LOOP_HANDLER_HPP
#define IROHA_RUN_LOOP_HANDLER_HPP

#include <ciso646>
#include <condition_variable>

#include <rxcpp/rx-lite.hpp>

namespace iroha {
  namespace schedulers {

    inline void handleEvents(rxcpp::composite_subscription &subscription,
                             rxcpp::schedulers::run_loop &run_loop) {
      std::condition_variable wait_cv;

      run_loop.set_notify_earlier_wakeup(
          [&wait_cv](const auto &) { wait_cv.notify_one(); });

      std::mutex wait_mutex;
      std::unique_lock<std::mutex> lock(wait_mutex);
      while (subscription.is_subscribed() or not run_loop.empty()) {
        while (not run_loop.empty()
               and run_loop.peek().when <= run_loop.now()) {
          run_loop.dispatch();
        }

        if (run_loop.empty()) {
          wait_cv.wait(lock, [&run_loop, &subscription]() {
            return not subscription.is_subscribed() or not run_loop.empty();
          });
        } else {
          wait_cv.wait_until(lock, run_loop.peek().when);
        }
      }
    }
  }  // namespace schedulers
}  // namespace iroha

#endif  // IROHA_RUN_LOOP_HANDLER_HPP
