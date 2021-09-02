/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SUBSCRIPTION_THREAD_HANDLER_HPP
#define IROHA_SUBSCRIPTION_THREAD_HANDLER_HPP

#include <assert.h>
#include <algorithm>
#include <chrono>
#include <deque>
#include <functional>
#include <mutex>
#include <shared_mutex>
#include <thread>

#include "common/common.hpp"
#include "subscription/scheduler_impl.hpp"

namespace iroha::subscription {

  class ThreadHandler final : public SchedulerBase {
   private:
    std::thread worker_;

   public:
    ThreadHandler() {
      worker_ = std::thread(
          [](ThreadHandler *__this) { return __this->process(); }, this);
    }

    void dispose(bool wait_for_release = true) {
      SchedulerBase::dispose(wait_for_release);
      if (wait_for_release)
        worker_.join();
      else
        worker_.detach();
    }
  };

}  // namespace iroha::subscription

#endif  // IROHA_SUBSCRIPTION_THREAD_HANDLER_HPP
