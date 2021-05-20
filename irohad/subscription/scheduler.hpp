/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SUBSCRIPTION_SCHEDULER_HPP
#define IROHA_SUBSCRIPTION_SCHEDULER_HPP

#include <functional>

#include "common/common.hpp"

namespace iroha::subscription {

  class IScheduler {
   public:
    using Task = std::function<void()>;
    virtual ~IScheduler() {}

    /// Stops sheduler work and tasks execution
    virtual void dispose(bool wait_for_release = true) = 0;

    /// Checks if current scheduler executes task
    virtual bool isBusy() const = 0;

    /// Adds task to execution queue
    virtual void add(Task &&t) = 0;

    /// Adds delayed task to execution queue
    virtual void addDelayed(std::chrono::microseconds timeout, Task &&t) = 0;
  };

}  // namespace iroha::subscription

#endif  // IROHA_SUBSCRIPTION_SCHEDULER_HPP
