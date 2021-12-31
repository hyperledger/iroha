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
    using Predicate = std::function<bool()>;
    virtual ~IScheduler() {}

    /// Stops sheduler work and tasks execution
    virtual void dispose(bool wait_for_release = true) = 0;

    /// Checks if current scheduler executes task
    virtual bool isBusy() const = 0;

    /// If scheduller is not busy it takes task for execution. Otherwise it
    /// returns it back.
    virtual std::optional<Task> uploadIfFree(std::chrono::microseconds timeout,
                                             Task &&task) = 0;

    /// Adds delayed task to execution queue
    virtual void addDelayed(std::chrono::microseconds timeout, Task &&t) = 0;

    /// Adds task that will be periodicaly called with timeout period after
    /// timeout, until predicate return true
    virtual void repeat(std::chrono::microseconds timeout,
                        Task &&t,
                        Predicate &&pred) = 0;
  };

}  // namespace iroha::subscription

#endif  // IROHA_SUBSCRIPTION_SCHEDULER_HPP
