/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SUBSCRIPTION_DISPATCHER_HPP
#define IROHA_SUBSCRIPTION_DISPATCHER_HPP

#include <optional>

#include "common/common.hpp"
#include "subscription/scheduler.hpp"

namespace iroha::subscription {

  struct IDispatcher {
    using Tid = uint32_t;
    using Task = IScheduler::Task;
    using Predicate = IScheduler::Predicate;
    static constexpr Tid kExecuteInPool = std::numeric_limits<Tid>::max();

    virtual ~IDispatcher() {}

    virtual std::optional<Tid> bind(std::shared_ptr<IScheduler> scheduler) = 0;
    virtual bool unbind(Tid tid) = 0;

    virtual void dispose() = 0;
    virtual void add(Tid tid, Task &&task) = 0;
    virtual void addDelayed(Tid tid,
                            std::chrono::microseconds timeout,
                            Task &&task) = 0;
    virtual void repeat(Tid tid,
                        std::chrono::microseconds timeout,
                        Task &&task,
                        Predicate &&pred) = 0;
  };

}  // namespace iroha::subscription

#endif  // IROHA_SUBSCRIPTION_DISPATCHER_HPP
