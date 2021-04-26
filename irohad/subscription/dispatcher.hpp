/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SUBSCRIPTION_DISPATCHER_HPP
#define IROHA_SUBSCRIPTION_DISPATCHER_HPP

#include "subscription/common.hpp"
#include "subscription/thread_handler.hpp"

namespace iroha::subscription {

  template <uint32_t kCount, uint32_t kPoolSize>
  struct IDispatcher {
    using Tid = uint32_t;
    using Task = ThreadHandler::Task;

    static constexpr Tid kExecuteInPool = std::numeric_limits<Tid>::max();
    static constexpr uint32_t kHandlersCount = kCount;
    static constexpr uint32_t kPoolThreadsCount = kPoolSize;

    virtual ~IDispatcher() {}

    template <Tid kId>
    static constexpr void checkTid() {
      static_assert(kId < kHandlersCount || kId == kExecuteInPool,
                    "Unexpected TID handler.");
    }

    virtual void dispose() = 0;
    virtual void add(Tid tid, Task &&task) = 0;
    virtual void addDelayed(Tid tid,
                            std::chrono::microseconds timeout,
                            Task &&task) = 0;
  };

}  // namespace iroha::subscription

#endif  // IROHA_SUBSCRIPTION_DISPATCHER_HPP
