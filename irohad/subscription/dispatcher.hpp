/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SUBSCRIPTION_DISPATCHER_HPP
#define IROHA_SUBSCRIPTION_DISPATCHER_HPP

#include "subscription/common.hpp"
#include "subscription/thread_handler.hpp"

namespace iroha::subscription {

  template <uint32_t kCount>
  class Dispatcher final : utils::NoCopy, utils::NoMove {
   public:
    static constexpr uint32_t kHandlersCount = kCount;
    using Task = ThreadHandler::Task;
    using Tid = uint32_t;

   private:
    ThreadHandler handlers_[kHandlersCount];

   public:
    Dispatcher() = default;

    template <Tid kId>
    static constexpr void checkTid() {
      static_assert(kId < kHandlersCount, "Unexpected TID handler.");
    }

    template <typename F>
    void add(Tid tid, F &&f) {
      assert(tid < kHandlersCount);
      handlers_[tid].add(std::forward<F>(f));
    }

    template <typename F>
    void addDelayed(Tid tid, std::chrono::microseconds timeout, F &&f) {
      assert(tid < kHandlersCount);
      handlers_[tid].addDelayed(timeout, std::forward<F>(f));
    }
  };

}  // namespace iroha::subscription

#endif  // IROHA_SUBSCRIPTION_DISPATCHER_HPP
