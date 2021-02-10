/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SUBSCRIPTION_DISPATCHER_HPP
#define IROHA_SUBSCRIPTION_DISPATCHER_HPP

#include "subscription/common.hpp"

namespace iroha::subscription {

  template <size_t kCount>
  class Dispatcher final : utils::NoCopy, utils::NoMove {
   public:
    static constexpr size_t kHandlersCount = kCount;
    using Task = threadHandler::Task;

   private:
    threadHandler handlers_[kHandlersCount];

   public:
    Dispatcher() = default;

    template <size_t I, typename F>
    void add(F &&f) {
      static_assert(I < kHandlersCount, "Handler index is out-of-bound.");
      handlers_[I].add(std::forward<F>(f));
    }

    template <size_t I, typename F>
    void addDelayed(size_t timeoutUs, F &&f) {
      static_assert(I < kHandlersCount, "Handler index is out-of-bound.");
      handlers_[I].addDelayed(timeoutUs, std::forward<F>(f));
    }
  };

}  // namespace iroha::subscription

#endif  // IROHA_SUBSCRIPTION_DISPATCHER_HPP
