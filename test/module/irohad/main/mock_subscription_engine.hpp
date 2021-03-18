/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_SUBSCRIPTION_ENGINE_HPP
#define IROHA_MOCK_SUBSCRIPTION_ENGINE_HPP

#include "consensus/yac/timer.hpp"

#include <atomic>
#include <gmock/gmock.h>

namespace iroha {

  class MockDispatcher final {
   public:
    using Tid = uint32_t;

   public:
    MockDispatcher() = default;

    template <typename F>
    void add(Tid tid, F &&f) {
      std::forward<F>(f)();
    }

    template <typename F>
    void addDelayed(Tid tid, std::chrono::microseconds /*timeout*/, F &&f) {
      std::forward<F>(f)();
    }
  };

  class MockSubscriptionManager {
   public:
    using Dispatcher = MockDispatcher;

   private:
    using DispatcherPtr = std::shared_ptr<Dispatcher>;

   private:
    DispatcherPtr dispatcher_;

   public:
    MockSubscriptionManager() : dispatcher_(std::make_shared<Dispatcher>()) {}

    DispatcherPtr dispatcher() const {
      return dispatcher_;
    }
  };

  static std::shared_ptr<MockSubscriptionManager> getSubscription() {
    return std::make_shared<MockSubscriptionManager>();
  }
}  // namespace iroha
#endif  // IROHA_MOCK_SUBSCRIPTION_ENGINE_HPP
