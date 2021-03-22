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

    /*template <typename EventKey, typename... Args>
    auto getEngine() {
      using EngineType =
          SubscriptionEngine<EventKey,
                             Dispatcher,
                             Subscriber<EventKey, Dispatcher, Args...>>;
      constexpr auto engineId = getSubscriptionType<Args...>();
      std::lock_guard lock(engines_cs_);
      if (auto it = engines_.find(engineId); it != engines_.end()) {
        return std::reinterpret_pointer_cast<EngineType>(it->second);
      }
      auto obj = std::make_shared<EngineType>(dispatcher_);
      engines_[engineId] = std::reinterpret_pointer_cast<void>(obj);
      return obj;
    }*/

    /*template <typename EventKey, typename... Args>
    void notify(const EventKey &key, Args const &... args) {
      notifyDelayed(std::chrono::microseconds(0ull), key, args...);
    }*/

    /*template <typename EventKey, typename... Args>
    void notifyDelayed(std::chrono::microseconds timeout,
                       const EventKey &key,
                       Args const &... args) {
      using EngineType =
          SubscriptionEngine<EventKey,
                             Dispatcher,
                             Subscriber<EventKey, Dispatcher, Args...>>;
      constexpr auto engineId = getSubscriptionType<Args...>();
      std::shared_ptr<EngineType> engine;
      {
        std::lock_guard lock(engines_cs_);
        if (auto it = engines_.find(engineId); it != engines_.end())
          engine = std::reinterpret_pointer_cast<EngineType>(it->second);
        else
          return;
      }
      if (engine)
        engine->notifyDelayed(timeout, key, args...);
    }*/

    DispatcherPtr dispatcher() const {
      return dispatcher_;
    }
  };

  static std::shared_ptr<MockSubscriptionManager> getSubscription() {
    return std::make_shared<MockSubscriptionManager>();
  }
}  // namespace iroha
#endif  // IROHA_MOCK_SUBSCRIPTION_ENGINE_HPP
