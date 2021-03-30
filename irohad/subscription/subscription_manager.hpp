/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SUBSCRIPTION_SUBSCRIPTION_MANAGER_HPP
#define IROHA_SUBSCRIPTION_SUBSCRIPTION_MANAGER_HPP

#include <memory>
#include <shared_mutex>
#include <unordered_map>

#include "common/compile-time_murmur2.hpp"
#include "subscription/common.hpp"
#include "subscription/dispatcher.hpp"
#include "subscription/subscriber.hpp"
#include "subscription/subscription_engine.hpp"

namespace iroha::subscription {

  /**
   * Class-aggregator that keeps all event engines inside. On notification it
   * selects the appropriate engine and calls notification in it.
   * @tparam kHandlersCount number of supported thread handlers
   */
  template <uint32_t kHandlersCount, uint32_t kPoolSize>
  class SubscriptionManager final
      : public std::enable_shared_from_this<
            SubscriptionManager<kHandlersCount, kPoolSize>>,
        utils::NoMove,
        utils::NoCopy {
   public:
    using Dispatcher = subscription::Dispatcher<kHandlersCount, kPoolSize>;

   private:
    using EngineHash = uint64_t;
    using DispatcherPtr = std::shared_ptr<Dispatcher>;
    using EnginesList = std::unordered_map<EngineHash, std::shared_ptr<void>>;

   private:
    DispatcherPtr dispatcher_;
    std::shared_mutex engines_cs_;
    EnginesList engines_;
    std::atomic_flag disposed_;

   private:
    template <typename... Args>
    static constexpr EngineHash getSubscriptionType() {
#ifdef _WIN32
      constexpr EngineHash value = CT_MURMUR2(__FUNCSIG__);
#else   //_WIN32
      constexpr EngineHash value = CT_MURMUR2(__PRETTY_FUNCTION__);
#endif  //_WIN32
      return value;
    }

   public:
    SubscriptionManager() : dispatcher_(std::make_shared<Dispatcher>()) {
      disposed_.clear();
    }

    void dispose() {
      if (!disposed_.test_and_set()) {
        std::shared_lock lock(engines_cs_);
        for (auto &descriptor : engines_)
          std::reinterpret_pointer_cast<IDisposable>(descriptor.second)
              ->dispose();

        dispatcher_->dispose();
      }
    }

    template <typename EventKey, typename... Args>
    auto getEngine() {
      using EngineType =
          SubscriptionEngine<EventKey,
                             Dispatcher,
                             Subscriber<EventKey, Dispatcher, Args...>>;
      constexpr auto engineId = getSubscriptionType<Args...>();
      {
        std::shared_lock lock(engines_cs_);
        if (auto it = engines_.find(engineId); it != engines_.end()) {
          return std::reinterpret_pointer_cast<EngineType>(it->second);
        }
      }
      std::unique_lock lock(engines_cs_);
      if (auto it = engines_.find(engineId); it != engines_.end()) {
        return std::reinterpret_pointer_cast<EngineType>(it->second);
      }
      auto obj = std::make_shared<EngineType>(dispatcher_);
      engines_[engineId] = std::reinterpret_pointer_cast<void>(obj);
      return obj;
    }

    template <typename EventKey, typename... Args>
    void notify(const EventKey &key, Args const &... args) {
      notifyDelayed(std::chrono::microseconds(0ull), key, args...);
    }

    template <typename EventKey, typename... Args>
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
        std::shared_lock lock(engines_cs_);
        if (auto it = engines_.find(engineId); it != engines_.end())
          engine = std::reinterpret_pointer_cast<EngineType>(it->second);
        else
          return;
      }
      assert(engine);
      engine->notifyDelayed(timeout, key, args...);
    }

    DispatcherPtr dispatcher() const {
      return dispatcher_;
    }
  };
}  // namespace iroha::subscription

#endif  // IROHA_SUBSCRIPTION_SUBSCRIPTION_MANAGER_HPP
