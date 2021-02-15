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

  template <uint32_t kHandlersCount>
  class SubscriptionManager final : public std::enable_shared_from_this<
                                        SubscriptionManager<kHandlersCount>>,
                                    utils::NoMove,
                                    utils::NoCopy {
   public:
    using Dispatcher = subscription::Dispatcher<kHandlersCount>;

   private:
    using EngineHash = uint64_t;
    using DispatcherPtr = std::shared_ptr<Dispatcher>;
    using EnginesList = std::unordered_map<EngineHash, std::shared_ptr<void>>;

   private:
    DispatcherPtr dispatcher_;
    std::mutex engines_cs_;
    EnginesList engines_;

   private:
    template <typename... Args>
    static constexpr EngineHash getSubscriptionType() {
      constexpr EngineHash value = CT_MURMUR2(__PRETTY_FUNCTION__);
      return value;
    }

   public:
    SubscriptionManager() : dispatcher_(std::make_shared<Dispatcher>()) {}

    template <typename EventKey, typename... Args>
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
    }

    template <typename EventKey, typename... Args>
    void notify(const EventKey &key, Args &&... args) {
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
        engine->notify(key, std::forward<Args>(args)...);
    }
  };
}  // namespace iroha::subscription

#endif  // IROHA_SUBSCRIPTION_SUBSCRIPTION_MANAGER_HPP
