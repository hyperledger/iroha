/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SUBSCRIPTION_SUBSCRIPTION_MANAGER_HPP
#define IROHA_SUBSCRIPTION_SUBSCRIPTION_MANAGER_HPP

#include <memory>
#include <shared_mutex>
#include <unordered_map>

#include "subscription/common.hpp"
#include "subscription/dispatcher.hpp"
#include "subscription/subscriber.hpp"
#include "subscription/subscription_engine.hpp"
#include "common/compile-time_murmur2.hpp"

namespace iroha::subscription {

  template <uint32_t kHandlersCount>
  class SubscriptionManager final : public std::enable_shared_from_this<
                                        SubscriptionManager<kHandlersCount>>,
                                    utils::NoMove,
                                    utils::NoCopy {
   public:
   private:
    using EngineHash = uint64_t;
    using Dispatcher = subscription::Dispatcher<kHandlersCount>;
    using DispatcherPtr = std::shared_ptr<Dispatcher>;
    using EnginesList = std::unordered_map<EngineHash, std::shared_ptr<void *>>;

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

    template <typename EventKey,
              typename Dispatcher,
              typename Receiver,
              typename... Args>
    auto getOrCreate() {
      constexpr auto engineId = getSubscriptionType<Args...>();
      std::lock_guard lock(engines_cs_);
      if (auto it = engines_.find(engineId); it != engines_.end()) {
        return std::reinterpret_pointer_cast<
            SubscriptionEngine<EventKey, Dispatcher, Receiver>>(it->second);
      }
      auto obj =
          std::make_shared<SubscriptionEngine<EventKey, Dispatcher, Receiver>>(
              dispatcher_);
      engines_[engineId] = obj;
      return obj;
    }

    template <typename EventKey,
              typename Dispatcher,
              typename Receiver,
              typename... Args>
    auto get() {
      constexpr auto engineId = getSubscriptionType<Args...>();
      std::lock_guard lock(engines_cs_);
      if (auto it = engines_.find(engineId); it != engines_.end()) {
        return std::reinterpret_pointer_cast<
            SubscriptionEngine<EventKey, Dispatcher, Receiver>>(it->second);
      }
      return std::shared_ptr<
          SubscriptionEngine<EventKey, Dispatcher, Receiver>>();
    }

   public:
    SubscriptionManager() : dispatcher_(std::make_shared<Dispatcher>()) {}

    template <typename Dispatcher::Tid kTid,
              typename EventKey,
              typename Dispatcher,
              typename Receiver,
              typename... Arguments>
    auto subscribe(
        SubscriptionSetId set_id,
        const EventKey &key,
        std::weak_ptr<Subscriber<EventKey, Dispatcher, Receiver, Arguments...>>
            ptr) {}
  };
}  // namespace iroha::subscription

#endif  // IROHA_SUBSCRIPTION_SUBSCRIPTION_MANAGER_HPP
