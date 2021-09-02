/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SUBSCRIPTION_SUBSCRIPTION_MANAGER_HPP
#define IROHA_SUBSCRIPTION_SUBSCRIPTION_MANAGER_HPP

#include <assert.h>
#include <memory>
#include <shared_mutex>
#include <unordered_map>

#include "common/common.hpp"
#include "common/compile-time_murmur2.hpp"
#include "subscription/dispatcher.hpp"
#include "subscription/subscriber.hpp"
#include "subscription/subscription_engine.hpp"

namespace iroha::subscription {

  /**
   * Class-aggregator that keeps all event engines inside. On notification it
   * selects the appropriate engine and calls notification in it.
   * @tparam kHandlersCount number of supported thread handlers
   * @tparam kPoolSize number of threads in thread pool
   */
  template <uint32_t kHandlersCount, uint32_t kPoolSize>
  class SubscriptionManager final
      : public std::enable_shared_from_this<
            SubscriptionManager<kHandlersCount, kPoolSize>>,
        utils::NoMove,
        utils::NoCopy {
   public:
    using Dispatcher = subscription::IDispatcher;

   private:
    using EngineHash = uint64_t;
    using DispatcherPtr = std::shared_ptr<Dispatcher>;
    using EnginesList = std::unordered_map<EngineHash, std::shared_ptr<void>>;

   private:
    /// Thread handlers dispatcher
    DispatcherPtr dispatcher_;
    std::shared_mutex engines_cs_;
    /// Engines container
    EnginesList engines_;
    std::atomic_flag disposed_;

   private:
    template <typename... Args>
    static constexpr EngineHash getSubscriptionHash() {
#ifdef _WIN32
      constexpr EngineHash value = CT_MURMUR2(__FUNCSIG__);
#else   //_WIN32
      constexpr EngineHash value = CT_MURMUR2(__PRETTY_FUNCTION__);
#endif  //_WIN32
      return value;
    }

   public:
    SubscriptionManager(DispatcherPtr dispatcher)
        : dispatcher_(std::move(dispatcher)) {
      disposed_.clear();
    }

    /**
     * Detaches the dispatcher from all engines and stops thread handlers
     * execution.
     */
    void dispose() {
      if (!disposed_.test_and_set()) {
        {
          std::shared_lock lock(engines_cs_);
          for (auto &descriptor : engines_)
            utils::reinterpret_pointer_cast<IDisposable>(descriptor.second)
                ->dispose();
        }
        dispatcher_->dispose();
      }
    }

    /**
     * Method returns the engine corresponding to current arguments set
     * transmission.
     * @tparam EventKey typeof event enum
     * @tparam Args arguments list of transmitted event data types
     * @return engine object
     */
    template <typename EventKey, typename... Args>
    auto getEngine() {
      using EngineType =
          SubscriptionEngine<EventKey,
                             Dispatcher,
                             Subscriber<EventKey, Dispatcher, Args...>>;
      constexpr auto engineId = getSubscriptionHash<Args...>();
      {
        std::shared_lock lock(engines_cs_);
        if (auto it = engines_.find(engineId); it != engines_.end()) {
          return utils::reinterpret_pointer_cast<EngineType>(it->second);
        }
      }
      std::unique_lock lock(engines_cs_);
      if (auto it = engines_.find(engineId); it != engines_.end()) {
        return utils::reinterpret_pointer_cast<EngineType>(it->second);
      }

      /// To be sure IDisposable is the first base class, because of later cast
      static_assert(std::is_base_of_v<IDisposable, EngineType>,
                    "Engine type must be derived from IDisposable.");
      assert(uintptr_t(reinterpret_cast<EngineType *>(0x1))
             == uintptr_t(static_cast<IDisposable *>(
                    reinterpret_cast<EngineType *>(0x1))));

      auto obj = std::make_shared<EngineType>(dispatcher_);
      engines_[engineId] = utils::reinterpret_pointer_cast<void>(obj);
      return obj;
    }

    /**
     * Make event notification to subscribers that are listening to this event
     * @tparam EventKey typeof event enum
     * @tparam Args arguments list of transmitted event data types
     * @param key event key
     * @param args transmitted data
     */
    template <typename EventKey, typename... Args>
    void notify(const EventKey &key, Args const &... args) {
      notifyDelayed(std::chrono::microseconds(0ull), key, args...);
    }

    /**
     * Make event notification to subscribers that are listening this event
     * after a delay
     * @tparam EventKey typeof event enum
     * @tparam Args arguments list of transmitted event data types
     * @param timeout delay before subscribers will be notified
     * @param key event key
     * @param args transmitted data
     */
    template <typename EventKey, typename... Args>
    void notifyDelayed(std::chrono::microseconds timeout,
                       const EventKey &key,
                       Args const &... args) {
      using EngineType =
          SubscriptionEngine<EventKey,
                             Dispatcher,
                             Subscriber<EventKey, Dispatcher, Args...>>;
      constexpr auto engineId = getSubscriptionHash<Args...>();
      std::shared_ptr<EngineType> engine;
      {
        std::shared_lock lock(engines_cs_);
        if (auto it = engines_.find(engineId); it != engines_.end())
          engine = utils::reinterpret_pointer_cast<EngineType>(it->second);
        else
          return;
      }
      assert(engine);
      engine->notifyDelayed(timeout, key, args...);
    }

    /**
     * Getter to retrieve a dispatcher.
     * @return dispatcher object
     */
    DispatcherPtr dispatcher() const {
      return dispatcher_;
    }
  };
}  // namespace iroha::subscription

#endif  // IROHA_SUBSCRIPTION_SUBSCRIPTION_MANAGER_HPP
