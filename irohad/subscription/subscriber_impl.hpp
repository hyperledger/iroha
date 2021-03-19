/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SUBSCRIPTION_SUBSCRIBER_IMPL_HPP
#define IROHA_SUBSCRIPTION_SUBSCRIBER_IMPL_HPP

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>

#include "subscription/common.hpp"
#include "subscription/subscriber.hpp"
#include "subscription/subscription_engine.hpp"

namespace iroha::subscription {

  /**
   * Is a wrapper class, which provides subscription to events from
   * SubscriptionEngine
   * @tparam EventKey is a type of a particular subscription event (might be a
   * key from an observed storage or a specific event type from an enumeration).
   * @tparam Dispatcher thread dispatcher
   * @tparam Receiver is a type of an object which is a part of Subscriber's
   * internal state and can be accessed on every event notification.
   * @tparam Arguments is a set of types of objects that are passed on every
   * event notification.
   */
  template <typename EventKey,
            typename Dispatcher,
            typename Receiver,
            typename... Arguments>
  class SubscriberImpl final
      : public Subscriber<EventKey, Dispatcher, Arguments...> {
   public:
    using ReceiverType = Receiver;
    using Hash = size_t;
    using Parent = Subscriber<EventKey, Dispatcher, Arguments...>;

    using SubscriptionEngineType = SubscriptionEngine<
        typename Parent::EventType,
        Dispatcher,
        Subscriber<typename Parent::EventType, Dispatcher, Arguments...>>;
    using SubscriptionEnginePtr = std::shared_ptr<SubscriptionEngineType>;
    using SubscriptionEngineWPtr = std::weak_ptr<SubscriptionEngineType>;

    using CallbackFnType =
        std::function<void(SubscriptionSetId,
                           ReceiverType &,
                           const typename Parent::EventType &,
                           const Arguments &...)>;

   private:
    using SubscriptionsContainer =
        std::unordered_map<typename Parent::EventType,
                           typename SubscriptionEngineType::IteratorType>;
    using SubscriptionsSets =
        std::unordered_map<SubscriptionSetId, SubscriptionsContainer>;

    std::atomic<SubscriptionSetId> next_id_;
    SubscriptionEngineWPtr engine_;
    ReceiverType object_;

    std::mutex subscriptions_cs_;
    SubscriptionsSets subscriptions_sets_;

    CallbackFnType on_notify_callback_;

   public:
    template <typename... SubscriberConstructorArgs>
    SubscriberImpl(SubscriptionEnginePtr const &ptr,
                   SubscriberConstructorArgs &&... args)
        : next_id_(0ull),
          engine_(ptr),
          object_(std::forward<SubscriberConstructorArgs>(args)...) {}

    ~SubscriberImpl() {
      // Unsubscribe all
      if (auto engine = engine_.lock())
        for (auto &[_, subscriptions] : subscriptions_sets_)
          for (auto &[key, it] : subscriptions) engine->unsubscribe(key, it);
    }

    void setCallback(CallbackFnType &&f) {
      on_notify_callback_ = std::move(f);
    }

    SubscriptionSetId generateSubscriptionSetId() {
      return ++next_id_;
    }

    template <typename Dispatcher::Tid kTid>
    void subscribe(const typename Parent::EventType &key) {
      return subscribe<kTid>(0,key);
    }

    template <typename Dispatcher::Tid kTid>
    void subscribe(const typename Parent::EventType &key, CallbackFnType &&f) {
      setCallback(std::move(f));
      return subscribe<kTid>(0,key);
    }

    template <typename Dispatcher::Tid kTid>
    void subscribe(SubscriptionSetId id,
                   const typename Parent::EventType &key) {
      if (auto engine = engine_.lock()) {
        std::lock_guard lock(subscriptions_cs_);
        auto &&[it, inserted] = subscriptions_sets_[id].emplace(
            key, typename SubscriptionEngineType::IteratorType{});

        /// Here we check first local subscriptions because of strong connection
        /// with SubscriptionEngine.
        if (inserted)
          it->second = engine->template subscribe<kTid>(
              id, key, Parent::weak_from_this());
      }
    }

    /**
     * @param id -- subscription set id that unsubscribes from \arg key
     * @param key -- event key to unsubscribe from
     * @return true if was subscribed to \arg key, false otherwise
     */
    bool unsubscribe(SubscriptionSetId id,
                     const typename Parent::EventType &key) {
      std::lock_guard<std::mutex> lock(subscriptions_cs_);
      if (auto set_it = subscriptions_sets_.find(id);
          set_it != subscriptions_sets_.end()) {
        auto &subscriptions = set_it->second;
        auto it = subscriptions.find(key);
        if (subscriptions.end() != it) {
          if (auto engine = engine_.lock())
            engine->unsubscribe(key, it->second);
          subscriptions.erase(it);
          return true;
        }
      }
      return false;
    }

    /**
     * @param id -- subscription set id to unsubscribe from
     * @return true if was subscribed to \arg id, false otherwise
     */
    bool unsubscribe(SubscriptionSetId id) {
      std::lock_guard<std::mutex> lock(subscriptions_cs_);
      if (auto set_it = subscriptions_sets_.find(id);
          set_it != subscriptions_sets_.end()) {
        if (auto engine = engine_.lock()) {
          auto &subscriptions = set_it->second;
          for (auto &[key, it] : subscriptions) engine->unsubscribe(key, it);
        }

        subscriptions_sets_.erase(set_it);
        return true;
      }
      return false;
    }

    void unsubscribe() {
      std::lock_guard<std::mutex> lock(subscriptions_cs_);
      if (auto engine = engine_.lock())
        for (auto &[_, subscriptions] : subscriptions_sets_)
          for (auto &[key, it] : subscriptions) engine->unsubscribe(key, it);

      subscriptions_sets_.clear();
    }

    void on_notify(SubscriptionSetId set_id,
                   const typename Parent::EventType &key,
                   Arguments &&... args) override {
      if (nullptr != on_notify_callback_)
        on_notify_callback_(set_id, object_, key, std::move(args)...);
    }

    ReceiverType &get() {
      return object_;
    }
  };

}  // namespace iroha::subscription

#endif  // IROHA_SUBSCRIPTION_SUBSCRIBER_IMPL_HPP
