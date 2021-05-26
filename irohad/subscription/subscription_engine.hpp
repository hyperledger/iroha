/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SUBSCRIPTION_SUBSCRIPTION_ENGINE_HPP
#define IROHA_SUBSCRIPTION_SUBSCRIPTION_ENGINE_HPP

#include <assert.h>
#include <list>
#include <memory>
#include <shared_mutex>
#include <unordered_map>

#include "common/common.hpp"
#include "subscription/dispatcher.hpp"
#include "subscription/subscriber.hpp"

namespace iroha::subscription {

  struct IDisposable {
    virtual void dispose() = 0;
  };

  /**
   * @tparam EventKey - the type of a specific event from event set (e. g. a key
   * from a storage or a particular kind of event from an enumeration)
   * @tparam Dispatcher - thread handler
   * @tparam Receiver - the type of an object that is a part of a Subscriber
   * internal state and can be accessed on every event
   */
  template <typename EventKey, typename Dispatcher, typename Receiver>
  class SubscriptionEngine final
      : public IDisposable,
        public std::enable_shared_from_this<
            SubscriptionEngine<EventKey, Dispatcher, Receiver>>,
        utils::NoMove,
        utils::NoCopy {
   public:
    using EventKeyType = EventKey;
    using ReceiverType = Receiver;
    using SubscriberType = Receiver;
    using SubscriberWeakPtr = std::weak_ptr<SubscriberType>;
    using DispatcherType = typename std::decay<Dispatcher>::type;
    using DispatcherPtr = std::shared_ptr<DispatcherType>;

    /// List is preferable here because this container iterators remain
    /// alive after removal from the middle of the container
    /// using custom allocator
    using SubscribersContainer = std::list<std::tuple<typename Dispatcher::Tid,
                                                      SubscriptionSetId,
                                                      SubscriberWeakPtr>>;
    using IteratorType = typename SubscribersContainer::iterator;

   public:
    explicit SubscriptionEngine(DispatcherPtr const &dispatcher)
        : dispatcher_(dispatcher) {
      assert(dispatcher_);
    }
    ~SubscriptionEngine() = default;

    void dispose() override {
      dispatcher_.reset();
    }

   private:
    /// List of subscribers for a single event key
    struct SubscriptionContext final {
      std::mutex subscribers_list_cs;
      SubscribersContainer subscribers_list;
    };
    using KeyValueContainer =
        std::unordered_map<EventKeyType, SubscriptionContext>;

    mutable std::shared_mutex subscribers_map_cs_;

    /// Associative container with lists of subscribers by the event key
    KeyValueContainer subscribers_map_;

    /// Thread handlers dispatcher
    DispatcherPtr dispatcher_;

   public:
    /**
     * Stores Subscriber object to retrieve later notifications
     * @param tid Thread ID in which subscribers callback will be executed
     * @param set_id subscription set id is a group identifier in multiple
     * subscriptions
     * @param key notification event key that this subscriber will listen to
     * @param ptr subscriber weak pointer
     * @return a position in an internal container with subscribers(!!! it must
     * be kept valid in case the other subscriber will be deleted from this
     * container)
     */
    IteratorType subscribe(typename Dispatcher::Tid tid,
                           SubscriptionSetId set_id,
                           const EventKeyType &key,
                           SubscriberWeakPtr ptr) {
      std::unique_lock lock(subscribers_map_cs_);
      auto &subscribers_context = subscribers_map_[key];

      std::lock_guard l(subscribers_context.subscribers_list_cs);
      return subscribers_context.subscribers_list.emplace(
          subscribers_context.subscribers_list.end(),
          std::make_tuple(tid, set_id, std::move(ptr)));
    }

    /**
     * Stops the subscriber from listening to events
     * @param key notification event that must be unsubscribed
     * @param it_remove iterator to the subscribers position
     */
    void unsubscribe(const EventKeyType &key, const IteratorType &it_remove) {
      std::unique_lock lock(subscribers_map_cs_);
      auto it = subscribers_map_.find(key);
      if (subscribers_map_.end() != it) {
        auto &subscribers_context = it->second;
        std::lock_guard l(subscribers_context.subscribers_list_cs);
        subscribers_context.subscribers_list.erase(it_remove);
        if (subscribers_context.subscribers_list.empty())
          subscribers_map_.erase(it);
      }
    }

    /**
     * Number of subscribers which listen to the current notification event
     * @param key notification event
     * @return number of subscribers
     */
    size_t size(const EventKeyType &key) const {
      std::shared_lock lock(subscribers_map_cs_);
      if (auto it = subscribers_map_.find(key); it != subscribers_map_.end()) {
        auto &subscribers_context = it->second;
        std::lock_guard l(subscribers_context.subscribers_list_cs);
        return subscribers_context.subscribers_list.size();
      }
      return 0ull;
    }

    /**
     * Number of subscribers which listen to all notification events
     * @return number of subscribers
     */
    size_t size() const {
      std::shared_lock lock(subscribers_map_cs_);
      size_t count = 0ull;
      for (auto &it : subscribers_map_) {
        auto &subscribers_context = it->second;
        std::lock_guard l(subscribers_context.subscribers_list_cs);
        count += subscribers_context.subscribers_list.size();
      }
      return count;
    }

    /**
     * Notify the event subscribers without delay
     * @tparam EventParams notification event type
     * @param key notification event to be executed
     * @param args event data to transmit
     */
    template <typename... EventParams>
    void notify(const EventKeyType &key, EventParams const &... args) {
      notifyDelayed(std::chrono::microseconds(0ull), key, args...);
    }

    /**
     * Notify the event subscribers after a specified delay
     * @tparam EventParams notification event type
     * @param timeout delay before subscribers will be notified
     * @param key notification event to be executed
     * @param args event data to transmit
     */
    template <typename... EventParams>
    void notifyDelayed(std::chrono::microseconds timeout,
                       const EventKeyType &key,
                       EventParams const &... args) {
      auto dispatcher = dispatcher_;
      if (!dispatcher)
        return;

      std::shared_lock lock(subscribers_map_cs_);
      auto it = subscribers_map_.find(key);
      if (subscribers_map_.end() == it)
        return;

      auto &subscribers_container = it->second;
      std::lock_guard l(subscribers_container.subscribers_list_cs);
      for (auto it_sub = subscribers_container.subscribers_list.begin();
           it_sub != subscribers_container.subscribers_list.end();) {
        auto wsub = std::get<2>(*it_sub);
        auto id = std::get<1>(*it_sub);

        if (!wsub.expired()) {
          dispatcher->addDelayed(std::get<0>(*it_sub),
                                 timeout,
                                 [wsub(std::move(wsub)),
                                  id(id),
                                  key(key),
                                  args = std::make_tuple(args...)]() mutable {
                                   if (auto sub = wsub.lock())
                                     std::apply(
                                         [&](auto &&... args) {
                                           sub->on_notify(
                                               id, key, std::move(args)...);
                                         },
                                         std::move(args));
                                 });
          ++it_sub;
        } else {
          it_sub = subscribers_container.subscribers_list.erase(it_sub);
        }
      }
    }
  };

}  // namespace iroha::subscription

#endif  // IROHA_SUBSCRIPTION_SUBSCRIPTION_ENGINE_HPP
