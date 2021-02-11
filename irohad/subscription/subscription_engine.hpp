/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SUBSCRIPTION_SUBSCRIPTION_ENGINE_HPP
#define IROHA_SUBSCRIPTION_SUBSCRIPTION_ENGINE_HPP

#include <list>
#include <memory>
#include <shared_mutex>
#include <unordered_map>

#include "subscription/dispatcher.hpp"

namespace iroha::subscription {

  template <typename Event, typename Receiver, typename... Arguments>
  class Subscriber;

  using SubscriptionSetId = uint32_t;

  /**
   * @tparam EventKey - the type of a specific event from event set (e. g. a key
   * from a storage or a particular kind of event from an enumeration)
   * @tparam Receiver - the type of an object that is a part of a Subscriber
   * internal state and can be accessed on every event
   * @tparam EventParams - set of types of values passed on each event
   * notification
   */
  template <typename EventKey, typename Receiver>
  class SubscriptionEngine final
      : public std::enable_shared_from_this<
            SubscriptionEngine<EventKey, Receiver>> {
   public:
    using EventKeyType = EventKey;
    using ReceiverType = Receiver;
    using SubscriberType = Receiver;
    using SubscriberWeakPtr = std::weak_ptr<SubscriberType>;

    /// List is preferable here because this container iterators remain
    /// alive after removal from the middle of the container
    /// using custom allocator
    using SubscribersContainer =
        std::list<std::pair<SubscriptionSetId, SubscriberWeakPtr>>;
    using IteratorType = typename SubscribersContainer::iterator;

   public:
    SubscriptionEngine() = default;
    ~SubscriptionEngine() = default;

    SubscriptionEngine(SubscriptionEngine &&) = default;             // NOLINT
    SubscriptionEngine &operator=(SubscriptionEngine &&) = default;  // NOLINT

    SubscriptionEngine(const SubscriptionEngine &) = delete;
    SubscriptionEngine &operator=(const SubscriptionEngine &) = delete;

   private:
    template <typename KeyType, typename ValueType, typename... Args>
    friend class Subscriber;
    using KeyValueContainer =
        std::unordered_map<EventKeyType, SubscribersContainer>;

    mutable std::shared_mutex subscribers_map_cs_;
    KeyValueContainer subscribers_map_;

    IteratorType subscribe(SubscriptionSetId set_id,
                           const EventKeyType &key,
                           SubscriberWeakPtr ptr) {
      std::unique_lock lock(subscribers_map_cs_);
      auto &subscribers_list = subscribers_map_[key];
      return subscribers_list.emplace(subscribers_list.end(),
                                      std::make_pair(set_id, std::move(ptr)));
    }

    void unsubscribe(const EventKeyType &key, const IteratorType &it_remove) {
      std::unique_lock lock(subscribers_map_cs_);
      auto it = subscribers_map_.find(key);
      if (subscribers_map_.end() != it) {
        it->second.erase(it_remove);
        if (it->second.empty())
          subscribers_map_.erase(it);
      }
    }

   public:
    size_t size(const EventKeyType &key) const {
      std::shared_lock lock(subscribers_map_cs_);
      if (auto it = subscribers_map_.find(key); it != subscribers_map_.end())
        return it->second.size();

      return 0ull;
    }

    size_t size() const {
      std::shared_lock lock(subscribers_map_cs_);
      size_t count = 0ull;
      for (auto &it : subscribers_map_) count += it.second.size();
      return count;
    }

    template<typename... EventParams>
    void notify(const EventKeyType &key, const EventParams &... args) {
      std::shared_lock lock(subscribers_map_cs_);
      auto it = subscribers_map_.find(key);
      if (subscribers_map_.end() == it)
        return;

      auto &subscribers_container = it->second;
      for (auto it_sub = subscribers_container.begin();
           it_sub != subscribers_container.end();) {
        if (auto sub = it_sub->second.lock()) {
          sub->on_notify(it_sub->first, key, args...);
          ++it_sub;
        } else {
          it_sub = subscribers_container.erase(it_sub);
        }
      }
    }
  };

}  // namespace iroha::subscription

#endif  // IROHA_SUBSCRIPTION_SUBSCRIPTION_ENGINE_HPP
