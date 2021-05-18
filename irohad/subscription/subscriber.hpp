/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SUBSCRIPTION_SUBSCRIBER_HPP
#define IROHA_SUBSCRIPTION_SUBSCRIBER_HPP

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>

#include "common/common.hpp"

namespace iroha::subscription {

  using SubscriptionSetId = uint32_t;

  /**
   * Base class that determines the subscriber.
   * @tparam EventKey type of listening event
   * @tparam Dispatcher thread dispatcher to execute tasks
   * @tparam Arguments list of event arguments
   */
  template <typename EventKey, typename Dispatcher, typename... Arguments>
  class Subscriber : public std::enable_shared_from_this<
                         Subscriber<EventKey, Dispatcher, Arguments...>>,
                     utils::NoMove,
                     utils::NoCopy {
   public:
    using EventType = EventKey;
    virtual ~Subscriber() = default;

    /**
     * Notification callback function
     * @param set_id the id of the subscription set
     * @param key notified event
     * @param args event data
     */
    virtual void on_notify(SubscriptionSetId set_id,
                           const EventType &key,
                           Arguments &&... args) = 0;
  };

}  // namespace iroha::subscription

#endif  // IROHA_SUBSCRIPTION_SUBSCRIBER_HPP
