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

#include "subscription/common.hpp"

namespace iroha::subscription {

  using SubscriptionSetId = uint32_t;

  template <typename EventKey,
      typename Dispatcher,
      typename... Arguments>
  class Subscriber : public std::enable_shared_from_this<
      Subscriber<EventKey, Dispatcher, Arguments...>>,
                     utils::NoMove,
                     utils::NoCopy {
   protected:
    Subscriber() = default;

   public:
    using EventType = EventKey;

    virtual ~Subscriber() {}
    virtual void on_notify(SubscriptionSetId set_id,
                           const EventType &key,
                           const Arguments &... args) = 0;
  };

}  // namespace iroha::subscription

#endif  // IROHA_SUBSCRIPTION_SUBSCRIBER_HPP
