/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/impl/timer_impl.hpp"

#include "main/subscription.hpp"

using iroha::consensus::yac::TimerImpl;

TimerImpl::TimerImpl(std::chrono::milliseconds delay_milliseconds)
    : delay_milliseconds_(delay_milliseconds) {}

void TimerImpl::invokeAfterDelay(std::function<void()> handler) {
  getSubscription()->dispatcher()->addDelayed(SubscriptionEngineHandlers::kYac,
                                              delay_milliseconds_,
                                              std::move(handler));
}
