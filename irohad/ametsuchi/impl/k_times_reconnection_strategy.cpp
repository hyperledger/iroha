/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/k_times_reconnection_strategy.hpp"

using namespace iroha::ametsuchi;

// -------------------- | KTimesReconnectionStrategy | -----------------------

KTimesReconnectionStrategy::KTimesReconnectionStrategy(
    size_t number_of_reconnections)
    : max_number_of_reconnections_(number_of_reconnections),
      current_number_of_reconnections_(0u) {}

bool KTimesReconnectionStrategy::canReconnect() {
  if (current_number_of_reconnections_ > max_number_of_reconnections_) {
    return false;
  }
  return ++current_number_of_reconnections_ <= max_number_of_reconnections_;
}
void KTimesReconnectionStrategy::reset() {
  current_number_of_reconnections_ = 0u;
}

// -------------------- | KTimesReconnectionStrategyFactory | ------------------

KTimesReconnectionStrategyFactory::KTimesReconnectionStrategyFactory(
    size_t number_of_reconnections)
    : max_number_of_reconnections_(number_of_reconnections) {}

std::unique_ptr<ReconnectionStrategy>
KTimesReconnectionStrategyFactory::create() const {
  return std::make_unique<KTimesReconnectionStrategy>(
      max_number_of_reconnections_);
}
