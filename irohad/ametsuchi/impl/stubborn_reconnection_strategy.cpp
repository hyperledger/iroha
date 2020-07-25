/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/stubborn_reconnection_strategy.hpp"

using namespace iroha::ametsuchi;

// -------------------- | StubbornReconnectionStrategy | -----------------------

bool StubbornReconnectionStrategy::canReconnect() {
  // you can do it, just keep trying!
  return true;
}
void StubbornReconnectionStrategy::reset() {}

// ------------------- | StubbornReconnectionStrategyFactory | -----------------

std::unique_ptr<ReconnectionStrategy>
StubbornReconnectionStrategyFactory::create() const {
  return std::make_unique<StubbornReconnectionStrategy>();
}
