/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/reconnection_strategy.hpp"

#ifndef IROHA_AMETSUCHI_STUBBORN_RECONNECTION_STRATEGY_HPP
#define IROHA_AMETSUCHI_STUBBORN_RECONNECTION_STRATEGY_HPP

namespace iroha {
  namespace ametsuchi {
    /**
     * Class provides a strategy for reconnection with unlimited number of
     * attempts
     */
    class StubbornReconnectionStrategy : public ReconnectionStrategy {
     public:
      bool canReconnect() override;
      void reset() override;
    };

    class StubbornReconnectionStrategyFactory
        : public ReconnectionStrategyFactory {
     public:
      std::unique_ptr<ReconnectionStrategy> create() const override;
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_K_TIMES_RECONNECTION_STRATEGY_HPP
