/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_RECONNECTION_STRATEGY_HPP
#define IROHA_RECONNECTION_STRATEGY_HPP

#include <memory>

namespace iroha {
  namespace ametsuchi {
    /**
     * Class provides an interface for reconnection condition.
     */
    class ReconnectionStrategy {
     public:
      /**
       * Checks the possibility of reconnection
       * @return true if the reconnection can be performed
       */
      virtual bool canReconnect() = 0;

      /**
       * Reset strategy to default value
       */
      virtual void reset() = 0;

      virtual ~ReconnectionStrategy() = default;
    };

    /**
     * Class provides a factory which creates strategies on request
     */
    class ReconnectionStrategyFactory {
     public:
      virtual std::unique_ptr<ReconnectionStrategy> create() const = 0;

      virtual ~ReconnectionStrategyFactory() = default;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_RECONNECTION_STRATEGY_HPP
