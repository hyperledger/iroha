/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_RECONNECTION_STRATEGY_HPP
#define IROHA_RECONNECTION_STRATEGY_HPP

#include <memory>

namespace iroha {
  namespace ametsuchi {
    class ReconnectionStrategy {
     public:
      virtual bool canReconnect() = 0;
      virtual void reset() = 0;
      virtual ~ReconnectionStrategy() = default;
    };

    class ReconnectionStrategyFactory {
     public:
      virtual std::shared_ptr<ReconnectionStrategy>
      create() = 0;

      virtual ~ReconnectionStrategyFactory() = default;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_RECONNECTION_STRATEGY_HPP
