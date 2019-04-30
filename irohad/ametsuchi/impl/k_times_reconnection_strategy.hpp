/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/reconnection_strategy.hpp"

#ifndef IROHA_K_TIMES_RECONNECTION_STRATEGY_HPP
#define IROHA_K_TIMES_RECONNECTION_STRATEGY_HPP

namespace iroha {
  namespace ametsuchi {
    class KTimesReconnectionStrategy : public ReconnectionStrategy {
     public:
      KTimesReconnectionStrategy(size_t number_of_reconnections);

      KTimesReconnectionStrategy(const KTimesReconnectionStrategy &) = delete;
      KTimesReconnectionStrategy &operator=(
          const KTimesReconnectionStrategy &) = delete;

      bool canReconnect() override;
      void reset() override;

     private:
      const size_t max_number_of_reconnections_;
      size_t current_number_of_reconnections_;
    };

    class KTimesReconnectionStrategyFactory
        : public ReconnectionStrategyFactory {
     public:
      KTimesReconnectionStrategyFactory(size_t number_of_reconnections);

      std::shared_ptr<ReconnectionStrategy> create() override;

     private:
      const size_t max_number_of_reconnections_;
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_K_TIMES_RECONNECTION_STRATEGY_HPP
