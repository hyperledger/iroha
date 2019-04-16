/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_YAC_TIMER_HPP
#define IROHA_MOCK_YAC_TIMER_HPP

#include <gmock/gmock.h>

#include "consensus/yac/timer.hpp"

namespace iroha {
  namespace consensus {
    namespace yac {

      class MockTimer : public Timer {
       public:
        void invokeAfterDelay(std::function<void()> handler) override {
          handler();
        }

        MOCK_METHOD0(deny, void());

        MockTimer() = default;

        MockTimer(const MockTimer &rhs) {}

        MockTimer &operator=(const MockTimer &rhs) {
          return *this;
        }
      };

    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha
#endif  // IROHA_MOCK_YAC_TIMER_HPP
