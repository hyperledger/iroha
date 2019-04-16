/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_YAC_HASH_GATE_HPP
#define IROHA_MOCK_YAC_HASH_GATE_HPP

#include <gmock/gmock.h>

#include "consensus/yac/yac_gate.hpp"

namespace iroha {
  namespace consensus {
    namespace yac {

      class MockHashGate : public HashGate {
       public:
        MOCK_METHOD2(vote, void(YacHash, ClusterOrdering));

        MOCK_METHOD0(onOutcome, rxcpp::observable<Answer>());

        MockHashGate() = default;

        MockHashGate(const MockHashGate &rhs) {}

        MockHashGate(MockHashGate &&rhs) {}

        MockHashGate &operator=(const MockHashGate &rhs) {
          return *this;
        }
      };

    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha

#endif  // IROHA_MOCK_YAC_HASH_GATE_HPP
