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
        MOCK_METHOD(void,
                    vote,
                    (YacHash, ClusterOrdering, std::optional<ClusterOrdering>),
                    (override));

        MOCK_METHOD((std::optional<Answer>),
                    processRoundSwitch,
                    (consensus::Round const &,
                     shared_model::interface::types::PeerList const &,
                     shared_model::interface::types::PeerList const &),
                    (override));

        MOCK_METHOD0(stop, void());
      };

    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha

#endif  // IROHA_MOCK_YAC_HASH_GATE_HPP
