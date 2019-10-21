/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "multi_sig_transactions/mst_propagation_strategy_stub.hpp"

#include <rxcpp/rx-lite.hpp>

namespace iroha {
  rxcpp::observable<PropagationStrategy::PropagationData>
  PropagationStrategyStub::emitter() {
    return rxcpp::observable<>::empty<PropagationStrategy::PropagationData>();
  }
}  // namespace iroha
