/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROPAGATION_STRATEGY_STUB_HPP
#define IROHA_PROPAGATION_STRATEGY_STUB_HPP

#include "multi_sig_transactions/mst_propagation_strategy.hpp"

namespace iroha {
  class PropagationStrategyStub : public PropagationStrategy {
    rxcpp::observable<PropagationStrategy::PropagationData> emitter() override;
  };
}  // namespace iroha

#endif  // IROHA_PROPAGATION_STRATEGY_STUB_HPP
