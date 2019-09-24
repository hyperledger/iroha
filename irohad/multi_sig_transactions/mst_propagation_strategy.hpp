/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MST_PROPAGATION_STRATEGY_HPP
#define IROHA_MST_PROPAGATION_STRATEGY_HPP

#include <rxcpp/rx-lite.hpp>
#include <vector>
#include "interfaces/common_objects/peer.hpp"

namespace iroha {

  /**
   * Interface provides strategy for propagation states in network
   */
  class PropagationStrategy {
   public:
    virtual ~PropagationStrategy() = default;
    using PropagationData =
        std::vector<std::shared_ptr<shared_model::interface::Peer>>;

    /**
     * Provides observable that will be emit new results
     * with respect to own strategy
     */
    virtual rxcpp::observable<PropagationData> emitter() = 0;
  };
}  // namespace iroha

#endif  // IROHA_MST_PROPAGATION_STRATEGY_HPP
