/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SYNCHRONIZER_HPP
#define IROHA_SYNCHRONIZER_HPP

#include <optional>

#include "consensus/gate_object.hpp"
#include "synchronizer/synchronizer_common.hpp"

namespace iroha {
  namespace synchronizer {
    /**
     * Synchronizer is interface for fetching missed blocks
     */
    class Synchronizer {
     public:
      /**
       * Processing entry point for consensus outcome
       */
      virtual std::optional<SynchronizationEvent> processOutcome(
          consensus::GateObject object) = 0;

      virtual ~Synchronizer() = default;
    };

  }  // namespace synchronizer
}  // namespace iroha
#endif  // IROHA_SYNCHRONIZER_HPP
