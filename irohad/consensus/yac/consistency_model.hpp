/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CONSENSUS_CONSISTENCY_MODEL_HPP
#define IROHA_CONSENSUS_CONSISTENCY_MODEL_HPP

namespace iroha::consensus::yac {
  enum class ConsistencyModel {
    kBft,  ///< BFT consistency
    kCft,  ///< CFT consistency
  };
}  // namespace iroha::consensus::yac

#endif  // IROHA_CONSENSUS_CONSISTENCY_MODEL_HPP
