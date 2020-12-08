/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_ENGINE_TYPE_HPP
#define IROHA_SHARED_MODEL_ENGINE_TYPE_HPP

namespace shared_model::interface {

  /// Type of smart contract engine.
  enum class EngineType {
    kSolidity = 0,
  };

}  // namespace shared_model::interface

#endif
