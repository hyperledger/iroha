/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_CALL_ENGINE_HPP
#define IROHA_SHARED_MODEL_CALL_ENGINE_HPP

#include <functional>
#include <optional>
#include <string>

#include "interfaces/engine_type.hpp"

namespace shared_model::interface {

  /**
   * Call smart contract engine to deploy or execute a contract.
   */
  class CallEngine {
   public:
    using ModelType = CallEngine;

    virtual ~CallEngine();

    /**
     * @return which smart contract engine is to be called.
     */
    virtual EngineType type() const = 0;

    /**
     * @return hex address of the overriding caller address, on behalf of which
     * the contract is to be executed
     */
    virtual const std::string &caller() const = 0;

    /**
     * @return hex address of the called contract
     */
    virtual std::optional<std::reference_wrapper<const std::string>> callee()
        const = 0;

    /**
     * @return hex engine input data
     */
    virtual const std::string &input() const = 0;

    std::string toString() const;

    bool operator==(const CallEngine &rhs) const;
  };
}  // namespace shared_model::interface

#endif
