/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_CALL_ENGINE_HPP
#define IROHA_SHARED_MODEL_PROTO_CALL_ENGINE_HPP

#include "interfaces/commands/call_engine.hpp"

namespace iroha::protocol {
  class CallEngine;
  class Command;
}  // namespace iroha::protocol

namespace shared_model::proto {

  class CallEngine : public shared_model::interface::CallEngine {
   public:
    explicit CallEngine(iroha::protocol::Command &command);

    virtual ~CallEngine();

    shared_model::interface::EngineType type() const override;

    const std::string &caller() const override;

    std::optional<std::reference_wrapper<const std::string>> callee()
        const override;

    const std::string &input() const override;

   private:
    const iroha::protocol::CallEngine &call_engine_;
    shared_model::interface::EngineType type_;
  };

}  // namespace shared_model::proto

#endif
