/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_CALL_MODEL_HPP
#define IROHA_SHARED_MODEL_PROTO_CALL_MODEL_HPP

#include "interfaces/commands/call_model.hpp"

#include "commands.pb.h"

namespace shared_model::proto {
  class CallModel : public shared_model::interface::CallModel {
   public:
    explicit CallModel(iroha::protocol::Command &command);

    virtual ~CallModel();

    const std::string &name() const override;

    const std::string &version() const override;

    const iroha::protocol::CallModel &getTransport() const;

    bool operator==(const CallModel &rhs) const;

   private:
    const iroha::protocol::CallModel &call_model_;
  };
}  // namespace shared_model::proto

#endif
