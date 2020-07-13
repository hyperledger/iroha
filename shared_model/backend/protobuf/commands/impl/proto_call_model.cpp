/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_call_model.hpp"
#include "commands.pb.h"

namespace shared_model {
  namespace proto {

    CallModel::CallModel(iroha::protocol::Command &command)
        : call_model_{command.call_model()} {}

    CallModel::~CallModel() = default;

    const std::string &CallModel::name() const {
      const iroha::protocol::DataModelId &dm_id = call_model_.dm_id();
      return dm_id.name();
    }

    const std::string &CallModel::version() const {
      const iroha::protocol::DataModelId &dm_id = call_model_.dm_id();
      return dm_id.version();
    }

    const iroha::protocol::CallModel &CallModel::getTransport() const {
      return call_model_;
    }

    bool CallModel::operator==(const CallModel &rhs) const {
      return (name() == rhs.name() && version() == rhs.version());
    }

  }  // namespace proto
}  // namespace shared_model
