/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_set_setting_value.hpp"

namespace shared_model {
  namespace proto {

    SetSettingValue::SetSettingValue(iroha::protocol::Command &command)
        : set_setting_value_{command.set_setting_value()} {}

    const interface::types::SettingKeyType &SetSettingValue::key() const {
      return set_setting_value_.key();
    }

    const interface::types::SettingValueType &SetSettingValue::value() const {
      return set_setting_value_.value();
    }

  }  // namespace proto
}  // namespace shared_model