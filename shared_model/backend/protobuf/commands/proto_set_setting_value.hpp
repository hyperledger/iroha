/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_SET_SETTING_VALUE_HPP
#define IROHA_PROTO_SET_SETTING_VALUE_HPP

#include "commands.pb.h"
#include "interfaces/commands/set_setting_value.hpp"

namespace shared_model {
  namespace proto {
    class SetSettingValue final : public interface::SetSettingValue {
     public:
      explicit SetSettingValue(iroha::protocol::Command &command);

      const interface::types::SettingKeyType &key() const override;

      const interface::types::SettingValueType &value() const override;

     private:
      const iroha::protocol::SetSettingValue &set_setting_value_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_SET_SETTING_VALUE_HPP
