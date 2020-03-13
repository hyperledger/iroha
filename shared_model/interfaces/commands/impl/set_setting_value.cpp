/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/commands/set_setting_value.hpp"

namespace shared_model {
  namespace interface {

    std::string SetSettingValue::toString() const {
      return detail::PrettyStringBuilder()
          .init("SetSettingValue")
          .appendNamed("key", key())
          .appendNamed("value", value())
          .finalize();
    }

    bool SetSettingValue::operator==(const ModelType &rhs) const {
      return key() == rhs.key() and value() == rhs.value();
    }

  }  // namespace interface
}  // namespace shared_model
