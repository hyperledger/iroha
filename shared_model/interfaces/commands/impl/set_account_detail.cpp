/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/commands/set_account_detail.hpp"

namespace shared_model {
  namespace interface {

    std::string SetAccountDetail::toString() const {
      return detail::PrettyStringBuilder()
          .init("SetAccountDetail")
          .appendNamed("account_id", accountId())
          .appendNamed("key", key())
          .appendNamed("value", value())
          .finalize();
    }

    bool SetAccountDetail::operator==(const ModelType &rhs) const {
      return accountId() == rhs.accountId() and key() == rhs.key()
          and value() == rhs.value();
    }

  }  // namespace interface
}  // namespace shared_model
