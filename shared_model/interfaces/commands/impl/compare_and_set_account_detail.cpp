/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/commands/compare_and_set_account_detail.hpp"

namespace shared_model {
  namespace interface {

    std::string CompareAndSetAccountDetail::toString() const {
      return detail::PrettyStringBuilder()
          .init("CompareAndSetAccountDetail")
          .append("account_id", accountId())
          .append("key", key())
          .append("value", value())
          .append("old_value", oldValue().value_or("(none)"))
          .finalize();
    }

    bool CompareAndSetAccountDetail::operator==(const ModelType &rhs) const {
      return accountId() == rhs.accountId() and key() == rhs.key()
          and value() == rhs.value() and oldValue() == rhs.oldValue();
    }

  }  // namespace interface
}  // namespace shared_model
