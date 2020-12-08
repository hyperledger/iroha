/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_compare_and_set_account_detail.hpp"

namespace shared_model {
  namespace proto {

    CompareAndSetAccountDetail::CompareAndSetAccountDetail(
        iroha::protocol::Command &command)
        : compare_and_set_account_detail_{
              command.compare_and_set_account_detail()} {}

    const interface::types::AccountIdType &
    CompareAndSetAccountDetail::accountId() const {
      return compare_and_set_account_detail_.account_id();
    }

    const interface::types::AccountDetailKeyType &
    CompareAndSetAccountDetail::key() const {
      return compare_and_set_account_detail_.key();
    }

    const interface::types::AccountDetailValueType &
    CompareAndSetAccountDetail::value() const {
      return compare_and_set_account_detail_.value();
    }

    bool CompareAndSetAccountDetail::checkEmpty() const {
      return compare_and_set_account_detail_.check_empty();
    }

    const std::optional<interface::types::AccountDetailValueType>
    CompareAndSetAccountDetail::oldValue() const {
      if (compare_and_set_account_detail_.opt_old_value_case()
          == iroha::protocol::CompareAndSetAccountDetail::
                 OPT_OLD_VALUE_NOT_SET) {
        return std::nullopt;
      }
      return compare_and_set_account_detail_.old_value();
    }

  }  // namespace proto
}  // namespace shared_model
