/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/queries/get_account.hpp"

namespace shared_model {
  namespace interface {

    std::string GetAccount::toString() const {
      return detail::PrettyStringBuilder()
          .init("GetAccount")
          .appendNamed("account_id", accountId())
          .finalize();
    }

    bool GetAccount::operator==(const ModelType &rhs) const {
      return accountId() == rhs.accountId();
    }

  }  // namespace interface
}  // namespace shared_model
