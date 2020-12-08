/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/commands/create_account.hpp"

namespace shared_model {
  namespace interface {

    std::string CreateAccount::toString() const {
      return detail::PrettyStringBuilder()
          .init("CreateAccount")
          .appendNamed("account_name", accountName())
          .appendNamed("domain_id", domainId())
          .appendNamed("public_key", pubkey())
          .finalize();
    }

    bool CreateAccount::operator==(const ModelType &rhs) const {
      return accountName() == rhs.accountName() and domainId() == rhs.domainId()
          and pubkey() == rhs.pubkey();
    }

  }  // namespace interface
}  // namespace shared_model
