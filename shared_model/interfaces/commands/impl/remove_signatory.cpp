/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/commands/remove_signatory.hpp"

namespace shared_model {
  namespace interface {

    std::string RemoveSignatory::toString() const {
      return detail::PrettyStringBuilder()
          .init("RemoveSignatory")
          .appendNamed("account_id", accountId())
          .appendNamed("public_key", pubkey())
          .finalize();
    }

    bool RemoveSignatory::operator==(const ModelType &rhs) const {
      return accountId() == rhs.accountId() and pubkey() == rhs.pubkey();
    }

  }  // namespace interface
}  // namespace shared_model
