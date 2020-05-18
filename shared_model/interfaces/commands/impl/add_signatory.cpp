/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/commands/add_signatory.hpp"

namespace shared_model {
  namespace interface {

    std::string AddSignatory::toString() const {
      return detail::PrettyStringBuilder()
          .init("AddSignatory")
          .appendNamed("pubkey", pubkey())
          .appendNamed("account_id", accountId())
          .finalize();
    }

    bool AddSignatory::operator==(const ModelType &rhs) const {
      return pubkey() == rhs.pubkey() and accountId() == rhs.accountId();
    }

  }  // namespace interface
}  // namespace shared_model
