/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/commands/add_signatory.hpp"

#include "cryptography/public_key.hpp"

namespace shared_model {
  namespace interface {

    std::string AddSignatory::toString() const {
      return detail::PrettyStringBuilder()
          .init("AddSignatory")
          .append("pubkey", pubkey().toString())
          .append("account_id", accountId())
          .finalize();
    }

    bool AddSignatory::operator==(const ModelType &rhs) const {
      return pubkey() == rhs.pubkey() and accountId() == rhs.accountId();
    }

  }  // namespace interface
}  // namespace shared_model
