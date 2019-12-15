/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/commands/set_quorum.hpp"

namespace shared_model {
  namespace interface {

    std::string SetQuorum::toString() const {
      return detail::PrettyStringBuilder()
          .init("SetQuorum")
          .appendNamed("account_id", accountId())
          .appendNamed("quorum", newQuorum())
          .finalize();
    }

    bool SetQuorum::operator==(const ModelType &rhs) const {
      return accountId() == rhs.accountId() and newQuorum() == rhs.newQuorum();
    }

  }  // namespace interface
}  // namespace shared_model
