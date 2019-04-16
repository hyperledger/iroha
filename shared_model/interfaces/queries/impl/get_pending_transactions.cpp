/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/queries/get_pending_transactions.hpp"

namespace shared_model {
  namespace interface {

    std::string GetPendingTransactions::toString() const {
      return detail::PrettyStringBuilder()
          .init("GetPendingTransactions")
          .finalize();
    }

    bool GetPendingTransactions::operator==(const ModelType &rhs) const {
      return true;
    }

  }  // namespace interface
}  // namespace shared_model
