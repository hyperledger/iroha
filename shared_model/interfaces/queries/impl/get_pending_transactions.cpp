/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/queries/get_pending_transactions.hpp"

#include "interfaces/queries/tx_pagination_meta.hpp"

namespace shared_model {
  namespace interface {

    std::string GetPendingTransactions::toString() const {
      return detail::PrettyStringBuilder()
          .init("GetPendingTransactions")
          .append("pagination_meta", paginationMeta().toString())
          .finalize();
    }

    bool GetPendingTransactions::operator==(const ModelType &rhs) const {
      return true;
    }

  }  // namespace interface
}  // namespace shared_model
