/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/queries/get_pending_transactions.hpp"

#include "common/optional_reference_equal.hpp"
#include "interfaces/queries/tx_pagination_meta.hpp"

namespace shared_model {
  namespace interface {

    std::string GetPendingTransactions::toString() const {
      auto builder =
          detail::PrettyStringBuilder().init("GetPendingTransactions");
      if (paginationMeta()) {
        builder.appendNamed("pagination_meta", paginationMeta());
      }
      return builder.finalize();
    }

    bool GetPendingTransactions::operator==(const ModelType &rhs) const {
      return iroha::optionalReferenceEqual(paginationMeta(),
                                           rhs.paginationMeta());
    }

  }  // namespace interface
}  // namespace shared_model
