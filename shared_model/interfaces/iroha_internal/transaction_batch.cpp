/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/iroha_internal/transaction_batch.hpp"

#include "interfaces/transaction.hpp"
#include "utils/string_builder.hpp"

namespace shared_model {
  namespace interface {

    std::string TransactionBatch::toString() const {
      return detail::PrettyStringBuilder()
          .init("TransactionBatch")
          .appendNamed("Transactions", transactions())
          .finalize();
    }

  }  // namespace interface
}  // namespace shared_model
