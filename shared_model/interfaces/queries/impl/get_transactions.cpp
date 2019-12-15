/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/queries/get_transactions.hpp"

#include "cryptography/hash.hpp"
#include "utils/string_builder.hpp"

namespace shared_model {
  namespace interface {

    std::string GetTransactions::toString() const {
      return detail::PrettyStringBuilder()
          .init("GetTransactions")
          .append(transactionHashes())
          .finalize();
    }

    bool GetTransactions::operator==(const ModelType &rhs) const {
      return transactionHashes() == rhs.transactionHashes();
    }

  }  // namespace interface
}  // namespace shared_model
