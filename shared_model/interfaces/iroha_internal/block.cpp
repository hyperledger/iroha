/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/iroha_internal/block.hpp"

#include "interfaces/transaction.hpp"
#include "utils/string_builder.hpp"

namespace shared_model {
  namespace interface {

    std::string Block::toString() const {
      return detail::PrettyStringBuilder()
          .init("Block")
          .append("hash", hash().hex())
          .append("height", std::to_string(height()))
          .append("prevHash", prevHash().hex())
          .append("txsNumber", std::to_string(txsNumber()))
          .append("createdtime", std::to_string(createdTime()))
          .append("transactions")
          .appendAll(transactions(), [](auto &tx) { return tx.toString(); })
          .append("signatures")
          .appendAll(signatures(), [](auto &sig) { return sig.toString(); })
          .appendAll("rejected transactions",
                     rejected_transactions_hashes(),
                     [](auto &hash) { return hash.hex(); })
          .finalize();
    }

  }  // namespace interface
}  // namespace shared_model
