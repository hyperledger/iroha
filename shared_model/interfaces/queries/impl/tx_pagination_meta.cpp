/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/queries/tx_pagination_meta.hpp"

#include "cryptography/hash.hpp"

using namespace shared_model::interface;

bool TxPaginationMeta::operator==(const ModelType &rhs) const {
  return pageSize() == rhs.pageSize() and firstTxHash() == rhs.firstTxHash();
}

std::string TxPaginationMeta::toString() const {
  auto pretty_builder = detail::PrettyStringBuilder()
                            .init("TxPaginationMeta")
                            .appendNamed("page_size", pageSize());
  auto first_tx_hash = firstTxHash();
  if (first_tx_hash) {
    pretty_builder.appendNamed("first_tx_hash", first_tx_hash);
  }
  return pretty_builder.finalize();
}
