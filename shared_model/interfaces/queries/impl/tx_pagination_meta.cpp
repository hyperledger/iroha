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
  auto first_tx_time = firstTxTime();
  auto last_tx_time = lastTxTime();
  auto first_tx_height = firstTxHeight();
  auto last_tx_height = lastTxHeight();
  if (first_tx_hash) {
    pretty_builder.appendNamed("first_tx_hash", first_tx_hash);
  }
  if (first_tx_time) {
    pretty_builder.appendNamed("first_tx_time", first_tx_time);
  }
  if (last_tx_time) {
    pretty_builder.appendNamed("last_tx_time", last_tx_time);
  }
  if (first_tx_height) {
    pretty_builder.appendNamed("first_tx_height", first_tx_height);
  }
  if (last_tx_height) {
    pretty_builder.appendNamed("last_tx_height", last_tx_height);
  }
  return pretty_builder.finalize();
}
